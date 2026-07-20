import { Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { UpdateRecoveryDto } from '../dto/update-recovery.dto';
import { UserRepositoryInterface } from '../../auth/repositories/user.repository.interface';
import {
  isOtpExpired,
  parsePasswordOtpToken,
  parseVerifiedMarker,
  resolveUserId,
} from '../utils/password-otp-token.util';

@Injectable()
export class UpdatePasswordWithCodeService {
  constructor(
    @Inject('user-repository')
    private readonly userRepository: UserRepositoryInterface,
  ) {}

  async execute(updateRecoveryDto: UpdateRecoveryDto) {
    const { email, token, newPassword } = updateRecoveryDto;

    const user = await this.userRepository.findByEmail(email);
    if (!user) {
      throw new UnauthorizedException('Usuário não encontrado');
    }

    const allowed = await this.isChangeAllowed(user.passwordToken, token);
    if (!allowed) {
      throw new UnauthorizedException('Token inválido');
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    const userId = resolveUserId(user as { _id?: { toString(): string }; id?: string });
    await this.userRepository.update(userId, {
      password: hashedPassword,
      passwordToken: null,
    });

    return { success: true, message: 'Senha atualizada com sucesso' };
  }

  private async isChangeAllowed(
    stored: string | null | undefined,
    presentedCode: string,
  ): Promise<boolean> {
    const verified = parseVerifiedMarker(stored);
    if (verified) {
      return !isOtpExpired(verified.expiresAt);
    }

    const parsed = parsePasswordOtpToken(stored);
    if (!parsed || isOtpExpired(parsed.expiresAt)) {
      return false;
    }

    return bcrypt.compare(presentedCode.trim(), parsed.bcryptHash);
  }
}
