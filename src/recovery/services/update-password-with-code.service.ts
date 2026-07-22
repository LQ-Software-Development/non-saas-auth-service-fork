import { Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { UpdateRecoveryDto } from '../dto/update-recovery.dto';
import { UserRepositoryInterface } from '../../auth/repositories/user.repository.interface';
import {
  isOtpExpired,
  parsePasswordOtpToken,
  parseVerifiedMarker,
  resolveOtpThrottleKey,
  resolveUserId,
} from '../utils/password-otp-token.util';
import {
  OTP_RATE_LIMIT,
  OtpRateLimitService,
} from './otp-rate-limit.service';

const INVALID_CODE_MESSAGE = 'Código inválido';

@Injectable()
export class UpdatePasswordWithCodeService {
  constructor(
    @Inject('user-repository')
    private readonly userRepository: UserRepositoryInterface,
    @Inject(OTP_RATE_LIMIT)
    private readonly rateLimit: OtpRateLimitService,
  ) {}

  async execute(updateRecoveryDto: UpdateRecoveryDto) {
    const { email, token, newPassword } = updateRecoveryDto;
    const emailKey = email.trim().toLowerCase();

    const user = await this.userRepository.findByEmail(email);
    if (!user) {
      await this.rateLimit.assertValidateAllowed(emailKey);
      await this.rateLimit.registerValidateFailure(emailKey);
      throw new UnauthorizedException(INVALID_CODE_MESSAGE);
    }

    const throttleKey = resolveOtpThrottleKey(user);
    await this.rateLimit.assertValidateAllowed(throttleKey);

    const allowed = await this.isChangeAllowed(user.passwordToken, token);
    if (!allowed) {
      await this.rateLimit.registerValidateFailure(throttleKey);
      throw new UnauthorizedException(INVALID_CODE_MESSAGE);
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    const userId = resolveUserId(user as { _id?: { toString(): string }; id?: string });
    await this.userRepository.update(userId, {
      password: hashedPassword,
      passwordToken: null,
    });
    await this.rateLimit.clearValidateFailures(throttleKey);

    return { success: true, message: 'Senha atualizada com sucesso' };
  }

  private async isChangeAllowed(
    stored: string | null | undefined,
    presentedToken: string,
  ): Promise<boolean> {
    const verified = parseVerifiedMarker(stored);
    if (verified) {
      if (isOtpExpired(verified.expiresAt)) {
        return false;
      }
      return bcrypt.compare(presentedToken.trim(), verified.proofHash);
    }

    const parsed = parsePasswordOtpToken(stored);
    if (!parsed || isOtpExpired(parsed.expiresAt)) {
      return false;
    }

    return bcrypt.compare(presentedToken.trim(), parsed.bcryptHash);
  }
}
