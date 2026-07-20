import { Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { UserRepositoryInterface } from '../../auth/repositories/user.repository.interface';
import { ValidateCodeDto } from '../dto/validate-code.dto';
import {
  buildVerifiedMarker,
  isOtpExpired,
  parsePasswordOtpToken,
  resolveOtpThrottleKey,
  resolveUserId,
} from '../utils/password-otp-token.util';
import {
  OTP_RATE_LIMIT,
  OtpRateLimitService,
} from './otp-rate-limit.service';

@Injectable()
export class PostRecoveryValidateCodeService {
  constructor(
    @Inject('user-repository')
    private readonly userRepository: UserRepositoryInterface,
    @Inject(OTP_RATE_LIMIT)
    private readonly rateLimit: OtpRateLimitService,
  ) {}

  async execute(validateCodeDto: ValidateCodeDto) {
    const user = await this.userRepository.findByEmail(validateCodeDto.email);
    if (!user) {
      throw new UnauthorizedException('Usuário não encontrado');
    }

    const throttleKey = resolveOtpThrottleKey(user);
    await this.rateLimit.assertValidateAllowed(throttleKey);

    const parsed = parsePasswordOtpToken(user.passwordToken);
    if (!parsed || isOtpExpired(parsed.expiresAt)) {
      await this.rateLimit.registerValidateFailure(throttleKey);
      throw new UnauthorizedException('Token inválido');
    }

    const codeValid = await bcrypt.compare(
      validateCodeDto.token.trim(),
      parsed.bcryptHash,
    );
    if (!codeValid) {
      await this.rateLimit.registerValidateFailure(throttleKey);
      throw new UnauthorizedException('Token inválido');
    }

    const userId = resolveUserId(user as { _id?: { toString(): string }; id?: string });
    await this.userRepository.update(userId, {
      passwordToken: buildVerifiedMarker(parsed.expiresAt),
    });
    await this.rateLimit.clearValidateFailures(throttleKey);

    return { success: true };
  }
}
