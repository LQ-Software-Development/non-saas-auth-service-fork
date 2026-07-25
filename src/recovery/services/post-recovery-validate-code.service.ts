import { Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { randomBytes } from 'crypto';
import { UserRepositoryInterface } from '../../auth/repositories/user.repository.interface';
import { ValidateCodeDto } from '../dto/validate-code.dto';
import { LockoutException } from '../exceptions/lockout.exception';
import {
  OtpRateLimitService,
  OTP_RATE_LIMIT,
} from './otp-rate-limit.service';
import {
  buildVerifiedMarker,
  hashOtp,
  isExpired,
  resolveThrottleKey,
  resolveUserId,
  verifyOtp,
} from '../utils/otp-token.util';

const LOCKOUT_MS = 15 * 60 * 1000;
const MAX_OTP_ATTEMPTS = 5;

@Injectable()
export class PostRecoveryValidateCodeService {
  constructor(
    @Inject('user-repository')
    private readonly userRepository: UserRepositoryInterface,
    @Inject(OTP_RATE_LIMIT)
    private readonly otpRateLimit: OtpRateLimitService,
  ) {}

  async execute(validateCodeDto: ValidateCodeDto) {
    const user = await this.userRepository.findByEmail(validateCodeDto.email);
    const throttleKey = user
      ? resolveThrottleKey(user as { document?: string; email?: string })
      : resolveThrottleKey({ email: validateCodeDto.email });

    await this.otpRateLimit.assertValidateAllowed(throttleKey);

    if (!user) {
      await this.otpRateLimit.registerValidateFailure(throttleKey);
      throw new UnauthorizedException('Token inválido');
    }

    const userRecord = user as {
      _id?: string | { toString(): string };
      id?: string;
      passwordTokenHash?: string | null;
      passwordTokenExpiresAt?: Date | null;
      otpAttempts?: number;
      otpBlockedUntil?: Date | null;
    };

    if (
      userRecord.otpBlockedUntil &&
      new Date(userRecord.otpBlockedUntil).getTime() > Date.now()
    ) {
      throw new LockoutException(
        'Muitas tentativas inválidas. Tente novamente em 15 minutos.',
      );
    }

    const userId = resolveUserId(userRecord);
    const valid =
      !isExpired(userRecord.passwordTokenExpiresAt) &&
      (await verifyOtp(validateCodeDto.token, userRecord.passwordTokenHash));

    if (!valid) {
      const attempts = (userRecord.otpAttempts || 0) + 1;
      const update: Record<string, unknown> = { otpAttempts: attempts };
      if (attempts >= MAX_OTP_ATTEMPTS) {
        update.otpBlockedUntil = new Date(Date.now() + LOCKOUT_MS);
      }
      await this.userRepository.update(userId, update);
      await this.otpRateLimit.registerValidateFailure(throttleKey);
      throw new UnauthorizedException('Token inválido');
    }

    // Single-use OTP: burn hash and exchange for one-time reset proof.
    const expiresAt = userRecord.passwordTokenExpiresAt;
    if (!expiresAt) {
      throw new UnauthorizedException('Token inválido');
    }
    const expiresAtMs = new Date(expiresAt).getTime();
    const resetToken = randomBytes(32).toString('hex');
    const proofHash = await hashOtp(resetToken);
    await this.userRepository.update(userId, {
      passwordToken: buildVerifiedMarker(proofHash, expiresAtMs),
      passwordTokenHash: null,
      passwordTokenExpiresAt: new Date(expiresAtMs),
      otpAttempts: 0,
      otpBlockedUntil: null,
    });
    await this.otpRateLimit.clearValidateFailures(throttleKey);

    return { success: true, resetToken };
  }
}
