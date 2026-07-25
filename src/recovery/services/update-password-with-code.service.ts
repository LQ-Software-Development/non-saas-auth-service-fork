import { Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { UpdateRecoveryDto } from '../dto/update-recovery.dto';
import { UserRepositoryInterface } from '../../auth/repositories/user.repository.interface';
import * as bcrypt from 'bcrypt';
import { LockoutException } from '../exceptions/lockout.exception';
import {
  OtpRateLimitService,
  OTP_RATE_LIMIT,
} from './otp-rate-limit.service';
import {
  BCRYPT_COST,
  isExpired,
  resolveThrottleKey,
  resolveUserId,
  verifyOtp,
} from '../utils/otp-token.util';

const LOCKOUT_MS = 15 * 60 * 1000;
const MAX_OTP_ATTEMPTS = 5;

@Injectable()
export class UpdatePasswordWithCodeService {
  constructor(
    @Inject('user-repository')
    private readonly userRepository: UserRepositoryInterface,
    @Inject(OTP_RATE_LIMIT)
    private readonly otpRateLimit: OtpRateLimitService,
  ) {}

  async execute(updateRecoveryDto: UpdateRecoveryDto) {
    const { email, token, newPassword } = updateRecoveryDto;

    const user = await this.userRepository.findByEmail(email);
    const throttleKey = user
      ? resolveThrottleKey(user as { document?: string; email?: string })
      : resolveThrottleKey({ email });

    await this.otpRateLimit.assertValidateAllowed(throttleKey);

    if (!user) {
      await this.otpRateLimit.registerValidateFailure(throttleKey);
      throw new UnauthorizedException('Token inválido');
    }

    const userRecord = user as any;
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
      (await verifyOtp(token, userRecord.passwordTokenHash));

    if (!valid) {
      const attempts = (userRecord.otpAttempts || 0) + 1;
      const update: Record<string, unknown> = { otpAttempts: attempts };
      if (attempts >= MAX_OTP_ATTEMPTS) {
        update.otpBlockedUntil = new Date(Date.now() + LOCKOUT_MS);
      }
      await this.userRepository.update(userId, update as any);
      await this.otpRateLimit.registerValidateFailure(throttleKey);
      throw new UnauthorizedException('Token inválido');
    }

    const hashedPassword = await bcrypt.hash(newPassword, BCRYPT_COST);

    await this.userRepository.update(userId, {
      password: hashedPassword,
      passwordToken: null,
      passwordTokenHash: null,
      passwordTokenExpiresAt: null,
      otpAttempts: 0,
      otpBlockedUntil: null,
    } as any);
    await this.otpRateLimit.clearValidateFailures(throttleKey);

    return { success: true, message: 'Senha atualizada com sucesso' };
  }
}
