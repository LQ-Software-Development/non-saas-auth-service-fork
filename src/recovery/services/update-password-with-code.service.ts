import { Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { UpdateRecoveryDto } from '../dto/update-recovery.dto';
import { UserRepositoryInterface } from '../../auth/repositories/user.repository.interface';
import { LockoutException } from '../exceptions/lockout.exception';
import {
  OtpRateLimitService,
  OTP_RATE_LIMIT,
} from './otp-rate-limit.service';
import {
  BCRYPT_COST,
  isExpired,
  parseVerifiedMarker,
  resolveThrottleKey,
  resolveUserId,
  verifyOtp,
} from '../utils/otp-token.util';

const LOCKOUT_MS = 15 * 60 * 1000;
const MAX_OTP_ATTEMPTS = 5;

type UserOtpRecord = {
  _id?: string | { toString(): string };
  id?: string;
  passwordToken?: string | null;
  passwordTokenHash?: string | null;
  passwordTokenExpiresAt?: Date | null;
  otpAttempts?: number;
  otpBlockedUntil?: Date | null;
};

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

    const userRecord = user as UserOtpRecord;

    if (
      userRecord.otpBlockedUntil &&
      new Date(userRecord.otpBlockedUntil).getTime() > Date.now()
    ) {
      throw new LockoutException(
        'Muitas tentativas inválidas. Tente novamente em 15 minutos.',
      );
    }

    const userId = resolveUserId(userRecord);
    const valid = await this.isChangeAllowed(userRecord, token);

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

    const hashedPassword = await bcrypt.hash(newPassword, BCRYPT_COST);

    await this.userRepository.update(userId, {
      password: hashedPassword,
      passwordToken: null,
      passwordTokenHash: null,
      passwordTokenExpiresAt: null,
      otpAttempts: 0,
      otpBlockedUntil: null,
    });
    await this.otpRateLimit.clearValidateFailures(throttleKey);

    return { success: true, message: 'Senha atualizada com sucesso' };
  }

  private async isChangeAllowed(
    userRecord: UserOtpRecord,
    presentedToken: string,
  ): Promise<boolean> {
    const verified = parseVerifiedMarker(userRecord.passwordToken);
    if (verified) {
      if (Date.now() >= verified.expiresAtMs) {
        return false;
      }
      return verifyOtp(presentedToken, verified.proofHash);
    }

    return (
      !isExpired(userRecord.passwordTokenExpiresAt) &&
      (await verifyOtp(presentedToken, userRecord.passwordTokenHash))
    );
  }
}
