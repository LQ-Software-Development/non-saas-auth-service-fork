import { Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { randomBytes } from 'crypto';
import { UserRepositoryInterface } from '../../auth/repositories/user.repository.interface';
import { ValidateCodeDto } from '../dto/validate-code.dto';
import {
  BCRYPT_COST,
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

const INVALID_CODE_MESSAGE = 'Código inválido';

@Injectable()
export class PostRecoveryValidateCodeService {
  constructor(
    @Inject('user-repository')
    private readonly userRepository: UserRepositoryInterface,
    @Inject(OTP_RATE_LIMIT)
    private readonly rateLimit: OtpRateLimitService,
  ) {}

  async execute(validateCodeDto: ValidateCodeDto) {
    const emailKey = validateCodeDto.email.trim().toLowerCase();
    const user = await this.userRepository.findByEmail(validateCodeDto.email);
    if (!user) {
      await this.rateLimit.assertValidateAllowed(emailKey);
      await this.rateLimit.registerValidateFailure(emailKey);
      throw new UnauthorizedException(INVALID_CODE_MESSAGE);
    }

    const throttleKey = resolveOtpThrottleKey(user);
    await this.rateLimit.assertValidateAllowed(throttleKey);

    const parsed = parsePasswordOtpToken(user.passwordToken);
    if (!parsed || isOtpExpired(parsed.expiresAt)) {
      await this.rateLimit.registerValidateFailure(throttleKey);
      throw new UnauthorizedException(INVALID_CODE_MESSAGE);
    }

    const codeValid = await bcrypt.compare(
      validateCodeDto.token.trim(),
      parsed.bcryptHash,
    );
    if (!codeValid) {
      await this.rateLimit.registerValidateFailure(throttleKey);
      throw new UnauthorizedException(INVALID_CODE_MESSAGE);
    }

    const resetProof = randomBytes(32).toString('hex');
    const proofHash = await bcrypt.hash(resetProof, BCRYPT_COST);
    const userId = resolveUserId(user as { _id?: { toString(): string }; id?: string });
    await this.userRepository.update(userId, {
      passwordToken: buildVerifiedMarker(proofHash, parsed.expiresAt),
    });
    await this.rateLimit.clearValidateFailures(throttleKey);

    return { success: true, resetToken: resetProof };
  }
}
