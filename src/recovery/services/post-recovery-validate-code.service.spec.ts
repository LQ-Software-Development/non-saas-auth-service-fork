import { UnauthorizedException } from '@nestjs/common';
import { PostRecoveryValidateCodeService } from './post-recovery-validate-code.service';
import {
  InMemoryRedisLike,
  OtpRateLimitService,
} from './otp-rate-limit.service';
import { LockoutException } from '../exceptions/lockout.exception';
import {
  hashOtp,
  parseVerifiedMarker,
  verifyOtp,
} from '../utils/otp-token.util';

describe('PostRecoveryValidateCodeService', () => {
  let userRepository: {
    findByEmail: jest.Mock;
    update: jest.Mock;
  };
  let redis: InMemoryRedisLike;
  let otpRateLimit: OtpRateLimitService;
  let service: PostRecoveryValidateCodeService;

  const code = '654321';
  let user: {
    _id: string;
    email: string;
    document: string;
    passwordTokenHash: string | null;
    passwordToken?: string | null;
    passwordTokenExpiresAt: Date;
    otpAttempts: number;
    otpBlockedUntil: Date | null;
  };

  beforeEach(async () => {
    userRepository = {
      findByEmail: jest.fn(),
      update: jest.fn().mockResolvedValue({}),
    };
    redis = new InMemoryRedisLike();
    otpRateLimit = new OtpRateLimitService(redis);
    service = new PostRecoveryValidateCodeService(
      userRepository as never,
      otpRateLimit,
    );
    user = {
      _id: 'user-1',
      email: 'ada@example.com',
      document: '12345678900',
      passwordTokenHash: await hashOtp(code),
      passwordTokenExpiresAt: new Date(Date.now() + 5 * 60 * 1000),
      otpAttempts: 0,
      otpBlockedUntil: null,
    };
  });

  it('burns OTP hash and returns one-time resetToken', async () => {
    userRepository.findByEmail.mockResolvedValue(user);

    const result = await service.execute({ email: user.email, token: code });

    expect(result.success).toBe(true);
    expect(result.resetToken).toEqual(expect.any(String));
    expect(result.resetToken.length).toBeGreaterThan(20);

    const [, payload] = userRepository.update.mock.calls[0];
    expect(payload.passwordTokenHash).toBeNull();
    expect(payload.otpAttempts).toBe(0);
    const marker = parseVerifiedMarker(payload.passwordToken);
    expect(marker).not.toBeNull();
    if (!marker) {
      throw new Error('expected verified marker');
    }
    await expect(verifyOtp(result.resetToken, marker.proofHash)).resolves.toBe(
      true,
    );
  });

  it('rejects expired codes', async () => {
    user.passwordTokenExpiresAt = new Date(Date.now() - 1000);
    userRepository.findByEmail.mockResolvedValue(user);

    await expect(
      service.execute({ email: user.email, token: code }),
    ).rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('does not accept legacy plaintext passwordToken', async () => {
    user.passwordTokenHash = null;
    user.passwordToken = code;
    userRepository.findByEmail.mockResolvedValue(user);

    await expect(
      service.execute({ email: user.email, token: code }),
    ).rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('increments attempts and locks after 5 failures', async () => {
    userRepository.findByEmail.mockResolvedValue(user);

    for (let i = 0; i < 4; i++) {
      user.otpAttempts = i;
      await expect(
        service.execute({ email: user.email, token: '000000' }),
      ).rejects.toBeInstanceOf(UnauthorizedException);
    }

    user.otpAttempts = 4;
    await expect(
      service.execute({ email: user.email, token: '000000' }),
    ).rejects.toBeInstanceOf(LockoutException);

    const lastUpdate = userRepository.update.mock.calls[
      userRepository.update.mock.calls.length - 1
    ][1];
    expect(lastUpdate.otpAttempts).toBe(5);
    expect(lastUpdate.otpBlockedUntil).toBeInstanceOf(Date);
  });

  it('rejects when user otpBlockedUntil is in the future', async () => {
    user.otpBlockedUntil = new Date(Date.now() + 60_000);
    userRepository.findByEmail.mockResolvedValue(user);

    await expect(
      service.execute({ email: user.email, token: code }),
    ).rejects.toBeInstanceOf(LockoutException);
  });
});
