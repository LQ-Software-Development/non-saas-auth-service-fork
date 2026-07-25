import { UnauthorizedException } from '@nestjs/common';
import { PostRecoveryValidateCodeService } from './post-recovery-validate-code.service';
import {
  InMemoryRedisLike,
  OtpRateLimitService,
} from './otp-rate-limit.service';
import { LockoutException } from '../exceptions/lockout.exception';
import { hashOtp } from '../utils/otp-token.util';

describe('PostRecoveryValidateCodeService', () => {
  let userRepository: {
    findByEmail: jest.Mock;
    update: jest.Mock;
  };
  let redis: InMemoryRedisLike;
  let otpRateLimit: OtpRateLimitService;
  let service: PostRecoveryValidateCodeService;

  const code = '654321';
  let user: any;

  beforeEach(async () => {
    userRepository = {
      findByEmail: jest.fn(),
      update: jest.fn().mockResolvedValue({}),
    };
    redis = new InMemoryRedisLike();
    otpRateLimit = new OtpRateLimitService(redis);
    service = new PostRecoveryValidateCodeService(
      userRepository as any,
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

  it('verifies bcrypt hash and returns success', async () => {
    userRepository.findByEmail.mockResolvedValue(user);

    await expect(
      service.execute({ email: user.email, token: code }),
    ).resolves.toEqual({ success: true });
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

  it('clears hash and tokens on success (single-use)', async () => {
    userRepository.findByEmail.mockResolvedValue(user);

    await service.execute({ email: user.email, token: code });

    expect(userRepository.update).toHaveBeenCalledWith('user-1', {
      passwordToken: null,
      passwordTokenHash: null,
      passwordTokenExpiresAt: null,
      otpAttempts: 0,
      otpBlockedUntil: null,
    });
  });

  it('increments attempts and locks after 5 failures', async () => {
    userRepository.findByEmail.mockResolvedValue(user);
    jest
      .spyOn(otpRateLimit, 'assertValidateAllowed')
      .mockResolvedValue(undefined);

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
