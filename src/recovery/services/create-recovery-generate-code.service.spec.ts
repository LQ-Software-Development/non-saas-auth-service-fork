import { NotFoundException } from '@nestjs/common';
import { CreateRecoveryGenerateCodeService } from './create-recovery-generate-code.service';
import {
  InMemoryRedisLike,
  OtpRateLimitService,
} from './otp-rate-limit.service';
import { LockoutException } from '../exceptions/lockout.exception';
import * as bcrypt from 'bcrypt';
import { CODE_TTL_MS } from '../utils/otp-token.util';

describe('CreateRecoveryGenerateCodeService', () => {
  let userRepository: {
    findByEmail: jest.Mock;
    update: jest.Mock;
  };
  let otpRateLimit: OtpRateLimitService;
  let redis: InMemoryRedisLike;
  let service: CreateRecoveryGenerateCodeService;
  let fetchMock: jest.Mock;

  const user = {
    _id: 'user-1',
    name: 'Ada',
    email: 'ada@example.com',
    document: '12345678900',
  };

  beforeEach(() => {
    userRepository = {
      findByEmail: jest.fn(),
      update: jest.fn().mockResolvedValue({}),
    };
    redis = new InMemoryRedisLike();
    otpRateLimit = new OtpRateLimitService(redis);
    service = new CreateRecoveryGenerateCodeService(
      userRepository as any,
      otpRateLimit,
    );
    fetchMock = jest.fn().mockResolvedValue({ ok: true });
    (global as any).fetch = fetchMock;
    process.env.EMAIL_VERIFICATION_SENDER_URL = 'http://email.test';
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('stores bcrypt hash and expiresAt, clears plaintext passwordToken', async () => {
    userRepository.findByEmail.mockResolvedValue(user);
    const before = Date.now();

    await service.execute({ email: user.email });

    expect(userRepository.update).toHaveBeenCalledTimes(1);
    const [, payload] = userRepository.update.mock.calls[0];
    expect(payload.passwordToken).toBeNull();
    expect(payload.otpAttempts).toBe(0);
    expect(payload.otpBlockedUntil).toBeNull();
    expect(payload.passwordTokenHash).toEqual(expect.any(String));
    expect(payload.passwordTokenHash.startsWith('$2')).toBe(true);
    expect(payload.passwordTokenExpiresAt).toBeInstanceOf(Date);
    const expiresAt = payload.passwordTokenExpiresAt.getTime();
    expect(expiresAt).toBeGreaterThanOrEqual(before + CODE_TTL_MS - 1000);
    expect(expiresAt).toBeLessThanOrEqual(Date.now() + CODE_TTL_MS + 1000);

    const emailBody = JSON.parse(fetchMock.mock.calls[0][1].body);
    const plaintext = emailBody.data.passwordToken;
    expect(plaintext).toMatch(/^\d{6}$/);
    await expect(bcrypt.compare(plaintext, payload.passwordTokenHash)).resolves.toBe(
      true,
    );
  });

  it('applies rate limit before NotFoundException when user is missing', async () => {
    userRepository.findByEmail.mockResolvedValue(null);

    await expect(
      service.execute({ email: 'missing@example.com' }),
    ).rejects.toBeInstanceOf(NotFoundException);

    await service.execute({ email: 'missing@example.com' }).catch(() => undefined);
    await service.execute({ email: 'missing@example.com' }).catch(() => undefined);

    await expect(
      service.execute({ email: 'missing@example.com' }),
    ).rejects.toBeInstanceOf(LockoutException);
  });

  it('rate limits generate to 3 per hour for existing users', async () => {
    userRepository.findByEmail.mockResolvedValue(user);
    await service.execute({ email: user.email });
    await service.execute({ email: user.email });
    await service.execute({ email: user.email });
    await expect(service.execute({ email: user.email })).rejects.toBeInstanceOf(
      LockoutException,
    );
  });
});
