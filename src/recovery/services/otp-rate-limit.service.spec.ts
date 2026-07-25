import { ServiceUnavailableException } from '@nestjs/common';
import { LockoutException } from '../exceptions/lockout.exception';
import {
  InMemoryRedisLike,
  OtpRateLimitService,
} from './otp-rate-limit.service';

describe('OtpRateLimitService', () => {
  let redis: InMemoryRedisLike;
  let service: OtpRateLimitService;

  beforeEach(() => {
    redis = new InMemoryRedisLike();
    service = new OtpRateLimitService(redis);
  });

  describe('assertGenerateAllowed', () => {
    it('allows up to 3 generate requests per hour', async () => {
      await expect(service.assertGenerateAllowed('123')).resolves.toBeUndefined();
      await expect(service.assertGenerateAllowed('123')).resolves.toBeUndefined();
      await expect(service.assertGenerateAllowed('123')).resolves.toBeUndefined();
    });

    it('throws 429 on the 4th generate request within the window', async () => {
      await service.assertGenerateAllowed('123');
      await service.assertGenerateAllowed('123');
      await service.assertGenerateAllowed('123');
      await expect(service.assertGenerateAllowed('123')).rejects.toBeInstanceOf(
        LockoutException,
      );
    });
  });

  describe('assertValidateAllowed', () => {
    it('allows more than 5 validate requests so lockout can fire', async () => {
      for (let i = 0; i < 5; i++) {
        await expect(
          service.assertValidateAllowed('abc'),
        ).resolves.toBeUndefined();
      }
    });

    it('throws 429 after validate window is exceeded', async () => {
      for (let i = 0; i < 10; i++) {
        await service.assertValidateAllowed('window');
      }
      await expect(
        service.assertValidateAllowed('window'),
      ).rejects.toBeInstanceOf(LockoutException);
    });

    it('throws 429 when lockout key is present', async () => {
      await redis.set('otp:lock:locked-user', '1', 'EX', 900);
      await expect(
        service.assertValidateAllowed('locked-user'),
      ).rejects.toBeInstanceOf(LockoutException);
    });
  });

  describe('registerValidateFailure / clearValidateFailures', () => {
    it('locks after 5 failed validations and returns 429', async () => {
      await service.registerValidateFailure('doc1');
      await service.registerValidateFailure('doc1');
      await service.registerValidateFailure('doc1');
      await service.registerValidateFailure('doc1');
      await expect(
        service.registerValidateFailure('doc1'),
      ).rejects.toBeInstanceOf(LockoutException);

      await expect(
        service.assertValidateAllowed('doc1'),
      ).rejects.toBeInstanceOf(LockoutException);
    });

    it('clears failures and lock so validation is allowed again', async () => {
      for (let i = 0; i < 4; i++) {
        await service.registerValidateFailure('doc2');
      }
      await service.clearValidateFailures('doc2');
      await expect(service.assertValidateAllowed('doc2')).resolves.toBeUndefined();
    });
  });

  describe('fail closed', () => {
    it('throws 503 when Redis operations fail', async () => {
      const broken = {
        incr: jest.fn().mockRejectedValue(new Error('connection refused')),
        expire: jest.fn(),
        get: jest.fn(),
        set: jest.fn(),
        del: jest.fn(),
        ttl: jest.fn(),
      };
      const failing = new OtpRateLimitService(broken);
      await expect(failing.assertGenerateAllowed('x')).rejects.toBeInstanceOf(
        ServiceUnavailableException,
      );
    });
  });
});
