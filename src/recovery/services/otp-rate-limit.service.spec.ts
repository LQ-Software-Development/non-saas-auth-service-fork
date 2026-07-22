import { HttpException } from '@nestjs/common';
import {
  InMemoryRedisLike,
  OtpRateLimitService,
} from './otp-rate-limit.service';

describe('OtpRateLimitService', () => {
  let service: OtpRateLimitService;

  beforeEach(() => {
    service = new OtpRateLimitService(new InMemoryRedisLike());
  });

  it('allows up to 3 generate requests per hour then blocks', async () => {
    const key = 'doc-1';
    await service.assertGenerateAllowed(key);
    await service.assertGenerateAllowed(key);
    await service.assertGenerateAllowed(key);
    await expect(service.assertGenerateAllowed(key)).rejects.toBeInstanceOf(
      HttpException,
    );
  });

  it('allows up to 3 validate requests per hour then blocks', async () => {
    const key = 'email@test.com';
    await service.assertValidateAllowed(key);
    await service.assertValidateAllowed(key);
    await service.assertValidateAllowed(key);
    await expect(service.assertValidateAllowed(key)).rejects.toBeInstanceOf(
      HttpException,
    );
  });

  it('locks out after 5 failed validates', async () => {
    const key = 'lock-me';
    for (let i = 0; i < 5; i++) {
      await service.registerValidateFailure(key);
    }
    await expect(service.assertValidateAllowed(key)).rejects.toBeInstanceOf(
      HttpException,
    );
  });

  it('clears failures on success', async () => {
    const key = 'clear-me';
    for (let i = 0; i < 4; i++) {
      await service.registerValidateFailure(key);
    }
    await service.clearValidateFailures(key);
    await expect(service.assertValidateAllowed(key)).resolves.toBeUndefined();
  });
});
