import { UnauthorizedException } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { UpdatePasswordWithCodeService } from './update-password-with-code.service';
import {
  InMemoryRedisLike,
  OtpRateLimitService,
} from './otp-rate-limit.service';
import {
  buildVerifiedMarker,
  hashOtp,
} from '../utils/otp-token.util';

describe('UpdatePasswordWithCodeService', () => {
  let userRepository: {
    findByEmail: jest.Mock;
    update: jest.Mock;
  };
  let redis: InMemoryRedisLike;
  let otpRateLimit: OtpRateLimitService;
  let service: UpdatePasswordWithCodeService;

  const code = '112233';
  const newPassword = 'NewPass@123';
  let user: {
    _id: string;
    email: string;
    document: string;
    passwordToken?: string | null;
    passwordTokenHash: string | null;
    passwordTokenExpiresAt: Date | null;
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
    service = new UpdatePasswordWithCodeService(
      userRepository as never,
      otpRateLimit,
    );
    user = {
      _id: 'user-1',
      email: 'ada@example.com',
      document: '12345678900',
      passwordTokenHash: await hashOtp(code),
      passwordTokenExpiresAt: new Date(Date.now() + 5 * 60 * 1000),
      otpAttempts: 2,
      otpBlockedUntil: null,
    };
  });

  it('verifies OTP hash directly (without prior validate)', async () => {
    userRepository.findByEmail.mockResolvedValue(user);

    await expect(
      service.execute({
        email: user.email,
        token: code,
        newPassword,
      }),
    ).resolves.toEqual({
      success: true,
      message: 'Senha atualizada com sucesso',
    });

    const [, payload] = userRepository.update.mock.calls[0];
    expect(payload.passwordToken).toBeNull();
    expect(payload.passwordTokenHash).toBeNull();
    expect(payload.passwordTokenExpiresAt).toBeNull();
    expect(payload.otpAttempts).toBe(0);
    expect(payload.otpBlockedUntil).toBeNull();
    await expect(bcrypt.compare(newPassword, payload.password)).resolves.toBe(
      true,
    );
  });

  it('accepts resetToken after validate exchanged the OTP', async () => {
    const resetToken = 'a'.repeat(64);
    const proofHash = await hashOtp(resetToken);
    const expiresAtMs = Date.now() + 5 * 60 * 1000;
    user.passwordTokenHash = null;
    user.passwordToken = buildVerifiedMarker(proofHash, expiresAtMs);
    user.passwordTokenExpiresAt = new Date(expiresAtMs);
    userRepository.findByEmail.mockResolvedValue(user);

    await expect(
      service.execute({
        email: user.email,
        token: resetToken,
        newPassword,
      }),
    ).resolves.toEqual({
      success: true,
      message: 'Senha atualizada com sucesso',
    });
  });

  it('rejects expired codes', async () => {
    user.passwordTokenExpiresAt = new Date(Date.now() - 1);
    userRepository.findByEmail.mockResolvedValue(user);

    await expect(
      service.execute({
        email: user.email,
        token: code,
        newPassword,
      }),
    ).rejects.toBeInstanceOf(UnauthorizedException);
    expect(userRepository.update).toHaveBeenCalledWith(
      'user-1',
      expect.objectContaining({ otpAttempts: 3 }),
    );
  });

  it('rejects wrong codes and does not change password', async () => {
    userRepository.findByEmail.mockResolvedValue(user);

    await expect(
      service.execute({
        email: user.email,
        token: '999999',
        newPassword,
      }),
    ).rejects.toBeInstanceOf(UnauthorizedException);

    const updates = userRepository.update.mock.calls.map((c) => c[1]);
    expect(updates.every((u) => !u.password)).toBe(true);
  });
});
