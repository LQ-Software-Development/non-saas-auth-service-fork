import { UnauthorizedException } from '@nestjs/common';
import { UpdatePasswordWithCodeService } from './update-password-with-code.service';
import {
  buildPasswordOtpToken,
  buildVerifiedMarker,
  CODE_TTL_MS,
} from '../utils/password-otp-token.util';
import * as bcrypt from 'bcrypt';

describe('UpdatePasswordWithCodeService', () => {
  const userRepository = {
    findByEmail: jest.fn(),
    update: jest.fn(),
  };
  const rateLimit = {
    assertValidateAllowed: jest.fn(),
    registerValidateFailure: jest.fn(),
    clearValidateFailures: jest.fn(),
  };

  let service: UpdatePasswordWithCodeService;

  beforeEach(() => {
    jest.clearAllMocks();
    service = new UpdatePasswordWithCodeService(
      userRepository as never,
      rateLimit as never,
    );
  });

  it('requires reset proof after validate (verified marker)', async () => {
    const resetProof = 'a'.repeat(64);
    const proofHash = await bcrypt.hash(resetProof, 12);
    const expiresAt = Date.now() + CODE_TTL_MS;
    userRepository.findByEmail.mockResolvedValue({
      _id: 'u1',
      email: 'a@b.com',
      document: '111',
      passwordToken: buildVerifiedMarker(proofHash, expiresAt),
    });
    userRepository.update.mockResolvedValue({ isSuccess: true });

    const result = await service.execute({
      email: 'a@b.com',
      token: resetProof,
      newPassword: 'NewPass@123',
    });

    expect(result.success).toBe(true);
    expect(rateLimit.assertValidateAllowed).toHaveBeenCalledWith('111');
    expect(rateLimit.clearValidateFailures).toHaveBeenCalledWith('111');
    expect(userRepository.update).toHaveBeenCalledWith(
      'u1',
      expect.objectContaining({ passwordToken: null }),
    );
  });

  it('rejects change-password without matching reset proof', async () => {
    const proofHash = await bcrypt.hash('correct-proof', 12);
    userRepository.findByEmail.mockResolvedValue({
      _id: 'u1',
      email: 'a@b.com',
      passwordToken: buildVerifiedMarker(proofHash, Date.now() + CODE_TTL_MS),
    });

    await expect(
      service.execute({
        email: 'a@b.com',
        token: 'wrong-proof',
        newPassword: 'NewPass@123',
      }),
    ).rejects.toBeInstanceOf(UnauthorizedException);
    expect(rateLimit.registerValidateFailure).toHaveBeenCalled();
  });

  it('still accepts direct OTP path when marker is not verified', async () => {
    const passwordToken = await buildPasswordOtpToken(
      '654321',
      Date.now() + CODE_TTL_MS,
    );
    userRepository.findByEmail.mockResolvedValue({
      _id: 'u1',
      email: 'a@b.com',
      passwordToken,
    });
    userRepository.update.mockResolvedValue({ isSuccess: true });

    const result = await service.execute({
      email: 'a@b.com',
      token: '654321',
      newPassword: 'NewPass@123',
    });

    expect(result.success).toBe(true);
    expect(rateLimit.clearValidateFailures).toHaveBeenCalled();
  });

  it('uses generic message when user is missing', async () => {
    userRepository.findByEmail.mockResolvedValue(null);

    await expect(
      service.execute({
        email: 'missing@b.com',
        token: 'x',
        newPassword: 'NewPass@123',
      }),
    ).rejects.toThrow('Código inválido');
  });
});
