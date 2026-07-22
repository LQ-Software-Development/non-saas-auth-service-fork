import { UnauthorizedException } from '@nestjs/common';
import { PostRecoveryValidateCodeService } from './post-recovery-validate-code.service';
import {
  buildPasswordOtpToken,
  CODE_TTL_MS,
  parseVerifiedMarker,
} from '../utils/password-otp-token.util';
import * as bcrypt from 'bcrypt';

describe('PostRecoveryValidateCodeService', () => {
  const userRepository = {
    findByEmail: jest.fn(),
    update: jest.fn(),
  };
  const rateLimit = {
    assertValidateAllowed: jest.fn(),
    registerValidateFailure: jest.fn(),
    clearValidateFailures: jest.fn(),
  };

  let service: PostRecoveryValidateCodeService;

  beforeEach(() => {
    jest.clearAllMocks();
    service = new PostRecoveryValidateCodeService(
      userRepository as never,
      rateLimit as never,
    );
  });

  it('accepts valid code, stores proof hash marker, returns resetToken', async () => {
    const expiresAt = Date.now() + CODE_TTL_MS;
    const passwordToken = await buildPasswordOtpToken('654321', expiresAt);
    userRepository.findByEmail.mockResolvedValue({
      _id: 'u1',
      email: 'a@b.com',
      document: '111',
      passwordToken,
    });
    userRepository.update.mockResolvedValue({ isSuccess: true });

    const result = await service.execute({
      email: 'a@b.com',
      token: '654321',
    });

    expect(result.success).toBe(true);
    expect(result.resetToken).toEqual(expect.stringMatching(/^[a-f0-9]{64}$/));
    expect(userRepository.update).toHaveBeenCalledWith(
      'u1',
      expect.objectContaining({
        passwordToken: expect.stringMatching(/^verified\|/),
      }),
    );
    const stored = userRepository.update.mock.calls[0][1].passwordToken;
    const parsed = parseVerifiedMarker(stored);
    expect(parsed?.expiresAt).toBe(expiresAt);
    expect(parsed?.proofHash.startsWith('$2')).toBe(true);
    expect(await bcrypt.compare(result.resetToken, parsed.proofHash)).toBe(true);
    expect(rateLimit.clearValidateFailures).toHaveBeenCalled();
  });

  it('rejects wrong code and registers failure', async () => {
    const passwordToken = await buildPasswordOtpToken(
      '654321',
      Date.now() + CODE_TTL_MS,
    );
    userRepository.findByEmail.mockResolvedValue({
      _id: 'u1',
      email: 'a@b.com',
      passwordToken,
    });

    await expect(
      service.execute({ email: 'a@b.com', token: '000000' }),
    ).rejects.toBeInstanceOf(UnauthorizedException);
    expect(rateLimit.registerValidateFailure).toHaveBeenCalled();
  });

  it('rejects expired token', async () => {
    const passwordToken = await buildPasswordOtpToken(
      '654321',
      Date.now() - 1000,
    );
    userRepository.findByEmail.mockResolvedValue({
      _id: 'u1',
      email: 'a@b.com',
      passwordToken,
    });

    await expect(
      service.execute({ email: 'a@b.com', token: '654321' }),
    ).rejects.toBeInstanceOf(UnauthorizedException);
    expect(rateLimit.registerValidateFailure).toHaveBeenCalled();
  });

  it('uses generic message when user is missing', async () => {
    userRepository.findByEmail.mockResolvedValue(null);

    await expect(
      service.execute({ email: 'missing@b.com', token: '654321' }),
    ).rejects.toThrow('Código inválido');
    expect(rateLimit.assertValidateAllowed).toHaveBeenCalledWith(
      'missing@b.com',
    );
  });
});
