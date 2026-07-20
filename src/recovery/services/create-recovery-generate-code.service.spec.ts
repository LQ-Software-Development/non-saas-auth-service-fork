import { CreateRecoveryGenerateCodeService } from './create-recovery-generate-code.service';
import { parsePasswordOtpToken } from '../utils/password-otp-token.util';

describe('CreateRecoveryGenerateCodeService', () => {
  const userRepository = {
    findByEmail: jest.fn(),
    update: jest.fn(),
  };
  const rateLimit = {
    assertGenerateAllowed: jest.fn(),
  };
  const otpDelivery = {
    deliver: jest.fn(),
  };

  let service: CreateRecoveryGenerateCodeService;

  beforeEach(() => {
    jest.clearAllMocks();
    service = new CreateRecoveryGenerateCodeService(
      userRepository as never,
      rateLimit as never,
      otpDelivery as never,
    );
  });

  it('stores bcrypt hashed token (not plaintext) and delivers OTP', async () => {
    userRepository.findByEmail.mockResolvedValue({
      _id: 'u1',
      email: 'a@b.com',
      name: 'Ada',
      document: '12345678900',
      phone: '11999999999',
    });
    userRepository.update.mockResolvedValue({ isSuccess: true });
    otpDelivery.deliver.mockResolvedValue(true);

    const result = await service.execute({
      email: 'a@b.com',
      organizationId: 'org1',
    });

    expect(result.message).toContain('Se existir uma conta');
    expect(rateLimit.assertGenerateAllowed).toHaveBeenCalledWith('12345678900');
    expect(userRepository.update).toHaveBeenCalledWith(
      'u1',
      expect.objectContaining({
        passwordToken: expect.any(String),
      }),
    );

    const stored = userRepository.update.mock.calls[0][1].passwordToken as string;
    const parsed = parsePasswordOtpToken(stored);
    expect(parsed).not.toBeNull();
    expect(stored.match(/^\d{6}$/)).toBeNull();
    expect(otpDelivery.deliver).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: 'u1',
        email: 'a@b.com',
        code: expect.stringMatching(/^\d{6}$/),
      }),
    );
  });

  it('returns soft success and burns generate throttle when user is missing', async () => {
    userRepository.findByEmail.mockResolvedValue(null);

    const result = await service.execute({ email: 'Missing@B.com' });

    expect(result).toEqual({
      message: expect.stringContaining('Se existir uma conta'),
    });
    expect(rateLimit.assertGenerateAllowed).toHaveBeenCalledWith(
      'missing@b.com',
    );
    expect(userRepository.update).not.toHaveBeenCalled();
    expect(otpDelivery.deliver).not.toHaveBeenCalled();
  });
});
