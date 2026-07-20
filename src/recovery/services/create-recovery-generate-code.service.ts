import {
  Injectable,
  Inject,
  InternalServerErrorException,
} from '@nestjs/common';
import { randomInt } from 'crypto';
import { CreateRecoveryDto } from '../dto/create-recovery.dto';
import { UserRepositoryInterface } from '../../auth/repositories/user.repository.interface';
import {
  buildPasswordOtpToken,
  CODE_TTL_MS,
  resolveOtpThrottleKey,
  resolveUserId,
} from '../utils/password-otp-token.util';
import {
  OTP_RATE_LIMIT,
  OtpRateLimitService,
} from './otp-rate-limit.service';
import { OtpDeliveryService } from './otp-delivery.service';

const SOFT_SUCCESS_MESSAGE =
  'Se existir uma conta com este e-mail, enviaremos um código de recuperação.';

@Injectable()
export class CreateRecoveryGenerateCodeService {
  constructor(
    @Inject('user-repository')
    private readonly userRepository: UserRepositoryInterface,
    @Inject(OTP_RATE_LIMIT)
    private readonly rateLimit: OtpRateLimitService,
    private readonly otpDelivery: OtpDeliveryService,
  ) {}

  async execute(createRecoveryDto: CreateRecoveryDto) {
    const emailKey = createRecoveryDto.email.trim().toLowerCase();
    const user = await this.userRepository.findByEmail(createRecoveryDto.email);
    if (!user) {
      await this.rateLimit.assertGenerateAllowed(emailKey);
      return { message: SOFT_SUCCESS_MESSAGE };
    }

    const throttleKey = resolveOtpThrottleKey(user);
    await this.rateLimit.assertGenerateAllowed(throttleKey);

    const code = randomInt(100000, 1000000).toString();
    const expiresAt = Date.now() + CODE_TTL_MS;
    const passwordToken = await buildPasswordOtpToken(code, expiresAt);

    const userId = resolveUserId(user as { _id?: { toString(): string }; id?: string });
    await this.userRepository.update(userId, { passwordToken });

    const delivered = await this.otpDelivery.deliver({
      userId,
      email: createRecoveryDto.email,
      name: user.name,
      code,
      phone: user.phone,
      organizationId: createRecoveryDto.organizationId,
    });

    if (!delivered) {
      throw new InternalServerErrorException(
        'Falha ao enviar código de recuperação de senha',
      );
    }

    return { message: SOFT_SUCCESS_MESSAGE };
  }
}
