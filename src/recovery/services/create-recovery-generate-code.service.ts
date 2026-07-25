import {
  Injectable,
  Inject,
  NotFoundException,
  InternalServerErrorException,
} from '@nestjs/common';
import { randomInt } from 'crypto';
import { CreateRecoveryDto } from '../dto/create-recovery.dto';
import { UserRepositoryInterface } from '../../auth/repositories/user.repository.interface';
import {
  OtpRateLimitService,
  OTP_RATE_LIMIT,
} from './otp-rate-limit.service';
import {
  CODE_TTL_MS,
  hashOtp,
  resolveThrottleKey,
  resolveUserId,
} from '../utils/otp-token.util';

@Injectable()
export class CreateRecoveryGenerateCodeService {
  constructor(
    @Inject('user-repository')
    private readonly userRepository: UserRepositoryInterface,
    @Inject(OTP_RATE_LIMIT)
    private readonly otpRateLimit: OtpRateLimitService,
  ) {}

  async execute(createRecoveryDto: CreateRecoveryDto) {
    const user = await this.userRepository.findByEmail(createRecoveryDto.email);
    const throttleKey = user
      ? resolveThrottleKey(user as { document?: string; email?: string })
      : resolveThrottleKey({ email: createRecoveryDto.email });

    await this.otpRateLimit.assertGenerateAllowed(throttleKey);

    if (!user) {
      throw new NotFoundException('Usuário não encontrado');
    }

    const token = randomInt(100000, 1000000).toString();
    const passwordTokenHash = await hashOtp(token);
    const passwordTokenExpiresAt = new Date(Date.now() + CODE_TTL_MS);
    const userId = resolveUserId(
      user as { _id?: string | { toString(): string }; id?: string },
    );

    await this.userRepository.update(userId, {
      passwordToken: null,
      passwordTokenHash,
      passwordTokenExpiresAt,
      otpAttempts: 0,
      otpBlockedUntil: null,
    });

    const emailPayload = {
      data: {
        passwordToken: token,
        name: user.name,
        subject: 'Recuperação de Senha',
      },
      email: createRecoveryDto.email,
      template: 'recovery-password-code',
    };

    const emailServiceUrl = `${process.env.EMAIL_VERIFICATION_SENDER_URL}/emails`;

    try {
      const response = await fetch(emailServiceUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(emailPayload),
      });

      if (!response.ok) {
        throw new Error(`Erro ao enviar e-mail: ${response.statusText}`);
      }
    } catch (error) {
      throw new InternalServerErrorException(
        'Falha ao enviar e-mail de recuperação de senha ',
      );
    }
  }
}
