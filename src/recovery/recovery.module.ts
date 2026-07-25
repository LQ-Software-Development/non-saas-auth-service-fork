import { Module } from '@nestjs/common';
import { RecoveryController } from './recovery.controller';
import { CreateRecoveryGenerateCodeService } from './services/create-recovery-generate-code.service';
import { AuthModule } from '../auth/auth.module';
import { PostRecoveryValidateCodeService } from './services/post-recovery-validate-code.service';
import { UpdatePasswordWithCodeService } from './services/update-password-with-code.service';
import {
  createOtpRedisClientFromEnv,
  OTP_RATE_LIMIT,
  OTP_REDIS_CLIENT,
  OtpRateLimitService,
} from './services/otp-rate-limit.service';

@Module({
  imports: [AuthModule],
  controllers: [RecoveryController],
  providers: [
    {
      provide: OTP_REDIS_CLIENT,
      useFactory: () => createOtpRedisClientFromEnv(),
    },
    OtpRateLimitService,
    {
      provide: OTP_RATE_LIMIT,
      useExisting: OtpRateLimitService,
    },
    CreateRecoveryGenerateCodeService,
    PostRecoveryValidateCodeService,
    UpdatePasswordWithCodeService,
  ],
})
export class RecoveryModule {}
