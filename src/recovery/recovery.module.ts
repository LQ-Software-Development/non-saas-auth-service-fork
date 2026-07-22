import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { RecoveryController } from './recovery.controller';
import { CreateRecoveryGenerateCodeService } from './services/create-recovery-generate-code.service';
import { AuthModule } from '../auth/auth.module';
import { PostRecoveryValidateCodeService } from './services/post-recovery-validate-code.service';
import { UpdatePasswordWithCodeService } from './services/update-password-with-code.service';
import {
  OTP_RATE_LIMIT,
  OtpRateLimitService,
} from './services/otp-rate-limit.service';
import { OtpDeliveryService } from './services/otp-delivery.service';
import {
  Participant,
  ParticipantSchema,
} from '../organizations/participants/entities/participant.entity';

@Module({
  imports: [
    AuthModule,
    MongooseModule.forFeature([
      { name: Participant.name, schema: ParticipantSchema },
    ]),
  ],
  controllers: [RecoveryController],
  providers: [
    CreateRecoveryGenerateCodeService,
    PostRecoveryValidateCodeService,
    UpdatePasswordWithCodeService,
    OtpDeliveryService,
    OtpRateLimitService,
    { provide: OTP_RATE_LIMIT, useExisting: OtpRateLimitService },
  ],
})
export class RecoveryModule {}
