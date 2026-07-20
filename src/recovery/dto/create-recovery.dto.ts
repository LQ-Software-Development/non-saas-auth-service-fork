import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, IsOptional, IsString } from 'class-validator';

export class CreateRecoveryDto {
  @ApiProperty()
  @IsNotEmpty()
  @IsEmail()
  email: string;

  @ApiPropertyOptional({
    description: 'Organization/company id for omni-channel OTP delivery',
  })
  @IsOptional()
  @IsString()
  organizationId?: string;
}
