import { ApiProperty } from "@nestjs/swagger";
import { IsEmail, IsNotEmpty } from "class-validator";

export class UpdateRecoveryDto {
    @ApiProperty()
    @IsNotEmpty()
    @IsEmail()
    email: string;

    @ApiProperty({
      description:
        'OTP code, or resetToken returned by validate-code after successful OTP validation',
    })
    @IsNotEmpty()
    token: string;

    @ApiProperty()
    @IsNotEmpty()
    newPassword: string;
}
