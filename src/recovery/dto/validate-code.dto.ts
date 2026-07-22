import { ApiProperty } from "@nestjs/swagger";
import { IsEmail, IsNotEmpty } from "class-validator";

export class ValidateCodeDto {
    @ApiProperty()
    @IsNotEmpty()
    @IsEmail()
    email: string;

    @ApiProperty()
    @IsNotEmpty()
    token: string;
}

export class ValidateCodeResponseDto {
    @ApiProperty({ example: true })
    success: boolean;

    @ApiProperty({
      description:
        'High-entropy one-time proof required by change-password-with-code after validate-code',
    })
    resetToken: string;
}
