import {
  Body,
  Controller,
  Post,
  Put,
  Query,
  Request,
  UseGuards,
  UsePipes,
  ValidationPipe,
} from '@nestjs/common';
import {
  RefreshTokenDto,
  RefreshTokenInfoService,
} from './services/refresh-token-info.service';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import {
  ApiBadRequestResponse,
  ApiBearerAuth,
  ApiCreatedResponse,
  ApiInternalServerErrorResponse,
  ApiOperation,
  ApiTags,
} from '@nestjs/swagger';
import { ResendEmailVerificationService } from './services/resend-email-verification.service';
import { LoginUserDto } from './dto/login-user.dto';
import { LoginResponseDto } from './dto/login-response.dto';
import { LoginWithoutMetadataService } from './services/login-without-metadata.service';

@ApiTags('Autenticação V2')
@ApiBearerAuth()
@Controller('v2/auth')
export class AuthV2Controller {
  constructor(
    private readonly refreshTokenInfoService: RefreshTokenInfoService,
    private readonly resendEmailVerificationService: ResendEmailVerificationService,
    private readonly loginUserService: LoginWithoutMetadataService,
  ) {}

  /**
   * Breaking change: refresh requires body `{ refreshToken }` (opaque token from login).
   * Authorization Bearer access JWT is not accepted as a refresh credential.
   */
  @Post('refresh-token-info')
  @UsePipes(new ValidationPipe({ whitelist: true }))
  async refreshTokenInfo(
    @Body() body: RefreshTokenDto,
    @Query('withMetadata') withMetadata: string,
  ) {
    return this.refreshTokenInfoService.execute(
      body.refreshToken,
      withMetadata !== 'false',
    );
  }

  @UseGuards(JwtAuthGuard)
  @Put('email-verification')
  async resendEmailVerification(@Request() req: { user: { sub: string } }) {
    return this.resendEmailVerificationService.execute(req.user.sub);
  }

  @ApiOperation({ summary: 'Rota de login' })
  @ApiCreatedResponse({
    status: 201,
    type: LoginResponseDto,
    description: 'Usuario logado com sucesso',
  })
  @ApiBadRequestResponse({
    status: 400,
    description: 'O corpo da requisição esta errado ou usuário/senha incorretos',
  })
  @ApiInternalServerErrorResponse({
    status: 500,
    description: 'Erro interno ao tentar fazer login',
  })
  @Post('login')
  async login(@Body() data: LoginUserDto) {
    return await this.loginUserService.execute(data);
  }
}
