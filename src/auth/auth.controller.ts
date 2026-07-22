import {
  Body,
  Controller,
  Post,
  Put,
  Query,
  Request,
  UnauthorizedException,
  UseGuards,
  UsePipes,
  ValidationPipe,
} from '@nestjs/common';
import {
  RefreshTokenDto,
  RefreshTokenInfoService,
} from './services/refresh-token-info.service';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { RefreshTokenInfoGuard } from './guards/refresh-token-info.guard';
import {
  ApiBadRequestResponse,
  ApiBearerAuth,
  ApiCreatedResponse,
  ApiInternalServerErrorResponse,
  ApiOperation,
  ApiTags,
} from '@nestjs/swagger';
import { ResendEmailVerificationService } from './services/resend-email-verification.service';
import { LoginUserService } from './services/login-user.service';
import { LoginUserDto } from './dto/login-user.dto';
import { LoginResponseDto } from './dto/login-response.dto';

@ApiTags('Autenticação')
@ApiBearerAuth()
@Controller('')
export class AuthController {
  constructor(
    private readonly refreshTokenInfoService: RefreshTokenInfoService,
    private readonly resendEmailVerificationService: ResendEmailVerificationService,
    private readonly loginUserService: LoginUserService,
  ) {}

  /**
   * Dual-mode (compatibilidade reversa):
   * - body `{ refreshToken }` → fluxo opaco (15m access + rotação)
   * - Bearer JWT sem body → legado (90d access, sem rotação)
   */
  @UseGuards(RefreshTokenInfoGuard)
  @Post('auth/refresh-token-info')
  @UsePipes(
    new ValidationPipe({
      whitelist: true,
      skipMissingProperties: true,
      forbidNonWhitelisted: false,
    }),
  )
  async refreshTokenInfo(
    @Body() body: RefreshTokenDto | undefined,
    @Query('withMetadata') withMetadata: string,
    @Request() req: { user?: { sub: string } },
  ) {
    const wm = withMetadata !== 'false';
    if (body?.refreshToken) {
      return this.refreshTokenInfoService.executeByRefreshToken(
        body.refreshToken,
        wm,
      );
    }
    if (!req.user?.sub) {
      throw new UnauthorizedException();
    }
    return this.refreshTokenInfoService.executeLegacy(req.user.sub, wm);
  }

  @UseGuards(JwtAuthGuard)
  @Put('auth/email-verification')
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
  async login(@Body() data: LoginUserDto): Promise<LoginResponseDto> {
    const result = await this.loginUserService.login(data);
    return result.value;
  }
}
