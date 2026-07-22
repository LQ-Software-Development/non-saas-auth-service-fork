import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';

/**
 * Dual-mode auth for /auth/refresh-token-info:
 * - body.refreshToken present → novo fluxo opaco (Bearer opcional)
 * - sem body.refreshToken → exige Bearer JWT válido (legacy)
 */
@Injectable()
export class RefreshTokenInfoGuard implements CanActivate {
  constructor(private readonly jwtService: JwtService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request & { user?: { sub: string } }>();
    const refreshToken = (request.body as { refreshToken?: string } | undefined)
      ?.refreshToken;

    if (typeof refreshToken === 'string' && refreshToken.length > 0) {
      return true;
    }

    const token = this.extractTokenFromHeader(request);
    if (!token) {
      throw new UnauthorizedException();
    }

    try {
      const payload = await this.jwtService.verifyAsync<{ sub: string }>(token, {
        secret: process.env.JWT_SECRET,
      });
      request.user = payload;
    } catch {
      throw new UnauthorizedException();
    }

    return true;
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers.authorization?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}
