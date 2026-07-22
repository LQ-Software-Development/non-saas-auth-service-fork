import { UnauthorizedException } from '@nestjs/common';
import { RefreshTokenInfoGuard } from '../guards/refresh-token-info.guard';

describe('RefreshTokenInfoGuard', () => {
  let jwtService: { verifyAsync: jest.Mock };
  let guard: RefreshTokenInfoGuard;

  beforeEach(() => {
    jwtService = {
      verifyAsync: jest.fn().mockResolvedValue({ sub: 'user-1' }),
    };
    guard = new RefreshTokenInfoGuard(jwtService as never);
  });

  const makeContext = (req: Record<string, unknown>) =>
    ({
      switchToHttp: () => ({
        getRequest: () => req,
      }),
    }) as never;

  it('allows request when body.refreshToken is present (opaque path)', async () => {
    const req = { body: { refreshToken: 'opaque.token' }, headers: {} };
    await expect(guard.canActivate(makeContext(req))).resolves.toBe(true);
    expect(jwtService.verifyAsync).not.toHaveBeenCalled();
  });

  it('requires valid Bearer JWT for legacy path', async () => {
    const req: Record<string, unknown> = {
      body: {},
      headers: { authorization: 'Bearer legacy.jwt' },
    };
    await expect(guard.canActivate(makeContext(req))).resolves.toBe(true);
    expect(jwtService.verifyAsync).toHaveBeenCalled();
    expect(req.user).toEqual({ sub: 'user-1' });
  });

  it('rejects legacy path without Bearer', async () => {
    const req = { body: {}, headers: {} };
    await expect(guard.canActivate(makeContext(req))).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
  });

  it('rejects legacy path with invalid Bearer', async () => {
    jwtService.verifyAsync.mockRejectedValue(new Error('expired'));
    const req = {
      body: {},
      headers: { authorization: 'Bearer bad.jwt' },
    };
    await expect(guard.canActivate(makeContext(req))).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
  });
});
