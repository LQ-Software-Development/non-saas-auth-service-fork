import { UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { RefreshTokenInfoService } from './refresh-token-info.service';
import { RefreshTokenService } from './refresh-token.service';

describe('RefreshTokenInfoService', () => {
  const userId = '507f1f77bcf86cd799439011';
  const mockUser = {
    id: userId,
    name: 'Alice',
    email: 'a@b.com',
    verifiedEmail: true,
    phone: '11999999999',
    document: '12345678901',
  };

  let jwtService: { sign: jest.Mock };
  let userModel: { findById: jest.Mock };
  let organizationModel: { find: jest.Mock };
  let participantModel: { find: jest.Mock };
  let refreshTokenService: {
    findUserIdByRefreshToken: jest.Mock;
    rotateRefreshToken: jest.Mock;
  };
  let service: RefreshTokenInfoService;

  beforeEach(() => {
    jwtService = { sign: jest.fn().mockReturnValue('access.jwt') };
    userModel = { findById: jest.fn().mockResolvedValue(mockUser) };
    participantModel = { find: jest.fn().mockResolvedValue([]) };
    organizationModel = {
      find: jest.fn().mockReturnValue({
        select: jest.fn().mockResolvedValue([]),
      }),
    };
    refreshTokenService = {
      findUserIdByRefreshToken: jest.fn().mockResolvedValue(userId),
      rotateRefreshToken: jest.fn().mockResolvedValue('new.opaque.refresh'),
    };

    service = new RefreshTokenInfoService(
      jwtService as unknown as JwtService,
      userModel as never,
      organizationModel as never,
      participantModel as never,
      refreshTokenService as unknown as RefreshTokenService,
    );
  });

  it('executeByRefreshToken rotates opaque token and signs 15m access', async () => {
    const result = await service.executeByRefreshToken('old.opaque.refresh', true);

    expect(refreshTokenService.findUserIdByRefreshToken).toHaveBeenCalledWith(
      'old.opaque.refresh',
    );
    expect(refreshTokenService.rotateRefreshToken).toHaveBeenCalledWith(
      userId,
      'old.opaque.refresh',
    );
    expect(jwtService.sign).toHaveBeenCalledWith(
      expect.objectContaining({ sub: userId, email: 'a@b.com' }),
      { expiresIn: expect.any(String) },
    );
    expect(result).toEqual(
      expect.objectContaining({
        token: 'access.jwt',
        refreshToken: 'new.opaque.refresh',
        userId,
      }),
    );
  });

  it('executeLegacy signs without expiresIn override and omits refreshToken', async () => {
    const result = await service.executeLegacy(userId, true);

    expect(refreshTokenService.findUserIdByRefreshToken).not.toHaveBeenCalled();
    expect(refreshTokenService.rotateRefreshToken).not.toHaveBeenCalled();
    expect(jwtService.sign).toHaveBeenCalledWith(
      expect.objectContaining({ sub: userId, email: 'a@b.com' }),
    );
    expect(jwtService.sign.mock.calls[0]).toHaveLength(1);
    expect(result).toEqual(
      expect.objectContaining({
        token: 'access.jwt',
        userId,
        name: 'Alice',
      }),
    );
    expect(result).not.toHaveProperty('refreshToken');
  });

  it('executeLegacy rejects unknown user', async () => {
    userModel.findById.mockResolvedValue(null);
    await expect(service.executeLegacy(userId)).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
  });

  it('executeByRefreshToken rejects when user missing after lookup', async () => {
    userModel.findById.mockResolvedValue(null);
    await expect(
      service.executeByRefreshToken('opaque'),
    ).rejects.toBeInstanceOf(UnauthorizedException);
  });
});
