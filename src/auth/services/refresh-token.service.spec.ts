import { UnauthorizedException } from '@nestjs/common';
import { RefreshTokenService } from './refresh-token.service';
import * as bcrypt from 'bcrypt';

describe('RefreshTokenService', () => {
  const userModel = {
    findById: jest.fn(),
    findByIdAndUpdate: jest.fn(),
    findOne: jest.fn(),
  };

  let service: RefreshTokenService;
  const userId = '507f1f77bcf86cd799439011';

  beforeEach(() => {
    jest.clearAllMocks();
    service = new RefreshTokenService(userModel as never);

    userModel.findById.mockReturnValue({
      exec: jest.fn().mockResolvedValue({
        _id: userId,
        id: userId,
        metadata: {},
      }),
    });
    userModel.findByIdAndUpdate.mockReturnValue({
      exec: jest.fn().mockResolvedValue({}),
    });
  });

  it('issues opaque refresh token and stores bcrypt hash in metadata', async () => {
    const token = await service.issueRefreshToken(userId);
    expect(token.startsWith(`${userId}.`)).toBe(true);

    const updateArg = userModel.findByIdAndUpdate.mock.calls[0][1];
    expect(updateArg.metadata.refreshTokenHash.startsWith('$2')).toBe(true);
    expect(updateArg.metadata.refreshTokenExpiresAt).toBeGreaterThan(Date.now());
    expect(updateArg.metadata.refreshTokenLookup).toEqual(expect.any(String));
  });

  it('rotates refresh token when presented token is valid', async () => {
    const issued = await service.issueRefreshToken(userId);
    const firstMeta = userModel.findByIdAndUpdate.mock.calls[0][1].metadata;

    userModel.findById.mockReturnValue({
      exec: jest.fn().mockResolvedValue({
        _id: userId,
        id: userId,
        metadata: firstMeta,
      }),
    });

    const rotated = await service.rotateRefreshToken(userId, issued);
    expect(rotated).not.toBe(issued);
    expect(rotated.startsWith(`${userId}.`)).toBe(true);
  });

  it('rejects invalid refresh token', async () => {
    userModel.findById.mockReturnValue({
      exec: jest.fn().mockResolvedValue({
        _id: userId,
        id: userId,
        metadata: {
          refreshTokenHash: await bcrypt.hash('other', 12),
          refreshTokenExpiresAt: Date.now() + 10000,
          refreshTokenLookup: 'x',
        },
      }),
    });

    await expect(
      service.rotateRefreshToken(userId, `${userId}.deadbeef`),
    ).rejects.toBeInstanceOf(UnauthorizedException);
  });
});
