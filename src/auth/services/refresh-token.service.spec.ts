import { UnauthorizedException } from '@nestjs/common';
import {
  parseExpiresInToMs,
  RefreshTokenService,
} from './refresh-token.service';
import * as bcrypt from 'bcrypt';
import { createHash } from 'crypto';

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

  it('rejects invalid refresh token and revokes on hash mismatch', async () => {
    const lookup = createHash('sha256')
      .update(`${userId}.deadbeef`)
      .digest('hex');
    userModel.findById.mockReturnValue({
      exec: jest.fn().mockResolvedValue({
        _id: userId,
        id: userId,
        metadata: {
          refreshTokenHash: await bcrypt.hash('other', 12),
          refreshTokenExpiresAt: Date.now() + 10000,
          refreshTokenLookup: lookup,
        },
      }),
    });

    await expect(
      service.rotateRefreshToken(userId, `${userId}.deadbeef`),
    ).rejects.toBeInstanceOf(UnauthorizedException);

    const clearArg = userModel.findByIdAndUpdate.mock.calls.at(-1)[1];
    expect(clearArg.metadata.refreshTokenHash).toBeUndefined();
    expect(clearArg.metadata.refreshTokenLookup).toBeUndefined();
  });

  it('findUserIdByRefreshToken fails closed without lookup hit', async () => {
    userModel.findOne.mockReturnValue({
      exec: jest.fn().mockResolvedValue(null),
    });

    await expect(
      service.findUserIdByRefreshToken(`${userId}.nosuchtoken`),
    ).rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('findUserIdByRefreshToken returns userId only on lookup hit', async () => {
    const opaque = `${userId}.secrettoken`;
    const lookup = createHash('sha256').update(opaque).digest('hex');
    userModel.findOne.mockReturnValue({
      exec: jest.fn().mockResolvedValue({
        _id: userId,
        id: userId,
        metadata: { refreshTokenLookup: lookup },
      }),
    });

    await expect(service.findUserIdByRefreshToken(opaque)).resolves.toBe(
      userId,
    );
  });

  it('parses JWT_REFRESH_EXPIRES_IN durations', () => {
    expect(parseExpiresInToMs('90d')).toBe(90 * 24 * 60 * 60 * 1000);
    expect(parseExpiresInToMs('15m')).toBe(15 * 60 * 1000);
    expect(parseExpiresInToMs(undefined)).toBe(90 * 24 * 60 * 60 * 1000);
  });
});
