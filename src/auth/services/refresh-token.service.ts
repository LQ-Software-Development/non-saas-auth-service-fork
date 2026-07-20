import {
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import * as bcrypt from 'bcrypt';
import { createHash, randomBytes } from 'crypto';
import { Model } from 'mongoose';
import { User } from '../database/providers/schema/user.schema';

const BCRYPT_COST = 12;
const DEFAULT_REFRESH_TTL_MS = 90 * 24 * 60 * 60 * 1000;

export const JWT_ACCESS_EXPIRES_IN =
  process.env.JWT_ACCESS_EXPIRES_IN || '15m';
export const JWT_REFRESH_EXPIRES_IN =
  process.env.JWT_REFRESH_EXPIRES_IN || '90d';

export function parseExpiresInToMs(value: string | undefined): number {
  if (!value?.trim()) {
    return DEFAULT_REFRESH_TTL_MS;
  }
  const match = /^(\d+)\s*([dhms])$/i.exec(value.trim());
  if (!match) {
    return DEFAULT_REFRESH_TTL_MS;
  }
  const amount = parseInt(match[1], 10);
  const unit = match[2].toLowerCase();
  if (unit === 'd') {
    return amount * 24 * 60 * 60 * 1000;
  }
  if (unit === 'h') {
    return amount * 60 * 60 * 1000;
  }
  if (unit === 'm') {
    return amount * 60 * 1000;
  }
  if (unit === 's') {
    return amount * 1000;
  }
  return DEFAULT_REFRESH_TTL_MS;
}

const REFRESH_TTL_MS = parseExpiresInToMs(JWT_REFRESH_EXPIRES_IN);

type UserMetadata = Record<string, unknown>;

@Injectable()
export class RefreshTokenService {
  constructor(
    @InjectModel(User.name)
    private readonly userModel: Model<User>,
  ) {}

  async issueRefreshToken(userId: string): Promise<string> {
    const secret = randomBytes(48).toString('hex');
    const opaque = `${userId}.${secret}`;
    const refreshTokenHash = await bcrypt.hash(secret, BCRYPT_COST);
    const refreshTokenExpiresAt = Date.now() + REFRESH_TTL_MS;
    const refreshTokenLookup = sha256(opaque);

    const user = await this.userModel.findById(userId).exec();
    if (!user) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    const previousLookup = (user.metadata as UserMetadata | undefined)
      ?.refreshTokenLookup as string | undefined;

    const metadata: UserMetadata = {
      ...(user.metadata ?? {}),
      refreshTokenHash,
      refreshTokenExpiresAt,
      refreshTokenLookup,
      ...(previousLookup
        ? { previousRefreshTokenLookup: previousLookup }
        : {}),
    };

    await this.userModel.findByIdAndUpdate(userId, { metadata }).exec();
    return opaque;
  }

  async rotateRefreshToken(
    userId: string,
    presentedToken: string,
  ): Promise<string> {
    const parsed = parseOpaqueRefreshToken(presentedToken);
    if (!parsed || parsed.userId !== userId) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    const user = await this.userModel.findById(userId).exec();
    if (!user) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    const metadata = (user.metadata ?? {}) as UserMetadata;
    const storedHash = metadata.refreshTokenHash as string | undefined;
    const expiresAt = metadata.refreshTokenExpiresAt as number | undefined;
    const lookup = metadata.refreshTokenLookup as string | undefined;
    const previousLookup = metadata.previousRefreshTokenLookup as
      | string
      | undefined;
    const presentedLookup = sha256(presentedToken);

    if (previousLookup && previousLookup === presentedLookup) {
      await this.clearRefreshMetadata(userId, metadata);
      throw new UnauthorizedException('Invalid refresh token');
    }

    if (!storedHash || !expiresAt || Date.now() >= expiresAt) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    if (!lookup || lookup !== presentedLookup) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    const valid = await bcrypt.compare(parsed.secret, storedHash);
    if (!valid) {
      await this.clearRefreshMetadata(userId, metadata);
      throw new UnauthorizedException('Invalid refresh token');
    }

    return this.issueRefreshToken(userId);
  }

  async findUserIdByRefreshToken(presentedToken: string): Promise<string> {
    const parsed = parseOpaqueRefreshToken(presentedToken);
    if (!parsed) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    const lookup = sha256(presentedToken);
    const user = await this.userModel
      .findOne({ 'metadata.refreshTokenLookup': lookup })
      .exec();

    if (!user) {
      // One-step reuse: presented token matches a rotated (previous) lookup
      const reused = await this.userModel
        .findOne({ 'metadata.previousRefreshTokenLookup': lookup })
        .exec();
      if (reused) {
        const userId = reused.id || reused._id.toString();
        await this.clearRefreshMetadata(
          userId,
          (reused.metadata ?? {}) as UserMetadata,
        );
      }
      throw new UnauthorizedException('Invalid refresh token');
    }

    return user.id || user._id.toString();
  }

  private async clearRefreshMetadata(
    userId: string,
    current: UserMetadata,
  ): Promise<void> {
    const metadata: UserMetadata = { ...current };
    delete metadata.refreshTokenHash;
    delete metadata.refreshTokenExpiresAt;
    delete metadata.refreshTokenLookup;
    delete metadata.previousRefreshTokenLookup;
    await this.userModel.findByIdAndUpdate(userId, { metadata }).exec();
  }
}

export function parseOpaqueRefreshToken(
  token: string,
): { userId: string; secret: string } | null {
  if (!token?.includes('.')) {
    return null;
  }
  const dot = token.indexOf('.');
  const userId = token.slice(0, dot);
  const secret = token.slice(dot + 1);
  if (!userId || !secret) {
    return null;
  }
  return { userId, secret };
}

function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}
