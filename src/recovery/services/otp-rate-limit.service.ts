import {
  HttpException,
  HttpStatus,
  Inject,
  Injectable,
  Optional,
} from '@nestjs/common';
import { Redis } from 'ioredis';

export const OTP_RATE_LIMIT = 'otp-rate-limit';

const THROTTLE_WINDOW_SEC = 3600;
const THROTTLE_MAX = 3;
const FAIL_MAX = 5;
const LOCKOUT_TTL_SEC = 15 * 60;

export interface RedisLike {
  incr(key: string): Promise<number>;
  expire(key: string, seconds: number): Promise<number>;
  get(key: string): Promise<string | null>;
  set(
    key: string,
    value: string,
    expiryMode?: string,
    ttl?: number,
  ): Promise<'OK' | null>;
  del(...keys: string[]): Promise<number>;
}

/** In-memory Redis stand-in for unit tests. */
export class InMemoryRedisLike implements RedisLike {
  private readonly store = new Map<string, { value: string; expiresAt?: number }>();

  private isExpired(entry: { expiresAt?: number }): boolean {
    return entry.expiresAt !== undefined && Date.now() >= entry.expiresAt;
  }

  private read(key: string): string | null {
    const entry = this.store.get(key);
    if (!entry) {
      return null;
    }
    if (this.isExpired(entry)) {
      this.store.delete(key);
      return null;
    }
    return entry.value;
  }

  async incr(key: string): Promise<number> {
    const current = this.read(key);
    const next = (current ? parseInt(current, 10) : 0) + 1;
    const existing = this.store.get(key);
    this.store.set(key, {
      value: String(next),
      expiresAt: existing && !this.isExpired(existing) ? existing.expiresAt : undefined,
    });
    return next;
  }

  async expire(key: string, seconds: number): Promise<number> {
    const entry = this.store.get(key);
    if (!entry || this.isExpired(entry)) {
      return 0;
    }
    entry.expiresAt = Date.now() + seconds * 1000;
    this.store.set(key, entry);
    return 1;
  }

  async get(key: string): Promise<string | null> {
    return this.read(key);
  }

  async set(
    key: string,
    value: string,
    expiryMode?: string,
    ttl?: number,
  ): Promise<'OK' | null> {
    let expiresAt: number | undefined;
    if (expiryMode === 'EX' && typeof ttl === 'number') {
      expiresAt = Date.now() + ttl * 1000;
    }
    this.store.set(key, { value, expiresAt });
    return 'OK';
  }

  async del(...keys: string[]): Promise<number> {
    let removed = 0;
    for (const key of keys) {
      if (this.store.delete(key)) {
        removed += 1;
      }
    }
    return removed;
  }
}

@Injectable()
export class OtpRateLimitService {
  private readonly redis: RedisLike;

  constructor(
    @Optional()
    @Inject('otp-redis-client')
    redisClient?: RedisLike,
  ) {
    this.redis = redisClient ?? createDefaultRedisClient();
  }

  async assertGenerateAllowed(throttleKey: string): Promise<void> {
    await this.assertThrottle(`auth:otp:gen:${throttleKey}`);
  }

  async assertValidateAllowed(throttleKey: string): Promise<void> {
    const lockKey = `auth:otp:lock:${throttleKey}`;
    const locked = await this.redis.get(lockKey);
    if (locked) {
      throw new HttpException(
        'Muitas tentativas inválidas. Tente novamente mais tarde.',
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }
    await this.assertThrottle(`auth:otp:val:${throttleKey}`);
  }

  async registerValidateFailure(throttleKey: string): Promise<void> {
    const failKey = `auth:otp:fail:${throttleKey}`;
    const count = await this.redis.incr(failKey);
    if (count === 1) {
      await this.redis.expire(failKey, LOCKOUT_TTL_SEC);
    }
    if (count >= FAIL_MAX) {
      await this.redis.set(
        `auth:otp:lock:${throttleKey}`,
        '1',
        'EX',
        LOCKOUT_TTL_SEC,
      );
      await this.redis.del(failKey);
    }
  }

  async clearValidateFailures(throttleKey: string): Promise<void> {
    await this.redis.del(
      `auth:otp:fail:${throttleKey}`,
      `auth:otp:lock:${throttleKey}`,
    );
  }

  private async assertThrottle(key: string): Promise<void> {
    const count = await this.redis.incr(key);
    if (count === 1) {
      await this.redis.expire(key, THROTTLE_WINDOW_SEC);
    }
    if (count > THROTTLE_MAX) {
      throw new HttpException(
        'Limite de tentativas excedido. Tente novamente em até 1 hora.',
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }
  }
}

function createDefaultRedisClient(): RedisLike {
  if (process.env.NODE_ENV === 'test') {
    return new InMemoryRedisLike();
  }

  const host = process.env.REDIS_HOST || 'localhost';
  const port = parseInt(process.env.REDIS_PORT || '6379', 10);
  const password = process.env.REDIS_PASSWORD || undefined;

  // Eager connect so OTP throttle fails closed if Redis is down (no silent bypass).
  return new Redis({
    host,
    port,
    password: password || undefined,
    maxRetriesPerRequest: 1,
    enableOfflineQueue: false,
    connectTimeout: 3000,
  });
}

export const otpRateLimitProvider = {
  provide: OTP_RATE_LIMIT,
  useClass: OtpRateLimitService,
};
