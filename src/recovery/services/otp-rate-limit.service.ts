import {
  Inject,
  Injectable,
  Optional,
  ServiceUnavailableException,
} from '@nestjs/common';
import Redis from 'ioredis';
import { LockoutException } from '../exceptions/lockout.exception';

export const OTP_REDIS_CLIENT = 'otp-redis-client';
export const OTP_RATE_LIMIT = 'OTP_RATE_LIMIT';

const WINDOW_SECONDS = 60 * 60;
const MAX_REQUESTS_PER_WINDOW = 3;
const MAX_FAILURES = 5;
const LOCKOUT_SECONDS = 15 * 60;
const FAILURE_TTL_SECONDS = 60 * 60;

export interface RedisLike {
  incr(key: string): Promise<number>;
  expire(key: string, seconds: number): Promise<number>;
  get(key: string): Promise<string | null>;
  set(key: string, value: string, ...args: Array<string | number>): Promise<'OK' | null>;
  del(...keys: string[]): Promise<number>;
  ttl(key: string): Promise<number>;
}

/** In-memory Redis subset for unit tests. */
export class InMemoryRedisLike implements RedisLike {
  private store = new Map<string, { value: string; expiresAt?: number }>();

  private purgeIfExpired(key: string): void {
    const entry = this.store.get(key);
    if (!entry) {
      return;
    }
    if (entry.expiresAt != null && Date.now() >= entry.expiresAt) {
      this.store.delete(key);
    }
  }

  async incr(key: string): Promise<number> {
    this.purgeIfExpired(key);
    const entry = this.store.get(key);
    const next = entry ? Number(entry.value) + 1 : 1;
    this.store.set(key, {
      value: String(next),
      expiresAt: entry?.expiresAt,
    });
    return next;
  }

  async expire(key: string, seconds: number): Promise<number> {
    this.purgeIfExpired(key);
    const entry = this.store.get(key);
    if (!entry) {
      return 0;
    }
    entry.expiresAt = Date.now() + seconds * 1000;
    this.store.set(key, entry);
    return 1;
  }

  async get(key: string): Promise<string | null> {
    this.purgeIfExpired(key);
    return this.store.get(key)?.value ?? null;
  }

  async set(
    key: string,
    value: string,
    ...args: Array<string | number>
  ): Promise<'OK' | null> {
    let ttlSeconds: number | undefined;
    for (let i = 0; i < args.length; i++) {
      const arg = args[i];
      if (
        (arg === 'EX' || arg === 'ex') &&
        typeof args[i + 1] === 'number'
      ) {
        ttlSeconds = args[i + 1] as number;
      }
    }
    this.store.set(key, {
      value,
      expiresAt:
        ttlSeconds != null ? Date.now() + ttlSeconds * 1000 : undefined,
    });
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

  async ttl(key: string): Promise<number> {
    this.purgeIfExpired(key);
    const entry = this.store.get(key);
    if (!entry) {
      return -2;
    }
    if (entry.expiresAt == null) {
      return -1;
    }
    return Math.max(0, Math.ceil((entry.expiresAt - Date.now()) / 1000));
  }

  clear(): void {
    this.store.clear();
  }
}

export function createOtpRedisClientFromEnv(): Redis {
  const host = process.env.REDIS_HOST || 'localhost';
  const port = parseInt(process.env.REDIS_PORT || '6379', 10);
  const password = process.env.REDIS_PASSWORD || undefined;
  return new Redis({
    host,
    port,
    password: password || undefined,
    maxRetriesPerRequest: 1,
    enableReadyCheck: true,
    lazyConnect: false,
  });
}

@Injectable()
export class OtpRateLimitService {
  constructor(
    @Optional()
    @Inject(OTP_REDIS_CLIENT)
    private readonly redis: RedisLike,
  ) {
    if (!this.redis) {
      throw new Error(
        'OtpRateLimitService requires an otp-redis-client provider',
      );
    }
  }

  private genKey(key: string): string {
    return `otp:gen:${key}`;
  }

  private valKey(key: string): string {
    return `otp:val:${key}`;
  }

  private lockKey(key: string): string {
    return `otp:lock:${key}`;
  }

  private failKey(key: string): string {
    return `otp:fail:${key}`;
  }

  private async withRedis<T>(operation: () => Promise<T>): Promise<T> {
    try {
      return await operation();
    } catch (error) {
      if (
        error instanceof LockoutException ||
        error instanceof ServiceUnavailableException
      ) {
        throw error;
      }
      throw new ServiceUnavailableException(
        'Serviço de limite de tentativas indisponível. Tente novamente mais tarde.',
      );
    }
  }

  private async assertThrottle(
    redisKey: string,
    errorMessage: string,
  ): Promise<void> {
    const count = await this.redis.incr(redisKey);
    if (count === 1) {
      await this.redis.expire(redisKey, WINDOW_SECONDS);
    }
    if (count > MAX_REQUESTS_PER_WINDOW) {
      throw new LockoutException(errorMessage);
    }
  }

  async assertGenerateAllowed(key: string): Promise<void> {
    await this.withRedis(async () => {
      await this.assertThrottle(
        this.genKey(key),
        'Limite de geração de código excedido. Tente novamente em até 1 hora.',
      );
    });
  }

  async assertValidateAllowed(key: string): Promise<void> {
    await this.withRedis(async () => {
      const locked = await this.redis.get(this.lockKey(key));
      if (locked) {
        throw new LockoutException(
          'Muitas tentativas inválidas. Tente novamente em 15 minutos.',
        );
      }
      await this.assertThrottle(
        this.valKey(key),
        'Limite de validação de código excedido. Tente novamente em até 1 hora.',
      );
    });
  }

  async registerValidateFailure(key: string): Promise<void> {
    await this.withRedis(async () => {
      const failKey = this.failKey(key);
      const failures = await this.redis.incr(failKey);
      if (failures === 1) {
        await this.redis.expire(failKey, FAILURE_TTL_SECONDS);
      }
      if (failures >= MAX_FAILURES) {
        await this.redis.set(this.lockKey(key), '1', 'EX', LOCKOUT_SECONDS);
        await this.redis.del(failKey);
        throw new LockoutException(
          'Muitas tentativas inválidas. Tente novamente em 15 minutos.',
        );
      }
    });
  }

  async clearValidateFailures(key: string): Promise<void> {
    await this.withRedis(async () => {
      await this.redis.del(this.failKey(key), this.lockKey(key));
    });
  }
}
