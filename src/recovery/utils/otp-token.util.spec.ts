import {
  BCRYPT_COST,
  CODE_TTL_MS,
  hashOtp,
  isExpired,
  resolveThrottleKey,
  resolveUserId,
  verifyOtp,
} from './otp-token.util';

describe('otp-token.util', () => {
  describe('hashOtp / verifyOtp', () => {
    it('hashes and verifies a code with bcrypt', async () => {
      const code = '123456';
      const hash = await hashOtp(code);
      expect(hash).not.toEqual(code);
      expect(hash.startsWith('$2')).toBe(true);
      await expect(verifyOtp(code, hash)).resolves.toBe(true);
      await expect(verifyOtp('000000', hash)).resolves.toBe(false);
    });

    it('returns false when hash is missing or invalid', async () => {
      await expect(verifyOtp('123456', null)).resolves.toBe(false);
      await expect(verifyOtp('123456', undefined)).resolves.toBe(false);
      await expect(verifyOtp('123456', '')).resolves.toBe(false);
      await expect(verifyOtp('123456', 'not-a-bcrypt-hash')).resolves.toBe(
        false,
      );
    });

    it('uses cost factor 10', () => {
      expect(BCRYPT_COST).toBe(10);
    });
  });

  describe('isExpired', () => {
    it('treats missing expiresAt as expired', () => {
      expect(isExpired(null)).toBe(true);
      expect(isExpired(undefined)).toBe(true);
    });

    it('rejects codes older than 10 minutes', () => {
      expect(CODE_TTL_MS).toBe(10 * 60 * 1000);
      const now = new Date('2026-01-01T12:10:00.000Z');
      const expiresAt = new Date('2026-01-01T12:00:00.000Z');
      expect(isExpired(expiresAt, now)).toBe(true);
    });

    it('accepts codes within 10 minutes', () => {
      const now = new Date('2026-01-01T12:05:00.000Z');
      const expiresAt = new Date('2026-01-01T12:10:00.000Z');
      expect(isExpired(expiresAt, now)).toBe(false);
    });
  });

  describe('resolveThrottleKey / resolveUserId', () => {
    it('prefers document digits over email', () => {
      expect(
        resolveThrottleKey({ document: '123.456.789-00', email: 'A@B.com' }),
      ).toBe('12345678900');
    });

    it('falls back to lowercased email', () => {
      expect(resolveThrottleKey({ email: 'User@Example.COM' })).toBe(
        'user@example.com',
      );
    });

    it('resolves user id from _id or id', () => {
      expect(resolveUserId({ _id: 'abc' })).toBe('abc');
      expect(resolveUserId({ id: 'xyz' })).toBe('xyz');
      expect(resolveUserId({ _id: { toString: () => 'obj' } })).toBe('obj');
    });
  });
});
