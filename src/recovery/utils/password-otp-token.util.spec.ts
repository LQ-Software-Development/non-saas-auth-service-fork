import {
  buildPasswordOtpToken,
  buildVerifiedMarker,
  CODE_TTL_MS,
  isOtpExpired,
  parsePasswordOtpToken,
  parseVerifiedMarker,
  resolveOtpThrottleKey,
} from './password-otp-token.util';
import * as bcrypt from 'bcrypt';

describe('password-otp-token.util', () => {
  it('builds and parses a bcrypt|expiresAt token', async () => {
    const expiresAt = Date.now() + CODE_TTL_MS;
    const stored = await buildPasswordOtpToken('123456', expiresAt);
    const parsed = parsePasswordOtpToken(stored);

    expect(parsed).not.toBeNull();
    expect(parsed.expiresAt).toBe(expiresAt);
    expect(parsed.bcryptHash.startsWith('$2')).toBe(true);
    expect(await bcrypt.compare('123456', parsed.bcryptHash)).toBe(true);
    expect(stored.includes('123456')).toBe(false);
  });

  it('returns null for invalid stored tokens', () => {
    expect(parsePasswordOtpToken(undefined)).toBeNull();
    expect(parsePasswordOtpToken('plaintext')).toBeNull();
    expect(parsePasswordOtpToken('notahash|abc')).toBeNull();
  });

  it('detects expiry', () => {
    expect(isOtpExpired(Date.now() - 1)).toBe(true);
    expect(isOtpExpired(Date.now() + 60_000)).toBe(false);
  });

  it('builds and parses verified marker with proof hash', async () => {
    const expiresAt = Date.now() + CODE_TTL_MS;
    const proofHash = await bcrypt.hash('reset-proof', 12);
    const marker = buildVerifiedMarker(proofHash, expiresAt);
    const parsed = parseVerifiedMarker(marker);
    expect(parsed).toEqual({ verified: true, proofHash, expiresAt });
    expect(parsePasswordOtpToken(marker)).toBeNull();
    expect(parseVerifiedMarker(`verified|${expiresAt}`)).toBeNull();
  });

  it('resolves throttle key preferring document digits', () => {
    expect(
      resolveOtpThrottleKey({ document: '123.456.789-00', email: 'A@B.com' }),
    ).toBe('12345678900');
    expect(resolveOtpThrottleKey({ email: 'A@B.com' })).toBe('a@b.com');
  });
});
