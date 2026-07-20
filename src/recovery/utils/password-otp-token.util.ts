import * as bcrypt from 'bcrypt';

export const CODE_TTL_MS = 10 * 60 * 1000;
export const BCRYPT_COST = 12;
export const VERIFIED_MARKER = 'verified';

export type ParsedPasswordOtpToken = {
  bcryptHash: string;
  expiresAt: number;
};

export type ParsedVerifiedMarker = {
  verified: true;
  expiresAt: number;
};

export async function buildPasswordOtpToken(
  code: string,
  expiresAt: number,
): Promise<string> {
  const bcryptHash = await bcrypt.hash(code, BCRYPT_COST);
  return `${bcryptHash}|${expiresAt}`;
}

export function parsePasswordOtpToken(
  stored: string | null | undefined,
): ParsedPasswordOtpToken | null {
  if (!stored?.trim()) {
    return null;
  }
  const parts = stored.trim().split('|');
  if (parts.length < 2) {
    return null;
  }
  const [bcryptHash, expiresRaw] = parts;
  const expiresAt = parseInt(expiresRaw, 10);
  if (!bcryptHash.startsWith('$2') || !Number.isFinite(expiresAt)) {
    return null;
  }
  return { bcryptHash, expiresAt };
}

export function parseVerifiedMarker(
  stored: string | null | undefined,
): ParsedVerifiedMarker | null {
  if (!stored?.trim()) {
    return null;
  }
  const parts = stored.trim().split('|');
  if (parts.length !== 2 || parts[0] !== VERIFIED_MARKER) {
    return null;
  }
  const expiresAt = parseInt(parts[1], 10);
  if (!Number.isFinite(expiresAt)) {
    return null;
  }
  return { verified: true, expiresAt };
}

export function buildVerifiedMarker(expiresAt: number): string {
  return `${VERIFIED_MARKER}|${expiresAt}`;
}

export function isOtpExpired(expiresAt: number, now = Date.now()): boolean {
  return !Number.isFinite(expiresAt) || now >= expiresAt;
}

export function resolveOtpThrottleKey(user: {
  document?: string | null;
  email?: string | null;
}): string {
  const digits = (user.document ?? '').replace(/\D/g, '');
  if (digits.length > 0) {
    return digits;
  }
  return (user.email ?? '').trim().toLowerCase();
}

export function resolveUserId(user: {
  _id?: { toString(): string } | string;
  id?: string;
}): string {
  if (user._id) {
    return typeof user._id === 'string' ? user._id : user._id.toString();
  }
  if (user.id) {
    return user.id;
  }
  throw new Error('User id not found');
}
