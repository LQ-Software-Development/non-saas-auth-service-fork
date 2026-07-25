import * as bcrypt from 'bcrypt';

export const CODE_TTL_MS = 10 * 60 * 1000;
export const BCRYPT_COST = 10;
export const VERIFIED_MARKER = 'verified';

export type ParsedVerifiedMarker = {
  proofHash: string;
  expiresAtMs: number;
};

export async function hashOtp(code: string): Promise<string> {
  return bcrypt.hash(code, BCRYPT_COST);
}

export async function verifyOtp(
  code: string,
  hash: string | null | undefined,
): Promise<boolean> {
  if (!hash || typeof hash !== 'string') {
    return false;
  }
  try {
    return await bcrypt.compare(code, hash);
  } catch {
    return false;
  }
}

export function isExpired(
  expiresAt: Date | null | undefined,
  now: Date = new Date(),
): boolean {
  if (!expiresAt) {
    return true;
  }
  const expiresMs =
    expiresAt instanceof Date
      ? expiresAt.getTime()
      : new Date(expiresAt).getTime();
  if (Number.isNaN(expiresMs)) {
    return true;
  }
  return now.getTime() >= expiresMs;
}

/**
 * After validate-code succeeds, OTP hash is burned and replaced by a one-time
 * reset proof stored in passwordToken as: verified|<bcryptHash>|<expiresAtMs>
 */
export function buildVerifiedMarker(
  proofHash: string,
  expiresAtMs: number,
): string {
  return `${VERIFIED_MARKER}|${proofHash}|${expiresAtMs}`;
}

export function parseVerifiedMarker(
  stored: string | null | undefined,
): ParsedVerifiedMarker | null {
  if (!stored?.trim()) {
    return null;
  }
  const parts = stored.trim().split('|');
  if (parts.length !== 3 || parts[0] !== VERIFIED_MARKER) {
    return null;
  }
  const proofHash = parts[1];
  const expiresAtMs = parseInt(parts[2], 10);
  if (!proofHash.startsWith('$2') || !Number.isFinite(expiresAtMs)) {
    return null;
  }
  return { proofHash, expiresAtMs };
}

export function resolveThrottleKey(user: {
  document?: string;
  email?: string;
}): string {
  const digits = (user.document || '').replace(/\D/g, '');
  if (digits) {
    return digits;
  }
  return (user.email || '').toLowerCase();
}

export function resolveUserId(user: {
  _id?: string | { toString(): string };
  id?: string;
}): string {
  if (user._id != null) {
    return typeof user._id === 'string' ? user._id : user._id.toString();
  }
  if (user.id != null) {
    return user.id;
  }
  throw new Error('User id not found');
}
