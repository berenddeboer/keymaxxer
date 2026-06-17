import { randomBytes, scryptSync, timingSafeEqual } from "node:crypto";

/**
 * Memory-hard key derivation. The vault's 32-byte encryption key is derived
 * from a passphrase + salt with scrypt — it is never stored at rest. The salt
 * is not secret and lives in the vault metadata file.
 */

export interface ScryptParams {
  /** CPU/memory cost. 2^15 = ~64 MB of work, ~150ms. */
  N: number;
  r: number;
  p: number;
  keylen: number;
}

export const DEFAULT_SCRYPT: ScryptParams = { N: 1 << 15, r: 8, p: 1, keylen: 32 };

/** A fresh random salt, hex-encoded. */
export function generateSalt(bytes = 16): string {
  return randomBytes(bytes).toString("hex");
}

/** Derive the hex encryption key from a passphrase and salt. */
export function deriveKey(passphrase: string, saltHex: string, params: ScryptParams = DEFAULT_SCRYPT): string {
  const salt = Buffer.from(saltHex, "hex");
  // maxmem must exceed 128 * N * r; give scrypt generous headroom.
  const maxmem = 256 * params.N * params.r;
  const key = scryptSync(passphrase.normalize("NFKC"), salt, params.keylen, {
    N: params.N,
    r: params.r,
    p: params.p,
    maxmem,
  });
  return key.toString("hex");
}

/** Constant-time comparison of two hex strings of equal length. */
export function hexEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a, "hex"), Buffer.from(b, "hex"));
}
