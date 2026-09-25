import { randomBytes } from "node:crypto";
import { constantTimeEqual, hmacDigest, sha256Hex } from "./encoding";

/**
 * Sealed public addressing.
 *
 * Public object addresses are derived with a server-side HMAC secret:
 *
 *   id     = "m" + base16(HMAC(secret, "public-id" || mediaId || processedSha256))
 *   key    = `media/${id}.webp`
 *
 * Properties:
 * - cannot be computed by an outsider, so the public bucket cannot be
 *   enumerated or "confirmed" by guessing media ids;
 * - bound to the *processed* (blurred, re-encoded, watermarked) bytes, not to
 *   the original image — the address leaks nothing about the original content
 *   and cannot be derived from an original hash;
 * - the original image never leaves the private quarantine bucket.
 */

export const PUBLIC_ID_LENGTH = 44; // "m" + 43 hex chars (HMAC truncated to 21.5 bytes)
const HMAC_LABEL = Buffer.from("map:media:public-id:");
const PUBLIC_KEY_PREFIX = "media/";

function digest(secret: string, mediaId: string, processedSha256: string): Buffer {
  return hmacDigest(secret, Buffer.concat([
    HMAC_LABEL,
    Buffer.from(mediaId),
    Buffer.from([0x00]),
    Buffer.from(processedSha256)
  ]));
}

export function derivePublicId(secret: string, mediaId: string, processedSha256: string): string {
  return `m${digest(secret, mediaId, processedSha256).toString("hex").slice(0, 43)}`;
}

export function publicObjectKey(publicId: string): string {
  return `${PUBLIC_KEY_PREFIX}${publicId}.webp`;
}

export function publicThumbnailObjectKey(publicId: string): string {
  return `${PUBLIC_KEY_PREFIX}${publicId}.thumb.webp`;
}

export function isPublicId(value: string): boolean {
  return /^m[0-9a-f]{43}$/.test(value);
}

/** Re-derives the address for claimed bytes and compares in constant time. */
export function publicIdMatches(
  claimedPublicId: string,
  secret: string,
  mediaId: string,
  processedSha256: string
): boolean {
  if (!isPublicId(claimedPublicId)) return false;
  const expected = derivePublicId(secret, mediaId, processedSha256);
  return constantTimeEqual(claimedPublicId, expected);
}

/**
 * Salted commitment to the original bytes. The raw original hash must never
 * appear in a credential (knowing the original lets an outsider confirm it),
 * so only salt -> sha256(salt || originalHash) is retained.
 */
export interface SourceCommitment {
  salt: string;
  commitment: string;
}

export function createSourceCommitment(originalSha256: string, salt?: Buffer): SourceCommitment {
  const saltBytes = salt ?? randomBytes(16);
  const saltHex = saltBytes.toString("hex");
  const commitment = sha256Hex(Buffer.concat([saltBytes, Buffer.from(originalSha256)]));
  return { salt: saltHex, commitment };
}

/** Checks a stored commitment against the original hash it was made for. */
export function verifySourceCommitment(commitment: SourceCommitment, originalSha256: string): boolean {
  const expected = sha256Hex(Buffer.concat([Buffer.from(commitment.salt, "hex"), Buffer.from(originalSha256)]));
  return constantTimeEqual(expected, commitment.commitment);
}
