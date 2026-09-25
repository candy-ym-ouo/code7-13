import { describe, expect, it } from "vitest";
import {
  createSourceCommitment,
  derivePublicId,
  isPublicId,
  publicIdMatches,
  publicObjectKey,
  publicThumbnailObjectKey,
  verifySourceCommitment
} from "./addressing";

const SECRET = "address-secret-test";

describe("sealed public addressing", () => {
  it("derives unguessable, stable addresses and object keys", () => {
    const id = derivePublicId(SECRET, "0192f5b3-7b4c-7a2e-9f0a-123456789abc", "a".repeat(64));
    expect(isPublicId(id)).toBe(true);
    expect(id).toHaveLength(44);
    expect(derivePublicId(SECRET, "0192f5b3-7b4c-7a2e-9f0a-123456789abc", "a".repeat(64))).toBe(id);
    expect(publicObjectKey(id)).toBe(`media/${id}.webp`);
    expect(publicThumbnailObjectKey(id)).toBe(`media/${id}.thumb.webp`);
  });

  it("produces different addresses for different media and content", () => {
    const mediaA = "0192f5b3-7b4c-7a2e-9f0a-123456789abc";
    const mediaB = "0192f5b3-7b4c-7a2e-9f0a-123456789abd";
    const a = derivePublicId(SECRET, mediaA, "a".repeat(64));
    const b = derivePublicId(SECRET, mediaB, "a".repeat(64));
    const c = derivePublicId(SECRET, mediaA, "b".repeat(64));
    expect(a).not.toBe(b);
    expect(a).not.toBe(c);
  });

  it("cannot be derived without the secret", () => {
    const mediaId = "0192f5b3-7b4c-7a2e-9f0a-123456789abc";
    const sha = "a".repeat(64);
    const real = derivePublicId(SECRET, mediaId, sha);
    expect(publicIdMatches(real, "guessed-secret", mediaId, sha)).toBe(false);
    expect(publicIdMatches(real, SECRET, mediaId, sha)).toBe(true);
    expect(publicIdMatches(real, SECRET, mediaId, "b".repeat(64))).toBe(false);
    expect(isPublicId("media/guess.webp")).toBe(false);
  });

  it("stores only a salted commitment, never the original hash", () => {
    const originalSha = "f".repeat(64);
    const commitment = createSourceCommitment(originalSha);
    expect(commitment.commitment).not.toBe(originalSha);
    expect(commitment.commitment).not.toContain(originalSha);
    expect(verifySourceCommitment(commitment, originalSha)).toBe(true);
    expect(verifySourceCommitment(commitment, "e".repeat(64))).toBe(false);

    // Fresh salt each time => commitments do not correlate identical originals.
    const again = createSourceCommitment(originalSha);
    expect(again.commitment).not.toBe(commitment.commitment);
  });
});
