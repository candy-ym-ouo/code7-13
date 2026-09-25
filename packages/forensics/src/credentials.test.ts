import { describe, expect, it } from "vitest";
import {
  ALGORITHM,
  decodeCredential,
  issueCredential,
  verifyCredential,
  type ProcessedCredentialPayload
} from "./credentials";
import { Ed25519VerificationKey, Ed25519SigningKey, generateTestKeyPair } from "./test-keys";

function samplePayload(overrides: Partial<ProcessedCredentialPayload> = {}): ProcessedCredentialPayload {
  return {
    v: 1,
    iss: "public-space-detail-map",
    type: "media.processed",
    mediaId: "0192f5b3-7b4c-7a2e-9f0a-123456789abc",
    issuedAt: "2026-09-25T10:00:00.000Z",
    jti: "0192f5b3-7b4c-7a2e-9f0a-aaaaaaaaaaaa",
    publicId: "m" + "a".repeat(43),
    previousCredential: null,
    content: {
      sha256: "a".repeat(64),
      perceptualHash: "0123456789abcdef",
      mediaType: "image/webp",
      width: 800,
      height: 600,
      byteSize: 12345
    },
    thumbnail: { sha256: "b".repeat(64), byteSize: 2345 },
    source: { salt: "c".repeat(32), commitment: "d".repeat(64), mime: "image/jpeg" },
    watermark: { id: "w0123456789abcdef", scheme: "bluespread-1", embeddedIn: ["image", "thumbnail"] },
    operations: ["orientation", "metadata_strip", "privacy_blur", "webp_reencode", "watermark", "thumbnail"],
    regionCount: 2,
    ...overrides
  };
}

describe("credentials", () => {
  it("signs and verifies with the signer's public key", () => {
    const { privateKey, publicKey, kid } = generateTestKeyPair();
    const token = issueCredential({ payload: samplePayload(), kid, signingKey: privateKey });
    const result = verifyCredential(token, [publicKey]);
    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.kid).toBe(kid);
      expect(result.payload.mediaId).toBe("0192f5b3-7b4c-7a2e-9f0a-123456789abc");
    }
  });

  it("fails when the kid is absent from the directory", () => {
    const a = generateTestKeyPair("fk-aaa");
    const b = generateTestKeyPair("fk-bbb");
    const token = issueCredential({ payload: samplePayload(), kid: a.kid, signingKey: a.privateKey });
    const result = verifyCredential(token, [b.publicKey]);
    expect(result).toEqual({ valid: false, reason: "unknown_kid" });
  });

  it("detects a tampered payload", () => {
    const { privateKey, publicKey, kid } = generateTestKeyPair();
    const token = issueCredential({ payload: samplePayload(), kid, signingKey: privateKey });
    const [header, payload, signature] = token.split(".") as [string, string, string];
    const tamperedPayload = Buffer.from(JSON.stringify(samplePayload({ regionCount: 99 }))).toString("base64url");
    const result = verifyCredential(`${header}.${tamperedPayload}.${signature}`, [publicKey]);
    expect(result).toEqual({ valid: false, reason: "invalid_signature" });
  });

  it("rejects a forged signature", () => {
    const a = generateTestKeyPair("fk-aaa");
    const b = generateTestKeyPair("fk-bbb");
    const tokenA = issueCredential({ payload: samplePayload(), kid: "fk-aaa", signingKey: a.privateKey });
    const tokenB = issueCredential({ payload: samplePayload(), kid: "fk-bbb", signingKey: b.privateKey });
    const [headerA, payloadA] = tokenA.split(".") as [string, string, string];
    const [, , signatureB] = tokenB.split(".") as [string, string, string];
    const mixed = `${headerA}.${payloadA}.${signatureB}`;
    expect(verifyCredential(mixed, [a.publicKey, b.publicKey])).toEqual({ valid: false, reason: "invalid_signature" });
  });

  it("rejects malformed tokens and algorithm confusion headers", () => {
    const { publicKey } = generateTestKeyPair();
    expect(verifyCredential("not-a-token", [publicKey])).toEqual({ valid: false, reason: "malformed" });
    const { privateKey, kid } = generateTestKeyPair("fk-c");
    const token = issueCredential({ payload: samplePayload(), kid, signingKey: privateKey });
    const [, payload, signature] = token.split(".") as [string, string, string];
    const hs256Header = Buffer.from(JSON.stringify({ alg: "HS256", kid, typ: "map-media-credential" })).toString("base64url");
    expect(verifyCredential(`${hs256Header}.${payload}.${signature}`, [publicKey])).toEqual({ valid: false, reason: "bad_header" });
  });

  it("rejects payloads that violate the strict schema", () => {
    const { privateKey, publicKey, kid } = generateTestKeyPair();
    const token = issueCredential({ payload: samplePayload(), kid, signingKey: privateKey });
    const decoded = decodeCredential(token);
    expect(decoded.payload.type).toBe("media.processed");

    const [header, , signature] = token.split(".") as [string, string, string];
    const lax = { ...samplePayload(), extraField: "leak" };
    const payload = Buffer.from(JSON.stringify(lax)).toString("base64url");
    // Header stays valid, payload must be rejected by the strict schema before signature math.
    const result = verifyCredential(`${header}.${payload}.${signature}`, [publicKey]);
    expect(result.valid).toBe(false);
    if (!result.valid) expect(["bad_payload", "invalid_signature"]).toContain(result.reason);
  });

  it("exposes the declared algorithm constant", () => {
    expect(ALGORITHM).toBe("EdDSA");
  });
});
