import { describe, expect, it } from "vitest";
import {
  canonicalJson,
  createKeyStore,
  decryptPrivateKey,
  deriveWatermarkSecret,
  encryptPrivateKey,
  findCredentialById,
  findProcessedCredentialByFingerprint,
  generateSigningKey,
  getPublicKeyByKid,
  issueCredential,
  listCredentialsForMedia,
  listPublicKeys,
  signPayload,
  verifyCredential,
  verifyPayload,
  watermarkFingerprint,
  type QueryFn
} from "./forensics";

const KEK = "test-kek-0123456789abcdef0123456789";

type KeyRow = {
  kid: string;
  algorithm: string;
  public_key_pem: string;
  private_key_enc: string;
  status: string;
  created_at: Date;
  retired_at: Date | null;
};

type CredentialRow = {
  id: string;
  media_id: string;
  type: string;
  kid: string;
  claims: Record<string, unknown>;
  payload: string;
  signature: string;
  issued_at: Date;
  created_at: Date;
};

/** 内存版 query：按模块使用的固定 SQL 语义模拟 PostgreSQL，包括 active 唯一约束。 */
function createFakeDb() {
  const keys: KeyRow[] = [];
  const credentials: CredentialRow[] = [];

  const query: QueryFn = async (text, params = []) => {
    if (text.includes("FROM media_signing_keys WHERE status = 'active'")) {
      return { rows: keys.filter((key) => key.status === "active") };
    }
    if (text.includes("FROM media_signing_keys WHERE kid = $1")) {
      return { rows: keys.filter((key) => key.kid === params[0]) };
    }
    if (text.includes("FROM media_signing_keys ORDER BY created_at ASC")) {
      return { rows: [...keys].sort((a, b) => a.created_at.getTime() - b.created_at.getTime()) };
    }
    if (text.includes("INSERT INTO media_signing_keys")) {
      const [kid, publicKeyPem, privateKeyEnc] = params as [string, string, string];
      if (keys.some((key) => key.kid === kid)) return { rows: [] };
      if (keys.some((key) => key.status === "active")) return { rows: [] };
      keys.push({
        kid,
        algorithm: "ed25519",
        public_key_pem: publicKeyPem,
        private_key_enc: privateKeyEnc,
        status: "active",
        created_at: new Date(),
        retired_at: null
      });
      return { rows: [{ kid }] };
    }
    if (text.includes("INSERT INTO media_credentials")) {
      const [id, mediaId, type, kid, claims, payload, signature, issuedAt] = params as [
        string, string, string, string, string, string, string, Date
      ];
      // ON CONFLICT DO NOTHING：同媒体同类型只保留第一份凭证
      if (credentials.some((row) => row.id === id)) return { rows: [] };
      if (credentials.some((row) => row.media_id === mediaId && row.type === type)) return { rows: [] };
      credentials.push({
        id, media_id: mediaId, type, kid,
        claims: JSON.parse(claims), payload, signature,
        issued_at: issuedAt, created_at: new Date()
      });
      return { rows: [] };
    }
    if (text.includes("FROM media_credentials WHERE id = $1")) {
      return { rows: credentials.filter((row) => row.id === params[0]) };
    }
    if (text.includes("FROM media_credentials WHERE media_id = $1")) {
      return { rows: credentials.filter((row) => row.media_id === params[0]) };
    }
    if (text.includes("claims->>'watermarkFingerprint' = $1")) {
      return { rows: credentials.filter((row) => row.type === "processed" && row.claims.watermarkFingerprint === params[0]) };
    }
    throw new Error(`Unexpected SQL in test: ${text}`);
  };

  function rotate() {
    const generated = generateSigningKey();
    for (const key of keys) {
      if (key.status === "active") {
        key.status = "retired";
        key.retired_at = new Date();
      }
    }
    keys.push({
      kid: generated.kid,
      algorithm: "ed25519",
      public_key_pem: generated.publicKeyPem,
      private_key_enc: encryptPrivateKey(generated.privateKeyPem, KEK),
      status: "active",
      created_at: new Date(Date.now() + 1),
      retired_at: null
    });
    return generated;
  }

  return { query, rotate, keys, credentials };
}

describe("signing key encryption", () => {
  it("round-trips a private key through AES-256-GCM encryption", () => {
    const key = generateSigningKey();
    const encrypted = encryptPrivateKey(key.privateKeyPem, KEK);
    expect(encrypted).not.toContain("PRIVATE KEY");
    expect(decryptPrivateKey(encrypted, KEK)).toBe(key.privateKeyPem);
  });

  it("rejects decryption with a wrong KEK", () => {
    const key = generateSigningKey();
    const encrypted = encryptPrivateKey(key.privateKeyPem, KEK);
    expect(() => decryptPrivateKey(encrypted, `${KEK}-other`)).toThrow();
  });

  it("rejects short KEKs", () => {
    const key = generateSigningKey();
    expect(() => encryptPrivateKey(key.privateKeyPem, "too-short")).toThrow(/32/);
  });
});

describe("payload signing", () => {
  it("verifies a valid signature and rejects tampering", () => {
    const key = generateSigningKey();
    const payload = canonicalJson({ b: 1, a: ["x", { y: 2 }] });
    const signature = signPayload(key.privateKeyPem, payload);
    expect(verifyPayload(key.publicKeyPem, payload, signature)).toBe(true);
    expect(verifyPayload(key.publicKeyPem, `${payload} `, signature)).toBe(false);
    expect(verifyPayload(generateSigningKey().publicKeyPem, payload, signature)).toBe(false);
    expect(verifyPayload(key.publicKeyPem, payload, "not-a-signature")).toBe(false);
  });

  it("canonicalizes JSON independent of key order", () => {
    expect(canonicalJson({ b: 1, a: { d: 4, c: 3 } })).toBe(canonicalJson({ a: { c: 3, d: 4 }, b: 1 }));
  });
});

describe("credential lifecycle across key rotation", () => {
  it("keeps old credentials verifiable after rotation and signs new ones with the new key", async () => {
    const db = createFakeDb();
    const store = createKeyStore(db.query, KEK);

    const firstKey = await store.ensureActiveKey();
    // ensureActiveKey 是幂等的，并发自举也只有一把 active 密钥
    expect((await store.ensureActiveKey()).kid).toBe(firstKey.kid);

    const oldCredential = await issueCredential(db.query, firstKey, {
      id: "11111111-1111-4111-8111-111111111111",
      mediaId: "22222222-2222-4222-8222-222222222222",
      type: "processed",
      claims: {
        mediaId: "22222222-2222-4222-8222-222222222222",
        processedSha256: "a".repeat(64),
        perceptualHash: "0123456789abcdef",
        width: 1024,
        height: 768,
        watermarkFingerprint: "0123456789abcdef",
        processedAt: new Date().toISOString(),
        privacy: { metadataRemoved: true, serverReencoded: true, manualRegionCount: 1, detectorRegionCount: 0 }
      }
    });

    const rotatedTo = db.rotate();
    expect(rotatedTo.kid).not.toBe(firstKey.kid);

    // 旧凭证仍可用 retired 公钥校验
    const storedOld = await findCredentialById(db.query, oldCredential.id);
    expect(storedOld).not.toBeNull();
    const oldResult = await verifyCredential(db.query, storedOld!);
    expect(oldResult).toEqual({ valid: true, keyStatus: "retired" });

    // 新凭证使用新密钥
    const newKey = await store.ensureActiveKey();
    expect(newKey.kid).toBe(rotatedTo.kid);
    const newCredential = await issueCredential(db.query, newKey, {
      id: "33333333-3333-4333-8333-333333333333",
      mediaId: "44444444-4444-4444-8444-444444444444",
      type: "deleted",
      claims: {
        mediaId: "44444444-4444-4444-8444-444444444444",
        processedSha256: "b".repeat(64),
        deletedAt: new Date().toISOString(),
        scope: "all_objects",
        executor: "media-maintenance"
      }
    });
    expect(newCredential.kid).toBe(rotatedTo.kid);
    const newResult = await verifyCredential(db.query, (await findCredentialById(db.query, newCredential.id))!);
    expect(newResult).toEqual({ valid: true, keyStatus: "active" });

    // 公钥列表包含 active 与 retired，外部可独立校验
    const publicKeys = await listPublicKeys(db.query);
    expect(publicKeys.map((key) => key.kid).sort()).toEqual([firstKey.kid, rotatedTo.kid].sort());
    expect(publicKeys.every((key) => !("privateKeyEnc" in key))).toBe(true);

    // 篡改 payload 或签名后校验失败
    const tampered = { ...storedOld!, payload: `${storedOld!.payload}x` };
    expect((await verifyCredential(db.query, tampered)).valid).toBe(false);
    const badSignature = { ...storedOld!, signature: signPayload(generateSigningKey().privateKeyPem, storedOld!.payload) };
    expect((await verifyCredential(db.query, badSignature)).valid).toBe(false);
  });

  it("looks processed credentials up by watermark fingerprint", async () => {
    const db = createFakeDb();
    const store = createKeyStore(db.query, KEK);
    const key = await store.ensureActiveKey();
    const secret = deriveWatermarkSecret(KEK);
    const mediaId = "55555555-5555-4555-8555-555555555555";
    const fingerprint = watermarkFingerprint(secret, mediaId);

    await issueCredential(db.query, key, {
      id: "66666666-6666-4666-8666-666666666666",
      mediaId,
      type: "processed",
      claims: { mediaId, processedSha256: "c".repeat(64), watermarkFingerprint: fingerprint, processedAt: new Date().toISOString() }
    });

    const found = await findProcessedCredentialByFingerprint(db.query, fingerprint);
    expect(found?.mediaId).toBe(mediaId);
    expect(await findProcessedCredentialByFingerprint(db.query, "0000000000000000")).toBeNull();

    const listed = await listCredentialsForMedia(db.query, mediaId);
    expect(listed).toHaveLength(1);
    expect(listed[0]?.kid).toBe(key.kid);
  });
});

describe("public claim whitelist", () => {
  it("refuses to sign claims that could leak private media data", async () => {
    const db = createFakeDb();
    const store = createKeyStore(db.query, KEK);
    const key = await store.ensureActiveKey();
    const base = { id: "77777777-7777-4777-8777-777777777777", mediaId: "88888888-8888-4888-8888-888888888888" };

    await expect(issueCredential(db.query, key, {
      ...base, type: "processed",
      claims: { mediaId: base.mediaId, quarantineObjectKey: "quarantine/x/y.jpg" }
    })).rejects.toThrow(/whitelist|leak/);

    await expect(issueCredential(db.query, key, {
      ...base, type: "deleted",
      claims: { mediaId: base.mediaId, deletedAt: new Date().toISOString(), scope: "all_objects", executor: "test", originalFilename: "img.jpg" }
    })).rejects.toThrow(/whitelist|leak/);

    await expect(issueCredential(db.query, key, {
      ...base, type: "processed",
      claims: { mediaId: base.mediaId, ownerId: "99999999-9999-4999-8999-999999999999" }
    })).rejects.toThrow(/whitelist|leak/);
  });

  it("derives stable watermark fingerprints that do not expose the media id", () => {
    const secret = deriveWatermarkSecret(KEK);
    const a = watermarkFingerprint(secret, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
    expect(a).toMatch(/^[0-9a-f]{16}$/);
    expect(a).toBe(watermarkFingerprint(secret, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"));
    expect(a).not.toBe(watermarkFingerprint(secret, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"));
    expect(a).not.toBe(watermarkFingerprint(deriveWatermarkSecret(`${KEK}-x`), "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"));
  });
});
