import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  sign as edSign,
  verify as edVerify
} from "node:crypto";

/**
 * 媒体取证：Ed25519 版本化签名密钥 + 可验证凭证。
 *
 * - 私钥使用 MEDIA_SIGNING_KEK 派生的 AES-256-GCM 密钥加密后落库。
 * - 轮换只把旧密钥标记为 retired，公钥永久保留，旧凭证按 kid 继续校验。
 * - 凭证的 payload 是签发时的规范化字符串原文，校验不依赖 JSON 重新序列化。
 * - 校验方（API、公众）只需要公钥，不接触 KEK 和私钥。
 */

export type QueryFn = (text: string, params?: unknown[]) => Promise<{ rows: unknown[] }>;

export type SigningKeyStatus = "active" | "retired";

export type PublicSigningKey = {
  kid: string;
  algorithm: "ed25519";
  publicKeyPem: string;
  status: SigningKeyStatus;
  createdAt: Date;
  retiredAt: Date | null;
};

export type ActiveSigningKey = {
  kid: string;
  publicKeyPem: string;
  privateKeyPem: string;
};

export type MediaCredentialType = "processed" | "deleted";

export type MediaCredentialRecord = {
  id: string;
  mediaId: string;
  type: MediaCredentialType;
  kid: string;
  claims: Record<string, unknown>;
  payload: string;
  signature: string;
  issuedAt: Date;
};

/** 允许进入公开校验响应的声明字段，除此之外的字段一律不得签发。 */
export const PROCESSED_CLAIM_KEYS = [
  "mediaId",
  "processedSha256",
  "perceptualHash",
  "width",
  "height",
  "watermarkFingerprint",
  "processedAt",
  "privacy"
] as const;

export const DELETED_CLAIM_KEYS = [
  "mediaId",
  "processedSha256",
  "deletedAt",
  "scope",
  "executor"
] as const;

const FORBIDDEN_CLAIM_PATTERN = /quarantine|original|owner|filename|object_?[kK]ey/i;

function assertPublicClaims(claims: Record<string, unknown>, allowed: readonly string[]): void {
  for (const key of Object.keys(claims)) {
    if (!allowed.includes(key)) {
      throw new Error(`Credential claim "${key}" is not in the public whitelist`);
    }
    if (FORBIDDEN_CLAIM_PATTERN.test(key)) {
      throw new Error(`Credential claim "${key}" may leak private media data`);
    }
  }
}

/** 递归排序键的规范化 JSON，保证同一 payload 的签名输入恒定。 */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, entry]) => entry !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([key, entry]) => `${JSON.stringify(key)}:${canonicalJson(entry)}`);
  return `{${entries.join(",")}}`;
}

function kekToAesKey(kek: string): Buffer {
  if (kek.length < 32) throw new Error("MEDIA_SIGNING_KEK must be at least 32 characters");
  return createHash("sha256").update(kek, "utf8").digest();
}

/** 格式：v1.<iv>.<tag>.<data>，均为 base64url。 */
export function encryptPrivateKey(privateKeyPem: string, kek: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", kekToAesKey(kek), iv);
  const data = Buffer.concat([cipher.update(privateKeyPem, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return ["v1", iv.toString("base64url"), tag.toString("base64url"), data.toString("base64url")].join(".");
}

export function decryptPrivateKey(encoded: string, kek: string): string {
  const [version, iv, tag, data] = encoded.split(".");
  if (version !== "v1" || !iv || !tag || !data) throw new Error("Unsupported encrypted key format");
  const decipher = createDecipheriv("aes-256-gcm", kekToAesKey(kek), Buffer.from(iv, "base64url"));
  decipher.setAuthTag(Buffer.from(tag, "base64url"));
  return Buffer.concat([decipher.update(Buffer.from(data, "base64url")), decipher.final()]).toString("utf8");
}

export function generateSigningKey(): ActiveSigningKey {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const kid = `ed25519-${createHash("sha256").update(publicKeyPem).digest("hex").slice(0, 16)}`;
  return { kid, publicKeyPem, privateKeyPem };
}

export function signPayload(privateKeyPem: string, payload: string): string {
  return edSign(null, Buffer.from(payload, "utf8"), privateKeyPem).toString("base64url");
}

export function verifyPayload(publicKeyPem: string, payload: string, signature: string): boolean {
  try {
    return edVerify(null, Buffer.from(payload, "utf8"), createPublicKey(publicKeyPem), Buffer.from(signature, "base64url"));
  } catch {
    return false;
  }
}

/** 水印密钥由 KEK 派生，不单独引入环境变量；水印指纹公开后无法反推媒体列表。 */
export function deriveWatermarkSecret(kek: string): string {
  return createHmac("sha256", kekToAesKey(kek)).update("media-watermark-v1").digest("hex");
}

export function watermarkFingerprint(watermarkSecret: string, mediaId: string): string {
  return createHmac("sha256", watermarkSecret).update(`media:${mediaId}`).digest("hex").slice(0, 16);
}

type KeyRow = {
  kid: string;
  algorithm: string;
  public_key_pem: string;
  private_key_enc: string;
  status: string;
  created_at: Date;
  retired_at: Date | null;
};

function toPublicKey(row: KeyRow): PublicSigningKey {
  return {
    kid: row.kid,
    algorithm: "ed25519",
    publicKeyPem: row.public_key_pem,
    status: row.status as SigningKeyStatus,
    createdAt: row.created_at,
    retiredAt: row.retired_at
  };
}

const KEY_COLUMNS = "kid, algorithm, public_key_pem, private_key_enc, status, created_at, retired_at";

/** 校验只需要公钥；retired 密钥同样可查，保证轮换后旧凭证可校验。 */
export async function getPublicKeyByKid(query: QueryFn, kid: string): Promise<PublicSigningKey | null> {
  const result = await query(`SELECT ${KEY_COLUMNS} FROM media_signing_keys WHERE kid = $1`, [kid]);
  const row = result.rows[0] as KeyRow | undefined;
  return row ? toPublicKey(row) : null;
}

export async function listPublicKeys(query: QueryFn): Promise<PublicSigningKey[]> {
  const result = await query(`SELECT ${KEY_COLUMNS} FROM media_signing_keys ORDER BY created_at ASC`);
  return (result.rows as KeyRow[]).map(toPublicKey);
}

/**
 * 签发侧密钥仓库（Worker 使用）。首次启动自举一把 active 密钥，
 * 部分唯一索引保证并发下只有一把；轮换由 `pnpm --filter @map/db forensics:rotate`
 * 在事务中完成，旧密钥保留为 retired。
 */
export function createKeyStore(query: QueryFn, kek: string) {
  async function findActiveRow(): Promise<KeyRow | null> {
    const result = await query(`SELECT ${KEY_COLUMNS} FROM media_signing_keys WHERE status = 'active'`);
    return (result.rows[0] as KeyRow | undefined) ?? null;
  }

  function toActiveKey(row: KeyRow): ActiveSigningKey {
    return { kid: row.kid, publicKeyPem: row.public_key_pem, privateKeyPem: decryptPrivateKey(row.private_key_enc, kek) };
  }

  return {
    async ensureActiveKey(): Promise<ActiveSigningKey> {
      const existing = await findActiveRow();
      if (existing) return toActiveKey(existing);
      const generated = generateSigningKey();
      await query(
        `INSERT INTO media_signing_keys(kid, algorithm, public_key_pem, private_key_enc, status)
         VALUES ($1, 'ed25519', $2, $3, 'active')
         ON CONFLICT (kid) DO NOTHING`,
        [generated.kid, generated.publicKeyPem, encryptPrivateKey(generated.privateKeyPem, kek)]
      );
      const created = await findActiveRow();
      if (!created) throw new Error("Failed to bootstrap the media signing key");
      return toActiveKey(created);
    },

    async getActiveKey(): Promise<ActiveSigningKey | null> {
      const existing = await findActiveRow();
      return existing ? toActiveKey(existing) : null;
    }
  };
}

export type KeyStore = ReturnType<typeof createKeyStore>;

export function buildCredentialPayload(input: {
  id: string;
  type: MediaCredentialType;
  mediaId: string;
  kid: string;
  issuedAt: string;
  claims: Record<string, unknown>;
}): string {
  return canonicalJson({
    version: 1,
    id: input.id,
    type: input.type,
    mediaId: input.mediaId,
    kid: input.kid,
    issuedAt: input.issuedAt,
    claims: input.claims
  });
}

export async function issueCredential(
  query: QueryFn,
  key: ActiveSigningKey,
  input: {
    id: string;
    mediaId: string;
    type: MediaCredentialType;
    claims: Record<string, unknown>;
    issuedAt?: Date;
  }
): Promise<MediaCredentialRecord> {
  assertPublicClaims(input.claims, input.type === "processed" ? PROCESSED_CLAIM_KEYS : DELETED_CLAIM_KEYS);
  const issuedAt = input.issuedAt ?? new Date();
  const payload = buildCredentialPayload({
    id: input.id,
    type: input.type,
    mediaId: input.mediaId,
    kid: key.kid,
    issuedAt: issuedAt.toISOString(),
    claims: input.claims
  });
  const signature = signPayload(key.privateKeyPem, payload);
  // 每种类型每个媒体只签发一次（部分唯一索引），重试和重复清理安全幂等
  const conflict = input.type === "processed"
    ? "ON CONFLICT (media_id) WHERE type = 'processed' DO NOTHING"
    : "ON CONFLICT (media_id) WHERE type = 'deleted' DO NOTHING";
  await query(
    `INSERT INTO media_credentials(id, media_id, type, kid, claims, payload, signature, issued_at)
     VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8)
     ${conflict}`,
    [input.id, input.mediaId, input.type, key.kid, JSON.stringify(input.claims), payload, signature, issuedAt]
  );
  return {
    id: input.id,
    mediaId: input.mediaId,
    type: input.type,
    kid: key.kid,
    claims: input.claims,
    payload,
    signature,
    issuedAt
  };
}

type CredentialRow = {
  id: string;
  media_id: string;
  type: string;
  kid: string;
  claims: Record<string, unknown>;
  payload: string;
  signature: string;
  issued_at: Date;
};

function toCredentialRecord(row: CredentialRow): MediaCredentialRecord {
  return {
    id: row.id,
    mediaId: row.media_id,
    type: row.type as MediaCredentialType,
    kid: row.kid,
    claims: row.claims,
    payload: row.payload,
    signature: row.signature,
    issuedAt: row.issued_at
  };
}

const CREDENTIAL_COLUMNS = "id, media_id, type, kid, claims, payload, signature, issued_at";

export async function findCredentialById(query: QueryFn, id: string): Promise<MediaCredentialRecord | null> {
  const result = await query(`SELECT ${CREDENTIAL_COLUMNS} FROM media_credentials WHERE id = $1`, [id]);
  const row = result.rows[0] as CredentialRow | undefined;
  return row ? toCredentialRecord(row) : null;
}

export async function listCredentialsForMedia(query: QueryFn, mediaId: string): Promise<MediaCredentialRecord[]> {
  const result = await query(
    `SELECT ${CREDENTIAL_COLUMNS} FROM media_credentials WHERE media_id = $1 ORDER BY created_at ASC`,
    [mediaId]
  );
  return (result.rows as CredentialRow[]).map(toCredentialRecord);
}

export async function findProcessedCredentialByFingerprint(
  query: QueryFn,
  fingerprint: string
): Promise<MediaCredentialRecord | null> {
  const result = await query(
    `SELECT ${CREDENTIAL_COLUMNS} FROM media_credentials
     WHERE type = 'processed' AND claims->>'watermarkFingerprint' = $1`,
    [fingerprint]
  );
  const row = result.rows[0] as CredentialRow | undefined;
  return row ? toCredentialRecord(row) : null;
}

/** 用凭证中的 kid 查公钥校验签名；retired 密钥同样有效。 */
export async function verifyCredential(
  query: QueryFn,
  credential: MediaCredentialRecord
): Promise<{ valid: boolean; keyStatus: SigningKeyStatus | "unknown" }> {
  const key = await getPublicKeyByKid(query, credential.kid);
  if (!key) return { valid: false, keyStatus: "unknown" };
  return { valid: verifyPayload(key.publicKeyPem, credential.payload, credential.signature), keyStatus: key.status };
}
