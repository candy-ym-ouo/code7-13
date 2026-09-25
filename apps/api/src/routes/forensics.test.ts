import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import Fastify, { type FastifyInstance } from "fastify";

const OWNER_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const MEDIA_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const CREDENTIAL_ID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const KEK = "api-test-kek-0123456789abcdef012";

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
};

/** 内存版数据库：keyA 签发凭证后轮换到 keyB，模拟生产轮换时间线。 */
const dbMock = vi.hoisted(() => {
  const state: { keys: KeyRow[]; credentials: CredentialRow[]; ready: Promise<void> } = {
    keys: [],
    credentials: [],
    ready: Promise.resolve()
  };

  const query = async (text: string, params: unknown[] = []): Promise<{ rows: unknown[] }> => {
    if (text.includes("FROM media_signing_keys WHERE kid = $1")) {
      return { rows: state.keys.filter((key) => key.kid === params[0]) };
    }
    if (text.includes("FROM media_signing_keys ORDER BY created_at ASC")) {
      return { rows: [...state.keys].sort((a, b) => a.created_at.getTime() - b.created_at.getTime()) };
    }
    if (text.includes("FROM media_credentials WHERE id = $1")) {
      return { rows: state.credentials.filter((row) => row.id === params[0]) };
    }
    if (text.includes("FROM media_credentials WHERE media_id = $1")) {
      return { rows: state.credentials.filter((row) => row.media_id === params[0]) };
    }
    if (text.includes("INSERT INTO media_credentials")) {
      const [id, mediaId, type, kid, claims, payload, signature, issuedAt] = params as [
        string, string, string, string, string, string, string, Date
      ];
      if (state.credentials.some((row) => row.media_id === mediaId && row.type === type)) return { rows: [] };
      state.credentials.push({
        id, media_id: mediaId, type, kid,
        claims: JSON.parse(claims), payload, signature, issued_at: issuedAt
      });
      return { rows: [] };
    }
    if (text.includes("FROM media_assets WHERE id = $1")) {
      return { rows: params[0] === MEDIA_ID ? [{ owner_id: OWNER_ID }] : [] };
    }
    throw new Error(`Unexpected SQL in test: ${text}`);
  };

  state.ready = (async () => {
    const forensics = await import("@map/shared/forensics");
    const keyA = forensics.generateSigningKey();
    state.keys.push({
      kid: keyA.kid,
      algorithm: "ed25519",
      public_key_pem: keyA.publicKeyPem,
      private_key_enc: forensics.encryptPrivateKey(keyA.privateKeyPem, KEK),
      status: "active",
      created_at: new Date(),
      retired_at: null
    });
    await forensics.issueCredential(query, keyA, {
      id: CREDENTIAL_ID,
      mediaId: MEDIA_ID,
      type: "processed",
      claims: {
        mediaId: MEDIA_ID,
        processedSha256: "a".repeat(64),
        perceptualHash: "0123456789abcdef",
        width: 1024,
        height: 768,
        watermarkFingerprint: "0123456789abcdef",
        processedAt: new Date().toISOString(),
        privacy: { metadataRemoved: true, serverReencoded: true, manualRegionCount: 1, detectorRegionCount: 0 }
      }
    });
    // 轮换：keyA 退役，keyB 生效
    const keyB = forensics.generateSigningKey();
    state.keys[0]!.status = "retired";
    state.keys[0]!.retired_at = new Date();
    state.keys.push({
      kid: keyB.kid,
      algorithm: "ed25519",
      public_key_pem: keyB.publicKeyPem,
      private_key_enc: forensics.encryptPrivateKey(keyB.privateKeyPem, KEK),
      status: "active",
      created_at: new Date(Date.now() + 1),
      retired_at: null
    });
  })();

  return { state, query };
});

vi.mock("../db", () => ({ query: dbMock.query }));

vi.mock("../auth", async () => {
  const { AppError } = await import("../errors");
  return {
    requireAuth: async (request: { headers: Record<string, unknown>; user?: unknown }) => {
      const id = request.headers["x-test-user-id"];
      if (typeof id !== "string" || !id) throw new AppError(401, "UNAUTHORIZED", "Authentication required");
      const role = typeof request.headers["x-test-role"] === "string" ? request.headers["x-test-role"] : "contributor";
      request.user = { id, role };
    }
  };
});

let app: FastifyInstance;

beforeAll(async () => {
  await dbMock.state.ready;
  const { forensicsRoutes } = await import("./forensics");
  app = Fastify({ logger: false });
  app.setErrorHandler((error: unknown, _request, reply) => {
    const err = error as { statusCode?: number; message?: string };
    return reply.code(err.statusCode ?? 500).send({ code: err.message ?? "error" });
  });
  await app.register(forensicsRoutes, { prefix: "/api/v1" });
});

afterAll(async () => {
  await app.close();
});

describe("public forensics endpoints", () => {
  it("publishes active and retired public keys without private material", async () => {
    const response = await app.inject({ method: "GET", url: "/api/v1/forensics/keys" });
    expect(response.statusCode).toBe(200);
    const body = response.json();
    expect(body.keys).toHaveLength(2);
    expect(body.keys.map((key: { status: string }) => key.status).sort()).toEqual(["active", "retired"]);
    for (const key of body.keys) {
      expect(key.publicKeyPem).toContain("BEGIN PUBLIC KEY");
      expect(JSON.stringify(key)).not.toMatch(/private|PRIVATE KEY/i);
    }
  });

  it("verifies a credential signed before the key rotation", async () => {
    const response = await app.inject({ method: "GET", url: `/api/v1/forensics/credentials/${CREDENTIAL_ID}` });
    expect(response.statusCode).toBe(200);
    const body = response.json();
    expect(body.valid).toBe(true);
    expect(body.keyStatus).toBe("retired");
    expect(body.claims.processedSha256).toBe("a".repeat(64));
  });

  it("never leaks original-image references through the public address", async () => {
    const response = await app.inject({ method: "GET", url: `/api/v1/forensics/credentials/${CREDENTIAL_ID}` });
    const raw = response.body;
    expect(raw).not.toMatch(/quarantine|original|owner|filename|object_?[kK]ey|private_key/i);
  });

  it("reports tampered credentials as invalid", async () => {
    const stored = dbMock.state.credentials[0]!;
    const original = stored.signature;
    stored.signature = `${original.slice(0, -2)}xx`;
    try {
      const response = await app.inject({ method: "GET", url: `/api/v1/forensics/credentials/${CREDENTIAL_ID}` });
      expect(response.statusCode).toBe(200);
      expect(response.json().valid).toBe(false);
    } finally {
      stored.signature = original;
    }
  });

  it("returns 404 for unknown credentials", async () => {
    const response = await app.inject({
      method: "GET",
      url: "/api/v1/forensics/credentials/00000000-0000-4000-8000-000000000000"
    });
    expect(response.statusCode).toBe(404);
  });
});

describe("media credential listing", () => {
  it("requires authentication and enforces ownership", async () => {
    const anonymous = await app.inject({ method: "GET", url: `/api/v1/forensics/media/${MEDIA_ID}/credentials` });
    expect(anonymous.statusCode).toBe(401);

    const stranger = await app.inject({
      method: "GET",
      url: `/api/v1/forensics/media/${MEDIA_ID}/credentials`,
      headers: { "x-test-user-id": "dddddddd-dddd-4ddd-8ddd-dddddddddddd" }
    });
    expect(stranger.statusCode).toBe(403);

    const owner = await app.inject({
      method: "GET",
      url: `/api/v1/forensics/media/${MEDIA_ID}/credentials`,
      headers: { "x-test-user-id": OWNER_ID }
    });
    expect(owner.statusCode).toBe(200);
    expect(owner.json().credentials).toHaveLength(1);
    expect(owner.json().credentials[0].valid).toBe(true);

    const moderator = await app.inject({
      method: "GET",
      url: `/api/v1/forensics/media/${MEDIA_ID}/credentials`,
      headers: { "x-test-user-id": "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", "x-test-role": "moderator" }
    });
    expect(moderator.statusCode).toBe(200);
  });
});
