import { vi, describe, it, expect, beforeAll } from "vitest";
import sharp from "sharp";
import { createHash } from "node:crypto";

// --- Boundary mocks (no DB, S3, Redis, ClamAV needed) -------------------------

process.env.DATABASE_URL = "postgres://map:map@localhost:5432/map";
process.env.S3_ENDPOINT = "http://localhost:9000";
process.env.S3_PUBLIC_ENDPOINT = "http://localhost:9000";
process.env.S3_ACCESS_KEY = "test";
process.env.S3_SECRET_KEY = "test";
process.env.S3_QUARANTINE_BUCKET = "quarantine";
process.env.S3_PUBLIC_BUCKET = "public";
process.env.PRIVACY_DETECTOR_URL = "";
process.env.FORENSICS_MASTER_KEY = "test-forensics-master-key-1234";
process.env.FORENSICS_WATERMARK_SECRET = "test-forensics-watermark-secret";
process.env.FORENSICS_ADDRESS_SECRET = "test-forensics-address-secret";

const state = vi.hoisted(() => ({
  stored: {} as Record<string, Record<string, unknown>>,
  written: {} as Record<string, Buffer<ArrayBufferLike>>,
  copied: [] as Array<{ source: string; destination: string }>,
  sourceBytes: Buffer.alloc(0) as Buffer<ArrayBufferLike>
}));

const { poolQuery } = vi.hoisted(() => {
  const poolQuery = vi.fn(async (text: string, params: unknown[] = []) => {
    const s = (state as { stored: Record<string, Record<string, unknown>> }).stored;
    if (text.includes("FROM media_assets WHERE id")) {
      return { rows: [s[params[0] as string] ?? null], rowCount: 1 };
    }
    if (text.startsWith("UPDATE media_assets")) {
      const row = s[params[0] as string];
      // Only the final "processed" update carries the public_id parameter.
      if (row && text.includes("public_id = $13")) {
        row.privacy_status = params[1];
        row.processed_object_key = params[2] ?? row.processed_object_key;
        row.thumbnail_object_key = params[3] ?? row.thumbnail_object_key;
        if (params[4] !== undefined) row.public_object_key = params[4];
        row.public_thumbnail_object_key = params[11];
        row.public_id = params[12];
        row.credential_hash = params[13];
      }
      return { rows: [], rowCount: 1 };
    }
    if (text.includes("FROM forensics_signing_keys")) {
      return { rows: [], rowCount: 0 };
    }
    if (text.includes("FROM media_credentials")) {
      return { rows: [], rowCount: 0 };
    }
    if (text.startsWith("INSERT")) {
      return { rows: [], rowCount: 1 };
    }
    return { rows: [], rowCount: 0 };
  });
  return { poolQuery };
});

vi.mock("./db", () => ({ pool: { query: (text: string, params?: unknown[]) => poolQuery(text, params) } }));
vi.mock("./clamav", () => ({ scanForMalware: vi.fn(async () => undefined) }));
vi.mock("./storage", () => ({
  readQuarantineObject: vi.fn(async () =>
    (state as { sourceBytes: Buffer }).sourceBytes
  ),
  writeQuarantineObject: vi.fn(async (key: string, body: Buffer) => {
    (state as { written: Record<string, Buffer> }).written[key] = body;
  }),
  copyToPublic: vi.fn(async (source: string, destination: string) => {
    (state as { copied: Array<{ source: string; destination: string }> }).copied.push({ source, destination });
  }),
  deleteObject: vi.fn(async () => undefined),
  objectExists: vi.fn(async () => true)
}));

beforeAll(async () => {
  state.sourceBytes = await sharp({
    create: { width: 400, height: 300, channels: 3, background: { r: 30, g: 120, b: 200 } }
  }).png().toBuffer();
});

describe("processMediaJob forensics integration", () => {
  it("watermarks outputs, signs a credential and uses sealed public keys", async () => {
    const mediaId = "0192f5b3-aaaa-7aaa-8aaa-aaaaaaaaaaaa";
    state.stored[mediaId] = {
      id: mediaId,
      privacy_status: "processing",
      quarantine_object_key: `quarantine/u/${mediaId}.png`,
      mime_type: "image/png",
      privacy_report: { manualRegions: [] }
    };

    const { processMediaJob } = await import("./media-job");
    await processMediaJob(mediaId);

    const row = state.stored[mediaId];
    expect(row.privacy_status).toBe("manual_review");

    const processedKey = `processed/${mediaId}.webp`;
    const thumbKey = `processed/${mediaId}.thumb.webp`;
    expect(state.written[processedKey]).toBeInstanceOf(Buffer);
    expect(state.written[thumbKey]).toBeInstanceOf(Buffer);

    // Sealed, unguessable public id — not based on the media id.
    expect(row.public_id).toMatch(/^m[0-9a-f]{43}$/);
    expect(String(row.public_id)).not.toContain(mediaId.replace(/-/g, ""));
    expect(row.credential_hash).toMatch(/^[0-9a-f]{64}$/);

    const credentialInsert = poolQuery.mock.calls.find(
      (call) => typeof call[0] === "string" && call[0].startsWith("INSERT INTO media_credentials")
    );
    expect(credentialInsert).toBeTruthy();
    const params = (credentialInsert?.[1] as unknown[]) ?? [];
    const token = params[4] as string;
    const payload = JSON.parse(params[5] as string) as {
      type: string;
      content: { sha256: string };
      source: { commitment: string };
      publicId: string;
      watermark: { id: string };
    };
    expect(payload.type).toBe("media.processed");
    expect(payload.source.commitment).toMatch(/^[0-9a-f]{64}$/);

    const originalSha = createHash("sha256").update(state.sourceBytes).digest("hex");
    // The original hash must never appear in the stored payload or the token.
    expect(params[5]).not.toContain(originalSha);
    expect(token).not.toContain(originalSha);
    expect(payload.content.sha256).toBe(
      createHash("sha256").update(state.written[processedKey]!).digest("hex")
    );
    expect(payload.publicId).toBe(row.public_id);

    // Manual-review path publishes nothing.
    expect(state.copied).toHaveLength(0);
  });
});
