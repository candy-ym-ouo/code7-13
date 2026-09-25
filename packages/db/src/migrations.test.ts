import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";

const migration = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), "../migrations/0001_init.sql"),
  "utf8"
);

describe("initial migration", () => {
  it("contains the core audited entities", () => {
    for (const table of [
      "users", "sessions", "auth_tokens", "categories", "map_features",
      "feature_revisions", "media_assets", "comments", "reports",
      "moderation_actions", "outbox_events", "audit_logs", "notifications"
    ]) {
      expect(migration).toContain(`CREATE TABLE ${table}`);
    }
  });

  it("adds public thumbnail and outbox recovery fields in migration 0002", () => {
    const followup = readFileSync(
      join(dirname(fileURLToPath(import.meta.url)), "../migrations/0002_media_public_thumb.sql"),
      "utf8"
    );
    expect(followup).toContain("public_thumbnail_object_key");
    expect(followup).toContain("updated_at timestamptz");
  });

  it("adds signing keys and verifiable credentials in migration 0003", () => {
    const forensics = readFileSync(
      join(dirname(fileURLToPath(import.meta.url)), "../migrations/0003_media_forensics.sql"),
      "utf8"
    );
    expect(forensics).toContain("CREATE TABLE media_signing_keys");
    expect(forensics).toContain("CREATE TABLE media_credentials");
    // 只有一把 active 密钥；retired 密钥保留公钥用于校验历史凭证
    expect(forensics).toContain("media_signing_keys_one_active_idx");
    // 每种凭证类型每个媒体只签发一次，保证重试幂等
    expect(forensics).toContain("media_credentials_processed_once_idx");
    expect(forensics).toContain("media_credentials_deleted_once_idx");
  });

  it("uses PostGIS geography points and spatial indexes", () => {
    expect(migration).toContain("geography(Point, 4326)");
    expect(migration).toContain("USING gist (geom)");
  });
});
