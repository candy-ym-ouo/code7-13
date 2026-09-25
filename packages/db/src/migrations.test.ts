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

  it("adds the forensics key directory and credential ledger in migration 0003", () => {
    const forensics = readFileSync(
      join(dirname(fileURLToPath(import.meta.url)), "../migrations/0003_forensics.sql"),
      "utf8"
    );
    expect(forensics).toContain("CREATE TABLE forensics_signing_keys");
    expect(forensics).toContain("CREATE TABLE media_credentials");
    // Private key is nullable: retirement erases it while the public key stays.
    expect(forensics).toContain("private_key_enc text");
    // Exactly one active signing key, and one immutable deletion credential per media.
    expect(forensics).toContain("ON forensics_signing_keys ((1)) WHERE status = 'active'");
    expect(forensics).toContain("ON media_credentials(media_id) WHERE type = 'media.deleted'");
    // Sealed public id lives on the asset; credentials FK the key directory.
    expect(forensics).toContain("ADD COLUMN public_id text");
    expect(forensics).toMatch(/kid text NOT NULL REFERENCES forensics_signing_keys\(kid\)/);
  });

  it("uses PostGIS geography points and spatial indexes", () => {
    expect(migration).toContain("geography(Point, 4326)");
    expect(migration).toContain("USING gist (geom)");
  });
});
