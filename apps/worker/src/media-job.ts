import type { PrivacyRegion } from "@map/shared/contracts";
import { createHash } from "node:crypto";
import { config } from "./config";
import { pool } from "./db";
import { deleteObject, objectExists, readQuarantineObject, writeQuarantineObject, copyToPublic } from "./storage";
import { scanForMalware } from "./clamav";
import { processPrivacyImage } from "./privacy";
import { getForensicsService } from "./forensics";

export async function processMediaJob(mediaId: string): Promise<void> {
  const result = await pool.query<{
    id: string;
    privacy_status: string;
    quarantine_object_key: string;
    mime_type: string;
    privacy_report: { manualRegions?: PrivacyRegion[] } | null;
  }>(
    `SELECT id, privacy_status, quarantine_object_key, mime_type, privacy_report
     FROM media_assets WHERE id = $1 AND deleted_at IS NULL`,
    [mediaId]
  );
  const media = result.rows[0];
  if (!media) throw new Error("Media record not found");
  if (!["processing", "failed"].includes(media.privacy_status)) {
    console.log(`skip media ${mediaId}: status=${media.privacy_status}`);
    return;
  }

  const autoPublish = Boolean(config.PRIVACY_DETECTOR_URL);
  let publishedKeys: string[] = [];

  try {
    await pool.query("UPDATE media_assets SET privacy_status = 'scanning', updated_at = now() WHERE id = $1", [mediaId]);
    const source = await readQuarantineObject(media.quarantine_object_key);
    await scanForMalware(source);

    await pool.query("UPDATE media_assets SET privacy_status = 'processing', updated_at = now() WHERE id = $1", [mediaId]);
    const manualRegions = media.privacy_report?.manualRegions ?? [];
    const processed = await processPrivacyImage(source, manualRegions);

    // Forensics: embed the invisible watermark, derive the sealed public
    // address and sign a verifiable processing credential. Only watermarked
    // bytes are ever copied to the public bucket.
    const forensics = await getForensicsService();
    const evidence = await forensics.issueProcessed(media.id, {
      image: processed.image,
      thumbnail: processed.thumbnail,
      width: processed.width,
      height: processed.height,
      perceptualHash: processed.perceptualHash,
      originalSha256: createHash("sha256").update(source).digest("hex"),
      originalMime: media.mime_type,
      regionCount: manualRegions.length + processed.detectorRegions.length
    });

    const processedKey = `processed/${media.id}.webp`;
    const thumbnailKey = `processed/${media.id}.thumb.webp`;
    await writeQuarantineObject(processedKey, evidence.watermarkedImage, "image/webp");
    await writeQuarantineObject(thumbnailKey, evidence.watermarkedThumbnail, "image/webp");

    const report = {
      manualRegions: processed.manualRegions,
      detectorRegions: processed.detectorRegions,
      detectorConfigured: autoPublish,
      originalMetadataRemoved: true,
      serverReencoded: true,
      width: processed.width,
      height: processed.height,
      sha256: evidence.payload.content.sha256,
      perceptualHash: processed.perceptualHash,
      publicId: evidence.publicId,
      watermarkId: evidence.watermarkId,
      credentialHash: evidence.credentialHash,
      completedAt: new Date().toISOString()
    };

    if (autoPublish) {
      await copyToPublic(processedKey, evidence.publicObjectKey);
      await copyToPublic(thumbnailKey, evidence.publicThumbnailObjectKey);
    }

    await pool.query(
      `UPDATE media_assets
       SET privacy_status = $2,
           processed_object_key = $3,
           thumbnail_object_key = $4,
           public_object_key = $5,
           public_thumbnail_object_key = $12,
           width = $6,
           height = $7,
           sha256 = $8,
           perceptual_hash = $9,
           privacy_report = $10::jsonb,
           failure_code = NULL,
           processed_at = now(),
           delete_after = now() + ($11::text || ' hours')::interval,
           public_id = $13,
           credential_hash = $14,
           updated_at = now()
       WHERE id = $1`,
      [
        mediaId,
        autoPublish ? "ready" : "manual_review",
        processedKey,
        thumbnailKey,
        autoPublish ? evidence.publicObjectKey : null,
        processed.width,
        processed.height,
        evidence.payload.content.sha256,
        processed.perceptualHash,
        JSON.stringify(report),
        String(config.ORIGINAL_RETENTION_HOURS),
        autoPublish ? evidence.publicThumbnailObjectKey : null,
        evidence.publicId,
        evidence.credentialHash
      ]
    );

    console.log(`media ${mediaId} processed as ${autoPublish ? "ready" : "manual_review"}`);
  } catch (error) {
    const message = error instanceof Error ? error.message.slice(0, 500) : "Unknown media processing error";
    await pool.query(
      `UPDATE media_assets
       SET privacy_status = 'failed', failure_code = $2,
           delete_after = now() + interval '7 days', updated_at = now()
       WHERE id = $1`,
      [mediaId, message]
    );
    if (autoPublish) {
      await Promise.allSettled(publishedKeys.map((key) => deleteObject(config.S3_PUBLIC_BUCKET, key)));
    }
    throw error;
  }
}

export async function cleanupOriginalMedia(): Promise<void> {
  const abandoned = await pool.query<{ id: string; quarantine_object_key: string }>(
    `SELECT id, quarantine_object_key FROM media_assets
     WHERE privacy_status = 'quarantined'
       AND created_at < now() - interval '24 hours'
       AND deleted_at IS NULL
     LIMIT 50`
  );
  for (const row of abandoned.rows) {
    try {
      if (await objectExists(config.S3_QUARANTINE_BUCKET, row.quarantine_object_key)) {
        await deleteObject(config.S3_QUARANTINE_BUCKET, row.quarantine_object_key);
      }
      await pool.query(
        `UPDATE media_assets
         SET privacy_status = 'deleted', deleted_at = now(), updated_at = now()
         WHERE id = $1`,
        [row.id]
      );
    } catch (error) {
      console.error({ mediaId: row.id, error }, "failed to clean abandoned upload");
    }
  }

  const result = await pool.query<{ id: string; quarantine_object_key: string }>(
    `SELECT id, quarantine_object_key FROM media_assets
     WHERE delete_after IS NOT NULL AND delete_after <= now()
       AND quarantine_object_key IS NOT NULL
       AND privacy_status IN ('ready', 'manual_review', 'rejected', 'failed', 'deleted')
     LIMIT 50`
  );
  for (const row of result.rows) {
    try {
      if (await objectExists(config.S3_QUARANTINE_BUCKET, row.quarantine_object_key)) {
        await deleteObject(config.S3_QUARANTINE_BUCKET, row.quarantine_object_key);
      }
      await pool.query("UPDATE media_assets SET delete_after = NULL, updated_at = now() WHERE id = $1", [row.id]);
    } catch (error) {
      console.error({ mediaId: row.id, error }, "failed to clean original media");
    }
  }
}

export async function markStaleFeatures(): Promise<void> {
  await pool.query(
    `UPDATE map_features
     SET needs_review_at = COALESCE(needs_review_at, now()), updated_at = now()
     WHERE status = 'published' AND freshness_expires_at <= now() AND needs_review_at IS NULL`
  );
}

export async function recoverStuckMedia(): Promise<string[]> {
  const result = await pool.query<{ id: string }>(
    `UPDATE media_assets
     SET privacy_status = 'processing', failure_code = 'Recovered after worker timeout', updated_at = now()
     WHERE privacy_status IN ('scanning', 'processing')
       AND updated_at < now() - interval '20 minutes'
       AND deleted_at IS NULL
     RETURNING id`
  );
  return result.rows.map((row) => row.id);
}

export async function cleanupDeletedMediaObjects(): Promise<void> {
  const result = await pool.query<{
    id: string;
    quarantine_object_key: string;
    processed_object_key: string | null;
    thumbnail_object_key: string | null;
    public_object_key: string | null;
    public_thumbnail_object_key: string | null;
  }>(
    `SELECT id, quarantine_object_key, processed_object_key, thumbnail_object_key,
            public_object_key, public_thumbnail_object_key
     FROM media_assets
     WHERE privacy_status = 'deleted'
       AND (quarantine_object_key NOT LIKE 'deleted/%'
         OR processed_object_key IS NOT NULL
         OR thumbnail_object_key IS NOT NULL
         OR public_object_key IS NOT NULL
         OR public_thumbnail_object_key IS NOT NULL)
     LIMIT 50`
  );

  for (const item of result.rows) {
    try {
      const targets: Array<{ key: string; bucket: string; kind: "original" | "processed" | "thumbnail" | "public" | "public_thumbnail" }> = [];
      if (!item.quarantine_object_key.startsWith("deleted/")) {
        targets.push({ key: item.quarantine_object_key, bucket: config.S3_QUARANTINE_BUCKET, kind: "original" });
      }
      if (item.processed_object_key) targets.push({ key: item.processed_object_key, bucket: config.S3_QUARANTINE_BUCKET, kind: "processed" });
      if (item.thumbnail_object_key) targets.push({ key: item.thumbnail_object_key, bucket: config.S3_QUARANTINE_BUCKET, kind: "thumbnail" });
      if (item.public_object_key) targets.push({ key: item.public_object_key, bucket: config.S3_PUBLIC_BUCKET, kind: "public" });
      if (item.public_thumbnail_object_key) targets.push({ key: item.public_thumbnail_object_key, bucket: config.S3_PUBLIC_BUCKET, kind: "public_thumbnail" });

      const outcomes = await Promise.allSettled(targets.map((target) => deleteObject(target.bucket, target.key)));

      // Issue deletion evidence once (unique constraint / ledger guard),
      // regardless of whether the API request or maintenance marked it deleted.
      const forensics = await getForensicsService();
      const existing = await pool.query<{ id: string }>(
        "SELECT 1 FROM media_credentials WHERE media_id = $1 AND type = 'media.deleted'",
        [item.id]
      );
      if (existing.rowCount === 0) {
        await forensics.issueDeletion({
          mediaId: item.id,
          deletedBy: "system",
          removedObjects: targets.map((target, index) => ({
            kind: target.kind,
            removed: outcomes[index]?.status === "fulfilled"
          }))
        });
      }

      await pool.query(
        `UPDATE media_assets
         SET quarantine_object_key = $2,
             processed_object_key = NULL,
             thumbnail_object_key = NULL,
             public_object_key = NULL,
             public_thumbnail_object_key = NULL,
             delete_after = NULL,
             updated_at = now()
         WHERE id = $1`,
        [item.id, `deleted/${item.id}.object`]
      );
    } catch (error) {
      console.error({ mediaId: item.id, error }, "failed to clean deleted media objects");
    }
  }
}

export async function markUnreferencedMediaDeleted(): Promise<void> {
  await pool.query(
    `UPDATE media_assets ma
     SET privacy_status = 'deleted', deleted_at = now(), updated_at = now()
     WHERE ma.deleted_at IS NULL
       AND ma.created_at < now() - interval '7 days'
       AND NOT EXISTS (
         SELECT 1 FROM revision_media rm WHERE rm.media_id = ma.id
       )`
  );
}
