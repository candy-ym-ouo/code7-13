import { readFile } from "node:fs/promises";
import sharp from "sharp";
import { deriveWatermarkSecret, findProcessedCredentialByFingerprint, verifyCredential, type QueryFn } from "@map/shared/forensics";
import { config } from "./config";
import { pool } from "./db";
import { extractWatermark } from "./watermark";

const queryFn: QueryFn = (text, params) => pool.query(text, params);

/**
 * 取证核查：从图片中提取不可见水印，并查找对应的处理凭证。
 * 用法：pnpm --filter @map/worker forensics:extract <图片路径>
 */
async function main() {
  const file = process.argv[2];
  if (!file) throw new Error("Usage: forensics:extract <image-file>");

  const source = await readFile(file);
  const decoded = await sharp(source, { limitInputPixels: config.MEDIA_MAX_PIXELS })
    .rotate()
    .raw()
    .toBuffer({ resolveWithObject: true });

  const secret = deriveWatermarkSecret(config.MEDIA_SIGNING_KEK);
  const watermark = extractWatermark(decoded.data, decoded.info.width, decoded.info.height, decoded.info.channels, secret);
  if (!watermark) {
    console.log("image is too small to carry a watermark");
    return;
  }
  console.log(`watermark fingerprint: ${watermark.fingerprint}`);
  console.log(`checksum valid: ${watermark.valid}, confidence: ${watermark.confidence.toFixed(3)}`);
  if (!watermark.valid) {
    console.log("checksum mismatch: image was not watermarked by this service or was heavily altered");
    return;
  }

  const credential = await findProcessedCredentialByFingerprint(queryFn, watermark.fingerprint);
  if (!credential) {
    console.log("no processed credential found for this fingerprint");
    return;
  }
  const verification = await verifyCredential(queryFn, credential);
  console.log(`credential ${credential.id} for media ${credential.mediaId}`);
  console.log(`issued at ${credential.issuedAt.toISOString()} with key ${credential.kid} (${verification.keyStatus})`);
  console.log(`signature valid: ${verification.valid}`);
}

main()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(() => void pool.end());
