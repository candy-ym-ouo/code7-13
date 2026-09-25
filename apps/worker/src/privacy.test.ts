import { beforeAll, describe, expect, it } from "vitest";
import sharp from "sharp";

let processPrivacyImage: typeof import("./privacy").processPrivacyImage;
let extractWatermark: typeof import("./watermark").extractWatermark;

const WATERMARK_SECRET = "privacy-test-watermark-secret";

beforeAll(async () => {
  process.env.DATABASE_URL = "postgres://map:map@localhost:5432/map";
  process.env.S3_ENDPOINT = "http://localhost:9000";
  process.env.S3_PUBLIC_ENDPOINT = "http://localhost:9000";
  process.env.S3_ACCESS_KEY = "test";
  process.env.S3_SECRET_KEY = "test";
  process.env.S3_QUARANTINE_BUCKET = "quarantine";
  process.env.S3_PUBLIC_BUCKET = "public";
  process.env.PRIVACY_DETECTOR_URL = "";
  process.env.MEDIA_SIGNING_KEK = "privacy-test-kek-0123456789abcdef";
  const module = await import("./privacy");
  processPrivacyImage = module.processPrivacyImage;
  extractWatermark = (await import("./watermark")).extractWatermark;
});

describe("privacy image processing", () => {
  it("creates the public thumbnail from the blurred server output", async () => {
    const source = await sharp({
      create: { width: 320, height: 320, channels: 3, background: { r: 20, g: 40, b: 160 } }
    }).composite([{
      input: Buffer.from('<svg width="320" height="320"><rect x="120" y="120" width="80" height="80" fill="#ff0000"/></svg>'),
      top: 0,
      left: 0
    }]).png().toBuffer();

    const result = await processPrivacyImage(source, [{ x: 0.33, y: 0.33, width: 0.34, height: 0.34 }]);
    const directThumbnail = await sharp(source)
      .resize({ width: 720, height: 720, fit: "inside", withoutEnlargement: true })
      .webp({ quality: 78, effort: 4 })
      .toBuffer();

    const processedRaw = await sharp(result.thumbnail).resize(64, 64, { fit: "fill" }).raw().toBuffer();
    const directRaw = await sharp(directThumbnail).resize(64, 64, { fit: "fill" }).raw().toBuffer();
    let difference = 0;
    for (let index = 0; index < processedRaw.length; index += 1) {
      difference += Math.abs((processedRaw[index] ?? 0) - (directRaw[index] ?? 0));
    }
    expect(result.image.length).toBeGreaterThan(0);
    expect(result.thumbnail.length).toBeGreaterThan(0);
    expect(difference).toBeGreaterThan(500);
  });

  it("embeds a recoverable watermark into the processed image", async () => {
    const source = await sharp({
      create: { width: 480, height: 360, channels: 3, background: { r: 90, g: 120, b: 150 } }
    }).composite([{
      input: Buffer.from('<svg width="480" height="360"><circle cx="240" cy="180" r="120" fill="#c04030"/></svg>'),
      top: 0,
      left: 0
    }]).png().toBuffer();

    const fingerprint = "0123456789abcdef";
    const withWatermark = await processPrivacyImage(source, [], { fingerprint, secret: WATERMARK_SECRET });
    expect(withWatermark.watermarkEmbedded).toBe(true);

    const decoded = await sharp(withWatermark.image).raw().toBuffer({ resolveWithObject: true });
    const extracted = extractWatermark(decoded.data, decoded.info.width, decoded.info.height, decoded.info.channels, WATERMARK_SECRET);
    expect(extracted).not.toBeNull();
    expect(extracted!.fingerprint).toBe(fingerprint);
    expect(extracted!.valid).toBe(true);

    const withoutWatermark = await processPrivacyImage(source, []);
    expect(withoutWatermark.watermarkEmbedded).toBe(false);
  });

  it("still processes tiny images when the watermark does not fit", async () => {
    const tiny = await sharp({
      create: { width: 96, height: 96, channels: 3, background: { r: 40, g: 90, b: 140 } }
    }).png().toBuffer();
    const result = await processPrivacyImage(tiny, [], { fingerprint: "0123456789abcdef", secret: WATERMARK_SECRET });
    expect(result.watermarkEmbedded).toBe(false);
    expect(result.image.length).toBeGreaterThan(0);
    expect(result.sha256).toMatch(/^[0-9a-f]{64}$/);
  });
});
