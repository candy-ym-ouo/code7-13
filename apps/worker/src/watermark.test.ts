import { describe, expect, it } from "vitest";
import sharp from "sharp";
import {
  canWatermark,
  embedWatermark,
  extractWatermark,
  WATERMARK_DELTA,
  watermarkCapacity
} from "./watermark";

const SECRET = "watermark-secret-for-tests";
const FINGERPRINT = "a1b2c3d4e5f60718";

/** 生成带噪声和渐变的类照片图像，对 WebP 量化最不友好。 */
async function photoLikeImage(width: number, height: number): Promise<Buffer> {
  const raw = Buffer.alloc(width * height * 3);
  let state = 42;
  const random = () => {
    state = (state * 1103515245 + 12345) & 0x7fffffff;
    return state / 0x7fffffff;
  };
  for (let y = 0; y < height; y += 1) {
    for (let x = 0; x < width; x += 1) {
      const offset = (y * width + x) * 3;
      raw[offset] = Math.min(255, Math.max(0, Math.round((x / width) * 200 + random() * 40)));
      raw[offset + 1] = Math.min(255, Math.max(0, Math.round((y / height) * 180 + random() * 50)));
      raw[offset + 2] = Math.min(255, Math.max(0, Math.round(120 + random() * 60)));
    }
  }
  return sharp(raw, { raw: { width, height, channels: 3 } }).png().toBuffer();
}

async function embedAndReencode(source: Buffer, fingerprint: string, secret = SECRET) {
  const decoded = await sharp(source).raw().toBuffer({ resolveWithObject: true });
  const { width, height } = decoded.info;
  const embedded = embedWatermark(decoded.data, width, height, 3, fingerprint, secret);
  expect(embedded).not.toBeNull();
  const webp = await sharp(embedded!, { raw: { width, height, channels: 3 } })
    .webp({ quality: 86, effort: 4 })
    .toBuffer();
  return sharp(webp).raw().toBuffer({ resolveWithObject: true });
}

describe("watermark embedding and extraction", () => {
  it("survives WebP quality=86 re-encoding", async () => {
    const source = await photoLikeImage(320, 320);
    const decoded = await embedAndReencode(source, FINGERPRINT);
    const result = extractWatermark(decoded.data, decoded.info.width, decoded.info.height, 3, SECRET);
    expect(result).not.toBeNull();
    expect(result!.fingerprint).toBe(FINGERPRINT);
    expect(result!.valid).toBe(true);
    expect(result!.confidence).toBeGreaterThan(0.8);
  });

  it("survives a blurred privacy region", async () => {
    const source = await photoLikeImage(320, 320);
    const decoded = await embedAndReencode(source, FINGERPRINT);
    // 模拟服务端隐私模糊：中间 40% 区域强模糊
    const { width, height } = decoded.info;
    const blurredRegion = await sharp(decoded.data, { raw: { width, height, channels: 3 } })
      .extract({ left: Math.floor(width * 0.3), top: Math.floor(height * 0.3), width: Math.floor(width * 0.4), height: Math.floor(height * 0.4) })
      .blur(24)
      .png()
      .toBuffer();
    const composited = await sharp(decoded.data, { raw: { width, height, channels: 3 } })
      .composite([{ input: blurredRegion, left: Math.floor(width * 0.3), top: Math.floor(height * 0.3) }])
      .webp({ quality: 86 })
      .toBuffer();
    const final = await sharp(composited).raw().toBuffer({ resolveWithObject: true });
    const result = extractWatermark(final.data, final.info.width, final.info.height, 3, SECRET);
    expect(result).not.toBeNull();
    expect(result!.fingerprint).toBe(FINGERPRINT);
    expect(result!.valid).toBe(true);
  });

  it("fails checksum with a wrong secret and extracts nothing from clean images", async () => {
    const source = await photoLikeImage(320, 320);
    const decoded = await embedAndReencode(source, FINGERPRINT);
    const wrongSecret = extractWatermark(decoded.data, decoded.info.width, decoded.info.height, 3, "other-secret");
    expect(wrongSecret === null || wrongSecret.fingerprint !== FINGERPRINT || !wrongSecret.valid).toBe(true);

    const clean = await sharp(source).raw().toBuffer({ resolveWithObject: true });
    const cleanResult = extractWatermark(clean.data, clean.info.width, clean.info.height, 3, SECRET);
    expect(cleanResult === null || !cleanResult.valid || cleanResult.confidence < 0.9).toBe(true);
  });

  it("keeps pixel changes invisible", async () => {
    const source = await photoLikeImage(256, 256);
    const decoded = await sharp(source).raw().toBuffer({ resolveWithObject: true });
    const embedded = embedWatermark(decoded.data, decoded.info.width, decoded.info.height, 3, FINGERPRINT, SECRET);
    expect(embedded).not.toBeNull();
    let maxDelta = 0;
    for (let index = 0; index < decoded.data.length; index += 1) {
      maxDelta = Math.max(maxDelta, Math.abs((embedded![index] ?? 0) - (decoded.data[index] ?? 0)));
    }
    expect(maxDelta).toBeLessThanOrEqual(WATERMARK_DELTA);
  });

  it("reports capacity honestly and skips images that are too small", async () => {
    expect(canWatermark(320, 320)).toBe(true);
    expect(canWatermark(64, 64)).toBe(false);
    expect(watermarkCapacity(320, 320)).toBeGreaterThanOrEqual(5);

    const tiny = await photoLikeImage(64, 64);
    const decoded = await sharp(tiny).raw().toBuffer({ resolveWithObject: true });
    expect(embedWatermark(decoded.data, 64, 64, 3, FINGERPRINT, SECRET)).toBeNull();
    expect(extractWatermark(decoded.data, 64, 64, 3, SECRET)).toBeNull();
  });

  it("rejects malformed fingerprints", async () => {
    const source = await photoLikeImage(160, 160);
    const decoded = await sharp(source).raw().toBuffer({ resolveWithObject: true });
    expect(() => embedWatermark(decoded.data, 160, 160, 3, "not-hex", SECRET)).toThrow(/fingerprint/);
  });
});
