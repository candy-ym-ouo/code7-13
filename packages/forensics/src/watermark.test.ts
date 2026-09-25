import { describe, expect, it } from "vitest";
import sharp from "sharp";
import { deriveWatermarkId, detectWatermark, embedWatermark, embedWatermarkRaw } from "./watermark";
import { noisyImage } from "./test-helpers";

const SECRET = "watermark-secret-test-value";

describe("spread-spectrum watermark", () => {
  it("round-trips the keyed id through a webp encode", async () => {
    const source = await noisyImage(512, 512);
    const mediaId = "0192f5b3-7b4c-7a2e-9f0a-123456789abc";
    const wmId = deriveWatermarkId(SECRET, mediaId);

    const watermarked = await embedWatermark(source, wmId, SECRET);
    const result = await detectWatermark(watermarked, SECRET, wmId);

    expect(result.matches).toBeGreaterThan(0.95);
    expect(result.id).toBe(wmId);
    expect(result.confidence).toBeGreaterThan(0.8);
  });

  it("is visually imperceptible (raw-domain PSNR above 43 dB)", async () => {
    const source = await noisyImage(512, 512);
    const wmId = deriveWatermarkId(SECRET, "22222222-3333-7444-8555-666666666666");

    const { data: before, info } = await sharp(source).ensureAlpha().raw().toBuffer({ resolveWithObject: true });
    const { data: after } = await embedWatermarkRaw(source, wmId, SECRET);
    expect(after.length).toBe(before.length);

    let mse = 0;
    for (let offset = 0; offset < before.length; offset += info.channels) {
      for (let channel = 0; channel < 3; channel += 1) {
        const diff = (before[offset + channel] ?? 0) - (after[offset + channel] ?? 0);
        mse += diff * diff;
      }
    }
    mse /= (before.length / info.channels) * 3;
    const psnr = 10 * Math.log10((255 * 255) / Math.max(1e-9, mse));
    expect(psnr).toBeGreaterThan(43);
  });

  it("survives aggressive re-encoding and resizing", async () => {
    const source = await noisyImage(640, 640);
    const wmId = deriveWatermarkId(SECRET, "11111111-2222-7333-8444-555555555555");

    const watermarked = await embedWatermark(source, wmId, SECRET);
    const attacked = await sharp(watermarked)
      .resize(560, 560, { fit: "fill" })
      .webp({ quality: 55, effort: 4 })
      .toBuffer();

    const result = await detectWatermark(attacked, SECRET, wmId);
    expect(result.matches).toBeGreaterThan(0.85);
  });

  it("does not match an unrelated candidate id", async () => {
    const source = await noisyImage(512, 512);
    const embedded = deriveWatermarkId(SECRET, "aaaaaaaa-aaaa-7aaa-8aaa-aaaaaaaaaaaa");
    const other = deriveWatermarkId(SECRET, "bbbbbbbb-bbbb-7bbb-8bbb-bbbbbbbbbbbb");

    const watermarked = await embedWatermark(source, embedded, SECRET);
    const result = await detectWatermark(watermarked, SECRET, other);
    expect(result.matches).toBeLessThan(0.7);
  });

  it("rejects images too small to carry the mark", async () => {
    const tiny = await noisyImage(32, 32);
    const wmId = deriveWatermarkId(SECRET, "cccccccc-cccc-7ccc-8ccc-cccccccccccc");
    await expect(embedWatermark(tiny, wmId, SECRET)).rejects.toThrow(/too small/);
  });
});
