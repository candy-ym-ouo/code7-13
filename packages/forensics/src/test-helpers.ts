import sharp from "sharp";

/** Deterministic noisy gradient so runs are reproducible but image-like. */
export async function noisyImage(width: number, height: number): Promise<Buffer> {
  const data = Buffer.alloc(width * height * 4);
  let state = 0x1234_5678;
  const rand = () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let value = state;
    value = Math.imul(value ^ (value >>> 15), value | 1);
    value ^= value + Math.imul(value ^ (value >>> 7), value | 61);
    return (value ^ (value >>> 14)) >>> 0;
  };
  for (let y = 0; y < height; y += 1) {
    for (let x = 0; x < width; x += 1) {
      const offset = (y * width + x) * 4;
      data[offset] = (x * 0.4 + (rand() % 24)) & 255;
      data[offset + 1] = (y * 0.4 + (rand() % 24)) & 255;
      data[offset + 2] = (128 + ((x - y) * 0.2 | 0) + (rand() % 40)) & 255;
      data[offset + 3] = 255;
    }
  }
  return sharp(data, { raw: { width, height, channels: 4 } }).png().toBuffer();
}
