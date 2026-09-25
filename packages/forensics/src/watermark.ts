import sharp from "sharp";
import { hmacDigest } from "./encoding";

/**
 * Invisible spread-spectrum watermark.
 *
 * A 64-bit id is embedded in the blue channel as the quantized parity of block
 * means. Blocks are visited in an order derived from HMAC(secret, id) so an
 * observer cannot locate the watermarked samples, and every bit is spread over
 * many blocks with majority voting — the mark survives WebP re-encoding and
 * moderate recompression. Detection needs only the watermark secret; the
 * embedded id itself is keyed and reveals nothing about the media.
 */

export const WATERMARK_SCHEME = "bluespread-1";
const WATERMARK_BITS = 64;
/** Fixed proportional grid; boundaries scale with the image, so resizing keeps blocks aligned. */
const GRID_COLS = 32;
const GRID_ROWS = 32;
/** Quantizer step in mean-luminance units; larger = stronger, more visible. */
const QUANT_STEP = 6;
const MIN_CELL_PIXELS = 3;

export function deriveWatermarkId(secret: string, mediaId: string): string {
  const digest = hmacDigest(secret, `map:wm:id:${mediaId}`).toString("hex").slice(0, 16);
  return `w${digest}`;
}

/** mulberry32 over a 32-bit state, returning raw uint32 values. */
function prng(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let value = state;
    value = Math.imul(value ^ (value >>> 15), value | 1);
    value ^= value + Math.imul(value ^ (value >>> 7), value | 61);
    return (value ^ (value >>> 14)) >>> 0;
  };
}

function seedFor(secret: string, watermarkId: string): number {
  const digest = hmacDigest(secret, `map:wm:order:${WATERMARK_SCHEME}:${watermarkId}`);
  return digest.readUInt32LE(0);
}

function gridCellCount(): number {
  return GRID_COLS * GRID_ROWS;
}

function shuffledOrder(length: number, secret: string, watermarkId: string): Uint32Array {
  const order = new Uint32Array(length);
  for (let index = 0; index < length; index += 1) order[index] = index;
  const rand = prng(seedFor(secret, watermarkId));
  for (let index = length - 1; index > 0; index -= 1) {
    const swap = Math.floor((rand() / 0x1_0000_0000) * (index + 1));
    const temporary = order[index] ?? 0;
    order[index] = order[swap] ?? 0;
    order[swap] = temporary;
  }
  return order;
}

interface RawImage {
  data: Buffer;
  width: number;
  height: number;
}

async function readRaw(input: Buffer | ArrayBuffer | Uint8Array, pixelLimit: number): Promise<RawImage> {
  const image = sharp(Buffer.from(input as Buffer), { limitInputPixels: pixelLimit });
  const { data, info } = await image.ensureAlpha().raw().toBuffer({ resolveWithObject: true });
  if (!info.width || !info.height) throw new Error("decoded image has no dimensions");
  return { data, width: info.width, height: info.height };
}

interface CellBounds {
  startX: number;
  startY: number;
  endX: number;
  endY: number;
}

function cellBounds(cellIndex: number, width: number, height: number): CellBounds {
  const cx = cellIndex % GRID_COLS;
  const cy = Math.floor(cellIndex / GRID_COLS);
  return {
    startX: Math.floor((cx * width) / GRID_COLS),
    startY: Math.floor((cy * height) / GRID_ROWS),
    endX: Math.floor(((cx + 1) * width) / GRID_COLS),
    endY: Math.floor(((cy + 1) * height) / GRID_ROWS)
  };
}

function cellMean(data: Buffer, width: number, height: number, cellIndex: number): number {
  const { startX, startY, endX, endY } = cellBounds(cellIndex, width, height);
  let sum = 0;
  for (let y = startY; y < endY; y += 1) {
    for (let x = startX; x < endX; x += 1) {
      sum += data[(y * width + x) * 4 + 2] ?? 0;
    }
  }
  return sum / Math.max(1, (endX - startX) * (endY - startY));
}

function setCellMean(data: Buffer, width: number, height: number, cellIndex: number, targetMean: number): void {
  const { startX, startY, endX, endY } = cellBounds(cellIndex, width, height);
  const count = Math.max(1, (endX - startX) * (endY - startY));
  let sum = 0;
  for (let y = startY; y < endY; y += 1) {
    for (let x = startX; x < endX; x += 1) {
      sum += data[(y * width + x) * 4 + 2] ?? 0;
    }
  }
  const delta = Math.round(targetMean - sum / count);
  if (delta === 0) return;
  for (let y = startY; y < endY; y += 1) {
    for (let x = startX; x < endX; x += 1) {
      const offset = (y * width + x) * 4 + 2;
      const value = data[offset] ?? 0;
      data[offset] = Math.max(0, Math.min(255, value + delta));
    }
  }
}

/** Nearest quantized mean whose parity class equals `bit`. */
function targetQuantizedMean(mean: number, bit: number): number {
  let quantized = Math.round(mean / (QUANT_STEP / 2));
  if ((quantized & 1) !== bit) {
    // Step to the adjacent value of the opposite parity with the most headroom.
    quantized += mean - quantized * (QUANT_STEP / 2) > 0 ? 1 : -1;
  }
  let target = quantized * (QUANT_STEP / 2);
  if (target > 255) target -= QUANT_STEP;
  if (target < 0) target += QUANT_STEP;
  return target;
}

export interface EmbedOptions {
  quality?: number;
  pixelLimit?: number;
}

export interface RawWatermark {
  data: Buffer;
  width: number;
  height: number;
}

/** Applies the watermark to raw RGBA pixels without encoding. */
export async function embedWatermarkRaw(
  input: Buffer,
  watermarkId: string,
  secret: string,
  options: { pixelLimit?: number } = {}
): Promise<RawWatermark> {
  const { data, width, height } = await readRaw(input, options.pixelLimit ?? 20_000_000);
  if (width < GRID_COLS * MIN_CELL_PIXELS || height < GRID_ROWS * MIN_CELL_PIXELS) {
    throw new Error(`image too small to carry the watermark: need at least ${GRID_COLS * MIN_CELL_PIXELS}px per side`);
  }

  const cellCount = gridCellCount();
  const bitString = BigInt(`0x${watermarkId.slice(1)}`).toString(2).padStart(WATERMARK_BITS, "0");
  const order = shuffledOrder(cellCount, secret, watermarkId);
  const usedSamples = Math.floor(order.length / WATERMARK_BITS) * WATERMARK_BITS;

  for (let sample = 0; sample < usedSamples; sample += 1) {
    const bit = Number(bitString[sample % WATERMARK_BITS]);
    const cellIndex = order[sample];
    if (cellIndex === undefined) continue;
    const mean = cellMean(data, width, height, cellIndex);
    setCellMean(data, width, height, cellIndex, targetQuantizedMean(mean, bit));
  }
  return { data, width, height };
}

export async function embedWatermark(
  input: Buffer,
  watermarkId: string,
  secret: string,
  options: EmbedOptions = {}
): Promise<Buffer> {
  const quality = options.quality ?? 86;
  const { data, width, height } = await embedWatermarkRaw(input, watermarkId, secret, options);
  return sharp(data, { raw: { width, height, channels: 4 } }).webp({ quality, effort: 4 }).toBuffer();
}

export interface WatermarkDetection {
  id: string;
  /** Fraction of quantized samples voting for the returned bits (0..1). */
  confidence: number;
  /** Fraction of recovered bits matching the expected id (0..1). */
  matches: number;
}

export async function detectWatermark(
  input: Buffer,
  secret: string,
  expectedId: string,
  options: { pixelLimit?: number } = {}
): Promise<WatermarkDetection> {
  const { data, width, height } = await readRaw(input, options.pixelLimit ?? 20_000_000);
  if (width < GRID_COLS * MIN_CELL_PIXELS || height < GRID_ROWS * MIN_CELL_PIXELS) {
    throw new Error("image too small to carry a watermark");
  }

  const cellCount = gridCellCount();
  const order = shuffledOrder(cellCount, secret, expectedId);
  const usedSamples = Math.floor(order.length / WATERMARK_BITS) * WATERMARK_BITS;
  const votes = new Array<number[]>(WATERMARK_BITS);
  for (let bit = 0; bit < WATERMARK_BITS; bit += 1) votes[bit] = [0, 0];

  for (let sample = 0; sample < usedSamples; sample += 1) {
    const bitIndex = sample % WATERMARK_BITS;
    const cellIndex = order[sample];
    if (cellIndex === undefined) continue;
    const mean = cellMean(data, width, height, cellIndex);
    const bit = Math.round(mean / (QUANT_STEP / 2)) & 1;
    const bucket = votes[bitIndex];
    if (!bucket) continue;
    bucket[bit] = (bucket[bit] ?? 0) + 1;
  }

  let bits = "";
  let agreeingSamples = 0;
  let totalSamples = 0;
  for (let bitIndex = 0; bitIndex < WATERMARK_BITS; bitIndex += 1) {
    const [zeros, ones] = votes[bitIndex] as [number, number];
    const winner = ones > zeros ? 1 : 0;
    bits += String(winner);
    agreeingSamples += winner === 1 ? ones : zeros;
    totalSamples += zeros + ones;
  }

  const id = `w${BigInt(`0b${bits}`).toString(16).padStart(16, "0")}`;
  const expectedBits = BigInt(`0x${expectedId.slice(1)}`).toString(2).padStart(WATERMARK_BITS, "0");
  let matching = 0;
  for (let bitIndex = 0; bitIndex < WATERMARK_BITS; bitIndex += 1) {
    if (bits[bitIndex] === expectedBits[bitIndex]) matching += 1;
  }

  return {
    id,
    confidence: totalSamples > 0 ? agreeingSamples / totalSamples : 0,
    matches: matching / WATERMARK_BITS
  };
}
