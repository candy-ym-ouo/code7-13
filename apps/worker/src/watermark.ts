import { createHash } from "node:crypto";

/**
 * 不可见水印：把 64 位媒体指纹 + 16 位校验和扩频嵌入 8x8 亮度块。
 *
 * 每个比特重复嵌入 rep 个伪随机块（位置由水印密钥和尺寸决定），
 * 通过把块均值量化到 Δ 网格的奇偶槽位表达 0/1，提取时多数表决。
 * Δ=10 的量化步长可以承受 WebP quality=86 的有损重编码和局部模糊，
 * 同时单个像素的改动不超过 ±5，肉眼不可见。
 */

export const WATERMARK_BLOCK_SIZE = 8;
export const WATERMARK_DELTA = 10;
export const WATERMARK_MIN_REPETITION = 5;
const FINGERPRINT_BITS = 64;
const CHECKSUM_BITS = 16;
const TOTAL_BITS = FINGERPRINT_BITS + CHECKSUM_BITS;

export function watermarkCapacity(width: number, height: number): number {
  const blocks = Math.floor(width / WATERMARK_BLOCK_SIZE) * Math.floor(height / WATERMARK_BLOCK_SIZE);
  return Math.floor(blocks / TOTAL_BITS);
}

export function canWatermark(width: number, height: number): boolean {
  return watermarkCapacity(width, height) >= WATERMARK_MIN_REPETITION;
}

function checksumBits(fingerprint: string, secret: string): boolean[] {
  const digest = createHash("sha256").update(`${secret}:checksum:${fingerprint}`).digest();
  const value = digest.readUInt16BE(0);
  const bits: boolean[] = [];
  for (let index = CHECKSUM_BITS - 1; index >= 0; index -= 1) bits.push(((value >> index) & 1) === 1);
  return bits;
}

function fingerprintBits(fingerprint: string): boolean[] {
  if (!/^[0-9a-f]{16}$/.test(fingerprint)) throw new Error("Watermark fingerprint must be 16 lowercase hex characters");
  const bytes = Buffer.from(fingerprint, "hex");
  const bits: boolean[] = [];
  for (const byte of bytes) {
    for (let index = 7; index >= 0; index -= 1) bits.push(((byte >> index) & 1) === 1);
  }
  return bits;
}

function mulberry32(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let value = state;
    value = Math.imul(value ^ (value >>> 15), value | 1);
    value ^= value + Math.imul(value ^ (value >>> 7), value | 61);
    return ((value ^ (value >>> 14)) >>> 0) / 4294967296;
  };
}

/** 块位置的伪随机排列：只依赖水印密钥和图像尺寸，提取方无需知道指纹。 */
function shuffledBlockIndices(width: number, height: number, secret: string): Uint32Array {
  const blocksX = Math.floor(width / WATERMARK_BLOCK_SIZE);
  const blocksY = Math.floor(height / WATERMARK_BLOCK_SIZE);
  const count = blocksX * blocksY;
  const indices = new Uint32Array(count);
  for (let index = 0; index < count; index += 1) indices[index] = index;
  const seed = createHash("sha256").update(`${secret}:positions:${width}x${height}`).digest().readUInt32BE(0);
  const random = mulberry32(seed);
  for (let index = count - 1; index > 0; index -= 1) {
    const swap = Math.floor(random() * (index + 1));
    const temp = indices[index]!;
    indices[index] = indices[swap]!;
    indices[swap] = temp;
  }
  return indices;
}

function blockMean(raw: Buffer, width: number, channels: number, blockIndex: number): number {
  const blocksX = Math.floor(width / WATERMARK_BLOCK_SIZE);
  const blockX = (blockIndex % blocksX) * WATERMARK_BLOCK_SIZE;
  const blockY = Math.floor(blockIndex / blocksX) * WATERMARK_BLOCK_SIZE;
  let sum = 0;
  let count = 0;
  for (let y = blockY; y < blockY + WATERMARK_BLOCK_SIZE; y += 1) {
    for (let x = blockX; x < blockX + WATERMARK_BLOCK_SIZE; x += 1) {
      const offset = (y * width + x) * channels;
      for (let channel = 0; channel < channels; channel += 1) {
        sum += raw[offset + channel] ?? 0;
        count += 1;
      }
    }
  }
  return count ? sum / count : 0;
}

function shiftBlock(raw: Buffer, width: number, channels: number, blockIndex: number, shift: number): void {
  const blocksX = Math.floor(width / WATERMARK_BLOCK_SIZE);
  const blockX = (blockIndex % blocksX) * WATERMARK_BLOCK_SIZE;
  const blockY = Math.floor(blockIndex / blocksX) * WATERMARK_BLOCK_SIZE;
  for (let y = blockY; y < blockY + WATERMARK_BLOCK_SIZE; y += 1) {
    for (let x = blockX; x < blockX + WATERMARK_BLOCK_SIZE; x += 1) {
      const offset = (y * width + x) * channels;
      for (let channel = 0; channel < channels; channel += 1) {
        const position = offset + channel;
        raw[position] = Math.min(255, Math.max(0, (raw[position] ?? 0) + shift));
      }
    }
  }
}

/** 把均值量化到与目标比特同奇偶的最近 Δ 槽位。 */
function quantizationTarget(mean: number, bit: boolean): number {
  const slot = mean / WATERMARK_DELTA;
  const parity = bit ? 1 : 0;
  let lower = Math.floor(slot);
  if (lower % 2 !== parity) lower -= 1;
  let upper = Math.ceil(slot);
  if (upper % 2 !== parity) upper += 1;
  const target = Math.abs(slot - lower) <= Math.abs(upper - slot) ? lower : upper;
  return Math.max(parity, target) * WATERMARK_DELTA;
}

/**
 * 在 raw 像素（RGB/RGBA，8 位）上嵌入指纹，返回新 buffer。
 * 图像太小（冗余不足）时返回 null，调用方应跳过水印而不是失败。
 */
export function embedWatermark(
  input: Buffer,
  width: number,
  height: number,
  channels: number,
  fingerprint: string,
  secret: string
): Buffer | null {
  const repetition = watermarkCapacity(width, height);
  if (repetition < WATERMARK_MIN_REPETITION) return null;

  const bits = [...fingerprintBits(fingerprint), ...checksumBits(fingerprint, secret)];
  const order = shuffledBlockIndices(width, height, secret);
  const raw = Buffer.from(input);

  for (let bitIndex = 0; bitIndex < bits.length; bitIndex += 1) {
    const bit = bits[bitIndex]!;
    for (let replica = 0; replica < repetition; replica += 1) {
      const block = order[bitIndex * repetition + replica]!;
      const mean = blockMean(raw, width, channels, block);
      const target = quantizationTarget(mean, bit);
      const shift = Math.round(target - mean);
      if (shift !== 0) shiftBlock(raw, width, channels, block, shift);
    }
  }
  return raw;
}

export type ExtractedWatermark = {
  fingerprint: string;
  /** 所有比特中多数票占比的均值，1 表示完全一致 */
  confidence: number;
  /** 校验和是否匹配 */
  valid: boolean;
};

export function extractWatermark(
  raw: Buffer,
  width: number,
  height: number,
  channels: number,
  secret: string
): ExtractedWatermark | null {
  const repetition = watermarkCapacity(width, height);
  if (repetition < WATERMARK_MIN_REPETITION) return null;

  const order = shuffledBlockIndices(width, height, secret);
  const bits: boolean[] = [];
  let confidenceSum = 0;

  for (let bitIndex = 0; bitIndex < TOTAL_BITS; bitIndex += 1) {
    let votes = 0;
    for (let replica = 0; replica < repetition; replica += 1) {
      const block = order[bitIndex * repetition + replica]!;
      const mean = blockMean(raw, width, channels, block);
      if (Math.round(mean / WATERMARK_DELTA) % 2 === 1) votes += 1;
    }
    const bit = votes * 2 > repetition;
    bits.push(bit);
    confidenceSum += (bit ? votes : repetition - votes) / repetition;
  }

  const fingerprintBytes: number[] = [];
  for (let index = 0; index < FINGERPRINT_BITS; index += 8) {
    let byte = 0;
    for (let bit = 0; bit < 8; bit += 1) byte = (byte << 1) | (bits[index + bit] ? 1 : 0);
    fingerprintBytes.push(byte);
  }
  const fingerprint = Buffer.from(fingerprintBytes).toString("hex");
  const expectedChecksum = checksumBits(fingerprint, secret);
  const actualChecksum = bits.slice(FINGERPRINT_BITS);
  const valid = expectedChecksum.every((bit, index) => bit === actualChecksum[index]);

  return { fingerprint, confidence: confidenceSum / TOTAL_BITS, valid };
}
