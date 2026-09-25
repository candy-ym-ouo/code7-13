import { createHash, createHmac, timingSafeEqual } from "node:crypto";

export function b64uEncode(value: Buffer | string): string {
  return Buffer.from(value).toString("base64url");
}

export function b64uDecode(value: string): Buffer {
  return Buffer.from(value, "base64url");
}

export function sha256Hex(value: Buffer | string): string {
  return createHash("sha256").update(value).digest("hex");
}

export function hmacDigest(secret: string | Buffer, data: string | Buffer): Buffer {
  return createHmac("sha256", secret).update(data).digest();
}

export function constantTimeEqual(a: Buffer | string, b: Buffer | string): boolean {
  const left = Buffer.isBuffer(a) ? a : Buffer.from(a);
  const right = Buffer.isBuffer(b) ? b : Buffer.from(b);
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}
