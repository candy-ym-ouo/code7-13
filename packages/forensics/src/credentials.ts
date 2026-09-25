import { z } from "zod";
import { b64uDecode, b64uEncode, sha256Hex } from "./encoding";

/**
 * Verifiable media credentials.
 *
 * Compact JWS-like serialization: base64url(header).base64url(payload).base64url(signature)
 * with Ed25519 signatures. Every credential carries the id (`kid`) of the key
 * that signed it; verifiers resolve that id against a public key directory
 * that retains *all* keys, including retired ones, so credentials stay
 * verifiable after key rotation.
 */

export const ALGORITHM = "EdDSA";
export const TOKEN_TYPE = "map-media-credential";
export const CREDENTIAL_VERSION = 1;
export const ISSUER = "public-space-detail-map";

const hash64 = z.string().regex(/^[0-9a-f]{64}$/);
const isoTimestamp = z.string().datetime({ offset: true });

export const processedCredentialPayloadSchema = z.strictObject({
  v: z.literal(1),
  iss: z.literal(ISSUER),
  type: z.literal("media.processed"),
  mediaId: z.string().uuid(),
  issuedAt: isoTimestamp,
  jti: z.string().uuid(),
  publicId: z.string().regex(/^m[0-9a-f]{43}$/),
  previousCredential: z.string().nullable(),
  content: z.strictObject({
    sha256: hash64,
    perceptualHash: z.string().regex(/^[0-9a-f]{16}$/),
    mediaType: z.literal("image/webp"),
    width: z.number().int().positive(),
    height: z.number().int().positive(),
    byteSize: z.number().int().positive()
  }),
  thumbnail: z.strictObject({
    sha256: hash64,
    byteSize: z.number().int().positive()
  }).nullable(),
  /** Only a salted commitment to the original bytes — never the raw hash. */
  source: z.strictObject({
    salt: z.string().regex(/^[0-9a-f]{32}$/),
    commitment: hash64,
    mime: z.string().min(1).max(100)
  }),
  watermark: z.strictObject({
    id: z.string().regex(/^w[0-9a-f]{16}$/),
    scheme: z.literal("bluespread-1"),
    embeddedIn: z.array(z.enum(["image", "thumbnail"]))
  }),
  operations: z.array(z.enum(["orientation", "metadata_strip", "privacy_blur", "webp_reencode", "watermark", "thumbnail"])),
  regionCount: z.number().int().min(0)
});

export const deletedCredentialPayloadSchema = z.strictObject({
  v: z.literal(1),
  iss: z.literal(ISSUER),
  type: z.literal("media.deleted"),
  mediaId: z.string().uuid(),
  issuedAt: isoTimestamp,
  jti: z.string().uuid(),
  publicId: z.string().regex(/^m[0-9a-f]{43}$/).nullable(),
  previousCredential: z.string().nullable(),
  deletedBy: z.enum(["owner", "moderator", "admin", "system"]),
  lastProcessedSha256: hash64.nullable(),
  removedObjects: z.array(z.strictObject({
    kind: z.enum(["original", "processed", "thumbnail", "public", "public_thumbnail"]),
    removed: z.boolean()
  })).min(1)
});

export const credentialPayloadSchema = z.discriminatedUnion("type", [
  processedCredentialPayloadSchema,
  deletedCredentialPayloadSchema
]);

export type ProcessedCredentialPayload = z.infer<typeof processedCredentialPayloadSchema>;
export type DeletedCredentialPayload = z.infer<typeof deletedCredentialPayloadSchema>;
export type CredentialPayload = z.infer<typeof credentialPayloadSchema>;

const credentialHeaderSchema = z.strictObject({
  alg: z.literal(ALGORITHM),
  kid: z.string().min(1).max(128),
  typ: z.literal(TOKEN_TYPE)
});

export interface SigningKey {
  /** Signs exactly the signing input `header.payload`. */
  sign(signingInput: Buffer): Buffer;
}

export interface PublicVerificationKey {
  kid: string;
  verify(message: Buffer, signature: Buffer): boolean;
}

export interface IssueCredentialInput<P extends CredentialPayload = CredentialPayload> {
  payload: P;
  kid: string;
  signingKey: SigningKey;
}

export function issueCredential({ payload, kid, signingKey }: IssueCredentialInput): string {
  const header: z.infer<typeof credentialHeaderSchema> = { alg: ALGORITHM, kid, typ: TOKEN_TYPE };
  const headerPart = b64uEncode(JSON.stringify(header));
  const payloadPart = b64uEncode(JSON.stringify(payload));
  const signingInput = Buffer.from(`${headerPart}.${payloadPart}`);
  const signaturePart = b64uEncode(signingKey.sign(signingInput));
  return `${headerPart}.${payloadPart}.${signaturePart}`;
}

export type VerifyFailure =
  | "malformed"
  | "bad_header"
  | "bad_payload"
  | "unknown_kid"
  | "invalid_signature";

export type VerifyResult =
  | { valid: true; kid: string; payload: CredentialPayload; credentialHash: string }
  | { valid: false; reason: VerifyFailure };

export interface DecodedCredential {
  kid: string;
  payload: CredentialPayload;
  credentialHash: string;
}

/** Parses the credential without checking the signature. */
export function decodeCredential(credential: string): DecodedCredential {
  const parts = credential.split(".");
  if (parts.length !== 3 || parts.some((part) => part.length === 0)) {
    throw new Error("malformed credential");
  }
  const [headerPart, payloadPart] = parts as [string, string, string];

  let header: unknown;
  try {
    header = JSON.parse(b64uDecode(headerPart).toString("utf8"));
  } catch {
    throw new Error("malformed header");
  }
  const headerResult = credentialHeaderSchema.safeParse(header);
  if (!headerResult.success) throw new Error("bad header");

  let payload: unknown;
  try {
    payload = JSON.parse(b64uDecode(payloadPart).toString("utf8"));
  } catch {
    throw new Error("malformed payload");
  }
  const payloadResult = credentialPayloadSchema.safeParse(payload);
  if (!payloadResult.success) throw new Error("bad payload");

  return { kid: headerResult.data.kid, payload: payloadResult.data, credentialHash: credentialHash(credential) };
}

export function verifyCredential(credential: string, keys: Iterable<PublicVerificationKey>): VerifyResult {
  const parts = credential.split(".");
  if (parts.length !== 3 || parts.some((part) => part.length === 0)) {
    return { valid: false, reason: "malformed" };
  }
  const [headerPart, payloadPart, signaturePart] = parts as [string, string, string];

  let header: unknown;
  try {
    header = JSON.parse(b64uDecode(headerPart).toString("utf8"));
  } catch {
    return { valid: false, reason: "malformed" };
  }
  const headerResult = credentialHeaderSchema.safeParse(header);
  if (!headerResult.success) return { valid: false, reason: "bad_header" };

  let payload: unknown;
  try {
    payload = JSON.parse(b64uDecode(payloadPart).toString("utf8"));
  } catch {
    return { valid: false, reason: "malformed" };
  }
  const payloadResult = credentialPayloadSchema.safeParse(payload);
  if (!payloadResult.success) return { valid: false, reason: "bad_payload" };

  let signature: Buffer;
  try {
    signature = b64uDecode(signaturePart);
  } catch {
    return { valid: false, reason: "malformed" };
  }
  const signingInput = Buffer.from(`${headerPart}.${payloadPart}`);

  let matchedKey: PublicVerificationKey | undefined;
  for (const key of keys) {
    if (key.kid === headerResult.data.kid) {
      matchedKey = key;
      break;
    }
  }
  if (!matchedKey) return { valid: false, reason: "unknown_kid" };
  if (!matchedKey.verify(signingInput, signature)) {
    return { valid: false, reason: "invalid_signature" };
  }

  return {
    valid: true,
    kid: matchedKey.kid,
    payload: payloadResult.data,
    credentialHash: credentialHash(credential)
  };
}

/** Stable digest used to chain deletion evidence to earlier credentials. */
export function credentialHash(credential: string): string {
  return sha256Hex(credential);
}
