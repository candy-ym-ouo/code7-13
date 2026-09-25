import { randomUUID } from "node:crypto";
import { createHash } from "node:crypto";
import {
  CREDENTIAL_VERSION,
  ISSUER,
  credentialHash,
  decodeCredential,
  issueCredential,
  verifyCredential,
  type DeletedCredentialPayload,
  type ProcessedCredentialPayload
} from "./credentials";
import { sha256Hex } from "./encoding";
import type { CredentialLedger, CredentialRecord } from "./ledger";
import { KeyRing, type PublicKeyEntry } from "./keys";
import { deriveWatermarkId, detectWatermark, embedWatermark, WATERMARK_SCHEME } from "./watermark";
import {
  createSourceCommitment,
  derivePublicId,
  publicIdMatches,
  publicObjectKey,
  publicThumbnailObjectKey
} from "./addressing";

/**
 * High-level orchestration: watermarked processing evidence, deletion evidence,
 * verification against the retained key directory, and sealed public keys.
 */

export interface ProcessedArtifactInput {
  image: Buffer;
  thumbnail: Buffer;
  width: number;
  height: number;
  perceptualHash: string;
  originalSha256: string;
  originalMime: string;
  regionCount: number;
}

export interface IssuedProcessedCredential {
  token: string;
  credentialHash: string;
  payload: ProcessedCredentialPayload;
  watermarkedImage: Buffer;
  watermarkedThumbnail: Buffer;
  publicId: string;
  publicObjectKey: string;
  publicThumbnailObjectKey: string;
  watermarkId: string;
}

export type DeletionActor = "owner" | "moderator" | "admin" | "system";

export type RemovalKind = "original" | "processed" | "thumbnail" | "public" | "public_thumbnail";

export interface RemovalResult {
  kind: RemovalKind;
  removed: boolean;
}

export interface IssueDeletionInput {
  mediaId: string;
  deletedBy: DeletionActor;
  removedObjects: RemovalResult[];
}

export interface IssuedDeletionCredential {
  token: string;
  credentialHash: string;
  payload: DeletedCredentialPayload;
}

export interface ForensicsSecrets {
  /** Protects sealed private keys at rest (folded through SHA-256). */
  masterKey: string;
  /** Key for invisible watermark ordering. */
  watermarkSecret: string;
  /** Key for public object address derivation. */
  addressSecret: string;
}

export interface ServiceClock {
  now: () => Date;
  randomUuid: () => string;
}

export class DuplicateDeletionError extends Error {
  constructor(public readonly mediaId: string) {
    super(`deletion credential for media ${mediaId} already exists`);
    this.name = "DuplicateDeletionError";
  }
}

export class ForensicsService {
  readonly clock: ServiceClock;

  constructor(
    readonly keyRing: KeyRing,
    private readonly ledger: CredentialLedger,
    private readonly secrets: ForensicsSecrets,
    clock?: Partial<ServiceClock>
  ) {
    this.clock = {
      now: clock?.now ?? (() => new Date()),
      randomUuid: clock?.randomUuid ?? randomUUID
    };
  }

  /**
   * Embeds the same keyed watermark into image and thumbnail, derives the
   * sealed public id for the final bytes, and issues a `media.processed`
   * credential. Returns the watermarked buffers the caller must store —
   * nothing else may be copied to the public bucket.
   */
  async issueProcessed(mediaId: string, input: ProcessedArtifactInput): Promise<IssuedProcessedCredential> {
    if (input.image.length === 0 || input.thumbnail.length === 0) {
      throw new Error("processed artifacts must not be empty");
    }

    const watermarkId = deriveWatermarkId(this.secrets.watermarkSecret, mediaId);
    const watermarkedImage = await embedWatermark(input.image, watermarkId, this.secrets.watermarkSecret, { quality: 86 });
    const watermarkedThumbnail = await embedWatermark(input.thumbnail, watermarkId, this.secrets.watermarkSecret, { quality: 78 });

    const contentSha256 = sha256Hex(watermarkedImage);
    const thumbnailSha256 = sha256Hex(watermarkedThumbnail);
    const publicId = derivePublicId(this.secrets.addressSecret, mediaId, contentSha256);
    const commitment = createSourceCommitment(input.originalSha256);
    const previous = await this.ledger.getLatestByType(mediaId, "media.processed");

    const payload: ProcessedCredentialPayload = {
      v: CREDENTIAL_VERSION,
      iss: ISSUER,
      type: "media.processed",
      mediaId,
      issuedAt: this.clock.now().toISOString(),
      jti: this.clock.randomUuid(),
      publicId,
      previousCredential: previous ? credentialHash(previous.token) : null,
      content: {
        sha256: contentSha256,
        perceptualHash: input.perceptualHash,
        mediaType: "image/webp",
        width: input.width,
        height: input.height,
        byteSize: watermarkedImage.length
      },
      thumbnail: {
        sha256: thumbnailSha256,
        byteSize: watermarkedThumbnail.length
      },
      source: {
        salt: commitment.salt,
        commitment: commitment.commitment,
        mime: input.originalMime
      },
      watermark: {
        id: watermarkId,
        scheme: WATERMARK_SCHEME,
        embeddedIn: ["image", "thumbnail"]
      },
      operations: ["orientation", "metadata_strip", "privacy_blur", "webp_reencode", "watermark", "thumbnail"],
      regionCount: input.regionCount
    };

    const { kid, signingKey } = await this.keyRing.activeKey();
    const token = issueCredential({ payload, kid, signingKey });
    const hash = credentialHash(token);
    await this.ledger.save({
      mediaId,
      type: "media.processed",
      token,
      credentialHash: hash,
      kid,
      payload,
      createdAt: payload.issuedAt
    });

    return {
      token,
      credentialHash: hash,
      payload,
      watermarkedImage,
      watermarkedThumbnail,
      publicId,
      publicObjectKey: publicObjectKey(publicId),
      publicThumbnailObjectKey: publicThumbnailObjectKey(publicId),
      watermarkId
    };
  }

  /**
   * Issues deletion evidence. Only hashes and opaque object kinds are recorded;
   * the original bytes are never referenced. Fails if a deletion credential
   * already exists — the deletion event is a single, immutable fact.
   */
  async issueDeletion(input: IssueDeletionInput): Promise<IssuedDeletionCredential> {
    const existing = await this.ledger.getLatestByType(input.mediaId, "media.deleted");
    if (existing) throw new DuplicateDeletionError(input.mediaId);

    const processed = await this.ledger.getLatestByType(input.mediaId, "media.processed");
    const latest = (await this.ledger.listForMedia(input.mediaId)).at(-1) ?? processed;

    const kinds: RemovalKind[] = [];
    const removedObjects = input.removedObjects
      .filter((entry) => {
        if (kinds.includes(entry.kind)) return false;
        kinds.push(entry.kind);
        return true;
      })
      .map((entry) => ({ kind: entry.kind, removed: entry.removed }))
      .sort((a, b) => a.kind.localeCompare(b.kind));

    if (removedObjects.length === 0) throw new Error("deletion evidence requires at least one removed object");

    const payload: DeletedCredentialPayload = {
      v: CREDENTIAL_VERSION,
      iss: ISSUER,
      type: "media.deleted",
      mediaId: input.mediaId,
      issuedAt: this.clock.now().toISOString(),
      jti: this.clock.randomUuid(),
      publicId: processed?.payload.type === "media.processed" ? processed.payload.publicId : null,
      previousCredential: latest ? credentialHash(latest.token) : null,
      deletedBy: input.deletedBy,
      lastProcessedSha256: processed?.payload.type === "media.processed" ? processed.payload.content.sha256 : null,
      removedObjects
    };

    const { kid, signingKey } = await this.keyRing.activeKey();
    const token = issueCredential({ payload, kid, signingKey });
    const hash = credentialHash(token);
    await this.ledger.save({
      mediaId: input.mediaId,
      type: "media.deleted",
      token,
      credentialHash: hash,
      kid,
      payload,
      createdAt: payload.issuedAt
    });

    return { token, credentialHash: hash, payload };
  }

  async verifyCredentialToken(token: string) {
    return verifyCredential(token, await this.keyRing.verificationKeys());
  }

  async publicKeyDirectory(): Promise<PublicKeyEntry[]> {
    return this.keyRing.publicKeyDirectory();
  }

  async rotateKeys(): Promise<string> {
    return this.keyRing.rotate(this.clock.now);
  }

  /**
   * Forensic check that public bytes are the exact processed image the
   * credential describes, that the sealed address matches, and that the
   * embedded watermark decodes to the credential's id.
   */
  async checkPublicBinding(
    token: string,
    publicBytes: Buffer
  ): Promise<{ credential: ReturnType<typeof decodeCredential>; address: boolean; watermark: Awaited<ReturnType<typeof detectWatermark>>; bytes: boolean }> {
    const credential = decodeCredential(token);
    if (credential.payload.type !== "media.processed") {
      throw new Error("binding check requires a media.processed credential");
    }
    const payload = credential.payload;
    const candidateSha256 = createHash("sha256").update(publicBytes).digest("hex");
    const bytes = candidateSha256 === payload.content.sha256;
    const address = publicIdMatches(
      payload.publicId,
      this.secrets.addressSecret,
      payload.mediaId,
      candidateSha256
    );
    const watermark = await detectWatermark(publicBytes, this.secrets.watermarkSecret, payload.watermark.id);
    return { credential, address, watermark, bytes };
  }
}
