import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { sha256Hex } from "./encoding";
import {
  DuplicateDeletionError,
  ForensicsService,
  type ProcessedArtifactInput,
  type RemovalResult
} from "./service";
import { InMemoryCredentialLedger, InMemoryKeyStore } from "./store-memory";
import { KeyRing, loadMasterKey } from "./keys";
import { noisyImage } from "./test-helpers";

const SECRETS = {
  masterKey: "master-key-test",
  watermarkSecret: "watermark-secret-test",
  addressSecret: "address-secret-test"
};

async function newService() {
  const keyRing = new KeyRing(new InMemoryKeyStore(), loadMasterKey(SECRETS.masterKey));
  const ledger = new InMemoryCredentialLedger();
  const service = new ForensicsService(keyRing, ledger, SECRETS, {
    now: () => new Date("2026-09-25T12:00:00.000Z"),
    randomUuid: () => "0192f5b3-0000-7000-8000-000000000001"
  });
  return { service, ledger };
}

async function artifacts(): Promise<ProcessedArtifactInput> {
  const image = await noisyImage(480, 360);
  const thumbnail = await noisyImage(200, 150);
  return {
    image,
    thumbnail,
    width: 480,
    height: 360,
    perceptualHash: "0123456789abcdef",
    originalSha256: "9".repeat(64),
    originalMime: "image/jpeg",
    regionCount: 1
  };
}

describe("forensics service", () => {
  it("issues a verifiable processed credential over watermarked bytes and a sealed key", async () => {
    const { service } = await newService();
    const mediaId = randomUUID();
    const issued = await service.issueProcessed(mediaId, await artifacts());

    const verification = await service.verifyCredentialToken(issued.token);
    expect(verification.valid).toBe(true);
    if (!verification.valid) throw new Error("credential did not verify");
    expect(verification.payload.type).toBe("media.processed");
    if (verification.payload.type !== "media.processed") return;
    expect(verification.payload.publicId).toBe(issued.publicId);
    expect(verification.payload.content.sha256).toBe(sha256Hex(issued.watermarkedImage));

    // The public key never contains original bytes: credential mentions only
    // the processed hash and a commitment.
    expect(issued.token).not.toContain("9".repeat(64));
    expect(issued.publicObjectKey).toBe(`media/${issued.publicId}.webp`);
  });

  it("keeps old credentials verifiable after key rotation", async () => {
    const { service } = await newService();
    const mediaId = randomUUID();
    const first = await service.issueProcessed(mediaId, await artifacts());
    const oldKid = first.payload && (await service.publicKeyDirectory()).find((k) => k.status === "active")?.kid;

    await service.rotateKeys();
    const afterRotation = await service.verifyCredentialToken(first.token);
    expect(afterRotation.valid).toBe(true);

    const second = await service.issueProcessed(randomUUID(), await artifacts());
    const verifySecond = await service.verifyCredentialToken(second.token);
    expect(verifySecond.valid).toBe(true);
    if (verifySecond.valid) {
      expect(verifySecond.kid).not.toBe(oldKid);
    }
  });

  it("binds credential, sealed address and watermark to the exact public bytes", async () => {
    const { service } = await newService();
    const mediaId = randomUUID();
    const issued = await service.issueProcessed(mediaId, await artifacts());

    const binding = await service.checkPublicBinding(issued.token, issued.watermarkedImage);
    expect(binding.bytes).toBe(true);
    expect(binding.address).toBe(true);
    expect(binding.watermark.matches).toBeGreaterThan(0.95);

    // A different image fails every binding.
    const other = await noisyImage(480, 360);
    const bad = await service.checkPublicBinding(issued.token, other);
    expect(bad.bytes).toBe(false);
    expect(bad.address).toBe(false);
  });

  it("issues immutable deletion evidence chained to the processed credential", async () => {
    const { service, ledger } = await newService();
    const mediaId = randomUUID();
    const processed = await service.issueProcessed(mediaId, await artifacts());

    const removed: RemovalResult[] = [
      { kind: "original", removed: true },
      { kind: "public", removed: true },
      { kind: "public_thumbnail", removed: true },
      { kind: "processed", removed: false }
    ];
    const deleted = await service.issueDeletion({ mediaId, deletedBy: "owner", removedObjects: removed });

    const verified = await service.verifyCredentialToken(deleted.token);
    expect(verified.valid).toBe(true);
    if (!verified.valid || verified.payload.type !== "media.deleted") throw new Error("bad deletion credential");
    expect(verified.payload.publicId).toBe(processed.publicId);
    expect(verified.payload.previousCredential).toBe(processed.credentialHash);
    expect(verified.payload.lastProcessedSha256).toBe(processed.payload.content.sha256);
    expect(verified.payload.removedObjects.map((entry) => entry.kind)).toEqual([
      "original", "processed", "public", "public_thumbnail"
    ]);

    // Deletion is a single immutable fact.
    await expect(service.issueDeletion({ mediaId, deletedBy: "admin", removedObjects: [{ kind: "original", removed: true }] }))
      .rejects.toBeInstanceOf(DuplicateDeletionError);

    // Credential stays verifiable after rotation.
    await service.rotateKeys();
    expect((await service.verifyCredentialToken(deleted.token)).valid).toBe(true);

    // Nothing in the deletion credential references the original bytes.
    expect(deleted.token).not.toContain("9".repeat(64));
    expect(await ledger.getLatestByType(mediaId, "media.deleted")).toBeTruthy();
  });

  it("rejects deletion evidence without any removed object", async () => {
    const { service } = await newService();
    await expect(
      service.issueDeletion({ mediaId: randomUUID(), deletedBy: "system", removedObjects: [] })
    ).rejects.toThrow(/at least one/);
  });

  it("watermarks both image and thumbnail with the same keyed id", async () => {
    const { service } = await newService();
    const mediaId = randomUUID();
    const issued = await service.issueProcessed(mediaId, await artifacts());
    expect(issued.payload.watermark.embeddedIn).toEqual(["image", "thumbnail"]);

    // Sealed public address cannot be guessed from the raw media id.
    const records = await service.publicKeyDirectory();
    expect(records.length).toBeGreaterThan(0);
    expect(issued.publicId).not.toContain(mediaId.replace(/-/g, ""));
  });
});
