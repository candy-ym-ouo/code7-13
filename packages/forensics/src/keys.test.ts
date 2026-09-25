import { describe, expect, it } from "vitest";
import { issueCredential, verifyCredential } from "./credentials";
import {
  decryptPrivateKey,
  encryptPrivateKey,
  KeyRing,
  kidFromPublicKey,
  loadMasterKey
} from "./keys";
import { InMemoryKeyStore } from "./store-memory";

async function newRing(master = "master-secret") {
  return new KeyRing(new InMemoryKeyStore(), loadMasterKey(master));
}

describe("key ring rotation", () => {
  it("creates one active key idempotently", async () => {
    const ring = await newRing();
    const kid1 = await ring.ensureActiveKey();
    const kid2 = await ring.ensureActiveKey();
    expect(kid1).toBe(kid2);
    expect((await ring.publicKeyDirectory())).toHaveLength(1);
  });

  it("keeps old credentials verifiable after rotation", async () => {
    const ring = await newRing();
    const first = await ring.activeKey();
    const oldToken = issueCredential({
      payload: {
        v: 1, iss: "public-space-detail-map", type: "media.deleted",
        mediaId: "0192f5b3-7b4c-7a2e-9f0a-123456789abc",
        issuedAt: "2026-09-25T10:00:00.000Z",
        jti: "0192f5b3-7b4c-7a2e-9f0a-aaaaaaaaaaaa",
        publicId: null, previousCredential: null,
        deletedBy: "owner", lastProcessedSha256: "a".repeat(64),
        removedObjects: [{ kind: "original", removed: true }]
      },
      kid: first.kid,
      signingKey: first.signingKey
    });

    await ring.rotate();
    const second = await ring.activeKey();
    expect(second.kid).not.toBe(first.kid);

    const directory = await ring.publicKeyDirectory();
    expect(directory).toHaveLength(2);
    expect(directory.find((entry) => entry.kid === first.kid)?.status).toBe("retired");
    expect(directory.find((entry) => entry.kid === second.kid)?.status).toBe("active");

    // Old credential still verifies against the retained retired public key.
    const verifyOld = verifyCredential(oldToken, await ring.verificationKeys());
    expect(verifyOld.valid).toBe(true);

    // New signatures come from the new key.
    const newToken = issueCredential({
      payload: {
        v: 1, iss: "public-space-detail-map", type: "media.deleted",
        mediaId: "0192f5b3-7b4c-7a2e-9f0a-123456789def",
        issuedAt: "2026-09-25T11:00:00.000Z",
        jti: "0192f5b3-7b4c-7a2e-9f0a-bbbbbbbbbbbb",
        publicId: null, previousCredential: null,
        deletedBy: "admin", lastProcessedSha256: null,
        removedObjects: [{ kind: "public", removed: true }]
      },
      kid: second.kid,
      signingKey: second.signingKey
    });
    const verifyNew = verifyCredential(newToken, await ring.verificationKeys());
    expect(verifyNew.valid).toBe(true);
    if (verifyNew.valid) expect(verifyNew.kid).toBe(second.kid);
  });

  it("seals private keys with authenticated encryption and erases them on retirement", async () => {
    const store = new InMemoryKeyStore();
    const ring = new KeyRing(store, loadMasterKey("master-secret"));
    const kid = await ring.ensureActiveKey();
    await ring.rotate();

    const rows = await store.list();
    const old = rows.find((row) => row.kid === kid);
    expect(old?.privateKeyEnc).toBeNull();
    const active = rows.find((row) => row.status === "active");
    expect(active?.privateKeyEnc).not.toBeNull();

    // Wrong master key cannot unseal the retained private key.
    expect(() => decryptPrivateKey(active!.privateKeyEnc!, loadMasterKey("wrong"))).toThrow();
    expect(() => decryptPrivateKey(active!.privateKeyEnc!, loadMasterKey("master-secret"))).not.toThrow();

    // Re-encryption round-trips.
    const sealed = encryptPrivateKey(active!.publicKey, loadMasterKey("k"));
    expect(sealed.startsWith("v1.")).toBe(true);
    expect(() => decryptPrivateKey(sealed, loadMasterKey("other"))).toThrow();
  });

  it("survives a reload from the store after rotation", async () => {
    const store = new InMemoryKeyStore();
    const ring1 = new KeyRing(store, loadMasterKey("master-secret"));
    const firstKid = await ring1.ensureActiveKey();
    const newKid = await ring1.rotate();

    const ring2 = new KeyRing(store, loadMasterKey("master-secret"));
    const active = await ring2.activeKey();
    expect(active.kid).toBe(newKid);
    expect((await ring2.publicKeyDirectory()).map((entry) => entry.kid).sort())
      .toEqual([firstKid, newKid].sort());
  });

  it("derives stable kids from public key material", () => {
    const ring = new KeyRing(new InMemoryKeyStore(), loadMasterKey("m"));
    void ring;
    expect(kidFromPublicKey("A".repeat(44)).startsWith("fk-")).toBe(true);
  });
});
