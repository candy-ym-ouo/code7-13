import {
  createCipheriv,
  createDecipheriv,
  createHash,
  generateKeyPairSync,
  randomBytes,
  sign as cryptoSign,
  verify as cryptoVerify,
  createPrivateKey,
  createPublicKey,
  type KeyObject
} from "node:crypto";
import { b64uDecode, b64uEncode, sha256Hex } from "./encoding";
import type { PublicVerificationKey, SigningKey } from "./credentials";

/**
 * Signing key lifecycle.
 *
 * Each key version has an id derived from its public key (`kid`). The active
 * key both signs and verifies; rotation demotes it to *retired*, where the
 * private key is erased and the public key is retained forever so credentials
 * issued by it remain verifiable.
 */

export type KeyStatus = "active" | "retired";

export interface StoredKey {
  kid: string;
  status: KeyStatus;
  /** SPKI DER, base64url encoded. Safe to publish. */
  publicKey: string;
  /** PKCS8 DER encrypted with the master key; null once retired. */
  privateKeyEnc: string | null;
  createdAt: string;
  retiredAt: string | null;
}

export interface PublicKeyEntry {
  kid: string;
  algorithm: "Ed25519";
  publicKey: string;
  status: KeyStatus;
  createdAt: string;
  retiredAt: string | null;
}

/** Persistence boundary. The pg adapter lives in ./store-pg. */
export interface KeyStore {
  list(): Promise<StoredKey[]>;
  insert(key: StoredKey): Promise<void>;
  markRetired(kid: string, retiredAt: string): Promise<void>;
  /**
   * Atomically activates `next` and retires the current active key, erasing
   * its sealed private key. Must run in a single transaction so the
   * "one active key" invariant can never be transiently violated.
   */
  rotateActive?(next: StoredKey, retiredAt: string): Promise<void>;
}

function exportSpkiBase64(publicKey: KeyObject): string {
  return b64uEncode(publicKey.export({ type: "spki", format: "der" }));
}

function exportPkcs8Base64(privateKey: KeyObject): string {
  return b64uEncode(privateKey.export({ type: "pkcs8", format: "der" }));
}

export function kidFromPublicKey(publicKey: string): string {
  return `fk-${sha256Hex(b64uDecode(publicKey)).slice(0, 32)}`;
}

/** Accepts raw bytes, base64url or hex; always folds through SHA-256 to get 32 bytes. */
export function loadMasterKey(material: string | Buffer): Buffer {
  return createHash("sha256").update(material).digest();
}

const ENC_PREFIX = "v1";

export function encryptPrivateKey(privateKeyPkcs8Base64: string, masterKey: Buffer): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", masterKey, iv);
  const ciphertext = Buffer.concat([cipher.update(b64uDecode(privateKeyPkcs8Base64)), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [ENC_PREFIX, b64uEncode(iv), b64uEncode(tag), b64uEncode(ciphertext)].join(".");
}

export function decryptPrivateKey(sealed: string, masterKey: Buffer): KeyObject {
  const parts = sealed.split(".");
  if (parts.length !== 4 || parts[0] !== ENC_PREFIX) throw new Error("unsupported sealed key version");
  const [, ivPart, tagPart, dataPart] = parts as [string, string, string, string];
  const iv = b64uDecode(ivPart);
  const tag = b64uDecode(tagPart);
  const data = b64uDecode(dataPart);
  const decipher = createDecipheriv("aes-256-gcm", masterKey, iv);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(data), decipher.final()]);
  return createPrivateKey({ key: plaintext, format: "der", type: "pkcs8" });
}

class Ed25519PrivateHandle implements SigningKey {
  constructor(private readonly privateKey: KeyObject) {}

  sign(message: Buffer): Buffer {
    return cryptoSign(null, message, this.privateKey);
  }
}

class Ed25519PublicHandle implements PublicVerificationKey {
  readonly kid: string;

  constructor(kid: string, private readonly publicKey: KeyObject) {
    this.kid = kid;
  }

  verify(message: Buffer, signature: Buffer): boolean {
    try {
      return cryptoVerify(null, message, this.publicKey, signature);
    } catch {
      return false;
    }
  }
}

export interface KeyDirectoryEntry {
  kid: string;
  publicKey: string;
  status: KeyStatus;
  createdAt: string;
  retiredAt: string | null;
}

export class KeyRing {
  private keys = new Map<string, StoredKey>();
  private activeKid: string | null = null;
  private activePrivateKey: KeyObject | null = null;
  private loaded = false;

  constructor(
    private readonly store: KeyStore,
    private readonly masterKey: Buffer
  ) {}

  private async load(): Promise<void> {
    if (this.loaded) return;
    await this.reload();
  }

  async reload(): Promise<void> {
    const rows = await this.store.list();
    this.keys = new Map(rows.map((row) => [row.kid, row]));
    const active = rows.filter((row) => row.status === "active");
    if (active.length > 1) throw new Error(`forensics key store has ${active.length} active keys; exactly one is required`);
    this.activeKid = active[0]?.kid ?? null;
    this.activePrivateKey = null;
    if (this.activeKid) {
      const row = this.keys.get(this.activeKid);
      if (!row?.privateKeyEnc) throw new Error("active key is missing its sealed private key");
      this.activePrivateKey = decryptPrivateKey(row.privateKeyEnc, this.masterKey);
    }
    this.loaded = true;
  }

  /** Creates an active key on first use; later calls are no-ops. */
  async ensureActiveKey(now: () => Date = () => new Date()): Promise<string> {
    await this.load();
    if (this.activeKid) return this.activeKid;

    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const publicKeyBase64 = exportSpkiBase64(publicKey);
    const kid = kidFromPublicKey(publicKeyBase64);
    const row: StoredKey = {
      kid,
      status: "active",
      publicKey: publicKeyBase64,
      privateKeyEnc: encryptPrivateKey(exportPkcs8Base64(privateKey), this.masterKey),
      createdAt: now().toISOString(),
      retiredAt: null
    };
    try {
      await this.store.insert(row);
    } catch {
      // Another worker initialized concurrently.
      await this.reload();
      if (this.activeKid) return this.activeKid;
      throw new Error("failed to initialize forensics signing key");
    }
    this.keys.set(kid, row);
    this.activeKid = kid;
    this.activePrivateKey = privateKey;
    return kid;
  }

  /** Generates a new active key; the old one becomes verify-only. */
  async rotate(now: () => Date = () => new Date()): Promise<string> {
    await this.ensureActiveKey(now);
    const oldKid = this.activeKid;

    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const publicKeyBase64 = exportSpkiBase64(publicKey);
    const kid = kidFromPublicKey(publicKeyBase64);
    if (this.keys.has(kid)) throw new Error("key rotation produced a colliding kid");
    const timestamp = now().toISOString();
    const row: StoredKey = {
      kid,
      status: "active",
      publicKey: publicKeyBase64,
      privateKeyEnc: encryptPrivateKey(exportPkcs8Base64(privateKey), this.masterKey),
      createdAt: timestamp,
      retiredAt: null
    };

    if (this.store.rotateActive && oldKid) {
      // Atomic: new key active + old private key erased in one transaction.
      await this.store.rotateActive(row, timestamp);
    } else {
      // First rotation (no prior active): just insert. Otherwise insert the
      // new row as retired, then swap — the atomic adapter is preferred.
      await this.store.insert(row);
      if (oldKid) await this.store.markRetired(oldKid, timestamp);
    }
    await this.reload();
    if (this.activeKid !== kid) throw new Error("key rotation did not activate the new key");
    return kid;
  }

  async activeKey(): Promise<{ kid: string; signingKey: SigningKey }> {
    await this.ensureActiveKey();
    if (!this.activeKid || !this.activePrivateKey) throw new Error("no active forensics signing key");
    return { kid: this.activeKid, signingKey: new Ed25519PrivateHandle(this.activePrivateKey) };
  }

  async publicKeyDirectory(): Promise<PublicKeyEntry[]> {
    await this.load();
    return [...this.keys.values()].map((row) => ({
      kid: row.kid,
      algorithm: "Ed25519",
      publicKey: row.publicKey,
      status: row.status,
      createdAt: row.createdAt,
      retiredAt: row.retiredAt
    }));
  }

  /** Verification handle for every retained key (active + retired). */
  async verificationKeys(): Promise<PublicVerificationKey[]> {
    await this.load();
    return [...this.keys.values()].map((row) =>
      new Ed25519PublicHandle(
        row.kid,
        createPublicKey({ key: b64uDecode(row.publicKey), format: "der", type: "spki" })
      )
    );
  }
}

/** Verify a credential against an exported public key directory (e.g. fetched remotely). */
export function verificationKeysFromDirectory(entries: Iterable<KeyDirectoryEntry>): PublicVerificationKey[] {
  const handles: PublicVerificationKey[] = [];
  for (const entry of entries) {
    handles.push(new Ed25519PublicHandle(
      entry.kid,
      createPublicKey({ key: b64uDecode(entry.publicKey), format: "der", type: "spki" })
    ));
  }
  return handles;
}
