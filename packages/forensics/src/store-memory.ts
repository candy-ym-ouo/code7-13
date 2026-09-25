import type { CredentialLedger, CredentialRecord } from "./ledger";
import type { KeyStore, StoredKey } from "./keys";

/** In-memory adapters for unit tests and ephemeral environments. */

export class InMemoryKeyStore implements KeyStore {
  private rows = new Map<string, StoredKey>();

  async list(): Promise<StoredKey[]> {
    return [...this.rows.values()].sort((a, b) => a.createdAt.localeCompare(b.createdAt));
  }

  async insert(key: StoredKey): Promise<void> {
    if (this.rows.has(key.kid)) throw new Error(`key ${key.kid} already exists`);
    this.rows.set(key.kid, { ...key });
  }

  async markRetired(kid: string, retiredAt: string): Promise<void> {
    const row = this.rows.get(kid);
    if (!row || row.status !== "active") throw new Error(`cannot retire unknown or inactive key ${kid}`);
    row.status = "retired";
    row.privateKeyEnc = null;
    row.retiredAt = retiredAt;
  }

  async rotateActive(next: StoredKey, retiredAt: string): Promise<void> {
    const actives = [...this.rows.values()].filter((row) => row.status === "active");
    if (actives.length === 0) throw new Error("key rotation found no active key to retire");
    for (const row of actives) {
      row.status = "retired";
      row.privateKeyEnc = null;
      row.retiredAt = retiredAt;
    }
    if (this.rows.has(next.kid)) throw new Error(`key ${next.kid} already exists`);
    this.rows.set(next.kid, { ...next });
  }
}

export class InMemoryCredentialLedger implements CredentialLedger {
  private rows: CredentialRecord[] = [];

  async save(record: CredentialRecord): Promise<void> {
    if (this.rows.some((row) => row.credentialHash === record.credentialHash)) return;
    this.rows.push({ ...record });
  }

  async listForMedia(mediaId: string): Promise<CredentialRecord[]> {
    return this.rows
      .filter((row) => row.mediaId === mediaId)
      .sort((a, b) => a.createdAt.localeCompare(b.createdAt));
  }

  async getLatestByType(mediaId: string, type: CredentialRecord["type"]): Promise<CredentialRecord | null> {
    const matches = this.rows
      .filter((row) => row.mediaId === mediaId && row.type === type)
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
    return matches[0] ? { ...matches[0] } : null;
  }
}
