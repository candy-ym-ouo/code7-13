import type { CredentialLedger, CredentialRecord } from "./ledger";
import type { KeyStore, StoredKey } from "./keys";

/**
 * PostgreSQL adapters for the key store and credential ledger.
 * The pool/client is injected so this package stays free of a pg dependency.
 * Executor shape matches `pg.Pool` / `pg.PoolClient`.
 */

export interface PgExecutor {
  query<T>(
    text: string,
    params?: readonly unknown[]
  ): Promise<{ rows: T[]; rowCount: number | null }>;
}

interface SigningKeyRow {
  kid: string;
  status: "active" | "retired";
  public_key: string;
  private_key_enc: string | null;
  created_at: Date | string;
  retired_at: Date | string | null;
}

export class PgKeyStore implements KeyStore {
  constructor(private readonly db: PgExecutor) {}

  async list(): Promise<StoredKey[]> {
    const result = await this.db.query<SigningKeyRow>(
      `SELECT kid, status, public_key, private_key_enc, created_at, retired_at
       FROM forensics_signing_keys ORDER BY created_at ASC`
    );
    return result.rows.map((row) => ({
      kid: row.kid,
      status: row.status,
      publicKey: row.public_key,
      privateKeyEnc: row.private_key_enc,
      createdAt: new Date(row.created_at).toISOString(),
      retiredAt: row.retired_at ? new Date(row.retired_at).toISOString() : null
    }));
  }

  async insert(key: StoredKey): Promise<void> {
    await this.db.query(
      `INSERT INTO forensics_signing_keys(kid, status, public_key, private_key_enc, created_at, retired_at)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [key.kid, key.status, key.publicKey, key.privateKeyEnc, key.createdAt, key.retiredAt]
    );
  }

  async markRetired(kid: string, retiredAt: string): Promise<void> {
    const result = await this.db.query(
      `UPDATE forensics_signing_keys
       SET status = 'retired', private_key_enc = NULL, retired_at = $2
       WHERE kid = $1 AND status = 'active'`,
      [kid, retiredAt]
    );
    if (!result.rowCount) throw new Error(`cannot retire unknown or inactive key ${kid}`);
  }

  async rotateActive(next: StoredKey, retiredAt: string): Promise<void> {
    // The injected executor may be a pool; pg exposes connect() for a transaction.
    const db = this.db as PgExecutor & {
      connect?: () => Promise<{
        query: PgExecutor["query"];
        release: () => void;
      }>;
    };
    if (!db.connect) {
      // Transactionless executor (tests): best-effort ordered calls.
      await this.insert({ ...next, status: "retired" });
      await this.db.query(
        `UPDATE forensics_signing_keys SET status = 'active', retired_at = NULL WHERE kid = $1`,
        [next.kid]
      );
      const active = await this.db.query<{ kid: string }>(
        `SELECT kid FROM forensics_signing_keys WHERE status = 'active' AND kid <> $1`,
        [next.kid]
      );
      for (const row of active.rows) await this.markRetired(row.kid, retiredAt);
      return;
    }

    const client = await db.connect();
    try {
      await client.query("BEGIN");
      // Retire first (erasing the private key) so the one-active invariant
      // holds when the new active key is inserted.
      const retired = await client.query<{ kid: string }>(
        `UPDATE forensics_signing_keys
         SET status = 'retired', private_key_enc = NULL, retired_at = $1
         WHERE status = 'active'
         RETURNING kid`,
        [retiredAt]
      );
      if (retired.rowCount === 0) {
        await client.query("ROLLBACK");
        throw new Error("key rotation found no active key to retire");
      }
      await client.query(
        `INSERT INTO forensics_signing_keys(kid, status, public_key, private_key_enc, created_at, retired_at)
         VALUES ($1, 'active', $2, $3, $4, NULL)`,
        [next.kid, next.publicKey, next.privateKeyEnc, next.createdAt]
      );
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }
}

interface CredentialRow {
  media_id: string;
  type: CredentialRecord["type"];
  token: string;
  credential_hash: string;
  kid: string;
  payload: CredentialRecord["payload"];
  created_at: Date | string;
}

export class PgCredentialLedger implements CredentialLedger {
  constructor(private readonly db: PgExecutor) {}

  async save(record: CredentialRecord): Promise<void> {
    await this.db.query(
      `INSERT INTO media_credentials(credential_hash, media_id, type, kid, token, payload, created_at)
       VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7)
       ON CONFLICT (credential_hash) DO NOTHING`,
      [
        record.credentialHash,
        record.mediaId,
        record.type,
        record.kid,
        record.token,
        JSON.stringify(record.payload),
        record.createdAt
      ]
    );
  }

  async listForMedia(mediaId: string): Promise<CredentialRecord[]> {
    const result = await this.db.query<CredentialRow>(
      `SELECT media_id, type, token, credential_hash, kid, payload, created_at
       FROM media_credentials WHERE media_id = $1 ORDER BY created_at ASC`,
      [mediaId]
    );
    return result.rows.map(mapRow);
  }

  async getLatestByType(mediaId: string, type: CredentialRecord["type"]): Promise<CredentialRecord | null> {
    const result = await this.db.query<CredentialRow>(
      `SELECT media_id, type, token, credential_hash, kid, payload, created_at
       FROM media_credentials WHERE media_id = $1 AND type = $2
       ORDER BY created_at DESC LIMIT 1`,
      [mediaId, type]
    );
    return result.rows[0] ? mapRow(result.rows[0]) : null;
  }
}

function mapRow(row: CredentialRow): CredentialRecord {
  return {
    mediaId: row.media_id,
    type: row.type,
    token: row.token,
    credentialHash: row.credential_hash,
    kid: row.kid,
    payload: row.payload,
    createdAt: new Date(row.created_at).toISOString()
  };
}
