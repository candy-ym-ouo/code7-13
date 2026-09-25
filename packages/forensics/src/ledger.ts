import type { CredentialPayload } from "./credentials";

/**
 * Append-only credential ledger. Records are immutable evidence; deletion
 * credentials must never be rewritten, even when media rows are purged.
 */

export type CredentialKind = "media.processed" | "media.deleted";

export interface CredentialRecord {
  mediaId: string;
  type: CredentialKind;
  token: string;
  credentialHash: string;
  kid: string;
  payload: CredentialPayload;
  createdAt: string;
}

export interface CredentialLedger {
  save(record: CredentialRecord): Promise<void>;
  listForMedia(mediaId: string): Promise<CredentialRecord[]>;
  getLatestByType(mediaId: string, type: CredentialKind): Promise<CredentialRecord | null>;
}
