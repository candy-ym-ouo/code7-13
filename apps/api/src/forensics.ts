import {
  ForensicsService,
  KeyRing,
  loadMasterKey,
  PgCredentialLedger,
  PgKeyStore
} from "@map/forensics";
import { config } from "./config";
import { pool } from "./db";

let service: ForensicsService | null = null;

export function getForensicsService(): ForensicsService {
  if (!service) {
    const ring = new KeyRing(new PgKeyStore(pool), loadMasterKey(config.FORENSICS_MASTER_KEY));
    service = new ForensicsService(ring, new PgCredentialLedger(pool), {
      masterKey: config.FORENSICS_MASTER_KEY,
      watermarkSecret: config.FORENSICS_WATERMARK_SECRET,
      addressSecret: config.FORENSICS_ADDRESS_SECRET
    });
  }
  return service;
}
