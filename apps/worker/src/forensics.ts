import {
  ForensicsService,
  KeyRing,
  loadMasterKey,
  PgCredentialLedger,
  PgKeyStore
} from "@map/forensics";
import { config } from "./config";
import { pool } from "./db";

/**
 * Process-wide forensics service. The key ring caches the active key, but
 * rotation happens via the API (possibly another process), so the cache is
 * refreshed periodically. Retired public keys stay loaded for verification.
 */
const KEY_REFRESH_INTERVAL_MS = 60_000;

let service: ForensicsService | null = null;
let lastReloadAt = 0;

async function initService(): Promise<ForensicsService> {
  const ring = new KeyRing(new PgKeyStore(pool), loadMasterKey(config.FORENSICS_MASTER_KEY));
  await ring.reload();
  return new ForensicsService(ring, new PgCredentialLedger(pool), {
    masterKey: config.FORENSICS_MASTER_KEY,
    watermarkSecret: config.FORENSICS_WATERMARK_SECRET,
    addressSecret: config.FORENSICS_ADDRESS_SECRET
  });
}

export async function getForensicsService(): Promise<ForensicsService> {
  if (!service) {
    service = await initService();
    lastReloadAt = Date.now();
    return service;
  }
  if (Date.now() - lastReloadAt > KEY_REFRESH_INTERVAL_MS) {
    await service.keyRing.reload();
    lastReloadAt = Date.now();
  }
  return service;
}
