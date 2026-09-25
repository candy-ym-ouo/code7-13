import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { PgCredentialLedger, verifyCredential } from "@map/forensics";
import { getForensicsService } from "../forensics";
import { requireAdmin, requireAuth } from "../auth";
import { forbidden, notFound } from "../errors";
import { pool } from "../db";

/**
 * Public verification surface: anyone may verify a credential against the
 * retained key directory and inspect the directory itself. Only public key
 * material and signed claims are exposed — originals are never referenced.
 */
export async function forensicsRoutes(app: FastifyInstance) {
  app.get("/forensics/keys", async () => {
    const service = getForensicsService();
    const keys = await service.publicKeyDirectory();
    return {
      v: 1,
      keys: keys.map((key) => ({
        kid: key.kid,
        alg: key.algorithm,
        publicKey: key.publicKey,
        status: key.status,
        createdAt: key.createdAt,
        retiredAt: key.retiredAt
      }))
    };
  });

  app.post("/forensics/verify", async (request, reply) => {
    const input = z.strictObject({ credential: z.string().min(10).max(20_000) }).safeParse(request.body);
    if (!input.success) {
      return reply.code(400).send({ code: "VALIDATION_FAILED", detail: "credential is required" });
    }
    const service = getForensicsService();
    const result = verifyCredential(input.data.credential, await service.keyRing.verificationKeys());
    if (!result.valid) {
      return reply.code(200).send({ valid: false, reason: result.reason });
    }
    return reply.code(200).send({
      valid: true,
      kid: result.kid,
      type: result.payload.type,
      mediaId: result.payload.mediaId,
      issuedAt: result.payload.issuedAt,
      payload: result.payload,
      credentialHash: result.credentialHash
    });
  });

  app.get("/media/:id/credentials", { preHandler: requireAuth }, async (request) => {
    const params = z.object({ id: z.string().uuid() }).parse(request.params);
    const ownerResult = await pool.query<{ owner_id: string; deleted_at: Date | null }>(
      "SELECT owner_id, deleted_at FROM media_assets WHERE id = $1",
      [params.id]
    );
    const row = ownerResult.rows[0];
    if (!row) throw notFound("Media not found");
    // Credentials (esp. deletion evidence) remain verifiable after soft-delete.
    if (row.deleted_at && !["moderator", "admin"].includes(request.user!.role)) {
      throw notFound("Media not found");
    }
    if (row.owner_id !== request.user!.id && !["moderator", "admin"].includes(request.user!.role)) {
      throw forbidden();
    }

    const service = getForensicsService();
    const keys = await service.keyRing.verificationKeys();
    const ledger = new PgCredentialLedger(pool);
    const records = await ledger.listForMedia(params.id);
    return {
      credentials: records.map((record) => {
        const verified = verifyCredential(record.token, keys);
        return {
          type: record.type,
          issuedAt: record.createdAt,
          kid: record.kid,
          credentialHash: record.credentialHash,
          validSignature: verified.valid,
          token: record.token
        };
      })
    };
  });

  app.post("/admin/forensics/rotate", { preHandler: requireAdmin }, async (request) => {
    const service = getForensicsService();
    const directoryBefore = await service.publicKeyDirectory();
    const newKid = await service.rotateKeys();

    await pool.query(
      `INSERT INTO audit_logs(actor_id, action, resource_type, resource_id, metadata)
       VALUES ($1, 'forensics.key_rotated', 'forensics_key', NULL, $2::jsonb)`,
      [request.user!.id, JSON.stringify({ previousKeyCount: directoryBefore.length, newKid })]
    );

    return {
      activeKeyId: newKid,
      retainedKeyIds: directoryBefore.map((key) => key.kid),
      note: "Retired public keys are retained; previously issued credentials remain verifiable."
    };
  });
}
