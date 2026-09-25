import type { FastifyInstance } from "fastify";
import { z } from "zod";
import {
  findCredentialById,
  listCredentialsForMedia,
  listPublicKeys,
  verifyCredential,
  type MediaCredentialRecord,
  type QueryFn
} from "@map/shared/forensics";
import { query } from "../db";
import { forbidden, notFound } from "../errors";
import { requireAuth } from "../auth";

const queryFn: QueryFn = (text, params) => query(text, params);

/**
 * 公开校验响应只包含签发时白名单内的声明：处理图哈希、尺寸、时间戳、
 * 水印指纹和删除范围。绝不返回隔离桶键、原图哈希、文件名或所有者信息，
 * 公开地址无法用于定位或还原原图。
 */
function credentialResponse(credential: MediaCredentialRecord, verification: { valid: boolean; keyStatus: string }) {
  return {
    id: credential.id,
    mediaId: credential.mediaId,
    type: credential.type,
    kid: credential.kid,
    issuedAt: credential.issuedAt,
    claims: credential.claims,
    payload: credential.payload,
    signature: credential.signature,
    valid: verification.valid,
    keyStatus: verification.keyStatus
  };
}

export async function forensicsRoutes(app: FastifyInstance) {
  // 公开：全部签名公钥（含 retired），任何人可离线校验历史凭证
  app.get("/forensics/keys", { config: { rateLimit: { max: 60, timeWindow: "1 minute" } } }, async () => {
    const keys = await listPublicKeys(queryFn);
    return {
      keys: keys.map((key) => ({
        kid: key.kid,
        algorithm: key.algorithm,
        publicKeyPem: key.publicKeyPem,
        status: key.status,
        createdAt: key.createdAt,
        retiredAt: key.retiredAt
      }))
    };
  });

  // 公开：凭证校验地址，按凭证内 kid 选择公钥，轮换后旧凭证仍可校验
  app.get("/forensics/credentials/:id", { config: { rateLimit: { max: 60, timeWindow: "1 minute" } } }, async (request) => {
    const params = z.object({ id: z.string().uuid() }).parse(request.params);
    const credential = await findCredentialById(queryFn, params.id);
    if (!credential) throw notFound("Credential not found");
    const verification = await verifyCredential(queryFn, credential);
    return credentialResponse(credential, verification);
  });

  // 所有者/审核员：某媒体签发的全部凭证
  app.get("/forensics/media/:id/credentials", { preHandler: requireAuth }, async (request) => {
    const params = z.object({ id: z.string().uuid() }).parse(request.params);
    const result = await query<{ owner_id: string }>(
      "SELECT owner_id FROM media_assets WHERE id = $1",
      [params.id]
    );
    const media = result.rows[0];
    if (!media) throw notFound("Media not found");
    if (media.owner_id !== request.user!.id && !["moderator", "admin"].includes(request.user!.role)) throw forbidden();

    const credentials = await listCredentialsForMedia(queryFn, params.id);
    return {
      credentials: await Promise.all(credentials.map(async (credential) =>
        credentialResponse(credential, await verifyCredential(queryFn, credential))
      ))
    };
  });
}
