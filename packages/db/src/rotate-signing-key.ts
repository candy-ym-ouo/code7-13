import dotenv from "dotenv";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

dotenv.config({ path: process.env.ENV_FILE || join(dirname(fileURLToPath(import.meta.url)), "../../../.env") });
import pg from "pg";
import { encryptPrivateKey, generateSigningKey } from "@map/shared/forensics";

const { Client } = pg;

/**
 * 轮换媒体签名密钥：当前 active 密钥标记为 retired，生成新的 active 密钥。
 * 旧密钥的公钥保留在库中，历史凭证仍可按 kid 校验。私钥用 MEDIA_SIGNING_KEK
 * 加密后落库，CLI 不会打印私钥。
 */
async function main() {
  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) throw new Error("DATABASE_URL is required");
  const kek = process.env.MEDIA_SIGNING_KEK;
  if (!kek || kek.length < 32) throw new Error("MEDIA_SIGNING_KEK must be set and at least 32 characters");

  const client = new Client({ connectionString: databaseUrl });
  await client.connect();
  try {
    await client.query("BEGIN");
    const previous = await client.query<{ kid: string }>(
      "SELECT kid FROM media_signing_keys WHERE status = 'active' FOR UPDATE"
    );
    const generated = generateSigningKey();
    await client.query("UPDATE media_signing_keys SET status = 'retired', retired_at = now() WHERE status = 'active'");
    await client.query(
      `INSERT INTO media_signing_keys(kid, algorithm, public_key_pem, private_key_enc, status)
       VALUES ($1, 'ed25519', $2, $3, 'active')`,
      [generated.kid, generated.publicKeyPem, encryptPrivateKey(generated.privateKeyPem, kek)]
    );
    await client.query("COMMIT");
    console.log(`rotated media signing key: ${previous.rows[0]?.kid ?? "(none)"} -> ${generated.kid}`);
    console.log("credentials signed with retired keys remain verifiable via their public keys");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    await client.end();
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
