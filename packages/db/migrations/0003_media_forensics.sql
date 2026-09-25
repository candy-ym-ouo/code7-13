CREATE TYPE media_credential_type AS ENUM ('processed', 'deleted');

-- Versioned Ed25519 signing keys. Private keys are stored encrypted with the
-- MEDIA_SIGNING_KEK environment secret. Retired keys keep their public key so
-- credentials issued before a rotation remain verifiable.
CREATE TABLE media_signing_keys (
  kid text PRIMARY KEY,
  algorithm text NOT NULL DEFAULT 'ed25519' CHECK (algorithm = 'ed25519'),
  public_key_pem text NOT NULL,
  private_key_enc text NOT NULL,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'retired')),
  created_at timestamptz NOT NULL DEFAULT now(),
  retired_at timestamptz
);
CREATE UNIQUE INDEX media_signing_keys_one_active_idx
  ON media_signing_keys(status) WHERE status = 'active';

-- Signed attestations. `payload` is the exact canonical string that was
-- signed, so verification never depends on JSON re-serialization. Claims are
-- duplicated as jsonb for indexing and must only contain public-safe fields
-- (no quarantine keys, owner ids, original filenames or original hashes).
CREATE TABLE media_credentials (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  media_id uuid NOT NULL REFERENCES media_assets(id) ON DELETE CASCADE,
  type media_credential_type NOT NULL,
  kid text NOT NULL REFERENCES media_signing_keys(kid),
  claims jsonb NOT NULL,
  payload text NOT NULL,
  signature text NOT NULL,
  issued_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX media_credentials_processed_once_idx
  ON media_credentials(media_id) WHERE type = 'processed';
CREATE UNIQUE INDEX media_credentials_deleted_once_idx
  ON media_credentials(media_id) WHERE type = 'deleted';
CREATE INDEX media_credentials_media_idx ON media_credentials(media_id, created_at DESC);
CREATE INDEX media_credentials_watermark_idx
  ON media_credentials((claims->>'watermarkFingerprint')) WHERE type = 'processed';
