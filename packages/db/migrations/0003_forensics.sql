-- Media forensics: signing key directory and verifiable credential ledger.

CREATE TABLE forensics_signing_keys (
  kid text PRIMARY KEY,
  status text NOT NULL CHECK (status IN ('active', 'retired')),
  public_key text NOT NULL,
  -- AES-256-GCM sealed PKCS8 key; erased on retirement while the public key
  -- is retained so every previously issued credential stays verifiable.
  private_key_enc text,
  created_at timestamptz NOT NULL,
  retired_at timestamptz
);

-- At most one active signing key at any time.
CREATE UNIQUE INDEX forensics_signing_keys_one_active_idx
  ON forensics_signing_keys ((1)) WHERE status = 'active';

CREATE TABLE media_credentials (
  credential_hash text PRIMARY KEY,
  media_id uuid NOT NULL,
  type text NOT NULL CHECK (type IN ('media.processed', 'media.deleted')),
  kid text NOT NULL REFERENCES forensics_signing_keys(kid),
  token text NOT NULL,
  payload jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX media_credentials_media_idx ON media_credentials(media_id, created_at);

-- The deletion event is a single immutable fact per media asset.
CREATE UNIQUE INDEX media_credentials_one_deletion_idx
  ON media_credentials(media_id) WHERE type = 'media.deleted';

-- Sealed public id of the watermarked, processed image. Never derived from
-- the original bytes. Null until processing completes.
ALTER TABLE media_assets
  ADD COLUMN public_id text,
  ADD COLUMN credential_hash text;
CREATE UNIQUE INDEX media_assets_public_id_idx ON media_assets(public_id) WHERE public_id IS NOT NULL;
