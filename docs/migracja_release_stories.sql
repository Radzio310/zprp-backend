-- BAZA Release Stories: pełnoekranowe premiery wersji + media w Cloudflare R2.
-- Idempotentne i bezpieczne do ponownego wykonania w PostgreSQL/Railway.

CREATE TABLE IF NOT EXISTS release_experiences (
  id                 SERIAL PRIMARY KEY,
  version_id         INTEGER NOT NULL UNIQUE
                       REFERENCES app_versions(id) ON DELETE CASCADE,
  status             VARCHAR NOT NULL DEFAULT 'draft',
  experience_mode    VARCHAR NOT NULL DEFAULT 'story_then_changelog',
  display_generation INTEGER NOT NULL DEFAULT 1,
  headline           VARCHAR NOT NULL DEFAULT 'BAZA przekracza kolejne granice',
  slides             JSONB NOT NULL DEFAULT '[]'::jsonb,
  published_at       TIMESTAMPTZ,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_release_experiences_version_id
  ON release_experiences(version_id);

CREATE TABLE IF NOT EXISTS release_story_assets (
  id            SERIAL PRIMARY KEY,
  experience_id INTEGER NOT NULL
                  REFERENCES release_experiences(id) ON DELETE CASCADE,
  object_key    VARCHAR(1024) NOT NULL UNIQUE,
  original_name VARCHAR(512),
  content_type  VARCHAR(128) NOT NULL DEFAULT 'image/webp',
  width         INTEGER NOT NULL,
  height        INTEGER NOT NULL,
  byte_size     INTEGER NOT NULL,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_release_story_assets_experience_id
  ON release_story_assets(experience_id);

