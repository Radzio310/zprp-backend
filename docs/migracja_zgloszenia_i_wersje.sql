-- ============================================================================
-- BAZA — migracja: komunikator zgłoszeń + wersje per platforma + push po judge_id
--
-- Uruchom RAZ na bazie produkcyjnej (Railway → Postgres → Query / psql).
-- Cała komenda jest idempotentna (IF NOT EXISTS), więc powtórne uruchomienie
-- niczego nie zepsuje.
--
-- Wstecz kompatybilne: żadna kolumna nie znika, żadna nie zmienia typu.
-- Starsze wersje aplikacji nie zauważą różnicy.
-- ============================================================================

BEGIN;

-- ─────────────────── 1) Zgłoszenia jako wątki ───────────────────

ALTER TABLE user_reports
  ADD COLUMN IF NOT EXISTS status          TEXT        NOT NULL DEFAULT 'open',
  ADD COLUMN IF NOT EXISTS title           TEXT,
  ADD COLUMN IF NOT EXISTS unread_by_admin BOOLEAN     NOT NULL DEFAULT TRUE,
  ADD COLUMN IF NOT EXISTS unread_by_user  BOOLEAN     NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- Stan „nieprzeczytane u admina” przepisujemy z istniejącej kolumny is_read,
-- żeby 61 dotychczasowych zgłoszeń nie zapaliło się nagle wszystkie na czerwono.
UPDATE user_reports SET unread_by_admin = NOT is_read;

-- Wątek sortuje się po updated_at — dla starych wpisów startujemy od daty utworzenia.
UPDATE user_reports SET updated_at = created_at WHERE updated_at IS NULL;

CREATE INDEX IF NOT EXISTS ix_user_reports_updated_at
  ON user_reports (updated_at DESC);
CREATE INDEX IF NOT EXISTS ix_user_reports_unread_by_admin
  ON user_reports (unread_by_admin);

-- ─────────────────── 2) Wiadomości w wątku ───────────────────

CREATE TABLE IF NOT EXISTS user_report_messages (
  id             SERIAL PRIMARY KEY,
  report_id      INTEGER     NOT NULL
                   REFERENCES user_reports(id) ON DELETE CASCADE,
  sender_type    TEXT        NOT NULL,          -- 'user' | 'admin'
  sender_id      TEXT        NOT NULL,          -- judge_id nadawcy
  sender_name    TEXT,
  content        TEXT        NOT NULL,
  attachment_url TEXT,                          -- '__archived__' po sprzątaniu
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_user_report_messages_report_id
  ON user_report_messages (report_id);
CREATE INDEX IF NOT EXISTS ix_user_report_messages_created_at
  ON user_report_messages (created_at);

-- ─────────────────── 3) Wersje per platforma ───────────────────

ALTER TABLE app_versions
  ADD COLUMN IF NOT EXISTS available_ios     BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS available_android BOOLEAN NOT NULL DEFAULT FALSE;

-- WAŻNE: istniejące wersje backfillujemy na TRUE dla obu platform.
-- Aplikacja pokazuje TYLKO wersje dostępne na swojej platformie, więc bez tego
-- po wdrożeniu zniknęłaby cała historia i przestałoby działać wymuszanie
-- aktualizacji. Nowe wersje domyślnie mają FALSE — sam odhaczasz platformę
-- w panelu, gdy wersja pojawi się w sklepie.
UPDATE app_versions
   SET available_ios = TRUE, available_android = TRUE
 WHERE created_at < NOW();

-- ─────────────────── 4) Push adresowany do sędziego ───────────────────

ALTER TABLE push_tokens
  ADD COLUMN IF NOT EXISTS judge_id TEXT;

CREATE INDEX IF NOT EXISTS ix_push_tokens_judge_id
  ON push_tokens (judge_id);

COMMIT;

-- ─────────────────── weryfikacja (opcjonalnie) ───────────────────
-- SELECT status, COUNT(*) FROM user_reports GROUP BY status;
-- SELECT version, to_show, available_ios, available_android FROM app_versions
--   ORDER BY created_at DESC LIMIT 10;
-- SELECT COUNT(*) FROM push_tokens WHERE judge_id IS NOT NULL;
