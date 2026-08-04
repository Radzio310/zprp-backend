-- ============================================================================
-- BAZA — migracja: komunikator zgłoszeń + wersje per platforma + push po judge_id
--
-- CZYSTY SQL — żadnych komend psql (\echo, \i), więc działa zarówno przez
-- `psql -f`, jak i po wklejeniu w okno zapytań Postgresa w panelu Railway.
-- Każde polecenie to osobna instrukcja zakończona średnikiem, bez bloków DO $$,
-- żeby konsola webowa nie miała problemu z podziałem na instrukcje.
--
-- Idempotentne: powtórne uruchomienie niczego nie zepsuje i NIE cofnie ustawień
-- zrobionych później w panelu (jednorazowe backfille pilnuje schema_migrations).
--
-- Wstecz kompatybilne: żadna kolumna nie znika, żadna nie zmienia typu.
-- ============================================================================

-- ─────────────────── 0) Rejestr wykonanych migracji ───────────────────
-- Dzięki niemu jednorazowe UPDATE-y wykonają się dokładnie raz.

CREATE TABLE IF NOT EXISTS schema_migrations (
  key        TEXT PRIMARY KEY,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─────────────────── 1) Zgłoszenia jako wątki ───────────────────

ALTER TABLE user_reports
  ADD COLUMN IF NOT EXISTS status          TEXT        NOT NULL DEFAULT 'open',
  ADD COLUMN IF NOT EXISTS title           TEXT,
  ADD COLUMN IF NOT EXISTS unread_by_admin BOOLEAN     NOT NULL DEFAULT TRUE,
  ADD COLUMN IF NOT EXISTS unread_by_user  BOOLEAN     NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- Stan „nieprzeczytane u admina” przepisujemy z istniejącej kolumny is_read,
-- żeby dotychczasowe zgłoszenia nie zapaliły się nagle wszystkie na czerwono.
-- Warunek NOT EXISTS sprawia, że to wykona się tylko przy pierwszym przebiegu.
UPDATE user_reports
   SET unread_by_admin = NOT is_read
 WHERE NOT EXISTS (
   SELECT 1 FROM schema_migrations WHERE key = '2026_08_reports_thread_backfill'
 );

-- Wątek sortuje się po updated_at — dla starych wpisów startujemy od utworzenia.
UPDATE user_reports
   SET updated_at = created_at
 WHERE NOT EXISTS (
   SELECT 1 FROM schema_migrations WHERE key = '2026_08_reports_thread_backfill'
 );

INSERT INTO schema_migrations (key)
VALUES ('2026_08_reports_thread_backfill')
ON CONFLICT (key) DO NOTHING;

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
 WHERE NOT EXISTS (
   SELECT 1 FROM schema_migrations WHERE key = '2026_08_versions_platform_backfill'
 );

INSERT INTO schema_migrations (key)
VALUES ('2026_08_versions_platform_backfill')
ON CONFLICT (key) DO NOTHING;

-- ─────────────────── 4) Push adresowany do sędziego ───────────────────

ALTER TABLE push_tokens
  ADD COLUMN IF NOT EXISTS judge_id TEXT;

CREATE INDEX IF NOT EXISTS ix_push_tokens_judge_id
  ON push_tokens (judge_id);

-- ─────────────────── 5) Kontrolka na koniec ───────────────────
-- Jedno zapytanie zamiast czterech, żeby konsola webowa pokazała wynik.

SELECT
  (SELECT COUNT(*) FROM user_reports)                        AS zgloszen_lacznie,
  (SELECT COUNT(*) FROM user_reports WHERE unread_by_admin)  AS nieprzeczytanych,
  (SELECT COUNT(*) FROM user_report_messages)                AS wiadomosci,
  (SELECT COUNT(*) FROM app_versions WHERE available_android) AS wersji_android,
  (SELECT COUNT(*) FROM app_versions WHERE available_ios)     AS wersji_ios,
  (SELECT COUNT(*) FROM schema_migrations)                    AS migracji_wykonanych;
