-- Premiery schema 2: podglad wersji, wymuszenie aktualizacji, linki do sklepow.
-- Idempotentne (db.py robi to samo przy starcie). Slajdy NIE wymagaja migracji
-- danych: stare slajdy (model 1) sa tlumaczone w locie przy odczycie, a zapis
-- z nowego edytora zapisuje slajdy z polem "schema": 2.

ALTER TABLE app_versions ADD COLUMN IF NOT EXISTS preview_shots jsonb NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE app_versions ADD COLUMN IF NOT EXISTS required boolean NOT NULL DEFAULT false;
ALTER TABLE app_versions ADD COLUMN IF NOT EXISTS store_urls jsonb NOT NULL DEFAULT '{}'::jsonb;
