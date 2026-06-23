# Zewnętrzne backupy — zprp-backend → Cloudflare R2

Automatyczne codzienne backupy bazy PostgreSQL i katalogu uploadów do Cloudflare R2 (S3-compatible), niezależne od Railway.

---

## Co jest backupowane

| Zasób | Format | Ścieżka w R2 |
|---|---|---|
| PostgreSQL (pg_dump) | `.dump.gz` (custom format + gzip) | `backups/postgres/daily/postgres_YYYY-MM-DD_HH-mm-ss.dump.gz` |
| Uploads / zdjęcia | `.tar.gz` | `backups/uploads/daily/uploads_YYYY-MM-DD_HH-mm-ss.tar.gz` |

Retencja domyślna: **14 dni** (konfigurowalna przez `BACKUP_RETENTION_DAYS`).

---

## Krok 1 — Utwórz bucket w Cloudflare R2

1. Wejdź na [dash.cloudflare.com](https://dash.cloudflare.com) → **R2 Object Storage**
2. Kliknij **Create bucket** → nazwa np. `zprp-backups` → region: `Automatic`
3. Po utworzeniu: upewnij się że **Public Access jest wyłączony** (domyślnie OFF — zostaw tak)

---

## Krok 2 — Utwórz API Token R2

1. W Cloudflare Dashboard → **R2 Object Storage** → **Manage R2 API Tokens**
2. Kliknij **Create API Token**
3. Uprawnienia:
   - **Object:Read** — dla bucketu `zprp-backups`
   - **Object:Write** — dla bucketu `zprp-backups`
   - Nie dawaj uprawnień do innych bucketów
4. Skopiuj: **Access Key ID** i **Secret Access Key** (Secret widoczny tylko raz!)
5. Skopiuj też **Endpoint URL** z ekranu bucketu: `https://<ACCOUNT_ID>.r2.cloudflarestorage.com`

---

## Krok 3 — Dodaj env vars w Railway

Wejdź w Railway → Twój serwis → **Settings → Variables** i dodaj:

```
BACKUP_S3_ENDPOINT       = https://<ACCOUNT_ID>.r2.cloudflarestorage.com
BACKUP_S3_REGION         = auto
BACKUP_S3_BUCKET         = zprp-backups
BACKUP_S3_ACCESS_KEY_ID  = <access key z R2>
BACKUP_S3_SECRET_ACCESS_KEY = <secret key z R2>
BACKUP_S3_PREFIX         = backups
BACKUP_UPLOADS_DIR       = /data/static
BACKUP_RETENTION_DAYS    = 14
BACKUP_NOTIFY_WEBHOOK_URL = https://discord.com/api/webhooks/...   ← opcjonalne
BEACH_DAILY_ACCOUNT_REPORT_WEBHOOK_URL = https://discord.com/api/webhooks/...   ← opcjonalne, gdy inny kanał niż backup
```

Po zapisaniu Railway automatycznie zrestartuje serwis.

---

## Harmonogram automatyczny

Backup uruchamiany jest **raz dziennie** wewnątrz pętli `_cleanup_loop()` w `main.py`.  
Pierwsze uruchomienie nastąpi po starcie serwisu (przy każdym restarcie jeśli w danym dniu jeszcze nie był).

Backup jest **pominięty** gdy zmienna `BACKUP_S3_BUCKET` nie jest ustawiona — bezpieczne dla środowisk dev.

Dzienny raport kont BAZA Beach jest wysyłany raz dziennie na `BEACH_DAILY_ACCOUNT_REPORT_WEBHOOK_URL`,
a jeśli ta zmienna nie jest ustawiona — na `BACKUP_NOTIFY_WEBHOOK_URL`. Raport zawiera te same 4 kategorie
z zakładki **Użytkownicy** w panelu admina oraz liczbę weryfikacji wykonanych w ostatnich 24h.

---

## Ręczne uruchomienie

### Lokalnie (wymaga `.env` z backup env vars):
```bash
cd zprp-backend
python scripts/backup_external.py
```

### Na Railway przez CLI:
```bash
railway run python scripts/backup_external.py
```

---

## Weryfikacja — sprawdź czy backup się zapisał

### R2 Dashboard:
1. Cloudflare Dashboard → R2 → `zprp-backups` → Browse
2. Folder `backups/postgres/daily/` — powinien być plik z dzisiejszą datą

### Railway logi:
Szukaj w logach serwisu:
```
🗄️ External backup: starting...
pg_dump → /tmp/backups/postgres_2026-05-26_02-00-00.dump
Compressing dump → /tmp/backups/postgres_2026-05-26_02-00-00.dump.gz
DB backup ready: ... (12.3 MB)
Uploading postgres_... → s3://zprp-backups/backups/postgres/daily/...
Upload OK: backups/postgres/daily/postgres_2026-05-26_02-00-00.dump.gz
🗄️ External backup: completed
```

---

## Restore bazy PostgreSQL

### Pobierz plik z R2:
Możesz pobrać przez R2 dashboard (Actions → Download) lub przez awscli/rclone z credentials.

### Odtworzenie do istniejącej bazy:
```bash
# 1. Rozpakuj dump
gunzip -c postgres_2026-05-26_02-00-00.dump.gz > restored.dump

# 2. Wgraj do bazy (nadpisze istniejące dane!)
pg_restore \
  --clean \
  --if-exists \
  --no-owner \
  --no-acl \
  --dbname "$DATABASE_URL" \
  restored.dump

# 3. Posprzątaj
rm restored.dump
```

### Test restore do osobnej testowej bazy:
```bash
# Utwórz testową bazę
createdb test_restore_db

# Restore do testowej bazy
gunzip -c postgres_2026-05-26.dump.gz > restored.dump
pg_restore --clean --if-exists --no-owner --no-acl \
  --dbname "postgresql://user:pass@localhost/test_restore_db" \
  restored.dump

# Sprawdź dane
psql "postgresql://user:pass@localhost/test_restore_db" -c "\dt"

# Usuń testową bazę po weryfikacji
dropdb test_restore_db
rm restored.dump
```

---

## Restore plików / uploadów

```bash
# Rozpakuj do katalogu uploadów
tar -xzf uploads_2026-05-26_02-00-00.tar.gz -C /data/

# Pliki wylądują w /data/uploads/ — jeśli serwis spodziewa się /data/static/:
# tar -xzf uploads_*.tar.gz --strip-components=1 -C /data/static/
```

> Archiwum zawiera folder `uploads/` wewnątrz — sprawdź strukturę przez `tar -tzf plik.tar.gz | head -20`

---

## Szyfrowanie archiwów (opcjonalne)

Bucket jest prywatny i R2 szyfruje dane at-rest — szyfrowanie client-side zazwyczaj nie jest potrzebne.  
Jeśli chcesz je dodać, zmodyfikuj `scripts/backup_external.py` dodając po każdym archiwum:

```python
# Szyfrowanie przez openssl (przed uploadem)
import subprocess, os
enc_path = gz_path + ".enc"
subprocess.run(
    ["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-iter", "100000",
     "-in", gz_path, "-out", enc_path,
     "-pass", f"pass:{os.environ['BACKUP_ENCRYPTION_PASSWORD']}"],
    check=True,
)
os.remove(gz_path)
gz_path = enc_path  # upload enc_path zamiast gz_path
```

Restore po szyfrowaniu:
```bash
openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 \
  -in postgres_...dump.gz.enc -out postgres_...dump.gz \
  -pass pass:"$BACKUP_ENCRYPTION_PASSWORD"
```

---

## Troubleshooting

| Problem | Rozwiązanie |
|---|---|
| `pg_dump: command not found` | Brakuje `postgresql-client` w Dockerfile — sprawdź czy jest w apt-get install |
| `Missing required env vars` | Dodaj brakujące zmienne w Railway → Variables |
| `Upload FAILED: InvalidAccessKeyId` | Sprawdź czy `BACKUP_S3_ACCESS_KEY_ID` i `BACKUP_S3_SECRET_ACCESS_KEY` są poprawne |
| `NoSuchBucket` | Sprawdź `BACKUP_S3_BUCKET` i `BACKUP_S3_ENDPOINT` (Account ID musi być właściwy) |
| Brak pliku uploads | `BACKUP_UPLOADS_DIR` nie istnieje — sprawdź czy volume jest zamontowany i ścieżka prawidłowa |
| Backup nie uruchamia się automatycznie | Sprawdź czy `BACKUP_S3_BUCKET` jest ustawiony w Railway env |
