# Weryfikacja adresów e-mail przez Brevo

Integracja weryfikacji e-mail dla kont **BAZA Beach** (`beach_users`). Po
rejestracji konto bez zatwierdzonej roli (zawodnik/trener/sędzia) musi potwierdzić
adres e-mail 6-cyfrowym kodem. Konta z zatwierdzoną rolą są zwolnione.

Wysyłka odbywa się przez **Brevo REST API** (`POST https://api.brevo.com/v3/smtp/email`),
**bez SMTP**. Klucz API żyje wyłącznie na Railway — nigdy w aplikacji mobilnej.

---

## 1. Zmienne środowiskowe (Railway)

| Zmienna | Wymagana | Przykład / domyślna |
|---|---|---|
| `BREVO_API_KEY` | ✅ (prod) | `xkeysib-…` |
| `BREVO_FROM_EMAIL` | ✅ (prod) | `noreply@moja-domena.pl` |
| `BREVO_FROM_NAME` | — | `BAZA Beach` |
| `EMAIL_CODE_SECRET` | ✅ (prod) | losowy długi sekret (HMAC) |
| `EMAIL_VERIFICATION_TTL_MINUTES` | — | `15` |
| `EMAIL_VERIFICATION_RESEND_SECONDS` | — | `60` |
| `EMAIL_VERIFICATION_GRACE_DAYS` | — | `90` |
| `EMAIL_GRACE_DELETE_ENABLED` | — | `true` |
| `EMAIL_GRACE_CLEANUP_INTERVAL_SECONDS` | — | `86400` |
| `BREVO_WEBHOOK_SECRET` | — (zalecane) | losowy sekret |
| `APP_PUBLIC_URL` | — | `https://…` |
| `ENVIRONMENT` | — | `production` |

W **produkcji** brak `BREVO_API_KEY` / `BREVO_FROM_EMAIL` / `EMAIL_CODE_SECRET`
zatrzymuje start aplikacji (fail-fast). Klucz API **nigdy** nie jest logowany i
**nie** może trafić do `EXPO_PUBLIC_*`.

---

## 2. Konfiguracja Brevo (operator — krok po kroku)

1. **Dodaj domenę**: Brevo → *Senders, Domains & Dedicated IPs* → *Domains* →
   *Add a domain* → wpisz `moja-domena.pl`.
2. **Dodaj rekordy DNS** wskazane przez Brevo (wartości **wklej dokładnie te,
   które wygeneruje Brevo** — nie wymyślaj ich):
   - **Brevo code** (rekord TXT weryfikujący domenę),
   - **DKIM** (rekord TXT/CNAME `mail._domainkey…`),
   - **DMARC** (rekord TXT `_dmarc` — np. `v=DMARC1; p=none; …`).
   Po dodaniu kliknij *Authenticate / Verify* w Brevo i poczekaj na propagację DNS.
3. **Utwórz nadawcę**: *Senders* → *Add a sender* → e-mail = `noreply@moja-domena.pl`
   (ten sam co `BREVO_FROM_EMAIL`). Potwierdź adres.
4. **Wygeneruj klucz API**: *SMTP & API* → *API Keys* → *Generate a new API key* →
   skopiuj wartość → wklej do Railway jako `BREVO_API_KEY`.
5. **Dodaj zmienne do Railway**: projekt → *Variables* → dodaj zmienne z sekcji 1
   → *Deploy*.

---

## 3. Migracja bazy

Schemat dopasowany do projektu (bez Alembica):
- nowe tabele (`email_verification_codes`, `email_delivery_events`,
  `email_rate_events`) tworzy `metadata.create_all` w `app/db.py`,
- nowe kolumny `beach_users` dodaje idempotentny `ALTER … IF NOT EXISTS` przy
  starcie (`main.py`), a backfill + unikalny indeks robi skrypt migracyjny.

Po wdrożeniu uruchom raz (Railway → *Shell* lub lokalnie z `DATABASE_URL` produkcyjnym):

```bash
cd zprp-backend
python migrate_email_verification.py --dry-run   # podgląd + raport konfliktów
python migrate_email_verification.py             # właściwa migracja
```

Skrypt:
1. dodaje kolumny (idempotentnie),
2. backfilluje `email_normalized = lower(trim(email))`,
3. ustawia 90-dniowy termin dla niezweryfikowanych kont,
4. **jeśli brak duplikatów** po lower/trim → tworzy **partial unique index**
   `uq_beach_users_email_normalized`; **jeśli są duplikaty** → wypisuje raport
   (zamaskowane adresy) i **nie** tworzy indeksu (rozwiąż duplikaty i uruchom ponownie).

> Migracja jest bezpieczna dla istniejących rekordów. `email` pozostaje nullable;
> nowe konta wymagają e-maila tylko gdy nie mają zatwierdzonej roli.

---

## 4. Endpointy (prefiks `/beach/auth`)

| Metoda | Ścieżka | Auth | Opis |
|---|---|---|---|
| POST | `/beach/auth/verify-email` | — | `{email, code}` → potwierdzenie kodem |
| POST | `/beach/auth/verify-email-code` | ✅ token | `{code}` → potwierdzenie dla zalogowanego |
| POST | `/beach/auth/resend-verification-code` | — | `{email}` → neutralna ponowna wysyłka |
| POST | `/beach/auth/start-email-verification` | ✅ token | `{email?}` → ustaw/zmień e-mail i wyślij kod |
| GET | `/beach/auth/email-status` | ✅ token | stan weryfikacji (zamaskowany e-mail, deadline) |
| POST | `/beach/webhooks/brevo/transactional` | sekret | webhook zdarzeń dostarczenia |

Rejestracja (`POST /beach/users/`) bez zmiany kontraktu: dodatkowo wysyła kod
(best-effort) i zwraca `BeachUserItem` z polami `email_verified`,
`requires_email_verification`.

Kody błędów weryfikacji: `INVALID_VERIFICATION_CODE` (400),
`VERIFICATION_CODE_EXPIRED` (400), `TOO_MANY_ATTEMPTS` (400, max 5 prób),
`RATE_LIMITED` (429), `EMAIL_DELIVERY_FAILED` (503).

---

## 5. Webhook zdarzeń transakcyjnych

1. Brevo → *Transactional* → *Settings* → *Webhook* → *Add a new webhook*.
2. URL: `https://<twoj-backend>/beach/webhooks/brevo/transactional?secret=<BREVO_WEBHOOK_SECRET>`
   (albo nagłówek `X-Webhook-Secret`).
3. Zaznacz zdarzenia: `delivered`, `hard_bounce`, `soft_bounce`, `blocked`,
   `spam`, `invalid`.
4. Zdarzenia trafiają do `email_delivery_events`. Przy `hard_bounce`/`invalid`
   adres jest oznaczany `email_delivery_blocked=true` (bez cofania weryfikacji
   już potwierdzonych kont).

---

## 6. Test wysyłki

```bash
# 1) zarejestruj konto bez roli z adresem testowym → przyjdzie kod
curl -X POST https://<backend>/beach/users/ -H 'Content-Type: application/json' \
  -d '{"full_name":"Test User","login":"test_user","password":"haslo123","email":"ty@twoja-domena.pl"}'

# 2) potwierdź kodem z maila
curl -X POST https://<backend>/beach/auth/verify-email -H 'Content-Type: application/json' \
  -d '{"email":"ty@twoja-domena.pl","code":"123456"}'
```

Podgląd wysłanych wiadomości: Brevo → *Transactional* → *Logs* (status, otwarcia,
bounce). `messageId` z logów odpowiada temu, co backend zapisuje w logach.

---

## 7. Testy automatyczne

```bash
cd zprp-backend
pip install -r requirements-dev.txt
pytest tests/test_email_unit.py          # 11 testów — bez bazy (mock Brevo)
DATABASE_URL=postgresql://… pytest tests  # pełny zestaw (20 scenariuszy) na Postgresie
```

Testy nigdy nie wysyłają prawdziwych wiadomości (Brevo mockowane przez `respx`
oraz fixture `fake_brevo`).

---

## 8. Logika bramki (aplikacja)

- Konto z **zatwierdzoną rolą** (zawodnik/trener/sędzia) → bez weryfikacji ("luz").
- Konto **bez roli** i z niezweryfikowanym e-mailem → na ekranie głównym pojawia
  się **obowiązkowy, niezamykalny** modal weryfikacji (`requires_email_verification`).
  Jeśli użytkownik nie podał adresu — podaje go w modalu (lub zmienia).
- **Istniejące** konta mają **90 dni** na weryfikację; po terminie niezweryfikowane,
  bezrolowe konta są usuwane przez dobowy job (`EMAIL_GRACE_DELETE_ENABLED`).
