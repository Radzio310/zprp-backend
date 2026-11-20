# Panel okręgowy: logowanie komputera kodem QR

Wdrożone 20.11.2026. Kod serwera: `app/panel_web_auth.py`, `app/panel_web_seal.py`, `app/panel_web_tables.py`.
Strona: BAZA_web `components/login/PanelQrLogin.tsx`, `utils/sealedPassword.ts`.
Aplikacja: BAZA `app/panel-komputer.tsx`, `utils/panelWebLogin.ts`.

## Po co
Panel okręgowy (`www.bazapodreka.app/panel`) logował się tylko loginem i hasłem ZPRP. Teraz można się zalogować kodem QR zatwierdzonym w aplikacji BAZA, tak jak w panelu Mentor. Hasło nie trafia do przeglądarki.

## Przebieg
1. Komputer: `POST /panel-web/auth/qr` zwraca `code`, `poll_token` i `approve_url = https://www.bazapodreka.app/okreg/zaloguj/{code}`. Kod żyje 3 minuty.
2. Kod zatwierdza drugie urządzenie, jedną z dwóch dróg:
   - **panel w przeglądarce telefonu** (dowolne konto zalogowane hasłem, także konto okręgu, np. komisja): karta konta → „Zaloguj inne urządzenie” (`/okreg/skanuj`) albo zwykły aparat telefonu. Obie prowadzą do strony `…/okreg/zaloguj/{code}` z przyciskiem „Zaloguj komputer”;
   - **aplikacja BAZA** (konta sędziowskie): kafel „Panel na komputerze” w Więcej panelu okręgu albo `refhandballapp://panel/login/{code}` (przycisk na tej samej stronie).
   Link `/okreg/zaloguj/*` celowo nie jest w AASA ani w filtrach Androida, więc kod zawsze otwiera przeglądarkę.
3. Zatwierdzające urządzenie wysyła `POST /panel-web/auth/qr/{code}/approve` ze swoim JWT. W treści są login i hasło ZPRP, zaszyfrowane kluczem publicznym serwera (`prepareEncryptedPayload`).
4. Serwer sprawdza dwie rzeczy:
   - login z danych to login z JWT, czyli zatwierdza konto zalogowane na zatwierdzającym urządzeniu;
   - ZPRP przyjmuje dane (`/baza_web/login`, a dla sędziego także profil).
   Potem zapisuje wynik przy kodzie.
5. Komputer odpytuje `GET /panel-web/auth/qr/{code}` z `poll_token` (długie odpytywanie). Po zatwierdzeniu odbiera jednorazowo:
   - `username`;
   - `password`, czyli szyfrogram pieczęci;
   - `sealed_expires_at`;
   - `login`, czyli odpowiedź jak z `/baza_web/login` plus `profile`.
   W tej samej chwili dane znikają z bazy.
6. Strona zapisuje `auth_password = "__baza_sealed__:" + password` i dalej działa jak po logowaniu hasłem.

## Pieczęć zamiast hasła
- Format: `"bzs1:" + base64url(nonce | AES-GCM({"p": hasło, "e": wygasa}))`. Klucz pochodzi z `SECRET_KEY`. Pieczęć jest ważna `SEAL_TTL` (12 h).
- Serwer zamyka pieczęć w szyfrogramie RSA swoim kluczem publicznym. Strona wysyła go tam, gdzie zwykle idzie zaszyfrowane hasło (`/zprp/*`, `/baza_web/profile`…).
- `deps.get_rsa_keys` zwraca `SealAwareKey`: przy `decrypt` otwiera pieczęć i oddaje hasło, a pozostałe szyfrogramy zostawia bez zmian. Dzięki temu żadnej trasy `/zprp/*` nie trzeba było zmieniać.
- JWT dla komputera daje `POST /panel-web/auth/token` (`{username, password: szyfrogram pieczęci}`). Trasa nie przyjmuje zwykłego hasła.
- Trasy odświeżenia, które biorą hasło jawnym tekstem (`/province/settlements/refresh`, `/province/clubs/refresh`), nie dostają pieczęci. Serwer używa wtedy konta okręgu.
- Po `sealed_expires_at` strona uznaje sesję za wygasłą: `AuthContext` traktuje to jak brak hasła.

## Bezpieczeństwo
- Zatwierdzenie wymaga JWT konta (aplikacja albo panel zalogowany hasłem). Tokeny stron (`scope`) są odrzucane.
- Urządzenie zalogowane kodem nie zatwierdzi kolejnego: ma tylko pieczęć, a pieczęć jako hasło jest odrzucana.
- Pieczęci nie da się użyć do zatwierdzenia kolejnego komputera.
- Do wygaśnięcia pieczęć jest równoważna hasłu dla tras, które go używają. Jest krótsza i bezpieczniejsza niż dotychczasowe hasło jawnym tekstem w `localStorage`. Wylogowanie usuwa ją z przeglądarki.
- Limity: 30 kodów na IP, 10 nieudanych zatwierdzeń na konto i 60 tokenów na IP, każdy w oknie 10 minut.

## Testy
`tests/test_panel_web_auth.py`
