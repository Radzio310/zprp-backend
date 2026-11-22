# Tryb prezentacji (filmy promocyjne)

Decyzja właściciela z 22.11.2026: wybrane konta (np. sędzia admina 5124 i konto okręgu
`ks_slzpr`) mogą w panelu okręgowym i w aplikacji BAZA klikać wszystko - oddać mecz na
giełdzie, przejąć go, zatwierdzić, zapisać obsadę w ZPRP, dodać niedyspozycję, ogłoszenie -
a NIC naprawdę się nie zmienia:

* zero wierszy widocznych dla innych użytkowników,
* zero wywołań baza.zprp.pl przy zapisie,
* zero pushy.

Odczyty zwracają prawdziwe dane. Na ekranach nie ma żadnego znaczka trybu - stan widać
tylko w Ustawieniach panelu okręgowego. Włącza go wyłącznie administrator aplikacji
(`admin_settings.allowed_admins`, `require_app_admin`).

## Jak włączyć

```
PUT /presentation/state
{ "enabled": true,
  "accounts": [{"kind": "judge", "value": "5124", "label": "Ja"},
               {"kind": "login", "value": "ks_slzpr", "label": "Okręg"}],
  "areas": ["market","obsada","settlements","offtimes","announcements","events"],
  "minutes": 180 }
```

* Konto administratora, który włącza, dopisuje się samo.
* `minutes` 15-480 (domyślnie 180). Po czasie tryb wyłącza się sam i czyści nakładkę.
  Ponowny PUT bez `minutes` przy włączonym trybie nie przesuwa terminu.
* `GET /presentation/state` - stan; `GET /presentation/ops` - dziennik udawanych operacji;
  `DELETE /presentation/ops` - czyści dziennik i nakładkę.
* `POST /presentation/scene {"scene":"market_offer_with_claims","province":"ŚLĄSKIE"}` -
  oferta obsadowego (tylko w nakładce) na prawdziwym nadchodzącym meczu okręgu z dwoma
  zgłoszeniami prawdziwych, aktywnych sędziów okręgu (nigdy pytającego). Panel pokazuje
  „Na giełdzie okręgu · 2 zgłoszenia". Działa tylko przy włączonym trybie (inaczej 409).
* `GET /presentation/judges?province=&q=` - wybór kont; `GET /presentation/diagnostics` -
  stan serwera (wersja = `RAILWAY_GIT_COMMIT_SHA`, baza, ostatnie synchronizacje:
  `province_match_sync_runs`, `province_judges.updated_at`, `province_offtime_sync_runs`;
  `errors_24h` = zgłoszenia z `client_error_reports` z ostatniej doby; `push_tokens`).

## Jak to działa

`app/presentation_middleware.py` - czysty ASGI, warstwa POD bramką klucza klienta i CORS.

1. Tryb wyłączony (stan w pamięci, z bazy najwyżej co 3 s) -> żądanie idzie prosto do
   aplikacji, bez czytania treści. Zero zmian zachowania.
2. Trasa spoza jawnej listy (`app/presentation_routes.py`) -> prosto do aplikacji. Nie ma
   reguły „każdy POST" - odczyty w POST (match-form, rights, candidates, suggest, forecast,
   szkic PDF...) zawsze przechodzą.
3. Kto pyta:
   * token BAZA (podpis sprawdzony, data ważności nie - wygasły token to dalej to konto);
     `judge_id` z tokenu porównujemy z kontami „judge", `sub` (login ZPRP) z kontami „login";
   * login konta podanego numerem poznajemy z tokenu (zapis w `learned_logins_json`)
     i z `baza_vips` (login -> numer);
   * BEZ tokenu (trasy /zprp/*, niedyspozycje ZPRP, ogłoszenia multipart) - treść żądania:
     RSA `username` / `judge_id` (także z base64 w środku, jak w `silesia`), jawne `user`
     i `judge_id`. Treść czytamy tylko przy włączonym trybie i tylko dla tras z listy;
     aplikacja dostaje ją potem nietkniętą. Gdy token jest, rozstrzyga sam (numer w treści
     bywa numerem sędziego, któremu ktoś INNY coś zapisuje).
4. Konto trybu + trasa zapisu -> handler NIE jest wołany. Wpis do `presentation_ops`
   (bez haseł - pola `password`, `username` i podobne jako `***`), udawana odpowiedź
   w kształcie z handlera. Gdy symulator się wywróci, wraca zwykłe „ok" - zapis i tak nie
   przechodzi.
5. Konto trybu + odczyt z nakładką -> prawdziwa odpowiedź z doklejonymi udawanymi zmianami.

Nakładka (`presentation_overlay`) jest wspólna dla wszystkich kont trybu (sędzia oddaje,
konto okręgu widzi w panelu) i niewidoczna dla nikogo innego.

## Co jest udawane i co widać potem w odczytach

| Obszar | Udawane zapisy | Doklejane do odczytów (tylko konta trybu) |
|---|---|---|
| giełda | POST /match-market/offers (201 `{id,status}`), DELETE /offers/{id}, listing-approval approve/reject, POST /offers/{id}/claims (201), DELETE /claims/me, reject, **approve (`{id,status:"done",applied:true,from,to}` - bez ZPRP)**, admin: notification-preferences, provinces/{p} PUT, offers/{id}/withdraw, notification-test/send (podgląd zamiast wysyłki) | GET /offers (market/mine/history), GET /offers/{id} (udawana oferta w całości), GET i POST /my-matches, /my-matches/recheck (gniazdo „już wisi") |
| giełda obsadowego | POST /crew-offers (201, pełny widok), claims (201), claims/me, assign (+ wpis do udawanego szkicu kolejki Obsady), unassign, DELETE, invite (bez pusha) | GET /crew-offers, GET /crew-offers/{id} (widok z `_offer_view` i `_claims_view`) |
| obsada | /zprp/obsada/save (`verified_slots` = wysłana zmiana, reszta z `expect`), save-hall, save-date, table-officials/save, /clear; PUT /province/assignment/draft (`{rev}`), mentor-pairs, judges/{id}, blocks, pauses, pairs, manual, clubs; Automat POST /province/assignment (**liczy naprawdę, bez zapisu przebiegu** - `DRY_RUN`); runs/{id}/applied, /undone; /assignment-drafts; PUT /province/me/availability | GET /province/assignment/draft, GET /bootstrap (pole `draft`, bez 304) |
| rozliczenia | PUT/PATCH /province-travel/{id}, settlements: modules, accounting/codes, exclusions, homes (+batch, DELETE), periods, register (DELETE, settings, doc-settings, doc-extra), splits (PUT/DELETE); PDF zestawienie/przejazdy idzie jako **szkic** (bez numeru w rejestrze); invoices: upload, approve, reopen, confirm, unconfirm, trash, restore, purge; bomby: POST, DELETE, void, manual, penalty, penalty-scale | - |
| niedyspozycje | /judge/offtimes/create, update, delete (ZPRP), /silesia/offtimes/set, DELETE /silesia/offtimes/{enc} (204), /silesia/offtimes/assigned (POST/PATCH/DELETE), /partner-offtimes (POST/PUT/DELETE), PUT /admin/zprp-unavailability/config | - (zapisane w nakładce `offtime`, lista z ZPRP pokazuje stan prawdziwy) |
| ogłoszenia | create (201, `AnnouncementResponse`), PUT, reaction, comment, comment_pin, comment_delete, DELETE (204) - bez pliku obrazka i bez pusha | GET /silesia/announcements/ (nowe, zmienione, usunięte) |
| wydarzenia i formularze | /province-events: v2 create/patch, cancel, uncancel, trash, restore, templates, rsvp, attendance/v2, checkin/open, checkin, title-image, stare `/`, PATCH, DELETE; /district-forms: tworzenie, zmiany, publish/close/reopen/archive/…, odpowiedzi `me`, wiersze, pliki | GET /province-events/feed i /item/{id} (moja odpowiedź RSVP i liczniki) |

Pełna lista z wzorcami ścieżek: `WRITE_ROUTES` i `READ_ROUTES` w `app/presentation_routes.py`.

### Czego nakładka NIE dokleja (znane ograniczenia)

* Liczniki `GET /match-market/context` i zakładek - bez zmian.
* Terminarz/obsada meczu po udawanym „Zapisz w ZPRP": `bootstrap`, mecze okręgu i dziennik
  zapisów pokazują stan prawdziwy (ekran pokazuje zmianę z odpowiedzi zapisu).
* Niedyspozycje: listy czytane z ZPRP i z okręgu nie pokazują udawanych wpisów.
* Nowe wydarzenia i formularze nie pojawiają się w listach (odpowiedź zapisu jest udawana);
  RSVP - tak.
* Rozliczenia, faktury, bomby - odpowiedzi „ok" (z echem wysłanych pól); listy bez zmian.
  Wczytanie faktur (`/province/invoices/upload`) w trybie nic nie odczytuje.
* `POST /province-events/checkin` oddaje `{"already": false, "event": null}`.
* Trasy bez tokenu i bez danych logowania w treści (anonimowe zapisy okresu przejściowego)
  nie dają się przypisać kontu - idą do aplikacji jak dotąd.

## Gwarancje bezpieczeństwa

* Wyłączony tryb albo konto spoza listy: żądanie idzie do aplikacji bez zmian (testy).
* Zapis konta trybu nigdy nie dochodzi do handlera; jedyny wyjątek to Automat i szkic PDF,
  które wołają prawdziwy handler w trybie „na sucho" (Automat pomija `INSERT` przebiegu;
  PDF dostaje `official=false`).
* Symulatory nie wołają ZPRP, nie wysyłają pushy i piszą wyłącznie do `presentation_*`.
* Błąd symulatora albo rozpoznania konta trybu -> udawane „ok", nie zapis.
* Baza chwilowo niedostępna przy odświeżeniu stanu -> zostaje ostatni znany stan.
* Wyłączenie, wygaśnięcie i `DELETE /ops` czyszczą nakładkę.
* Pamięć stanu jest per proces (odświeżanie co 3 s), więc przełączenie dociera do
  wszystkich procesów w ciągu kilku sekund.

## Ustawienia okręgu (te same Ustawienia)

* `GET /province/me/profile` - role z odznak (`sedzia`, `obsadowy`, `komisja`,
  `calendar_master`, `admin`, `vip`), `is_app_admin`, okręgi do wyboru.
* `GET|PUT /province/me/availability` - dni, rola w obsadzie, notatka; zapis tylko do
  własnego wiersza `province_judge_settings` (numer z tokenu). `needs_experienced` i
  `no_solo` zostają w gestii obsadowego. `home_city` z `province_settlement_judges`,
  potem `zprp_judges_seen`.
* Powiadomienia okręgu (`notificationTypes` w `push_tokens.notification_prefs`, brak
  klucza = włączone): `districtAnnouncements` (ogłoszenia, `schedule_province_push`),
  `districtEvents` (wydarzenia okręgu), `districtForms` (formularze okręgu - obok
  dawnego `province_events`).
