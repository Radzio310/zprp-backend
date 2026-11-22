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
  "areas": ["market","obsada","settlements","offtimes","announcements","events","ratings"],
  "minutes": 180 }
```

* Obszary (`area_labels` w odpowiedzi): `market` Giełda, `obsada` Obsada, `settlements`
  Rozliczenia, `offtimes` Niedyspozycje, `announcements` Ogłoszenia, `events` Wydarzenia
  i formularze, `ratings` Oceny młodych. Brak `areas` = wszystkie; nieznana nazwa = 400.
  Obszar dodany po zapisie stanu jest włączony (zapis `{"on": [...], "known": [...]}`;
  stary zapis jako lista znał sześć pierwszych).

* Konto administratora, który włącza, dopisuje się samo.
* `minutes` 15-480 (domyślnie 180). Po czasie tryb wyłącza się sam i czyści nakładkę.
  Ponowny PUT bez `minutes` przy włączonym trybie nie przesuwa terminu.
* `GET /presentation/state` - stan; `GET /presentation/ops` - dziennik udawanych operacji;
  `DELETE /presentation/ops` - czyści dziennik i nakładkę.
* `POST /presentation/scene` - scena w nakładce, tylko przy włączonym trybie (inaczej 409).
  Pola: `scene`, `province` (opcjonalnie - domyślnie okręg sędziego), `match_id`
  (opcjonalnie), `judge_id` (konto „judge" trybu; domyślnie pierwsze takie konto).
  * `market_offer_with_claims` (wymaga `province`) - oferta obsadowego na prawdziwym
    nadchodzącym meczu okręgu z dwoma zgłoszeniami prawdziwych, aktywnych sędziów okręgu
    (nigdy pytającego). Panel pokazuje „Na giełdzie okręgu · 2 zgłoszenia".
  * `market_giveaway_ready` - historia giełdy na jednym telefonie: najbliższy prawdziwy
    mecz okręgu (60 dni, po nakładce obsady), w którym sędzia stoi w gnieździe giełdy
    (najpierw taki, który da się wystawić zwyczajnie), jego oferta oddania (`open`, albo
    `approval_pending` przy < N h) i JEDNO zgłoszenie prawdziwego sędziego okręgu (nie
    oddający, nie pytający, nikt z obsady meczu). Odpowiedź: `offer_id`, `claim_id`,
    `giver`, `taker`, `approve.path/body` i `approve.judge_can_approve` (czy sam sędzia
    sceny rozstrzyga: odznaka obsadowego okręgu albo admin). Zatwierdzenie
    (`POST /match-market/offers/{id}/approve`) przestawia nakładkę obsady (oddający
    wychodzi, biorący wchodzi) i zapisuje w dzienniku „zapis w ZPRP udawany"
    (`extra.applied_to_zprp = "simulated"`). Panel okręgu (konto `ks_slzpr`) nie
    rozstrzyga giełdy sędziów - zatwierdza konto sędziego z prawem (np. 5124 jako admin).
    Bez meczu sędziego - 404 z wyjaśnieniem.
  * `young_rating_ready` - rozegrany w ostatnich 45 dniach mecz okręgu z aktywnym młodym
    sędzią na boisku (numer `base_judge_id` albo nazwisko), najpierw taki, w którego
    obsadzie stoi sam sędzia trybu (aplikacja pokazuje do oceny mecze z pliku meczów
    telefonu). Sędzia z listy młodych - 409 („młody sędzia nie wystawia ocen", co zrobić).
    Odpowiedź: mecz, `young_referee {id,name,slot}`, `rater.in_crew`, `missing` (czego
    brakuje, gdy sędziego nie ma w obsadzie), `save` (podpowiedź do zapisu oceny).
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
   * udawany numer w ścieżce (`>= 900000000`, oceny młodych: GET/PUT/DELETE
     `/young_referees/ratings/{id}`) - wystarcza sam: takiego wiersza nie ma w bazie, a
     aplikacja czyta i usuwa ocenę gołym `fetch`, bez tokenu;
   * BEZ tokenu (trasy /zprp/*, niedyspozycje ZPRP, ogłoszenia multipart, a z odczytów
     `/zprp/obsada/match-form`) - treść żądania:
     RSA `username` / `judge_id` (także z base64 w środku, jak w `silesia`), jawne `user`
     i `judge_id`. Treść czytamy tylko przy włączonym trybie i tylko dla tras z listy;
     aplikacja dostaje ją potem nietkniętą. Gdy token jest, rozstrzyga sam (numer w treści
     bywa numerem sędziego, któremu ktoś INNY coś zapisuje).
4. Konto trybu + trasa zapisu -> handler NIE jest wołany. Wpis do `presentation_ops`
   (bez haseł - pola `password`, `username` i podobne jako `***`), udawana odpowiedź
   w kształcie z handlera. Gdy symulator się wywróci, wraca zwykłe „ok" - zapis i tak nie
   przechodzi.
5. Konto trybu + odczyt z nakładką -> prawdziwa odpowiedź z doklejonymi udawanymi zmianami.
   Odpowiedź spakowana gzipem (bootstrap Obsady) jest rozpakowywana; trasy z ETagiem
   (bootstrap, Obsada na żywo) idą do handlera bez `If-None-Match`, żeby 304 nie schował
   nakładki.

Nakładka (`presentation_overlay`) jest wspólna dla wszystkich kont trybu (sędzia oddaje,
konto okręgu widzi w panelu) i niewidoczna dla nikogo innego.

## Co jest udawane i co widać potem w odczytach

| Obszar | Udawane zapisy | Doklejane do odczytów (tylko konta trybu) |
|---|---|---|
| giełda | POST /match-market/offers (201 `{id,status}`), DELETE /offers/{id}, listing-approval approve/reject, POST /offers/{id}/claims (201), DELETE /claims/me, reject, **approve (`{id,status:"done",applied:true,from,to}` - bez ZPRP; oddający wychodzi z gniazda w nakładce obsady, biorący wchodzi)**, admin: notification-preferences, provinces/{p} PUT, offers/{id}/withdraw, notification-test/send (podgląd zamiast wysyłki) | GET /offers (market/mine/history), GET /offers/{id} (udawana oferta w całości), GET i POST /my-matches, /my-matches/recheck (gniazdo „już wisi"; **nakładka obsady: mecz, w którym sędzia trybu stanął, przychodzi - z `canOffer` jak w handlerze; mecz, z którego zszedł, znika**; recheck tylko poprawia/zdejmuje) |
| giełda obsadowego | POST /crew-offers (201, pełny widok), claims (201), claims/me, assign (+ wpis do udawanego szkicu kolejki Obsady), unassign, DELETE, invite (bez pusha) | GET /crew-offers, GET /crew-offers/{id} (widok z `_offer_view` i `_claims_view`) |
| obsada | /zprp/obsada/save (`verified_slots` = wysłana zmiana, reszta z `expect`; **+ nakładka obsady**), save-hall, save-date, table-officials/save, /clear (**+ nakładka obsady**); PUT /province/assignment/draft (`{rev}`), mentor-pairs, judges/{id}, blocks, pauses, pairs, manual, clubs; Automat POST /province/assignment (**liczy naprawdę, bez zapisu przebiegu** - `DRY_RUN`); runs/{id}/applied, /undone; /assignment-drafts; PUT /province/me/availability | GET /province/assignment/draft, GET /bootstrap (pole `draft` i obsada meczów, bez 304, także z gzipem); **nakładka obsady**: GET /province/assignments i /province/assignments/{match_id} (`crew` + przeliczony `status`), GET /province/obsada-view/data (`crew`, `needs`, nowy `rev`, bez 304) i /changes (udawana zmiana na górze), POST /zprp/obsada/match-form (wybrana opcja gniazda po nazwisku; konto z RSA w treści) |
| oceny młodych | POST /young_referees/ratings (201, `YoungRefereeRatingItem`, numer udawany; 403 dla młodego oceniającego i 400 jak w handlerze - tylko odczyty), PUT /ratings/{id}, DELETE /ratings/{id} (prawdziwa ocena: łatka „usunięta" w nakładce) | GET /young_referees/ratings (te same filtry: province, young_referee_id - 1. lub 2. sędzia, mentor_name, date_from/to; ta sama kolejność), GET /ratings/{id}. Średnie i statystyki młodego aplikacja liczy z tej listy (`rating.avg_score`) |
| rozliczenia | PUT/PATCH /province-travel/{id}, settlements: modules, accounting/codes, exclusions, homes (+batch, DELETE), periods, register (DELETE, settings, doc-settings, doc-extra), splits (PUT/DELETE); PDF zestawienie/przejazdy idzie jako **szkic** (bez numeru w rejestrze); invoices: upload, approve, reopen, confirm, unconfirm, trash, restore, purge; bomby: POST, DELETE, void, manual, penalty, penalty-scale | - |
| niedyspozycje | /judge/offtimes/create, update, delete (ZPRP), /silesia/offtimes/set, DELETE /silesia/offtimes/{enc} (204), /silesia/offtimes/assigned (POST/PATCH/DELETE), /partner-offtimes (POST/PUT/DELETE), PUT /admin/zprp-unavailability/config | - (zapisane w nakładce `offtime`, lista z ZPRP pokazuje stan prawdziwy) |
| ogłoszenia | create (201, `AnnouncementResponse`), PUT, reaction, comment, comment_pin, comment_delete, DELETE (204) - bez pliku obrazka i bez pusha | GET /silesia/announcements/ (nowe, zmienione, usunięte) |
| wydarzenia i formularze | /province-events: v2 create/patch, cancel, uncancel, trash, restore, templates, rsvp, attendance/v2, checkin/open, checkin, title-image, stare `/`, PATCH, DELETE; /district-forms: tworzenie, zmiany, publish/close/reopen/archive/…, odpowiedzi `me`, wiersze, pliki | GET /province-events/feed i /item/{id} (moja odpowiedź RSVP i liczniki) |

Pełna lista z wzorcami ścieżek: `WRITE_ROUTES` i `READ_ROUTES` w `app/presentation_routes.py`.

### Nakładka obsady (`app/presentation_lineup.py`)

Wiersz `presentation_overlay` rodzaju `lineup`, klucz = numer meczu, `slots` w słowniku
modułu (`pierwszy`, `drugi`, `sekretarz`, `czas`, `delegat`, `delegat2`) jako
`{number, name}`; puste oba = gniazdo zwolnione. Nazwisko w postaci ZPRP („NAZWISKO
Imię"). Piszą: `/zprp/obsada/save` (numer z `assigned`, bo wartość opcji formularza nie
jest numerem sędziego; nazwisko z `NrSedzia_*_name`), stolikowy z aplikacji i
zatwierdzona wymiana na giełdzie. Ścieżka „przydział z giełdy obsadowego -> kolejka ->
Wyślij do ZPRP" przechodzi przez `/zprp/obsada/save`, więc też ląduje w nakładce.
Odczyty podmieniają gniazda w kształcie każdej odpowiedzi (migawka `NrSedzia_*`, `crew`
listy, `crew` Obsady na żywo, `slots` formularza ZPRP). Kopie z pamięci serwera
(bootstrap, Obsada na żywo) są nietknięte - łatamy gotową odpowiedź.

### Czego nakładka NIE dokleja (znane ograniczenia)

* Liczniki `GET /match-market/context` i zakładek - bez zmian.
* Lista meczów sędziego w aplikacji (zakładka „Mecze", ekran meczu) pochodzi WPROST
  z baza.zprp.pl / rozgrywki.zprp.pl (telefon, nie serwer) - nakładka jej nie dotyka.
  Serwerowa „moja lista" to `/match-market/my-matches` (arkusz „Oddaj mecz") - ta tak.
* Obsada po udawanym zapisie NIE wchodzi do: dziennika zapisów Obsady
  (`/province/assignment/zprp-history`), kandydatów i Automatu, `.ics` sędziego,
  `/silesia/matches/self/*` (Calendar Master), skanów ZPRP panelu
  (`/zprp/sedziowie/mecze/scrape_*`, `/zprp/terminarz/scrape*` - idą do ZPRP na żywo),
  filtrów listy (`q`, `only_gaps` liczone na stanie prawdziwym) i liczników `totals`.
* Oceny młodych: aplikacja czyta listę ocen (`GET /young_referees/ratings`) gołym
  `fetch`, BEZ tokenu - takiego odczytu nie da się przypisać kontu trybu, więc wraca stan
  prawdziwy (ekran ocen czyści wtedy lokalny wpis z udawanym numerem). Odczyt i zmiana
  oceny po udawanym numerze działają bez tokenu. Usunięcie PRAWDZIWEJ oceny bez tokenu
  idzie do handlera naprawdę - aplikacja musi wysłać token (patrz niżej).
* Niedyspozycje: listy czytane z ZPRP i z okręgu nie pokazują udawanych wpisów.
* Nowe wydarzenia i formularze nie pojawiają się w listach (odpowiedź zapisu jest udawana);
  RSVP - tak.
* Rozliczenia, faktury, bomby - odpowiedzi „ok" (z echem wysłanych pól); listy bez zmian.
  Wczytanie faktur (`/province/invoices/upload`) w trybie nic nie odczytuje.
* `POST /province-events/checkin` oddaje `{"already": false, "event": null}`.
* Trasy bez tokenu i bez danych logowania w treści (anonimowe zapisy okresu przejściowego)
  nie dają się przypisać kontu - idą do aplikacji jak dotąd. Dotyczy ocen młodych:
  `DELETE /young_referees/ratings/{prawdziwy id}` i odczyty listy w aplikacji
  (`YoungRefereeMatchRatingsModal.loadServerRatings`, `LoginForm`, `utils/zprp.ts`,
  `RefereeProfileSheet`, `more.tsx`) - do nagrania aplikacja powinna dołączać token BAZA
  (jak `adminWriteFetch`).

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
