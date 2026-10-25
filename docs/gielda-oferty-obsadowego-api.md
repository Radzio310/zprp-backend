# Giełda: oferty obsadowego - kontrakt API

Stan: 25.10.2026. Kod: `app/match_market_crew.py` (trasy), `app/match_market_crew_rules.py`
(reguły), `app/match_market_crew_tables.py` (tabele). Decyzje: pamięć `gielda-oferty-obsadowego`.

Prefiks: `/match-market/crew-offers`. Autoryzacja: ten sam JWT co reszta giełdy
(`Authorization: Bearer ...`), okręg z `province_judges`, nie z tokenu.
Wszystkie trasy wymagają włączonej giełdy okręgu (`market_enabled`, 403 z wyjaśnieniem).

Oferta obsadowego to OSOBNY typ od oddania meczu przez sędziego (`/match-market/offers`):
własne tabele, własne id, `type: "crew"`. Aplikacja scala obie listy i wyróżnia
`isNew: true` / `highlight: "new_match"` jako "NOWY mecz do wzięcia".

## Pojęcia

- Gniazda (język modułu Obsady): `pierwszy`, `drugi` (boisko), `sekretarz`, `czas` (stolik). Delegaci poza giełdą.
- Rola zgłoszenia: `table` albo `field`. Wybór roli jest wymagany tylko, gdy oferta ma OBA rodzaje (`needsRoleChoice`).
- Uprawnienie wystawiania/przydzielania: jak rozstrzyganie wymian (odznaki `approver_badges` okręgu, domyślnie "Obsadowy", oraz admin). Pole `canManage`.
- Filtr odznak: `{"mode": "none"|"include"|"exclude", "badges": ["..."]}`. `include` = widzą tylko mający którąś z odznak, `exclude` = nie widzą mający którąś. Obsadowy (`canManage`) widzi wszystko.
- Stany oferty `status`: `open`, `filled`, `expired`, `withdrawn`. Stan zgłoszenia: `pending`, `assigned`, `declined` (niewybrany po obsadzeniu), `withdrawn`.
- Błędy: koperta backendu (`{"error": ...}` albo `detail`) - klient czyta oba kształty (`serverMessage()`). KAŻDA odmowa niesie zdanie po polsku.

## 1. Podpowiedź przed wystawieniem

`GET /suggest?matchId=<id>[&province=]` (obsadowy)

```json
{
  "matchId": "123456", "match": {"matchCode": "LCM1/1", "hostTeam": "...", "matchAt": "...", "hall": "...", "crew": {}},
  "slots": ["sekretarz", "czas"],
  "skipped": [{"slot": "pierwszy", "reason": "Okręg nie obsadza tego gniazda w tym meczu."}],
  "editableSlots": ["pierwszy","drugi","sekretarz","czas"],
  "needs": {"field": 0, "table": 2, "club_table": 0},
  "roles": ["table"],
  "defaultDeadlineAt": "2026-11-06T17:00:00+00:00", "matchAt": "...",
  "canCreate": true, "problem": null, "existingOfferId": null
}
```
`slots` = wolne gniazda, które okręg obsadza (DRK: tylko stolik; deklaracja "4. sędzia przez klub" uwzględniona).
`canCreate: false` + `problem` = czemu nie (mecz nieobsadzany przez okręg / rozpoczęty / brak wolnych gniazd / jest już oferta).
`defaultDeadlineAt` = null, gdy do meczu jest mniej niż 24 h (wtedy podaj termin jawnie).

## 2. Wystawienie

`POST /` -> 201, ciało = pełny widok oferty (patrz niżej).
```json
{"matchId": "123456", "slots": ["sekretarz","czas"], "comment": "Mecz w sobotę, hala Szopienice",
 "badgeFilter": {"mode": "include", "badges": ["Stolikowi"]}, "deadlineAt": "2026-11-06T18:00:00+01:00"}
```
Pominięte `slots` = podpowiedź; pominięty `deadlineAt` = 24 h przed meczem; pominięty filtr = dla wszystkich.
Błędy: 403 (okręg nie obsadza meczu / brak uprawnienia), 404 (mecz), 409 (mecz ma już otwartą ofertę: "nr N"),
422 (gniazdo zajęte albo spoza prawa okręgu, filtr bez odznak, termin w przeszłości lub po meczu, mecz rozpoczęty).
Po wystawieniu leci push (tło) do WSZYSTKICH uprawnionych sędziów okręgu: filtr odznak + rola pasująca do slotów
(reguły ról Obsady: delegat nie na boisko, "tylko stolik" nie na boisko), bez wystawiającego i bez tych, którzy
już są w obsadzie meczu. Bez względu na dostępność/niedyspozycje. Respektuje wyłącznik "nowe oferty" w ustawieniach push.

## 3. Lista i szczegół

`GET /?scope=open|all[&province=]` -> `{"offers": [OfferView], "canManage": bool}`.
Sędzia widzi tylko oferty spełniające jego filtr i rolę oraz przyjmujące zgłoszenia (lub te, na które się zgłosił);
`scope=all` dodaje zamknięte z 30 dni. Obsadowy widzi wszystkie. Wygaszanie jest leniwe (przy odczycie).
`GET /{id}` -> OfferView; dla obsadowego z polem `claims` (sekcja 5). Sędzia spoza filtra dostaje 403 z wyjaśnieniem
(np. "Ta oferta jest ograniczona odznakami... Oferta jest dla sędziów z odznaką: X.").

OfferView:
```json
{
  "id": 7, "type": "crew", "isNew": true, "highlight": "new_match",
  "province": "SLASKIE", "matchId": "123456", "matchCode": "S/JmM/12",
  "match": {"matchCode": "...", "hostTeam": "...", "guestTeam": "...", "matchAt": "...", "hall": "...", "season": "...", "crew": {}},
  "slots": [{"slot": "sekretarz", "label": "sekretarz", "role": "table", "assignedTo": null, "claimId": null}],
  "roles": ["table"], "needsRoleChoice": false,
  "comment": "...", "badgeFilter": {"mode": "none", "badges": []},
  "deadlineAt": "...", "acceptingClaims": true, "status": "open", "closedReason": null,
  "createdBy": {"id": "5512", "name": "...", "photoUrl": null}, "createdAt": "...",
  "claimCount": 3, "myRoles": ["table"], "canManage": false,
  "myClaim": {"id": 4, "role": "field", "partner": {"id":"..","name":".."}, "packageComplete": true, "status": "pending", "slot": null, "note": null}
}
```
`myRoles` = role z oferty, na które reguły obsady pozwalają temu sędziemu. `isNew` = otwarta i przyjmuje zgłoszenia.
`closedReason`: `filled` | `expired` | `withdrawn`. Po terminie oferta ze zgłoszeniami zostaje `open` do decyzji
obsadowego (`acceptingClaims: false`); bez zgłoszeń wygasa. Początek meczu gasi zawsze.

## 4. Zgłoszenia sędziego

`POST /{id}/claims` -> 201 + OfferView (+ `claimId`).
```json
{"role": "field", "partnerId": "6021", "note": "mogę być od 14:00"}
```
`role` wymagana tylko przy ofercie z oboma rodzajami. `partnerId` tylko dla `field`, gdy oferta ma >= 2 gniazda boiskowe;
partner z tego samego okręgu, spełniający filtr i mogący stać na boisku. Pakiet (`packageComplete: true`,
w widoku obsadowego `packages`) powstaje, gdy OBOJE zgłoszeni wskazali siebie nawzajem.
Błędy: 403 (zamknięta / termin minął / mecz rozpoczęty / filtr odznak / już w obsadzie meczu / rola zabroniona),
409 (już zgłoszony), 422 (rola, partner), 404.
`DELETE /{id}/claims/me` -> OfferView. 409, gdy już przydzielony ("skontaktuj się z obsadowym"). Po wycofaniu można zgłosić się ponownie.

## 5. Zgłoszenia dla obsadowego

W `GET /{id}` (gdy `canManage`) pole `claims`:
```json
{"table": [Claim], "field": [Claim], "packages": [{"judges": [Person, Person], "claimIds": [4, 5]}]}
```
Claim:
```json
{"claimId": 4, "judge": {"id":"..","name":"..","photoUrl":null,"city":"Zabrze"}, "role": "field", "status": "pending",
 "slot": null, "note": "...", "createdAt": "...",
 "partner": {"id":"..","name":"..","photoUrl":null,"confirmed": true},
 "km": {"km": 42.0, "source": "district_table", "from": "Zabrze", "to": "Gliwice"},
 "season": {"field": 12, "table": 3, "total": 15}, "weekMatches": 2,
 "nearest": {"match_id":"..","code":"..","at":"..","gap_minutes": 190, "city":".."},
 "gap": {"level": "orange", "shortfall_minutes": 25, "overlap": false},
 "collisions": [{"match_id":"..","code":"..","at":"..","level":"red","shortfall_minutes":40,"overlap":true}],
 "unavailable": "Praca, 12:00-18:00"}
```
- `km.source`: `same_city` | `district_table` (tabela okręgu wg DATY meczu) | `national_table` (ZPRP) | `google` (pamięć/dopytanie) | `unknown` (km = null, nie zero).
  Miasto sędziego uwzględnia tymczasowe zmiany miasta w dniu meczu.
- `season` = mecze w bieżącym sezonie (boisko/stolik, rejestr + terminarz). `weekMatches` = inne mecze sędziego w tygodniu (pn-nd) meczu.
- `gap.level` (`yellow`/`orange`/`red`) liczy się jak ręczna obsada (pamięć obsada-odstep-ostrzezenie): ostrzeżenie, NIGDY blokada;
  `collisions` = wszystkie mecze w oknie 36 h z ocenionym odstępem. `unavailable` = niedyspozycja kolidująca z terminem (tekst) albo null.

## 6. Przydział i cofnięcie (obsadowy)

`POST /{id}/assign`
```json
{"claimId": 4, "slot": "sekretarz", "withPartner": false}
```
`slot` opcjonalny (domyślnie pierwsze wolne gniazdo tej roli); `withPartner: true` przydziela też partnera z potwierdzonego pakietu na drugie gniazdo boiskowe.
Efekt: wpis do WSPÓLNEJ kolejki Obsady (`PUT /province/assignment/draft`, ten sam mechanizm co ręczny wpis) ze zmianą
`{"id": "market-<claimId>", "kind": "slot", "slot": ..., "judge_id": ..., "name": ..., "source": "market", "offer_id": ..., "match_label": ...}`
oraz push "Przydzielono Cię". **Do ZPRP nic nie jedzie** - robi to istniejące "Zapisz" w Obsadzie. Klienci Obsady powinni znać
`source: "market"` (plakietka "z giełdy"; pole `offer_id` dodatkowo).
Gdy wszystkie gniazda oferty są przydzielone: oferta -> `filled`, niewybrani -> `declined` + push "Mecz obsadzony".
Błędy 409 z wyjaśnieniem: oferta zamknięta, zgłoszenie nie czeka na decyzję, gniazdo zajęte / innej roli, gniazdo już obsadzone
w terminarzu, w kolejce czeka inna zmiana tego gniazda, brak potwierdzonej pary, kolejka zmieniana przez innych (ponów).

`POST /{id}/claims/{claimId}/unassign` -> OfferView + `unassign: {removedFromQueue, queuedRemovalFromCrew, note}`.
Zgłoszenie wraca do `pending`; filled -> open (niewybrani wracają do `pending`), o ile mecz się nie zaczął; push "Cofnięto przydział".
Wpis jeszcze w kolejce znika; wpis już zapisany w ZPRP = do kolejki trafia zdjęcie z gniazda (`queuedRemovalFromCrew: true`).

## 7. Wycofanie oferty

`DELETE /{id}` (obsadowy) -> OfferView (`status: withdrawn`). Oczekujący zgłoszeni dostają push "Oferta wycofana".
Przydziały już wpisane do kolejki Obsady zostają (cofa się je osobno przez `unassign`).

## Push (deep-link)

`data`: `{"kind": "match_market_crew", "crewOfferId": "<id>", "province", "matchId", "matchNumber", "notificationThread": "match-market-crew-<id>"}`.
Aplikacja musi dodać gałąź `match_market_crew` w `normalizeNotificationTap` / `resolveNotificationTarget`
(otwiera ofertę `GET /match-market/crew-offers/{id}`). Teksty: "Nowy mecz do wzięcia", "Przydzielono Cię",
"Cofnięto przydział", "Mecz obsadzony", "Oferta wycofana".

## Uwagi dla klientów

- Kolumny JSON w tabelach ofert to Text (napis JSON) - serwer parsuje na każdej granicy odczytu; klient dostaje czysty JSON.
- Nowe tabele powstają przez `create_all` (bez migracji).
- Brak zadania w tle do wygaszania: stan liczy się przy odczycie listy/szczegółu/zgłoszenia.
