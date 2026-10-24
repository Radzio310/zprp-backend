# Tabela ligi po wyniku skróconym

Kod: `app/standings_provisional.py` (czyste reguły), `app/standings_refresh.py` (baza, ZPRP, harmonogram),
tabela `zprp_public_provisional_results` (nowa, tworzy ją `create_all`, bez migracji).

## Kontrakt

- `POST /proel/zprp/summary` (z `id_zawody`) - po sukcesie dodaje do odpowiedzi
  `standings: {provisional, competition_id, refresh_after_seconds:[60,300,900]}` albo
  `{provisional:false, reason, refresh:true}` (brak wyniku w żądaniu: pole pominięte).
- `GET /api/v1/handball/competitions/{id}/standings` - dodatkowo `provisional` (bool),
  `fetched_at` (najnowsze pobranie z ZPRP); wiersze z nałożonym wynikiem mają `provisional: true`,
  a `position` jest wspólne przy nierozstrzygniętym remisie (9, 9, 11).
- `POST /api/v1/handball/competitions/{id}/refresh` - bez ciała. Odpowiedź:
  `{competition_id, refreshed, throttled, error, fetched_at, provisional}`.
  Jedno pobranie z ZPRP na ligę na 2 min; równoległe wywołania czekają na to samo,
  późniejsze w oknie dostają stan z bazy (`throttled: true`). Nigdy nie zwraca błędu HTTP z powodu ZPRP.
- `GET /teams/{id}/season-chart` - `provisional` (bool); ostatni punkt `rounds[-1].provisional`.
- `overview` (`standings[]`) niesie ten sam `provisional` i miejsce wstępne.

## Reguły

- Wstępnie = oficjalne wiersze + jeden wpisany wynik (3/2/1/0 lub 2/1/0 wnioskowane z tabeli),
  kolejność: punkty, mecze bezpośrednie remisujących, bilans, bramki, inaczej wspólne miejsce.
- Nakładka obowiązuje, dopóki wiersze obu drużyn w oficjalnej tabeli są takie jak w chwili wpisu
  (podpis: mecze, punkty, bramki); zmiana = ZPRP przeliczyło, nakładka wyłączona. TTL 48 h.
- Po wpisie: pobrania oficjalne po 1, 5, 15 min (kończą się wcześniej, gdy ZPRP przeliczyło).
- Auto (pętla `run_zprp_public_scheduler`): liga z meczem dzisiaj, od startu + 90 min do 8 h,
  co 15 min; katalog (wszystkie tabele) raz na dobę w nocy 2-5 (po 30 h bez sukcesu o każdej porze).
