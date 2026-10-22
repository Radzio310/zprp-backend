# Transmisje meczów (BAZA pod Ręką) — kontrakt

Lekkie automatyczne wykrywanie transmisji (oficjalnych i prawdopodobnych) dla
publicznego portalu. Backend: `app/streams/` (reguły `rules.py`, parsery
`parsers.py`, sieć `net.py`, baza `store.py`, pętla `worker.py`, trasy
`routes.py`, znane kanały `seeds.py`), tabele w `app/stream_tables.py`
(`stream_channels`, `match_streams`, `stream_quota`). Wszystko **addytywne**.

Prefiks publiczny: `/api/v1/handball` (bez logowania, cache w pamięci 60 s,
`/streams/now` 30 s; pętla czyści cache po każdej zmianie).

## Typy

```jsonc
// Stream — konkretna transmisja/nagranie konkretnego meczu
{
  "id": 17,
  "match_id": "12345",
  "platform": "youtube",            // youtube | facebook | other
  "url": "https://www.youtube.com/watch?v=abcdEFGhijk",
  "embed_url": "https://www.youtube-nocookie.com/embed/abcdEFGhijk",  // null gdy nie-YouTube
  "video_id": "abcdEFGhijk",        // null gdy nie-YouTube
  "title": "Wybrzeże Gdańsk - Pogoń Szczecin | Liga Centralna",       // może być null
  "thumbnail_url": "https://i.ytimg.com/vi/abcdEFGhijk/hqdefault.jpg", // może być null
  "channel": {"title": "Handball Polska", "url": "https://www.youtube.com/@HandballPolska", "kind": "official", "verified": true},
                                    // null, gdy nieznany (np. link ZPRP); kind null dla kanału spoza tabeli
  "state": "live",                  // live | upcoming | vod | link
  "starts_at": "2026-10-22T18:00:00", // czas warszawski, naiwny (jak scheduled_at meczu); może być null
  "duration_s": 5400,               // tylko vod, inaczej null
  "confidence": "official"          // official | confirmed | possible ("possible" pokazywać przygaszone)
}

// Link — kafelek „Gdzie oglądać” (TV/płatne/kanał/Facebook), bez wykrywania live
{
  "platform": "polsat_box_go",      // polsat_sport | polsat_box_go | emocje_tv | youtube | facebook
  "title": "Polsat Box Go",
  "url": "https://polsatboxgo.pl/",
  "kind": "paid",                   // tv | paid | channel | facebook
  "note": "Transmisje Polsatu Sport online"  // może być null
}

// Channel — kanał przypisany do klubu
{
  "id": 3, "platform": "youtube",   // youtube | facebook
  "title": "Wybrzeże Gdańsk TV",
  "url": "https://www.youtube.com/@WybrzezeGdanskTV", "handle": "@WybrzezeGdanskTV",
  "kind": "club",                   // official | club | producer | broadcaster | tv
  "verified": false                 // false = wykryty automatycznie ze strony klubu
}

// StreamWithMatchCard = Stream + "match": <karta meczu jak w /competitions/{id}/schedule>
```

## Trasy publiczne

| Metoda i ścieżka | Odpowiedź |
|---|---|
| `GET /matches/{id}/streams` | `{streams: Stream[], where_to_watch: Link[], updated_at}` — 404 gdy brak meczu |
| `GET /streams/now` | `{live: StreamWithMatchCard[], soon: StreamWithMatchCard[] (upcoming, start w ciągu 3 h), today_tv: {match: Card, links: Link[]}[] (dzisiejsze mecze Superligi), updated_at}` |
| `GET /competitions/{id}/streams` | `{where_to_watch: Link[], recent: StreamWithMatchCard[] (≤12, vod, od najnowszych), upcoming: StreamWithMatchCard[] (≤12, live potem upcoming)}` — 404 gdy brak rozgrywek |
| `GET /clubs/{id}/streams` | `{channels: Channel[], recent: StreamWithMatchCard[] (≤8, od najnowszych)}` — 404 gdy brak klubu |

* Kolejność `streams`: `live` → `upcoming` → `vod` → `link`; w obrębie stanu
  `official` → `confirmed` → `possible`. Ukryte (`hidden`) nigdy nie wychodzą.
* `where_to_watch`: Superliga → Polsat Sport (tv), Polsat Box Go (paid),
  Emocje.TV (channel); Liga Centralna → kanał Handball Polska; I liga →
  playlista Czarny Piotruś MEDIA; potem kanały obu klubów (YouTube, na końcu Facebook).
* `updated_at` = ISO (UTC) ostatniego zapisu/potwierdzenia transmisji; null, gdy brak.

## Admin (`admin_write_guard`, jak inne trasy admina)

| Metoda i ścieżka | Ciało / odpowiedź |
|---|---|
| `GET /api/v1/handball/admin/streams/channels` | `{channels: ChannelAdmin[], quota: {day, units_used, search_calls, searches, searches_left, units_left}}` |
| `POST /api/v1/handball/admin/streams/channels` | `{url?, channel_id?, handle?, playlist_id?, title?, club_id?, association_id?, kind?, scope?: string[], verified?: bool, active?: bool}` → ChannelAdmin. Upsert po tożsamości kanału (UC…, @uchwyt, playlista, adres Facebooka); podane pola nadpisują. 422 gdy adres nie jest kanałem YouTube/Facebook. |
| `PATCH /api/v1/handball/admin/streams/{id}` | `{hidden?: bool, confidence?: "official"\|"confirmed"\|"possible"}` → Stream + `hidden`. Pewność od admina jest zamrożona (pętla jej nie zmienia), ukryty wpis nie wraca. |

`ChannelAdmin` = Channel + `channel_id, playlist_id, club_id, association_id,
scope, active, discovered_from (seed|club_website|admin), last_checked_at,
next_check_at, error`. Poziomy w `scope`: `OS` (Superliga), `LC`, `I`, `II`,
`MP-J` (MP młodzieży), `PP`.

## Mentor

Pokój meczu panelu mentorskiego (`GET /mentor-panel/pairs/{pair}/matches/{id}`)
ma pole `suggested_streams: Stream[]` — tylko YouTube, `official`/`confirmed`,
bez filmów już dodanych do pokoju. Szczegóły: `docs/mentor-panel.md` 4.13.

## Źródła, pewność i harmonogram

* ZPRP `stream_url` meczu → `official` (`link`, gdy nie YouTube).
* Kanały YouTube z tabeli: RSS kanału/playlisty (bez klucza), stan
  live/upcoming/vod z `videos.list` (z kluczem). Kanał klubu w oknie meczu:
  dodatkowo strona `/channel/UC…/live` (bez klucza).
* Kanały klubów wykrywane w tle ze stron WWW klubów (`zprp_public_clubs.website`):
  link do YouTube (@uchwyt / kanał) i Facebooka; stopki ze związkiem/TV pomijane.
* Strona z listą transmisji (`STREAMS_HINT_URL`) to wyłącznie podpowiedź:
  każdy film sprawdza API, a jej nazwa nigdzie nie wychodzi.
* Wyszukiwanie YouTube (`search.list`, 100 j.) — tylko dzisiejsze mecze
  Superligi, LC, I ligi, MP młodzieży bez znalezionej transmisji, od 30 min
  przed do 100 min po rozpoczęciu, ≤ 80 na dobę, z rezerwą jednostek na odświeżanie stanu.
* Pewność: obie drużyny w tytule + zgodny czas. Kanał oficjalny
  zweryfikowany → `official`; kanał klubu grającego → `official`
  (zweryfikowany) / `confirmed` (wykryty); inny znany kanał → `confirmed`;
  kanał nieznany → `confirmed` przy pewnym czasie transmisji, inaczej
  `possible`; jedna drużyna dopasowana tylko częściowo → `possible`. Słabsze
  nie są zapisywane. Odrzucane: wywiady, skróty, zapowiedzi, inna kategoria
  (junior/kobiety), data w tytule z innego dnia, VOD < 20 min.
* Harmonogram kanału: od 60 min przed meczem co 5 min, w trakcie co 3 min,
  do 24 h po meczu co godzinę, inne kanały raz na dobę.

Zmienne środowiskowe: `YOUTUBE_API_KEY` (opcjonalna; bez niej RSS, strony
kanałów i linki działają, nie ma stanu z API, podpowiedzi ani wyszukiwania),
`STREAMS_DISABLED=1` (wyłącza pętlę), `STREAMS_YT_DAILY_UNITS` (9500),
`STREAMS_YT_SEARCHES_PER_DAY` (80), `STREAMS_YT_RESERVE_UNITS` (1500),
`STREAMS_HINT_URL`, `STREAMS_START_DELAY_SECONDS` (45).
