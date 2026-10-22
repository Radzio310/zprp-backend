"""Znane kanały i kafelki „Gdzie oglądać” - stałe, bez sieci i bazy.

STAN WIEDZY (22.10.2026, sandbox bez dostępu do YouTube - nic tu nie było
sprawdzone na żywo):

* Handball Polska - oficjalny kanał ZPRP; od sezonu 2026/27 wszystkie mecze
  Ligi Centralnej K/M (produkcja RCS Livestream). Uchwyt `@HandballPolska`
  jest ZAŁOŻENIEM - identyfikator `UC...` ustala pętla w tle
  (`channels?forHandle=` z kluczem API albo strona kanału bez klucza).
  Gdy uchwyt okaże się inny, admin poprawia go `POST /admin/streams/channels`.
* Czarny Piotruś MEDIA - playlista I ligi (adres od właściciela, pewny).
  Kanał (`UC...`) poznajemy z kanału RSS playlisty.
* Polsat Sport / Polsat Box Go / Emocje.TV - tylko kafelki z linkiem (bez
  sprawdzania ramówek): Superliga w TV i online tam, gdzie Polsat nie pokazuje.
"""

from __future__ import annotations

from typing import Any

HANDBALL_POLSKA_KEY = "youtube:@handballpolska"
CZARNY_PIOTRUS_PLAYLIST = "PL3NkJuwI5L5d7vPRyvudHKhgP8Q1AMGeP"
CZARNY_PIOTRUS_KEY = f"youtube-playlist:{CZARNY_PIOTRUS_PLAYLIST}"

#: Kanały zasiewane przy starcie pętli (upsert po `key`, bez nadpisywania zmian admina).
SEED_CHANNELS: tuple[dict[str, Any], ...] = (
    {
        "key": HANDBALL_POLSKA_KEY,
        "platform": "youtube",
        "handle": "@HandballPolska",
        "title": "Handball Polska",
        "url": "https://www.youtube.com/@HandballPolska",
        "kind": "official",
        "verified": True,
        "scope": ["LC", "MP-J", "PP"],
    },
    {
        "key": CZARNY_PIOTRUS_KEY,
        "platform": "youtube",
        "playlist_id": CZARNY_PIOTRUS_PLAYLIST,
        "title": "Czarny Piotruś MEDIA",
        "url": f"https://www.youtube.com/playlist?list={CZARNY_PIOTRUS_PLAYLIST}",
        "kind": "producer",
        "verified": True,
        "scope": ["I"],
    },
)

#: Kafelki TV/płatne dla poziomu rozgrywek (Superliga = OS).
TV_LINKS: dict[str, tuple[dict[str, Any], ...]] = {
    "OS": (
        {"platform": "polsat_sport", "title": "Polsat Sport", "url": "https://www.polsatsport.pl/",
         "kind": "tv", "note": "Wybrane mecze ORLEN Superligi w telewizji"},
        {"platform": "polsat_box_go", "title": "Polsat Box Go", "url": "https://polsatboxgo.pl/",
         "kind": "paid", "note": "Transmisje Polsatu Sport online"},
        {"platform": "emocje_tv", "title": "Emocje.TV", "url": "https://emocje.tv/",
         "kind": "channel", "note": "Mecze ORLEN Superligi, których nie pokazuje Polsat"},
    ),
}

#: Który zasiany kanał jest kafelkiem „Gdzie oglądać” dla poziomu rozgrywek.
TIER_CHANNEL: dict[str, str] = {"LC": HANDBALL_POLSKA_KEY, "I": CZARNY_PIOTRUS_KEY}

#: Uchwyty/kanały, których NIE przypisujemy klubowi, choć bywają w stopce jego strony.
NOT_CLUB_HANDLES = frozenset({
    "handballpolska", "zprp", "zprppl", "zprp_pl", "ehf", "ehftv", "ehfel", "ehfcl", "ihf", "ihfhandball",
    "polsatsport", "polsatboxgo", "emocjetv", "youtube", "orlensuperliga", "superligapl", "superliga",
    "orlen", "pkoorlen", "ligacentralna", "rcslivestream",
})
NOT_CLUB_FACEBOOK = frozenset({
    "zprp", "zprppl", "zwiazekpilkirecznejwpolsce", "handballpolska", "orlensuperliga", "superligapl",
    "polsatsport", "ehf", "ehfeuro", "ihf", "facebook", "pages", "sharer", "share", "dialog", "plugins", "tr",
    "login", "home.php", "groups", "events", "watch", "photo", "photo.php", "help", "policies", "privacy",
})
