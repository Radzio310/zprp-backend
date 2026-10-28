"""Mentor x Handball Bastion - „Szukaj w Bastionie” (Archiwista) i „Wczytaj nagrania sezonu” (28.10.2026).

Kontrakt: `docs/mentor-panel.md` 8.10. Zasady:
  - Meczotekę czytamy WYŁĄCZNIE sesją connectora (`GET /games/search`), bez obchodzenia zabezpieczeń portalu.
    Połączenie wybiera prawdziwy użytkownik jak przy `playback`: domyślne, potem jego własne.
  - Pewność liczy SERWER (kod meczu, drużyny po normalizacji, data dnia w Warszawie). Pewne trafienie
    (`sure`) to tylko podpowiedź do zaznaczenia - niczego nie dodajemy sami; zapis to zwykłe `POST .../videos`.
  - Błędy Bastionu nigdy nie są 401: 409 / 403 / 503 / 429 z kopertą jak `playback`. W „nagraniach sezonu”
    awaria Bastionu nie zabiera YouTube: odpowiedź ma blok `bastion: {state, message}` i lista idzie dalej.
  - YouTube w „nagraniach sezonu” to wyłącznie transmisje, które pętla portalu już przypisała do meczów
    (`match_streams`, zero jednostek z dobowej puli); wyszukiwanie na żądanie zostaje w pokoju meczu (4.14).
"""

from __future__ import annotations

import asyncio
import re
import time
import unicodedata
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from fastapi import APIRouter, Depends, Response
from pydantic import BaseModel, Field
from sqlalchemy import and_, select

from app import mentor_bastion_client as CL
from app import mentor_bastion_rules as BR
from app import mentor_panel_core as C
from app import mentor_panel_rules as R
from app.mentor_panel_auth import base_actor, mentor_actor

router = APIRouter(prefix="/mentor-panel", tags=["Mentor Bastion"])
Actor = C.MentorActor

#: Ile wyników z jednego zapytania do Meczoteki (connector pozwala 1..50).
PAGE = 20
#: Najwięcej zapytań na jedno „Szukaj” (kod meczu, gospodarz, gość) - kończymy wcześniej po pewnym trafieniu.
MAX_QUERIES = 3
#: Ile kaset oddajemy Archiwiście.
MAX_GAMES = 12
#: Od tylu punktów kaseta może wskoczyć na bilet „Ten mecz”.
BEST_MIN = 60
#: Od tylu punktów kaseta trafia do listy nagrań sezonu.
SEASON_MIN = 55
#: Nagrania sezonu: najwięcej meczów w jednym przebiegu i równoległych zapytań do connectora.
SEASON_MAX_MATCHES = 40
SEASON_CONCURRENCY = 3
#: Nagrania sezonu: łączny czas przebiegu (po nim kończymy z tym, co jest, `bastion.deadline: true`).
SEASON_DEADLINE_S = 100.0
#: Jedno ponowienie po 429 (tylko w nagraniach sezonu) po tylu sekundach.
RETRY_429_DELAY_S = 3.0
#: Pamięć wyników Meczoteki na serwerze (na użytkownika i zapytanie) i limit prawdziwych zapytań na użytkownika.
SEARCH_CACHE_TTL_S = 600.0
SEARCH_CACHE_MAX = 600
RATE_WINDOW_S = 300.0
RATE_MAX = 120
#: Nazwa parametru wyszukiwania po sędzi w Meczotece (do potwierdzenia próbą): "q" = nazwisko jako zwykły tekst.
REFEREE_PARAM = "q"

#: Słowa, które nie odróżniają drużyn (formy prawne, skróty klubowe, sponsorzy ogólni).
TEAM_STOP = {
    "ks", "mks", "uks", "spr", "kpr", "kph", "azs", "mts", "sts", "gks", "tks", "lks", "mks", "zks", "sks", "ukp", "mksz",
    "klub", "sportowy", "sportowa", "sp", "zoo", "sa", "ssa", "spz", "o", "w", "i", "im", "handball", "team", "pilka",
    "reczna", "pilki", "recznej", "akademia", "szkola", "mistrzostwa", "sportu", "ii", "iii", "junior", "juniorzy",
}

DISABLED_MESSAGE = "Szukanie w Bastionie jest wyłączone na serwerze. YouTube i wklejony link działają dalej."
UNCONFIGURED_MESSAGE = "Bastion nie jest jeszcze podłączony do BAZY. YouTube i wklejony link działają dalej."
STATE_MESSAGES = {
    "auth_required": "Bastion nie jest połączony. Połącz konto w Ustawieniach Mentora, a Archiwista przeszuka meczotekę.",
    "forbidden": "To konto Bastionu nie ma dostępu do meczoteki.",
    "unavailable": BR.MSG_UNAVAILABLE,
    "rate_limited": BR.MSG_RATE_LIMITED,
}
CODE_KIND = {"BASTION_AUTH_REQUIRED": "auth_required", "BASTION_RESOURCE_FORBIDDEN": "forbidden",
             "BASTION_UNAVAILABLE": "unavailable", "BASTION_RATE_LIMITED": "rate_limited"}


# ─── Czyste reguły (testowane bez bazy i sieci) ─────────────────────────────


def _plain(value: Any) -> str:
    """Bez polskich znaków i wielkości liter (ł -> l osobno, NFKD go nie rozkłada)."""
    text = str(value or "").replace("ł", "l").replace("Ł", "L")
    return "".join(ch for ch in unicodedata.normalize("NFKD", text) if not unicodedata.combining(ch)).casefold()


def fold(value: Any) -> str:
    return "".join(ch for ch in _plain(value) if ch.isalnum())


def _alnum(value: Any) -> str:
    """Tylko litery i cyfry, z zachowaniem wielkości liter ("LCM/32" == "LCM 32", ale "JmK" != "JMK")."""
    return "".join(ch for ch in str(value or "") if ch.isalnum())


def team_tokens(name: Any) -> List[str]:
    """Rdzeń nazwy drużyny: słowa >= 3 znaki bez form prawnych i skrótów klubowych (KS, MKS, SPR...)."""
    words = re.split(r"[^0-9a-z]+", _plain(name))
    core = [w for w in words if len(w) >= 3 and w not in TEAM_STOP and not w.isdigit()]
    return core or [w for w in words if len(w) >= 2]


def team_similarity(a: Any, b: Any) -> float:
    """0..1: identyczna nazwa = 1, wspólny rdzeń = część wspólna słów, zawieranie się rdzeni = 0.85."""
    fa, fb = fold(a), fold(b)
    if not fa or not fb:
        return 0.0
    if fa == fb:
        return 1.0
    ta, tb = set(team_tokens(a)), set(team_tokens(b))
    if not ta or not tb:
        return 0.0
    common = ta & tb
    if common:
        return max(0.8, len(common) / len(ta | tb)) if len(common) >= min(len(ta), len(tb)) else len(common) / len(ta | tb)
    ja, jb = "".join(sorted(ta)), "".join(sorted(tb))
    if len(ja) >= 5 and len(jb) >= 5 and (ja in fb or jb in fa):
        return 0.85
    return 0.0


_DMY = re.compile(r"(\d{1,2})[./-](\d{1,2})[./-](\d{4})")
_YMD = re.compile(r"(\d{4})-(\d{2})-(\d{2})")


def parse_day(value: Any) -> Optional[date]:
    """Dzień meczu z Bastionu ("2026-10-12", "2026-10-12T18:00:00+02:00", "12.10.2026"). Godzina z czasem UTC
    przechodzi przez Warszawę (mecz o 23:30 UTC to już następny dzień w Polsce)."""
    if isinstance(value, datetime):
        return _warsaw(value)
    if isinstance(value, date):
        return value
    text = str(value or "").strip()
    if not text:
        return None
    if "T" in text and _YMD.match(text):
        try:
            moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
            return _warsaw(moment) if moment.tzinfo else moment.date()
        except ValueError:
            pass
    for rx, order in ((_YMD, (0, 1, 2)), (_DMY, (2, 1, 0))):
        m = rx.search(text)
        if m:
            parts = [int(g) for g in m.groups()]
            try:
                return date(parts[order[0]], parts[order[1]], parts[order[2]])
            except ValueError:
                return None
    return None


def _warsaw(moment: datetime) -> date:
    from app.streams.rules import WARSAW

    aware = moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)
    return aware.astimezone(WARSAW).date()


def card_day(card: Mapping[str, Any]) -> Optional[date]:
    raw = card.get("scheduled_at")
    when = R.aware(raw) if isinstance(raw, datetime) else _iso_dt(raw) if isinstance(raw, str) and raw else None
    return _warsaw(when) if when else None


def _iso_dt(text: str) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


_AGE = re.compile(r"\bu[\s-]?(\d{2})\b")
_YOUTH = re.compile(r"\b(junior\w*|mlodzik\w*|mlodziez\w*|kadet\w*|dzieci\w*|mini)\b")
_WOMEN = re.compile(r"\b(kobiet\w*|women|dziewcz\w*|dziewczat\w*|seniorki|zenski\w*)\b")


def category_profile(*texts: Any) -> Optional[Tuple[Optional[str], bool]]:
    """(wiek, kobiety) z nazw rozgrywek: "U18" -> "u18", juniorzy/młodzik/kadet -> "youth", brak znaku = senior. None = brak tekstu."""
    hay = " ".join(_plain(x) for x in texts if x).strip()
    if not hay:
        return None
    age = None
    m = _AGE.search(hay)
    if m:
        age = "u" + m.group(1)
    elif _YOUTH.search(hay):
        age = "youth"
    return age, bool(_WOMEN.search(hay))


def category_signal(game: Mapping[str, Any], card: Mapping[str, Any]) -> Optional[str]:
    """"same" / "diff" / None: U18, U16, juniorzy i kobiety to osobny sygnał (zgodny kod i drużyny nie ratują meczu z innej kategorii)."""
    a = category_profile(game.get("competition"), game.get("title"))
    b = category_profile(card.get("competition_name"), card.get("category"))
    if a is None or b is None:
        return None
    (age_a, women_a), (age_b, women_b) = a, b
    if women_a != women_b:
        return "diff"
    if age_a == age_b:
        return "same"
    if age_a and age_b and "youth" in (age_a, age_b):
        return "same"  # "juniorzy" bez numeru pasuje do każdego U..
    return "diff"


def score_game(game: Mapping[str, Any], card: Mapping[str, Any]) -> Dict[str, Any]:
    """Pewność 0..100 i sygnały. `sure` = zgadza się kod meczu (co do litery), obie drużyny i dzień (wtedy 100).

    Kod: +40 / tylko bez wielkości liter +15 / -15 (różny). Drużyny: obie +40, jedna +15, żadna -10 (kolejność obojętna). Dzień: ten sam +20,
    sąsiedni +10, dalszy -25. Kategoria (U18/U16/juniorzy/kobiety): inna -25 i nigdy `sure`. Brak danej = 0 punktów i sygnał `null` (nigdy nie zgadujemy)."""
    # Kod meczu z Bastionu = pisownia ZPRP ("LCM/32", próba 28.10). Wielkość liter niesie kategorię (JmK != JMK),
    # więc pełny sygnał daje tylko zgodność co do litery; zgodność bez wielkości liter to wskazówka ("case").
    exact_a, exact_b = _alnum(game.get("code")), _alnum(card.get("match_code"))
    code: Any = None
    if exact_a and exact_b:
        code = True if exact_a == exact_b else "case" if exact_a.casefold() == exact_b.casefold() else False
    h, a = game.get("home"), game.get("away")
    ch, ca = (card.get("home") or {}).get("name"), (card.get("away") or {}).get("name")
    teams: Optional[str] = None
    if (h or a) and (ch or ca):
        straight = (team_similarity(h, ch), team_similarity(a, ca))
        swapped = (team_similarity(h, ca), team_similarity(a, ch))
        pair = max(min(straight), min(swapped))
        single = max(*straight, *swapped)
        teams = "both" if pair >= 0.8 else "one" if single >= 0.8 else "none"
    gd, cd = parse_day(game.get("date")), card_day(card)
    day: Optional[str] = None
    if gd and cd:
        diff = abs((gd - cd).days)
        day = "same" if diff == 0 else "near" if diff == 1 else "far"
    points = 0
    points += {True: 40, "case": 15, False: -15, None: 0}[code]
    points += {"both": 40, "one": 15, "none": -10, None: 0}[teams]
    points += {"same": 20, "near": 10, "far": -25, None: 0}[day]
    category = category_signal(game, card)
    points += {"diff": -25, "same": 0, None: 0}[category]
    sure = code is True and teams == "both" and day == "same" and category != "diff"
    confidence = 100 if sure else max(0, min(99, points))
    return {"confidence": confidence, "sure": sure,
            "signals": {"code": code, "teams": teams, "date": day, "category": category}}


def search_queries(card: Mapping[str, Any], q: Optional[str] = None) -> List[str]:
    """Zapytania do Meczoteki: tekst użytkownika albo kod meczu, potem rdzeń gospodarza i gościa (bez powtórzeń)."""
    if R.s(q):
        return [R.s(q)[:80]]
    out: List[str] = []
    code = R.s(card.get("match_code"))
    if code:
        out.append(code[:80])
    for side in ("home", "away"):
        tokens = team_tokens((card.get(side) or {}).get("name"))
        if tokens:
            word = max(tokens, key=len)[:80]
            if word not in out:
                out.append(word)
    return out[:MAX_QUERIES]


def shape_game(game: Mapping[str, Any], card: Mapping[str, Any], added: Iterable[int]) -> Dict[str, Any]:
    item = int(game["bunny_item_id"])
    keep = ("title", "home", "away", "date", "competition", "code", "score", "video_state", "video_coverage", "duration_s")
    return {"bunny_item_id": item, "url": BR.canonical_game_url(item), **{k: game.get(k) for k in keep},
            "referees": game.get("referees") if isinstance(game.get("referees"), list) else [], "thumbnail_url": game.get("thumbnail_url"),
            **score_game(game, card), "added": item in set(added)}


def rank_games(games: Iterable[Mapping[str, Any]], card: Mapping[str, Any], added: Iterable[int]) -> List[Dict[str, Any]]:
    """Kasety bez powtórzeń, od najpewniejszej (remis: nowsza data)."""
    seen: Dict[int, Dict[str, Any]] = {}
    added = list(added)
    for g in games:
        try:
            item = int(g.get("bunny_item_id"))
        except (TypeError, ValueError):
            continue
        if item < 1 or item in seen:
            continue
        seen[item] = shape_game(g, card, added)
    return sorted(seen.values(), key=lambda g: (-g["confidence"], -(parse_day(g.get("date")) or date.min).toordinal()))[:MAX_GAMES]


def has_code(game: Mapping[str, Any]) -> bool:
    """Kod meczu zgodny co do litery - bez niego nie wskazujemy nikogo jako „Ten mecz" ani w nagraniach sezonu."""
    return (game.get("signals") or {}).get("code") is True


def best_of(games: List[Mapping[str, Any]]) -> Optional[int]:
    for g in games:
        if not g.get("added") and int(g.get("confidence") or 0) >= BEST_MIN and has_code(g):
            return int(g["bunny_item_id"])
    return None


# ─── Połączenie i zapytania ─────────────────────────────────────────────────


def person_key(name: Any) -> str:
    """Klucz osoby niezależny od wielkości liter, polskich znaków i kolejności słów ("RAWICKI Jakub" == "Jakub Rawicki")."""
    return " ".join(sorted(w for w in re.split(r"[^0-9a-z]+", _plain(name)) if w))


def has_person(game: Mapping[str, Any], name: Any, role: str = "referee") -> bool:
    key = person_key(name)
    return bool(key) and any(person_key(r.get("name")) == key and (r.get("role") or "referee") == role
                             for r in game.get("referees") or [] if isinstance(r, Mapping))


#: Skan okresu (filtr dat w Trybunie): strona 50 wierszy, do 10 stron. Czy portal sam filtruje daty - NIEPOTWIERDZONE (próba
#: `scripts/probe_meczoteka_referee.py`); dopóki `None`, paginujemy i filtrujemy lokalnie. Po potwierdzeniu: ("date_from", "date_to").
SCAN_PAGE = 50
SCAN_MAX_PAGES = 10
PORTAL_DATE_PARAMS: Optional[Tuple[str, str]] = None
#: Ustalane próbą (`scripts/probe_meczoteka_referee.py`, sekcja FILTRY), domyślnie wyłączone:
#:  - `PORTAL_PLAYED_PARAM`: ("parametr", "wartość") dla "Rozegrane" - lista zaczyna się wtedy od przeszłości, nie od przyszłości,
#:  - `QUERY_DATE_FORMAT`: np. "%Y-%m-%d" - jeśli `q` zna datę i składnię OR, zakres do 14 dni idzie jako q="d1 OR d2 ...",
#:  - `PORTAL_FILTER_PARAMS`: {"category": "parametr", "gender": "parametr"} - kategoria i płeć z portalu zasilają sygnał `category`.
PORTAL_PLAYED_PARAM: Optional[Tuple[str, str]] = None
QUERY_DATE_FORMAT: Optional[str] = None
QUERY_DATE_MAX_DAYS = 14
PORTAL_FILTER_PARAMS: Dict[str, str] = {}


def parse_hm(value: Any) -> Optional[int]:
    """"HH:MM" -> minuty od północy (None gdy zły format)."""
    m = re.fullmatch(r"([01]?\d|2[0-3]):([0-5]\d)", str(value or "").strip())
    return int(m.group(1)) * 60 + int(m.group(2)) if m else None


def game_minutes(game: Mapping[str, Any]) -> Optional[int]:
    """Godzina meczu (czas polski) w minutach; None = nieznana (mecz bez terminu albo 00:00:00 przy `unscheduled`)."""
    raw = str(game.get("date") or "")
    m = re.search(r"[ T](\d{2}):(\d{2})", raw)
    if not m or game.get("unscheduled"):
        return None
    return int(m.group(1)) * 60 + int(m.group(2))


def in_range(game: Mapping[str, Any], d_from: Optional[date], d_to: Optional[date], t_from: Optional[int], t_to: Optional[int]) -> bool:
    """Dzień w zakresie (włącznie) i godzina w oknie (okno przez północ: od > do). Godzina nieznana przechodzi filtr godzin."""
    day = parse_day(game.get("date"))
    if (d_from or d_to) and day is None:
        return False
    if d_from and day < d_from or d_to and day > d_to:
        return False
    if t_from is None and t_to is None:
        return True
    minutes = game_minutes(game)
    if minutes is None:
        return True
    lo, hi = t_from if t_from is not None else 0, t_to if t_to is not None else 24 * 60 - 1
    return lo <= minutes <= hi if lo <= hi else (minutes >= lo or minutes <= hi)


class _Stop(Exception):
    """Werdykt, po którym dalsze zapytania nie mają sensu (brak sesji, limit, awaria)."""

    def __init__(self, verdicts: List[Tuple[str, BR.PlaybackVerdict]]):
        super().__init__("stop")
        self.verdicts = verdicts


_search_cache: Dict[Tuple[Any, ...], Tuple[float, Tuple[List[Dict[str, Any]], bool]]] = {}
_totals: Dict[Tuple[Any, ...], Optional[int]] = {}
#: Granice zakresów dat (strona startowa po wyszukiwaniu binarnym) pamiętane 10 min - lista portalu rośnie.
_bound_cache: Dict[Tuple[Any, ...], Tuple[float, int]] = {}
_rate_log: Dict[str, List[float]] = {}


def forget_search_cache() -> None:
    _search_cache.clear()
    _totals.clear()
    _bound_cache.clear()
    _rate_log.clear()


def cache_get(key: Tuple[Any, ...], now: Optional[float] = None) -> Optional[Tuple[List[Dict[str, Any]], bool]]:
    hit = _search_cache.get(key)
    moment = time.monotonic() if now is None else now
    if hit and moment - hit[0] < SEARCH_CACHE_TTL_S:
        games, more = hit[1]
        return [dict(g) for g in games], more
    _search_cache.pop(key, None)
    return None


def cache_put(key: Tuple[Any, ...], games: List[Dict[str, Any]], more: bool, now: Optional[float] = None) -> None:
    if len(_search_cache) >= SEARCH_CACHE_MAX:
        _search_cache.clear()
    _search_cache[key] = (time.monotonic() if now is None else now, ([dict(g) for g in games], bool(more)))


def rate_allow(judge_id: str, now: Optional[float] = None) -> bool:
    """Limit prawdziwych zapytań do connectora na użytkownika (okno przesuwne); trafienia w pamięci nie liczą się."""
    moment = time.monotonic() if now is None else now
    log = [t for t in _rate_log.get(judge_id, []) if moment - t < RATE_WINDOW_S]
    if len(log) >= RATE_MAX:
        _rate_log[judge_id] = log
        return False
    log.append(moment)
    _rate_log[judge_id] = log
    return True


class Meczoteka:
    """Jedno połączenie na cały przebieg: pierwsze zapytanie wybiera scope (domyślne -> osobiste), kolejne go używają.

    Wyniki są pamiętane na serwerze ~10 minut (na użytkownika i zapytanie), prawdziwe zapytania mają limit na użytkownika,
    a gdy pierwsza strona nie ma żadnej kasety, a portal mówi `has_more`, czytamy też drugą."""

    def __init__(self, client: CL.ConnectorClient, scopes: List[str], real: Actor, *, retry_429: bool = False):
        self.client, self.scopes, self.real = client, scopes, real
        self.scope: Optional[str] = None
        self.retry_429 = retry_429
        self.total: Optional[int] = None
        self._page_total: Optional[int] = None

    def _owner(self, scope: str) -> Optional[str]:
        return self.real.judge_id if scope == "personal" else None

    async def _one(self, scope: str, params_extra: Dict[str, Any]) -> Tuple[BR.PlaybackVerdict, Dict[str, Any]]:
        from app.mentor_bastion import apply_verdict

        params = {"scope": scope, "limit": PAGE, "video": "with", **params_extra}
        owner = self._owner(scope)
        if scope == "personal":
            params["judge_id"] = owner
        for attempt in (0, 1):
            try:
                reply = await self.client.request("GET", "/games/search", params=params, timeout=20.0)
            except CL.ConnectorUnavailable:
                return BR.PlaybackVerdict("unavailable", "BASTION_UNAVAILABLE"), {}
            verdict = BR.classify_playback(reply.status, reply.body)
            if verdict.kind == "rate_limited" and self.retry_429 and attempt == 0:
                await asyncio.sleep(RETRY_429_DELAY_S)  # jedno ponowienie po 429 (nagrania sezonu)
                continue
            break
        if verdict.kind == "ok" and not isinstance(reply.body.get("games"), list):
            verdict = BR.PlaybackVerdict("unavailable", "BASTION_BAD_RESPONSE")
        await apply_verdict(scope, owner, verdict)
        return verdict, reply.body

    async def _page(self, extra: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], bool]:
        if self.scope:
            verdict, body = await self._one(self.scope, extra)
            if verdict.kind != "ok":
                raise _Stop([(self.scope, verdict)])
            self._page_total = body.get("total") if isinstance(body.get("total"), int) else None
            return [g for g in body["games"] if isinstance(g, dict)], bool(body.get("has_more"))
        verdicts: List[Tuple[str, BR.PlaybackVerdict]] = []
        for scope in self.scopes:
            verdict, body = await self._one(scope, extra)
            if verdict.kind == "ok":
                self.scope = scope
                self._page_total = body.get("total") if isinstance(body.get("total"), int) else None
                return [g for g in body["games"] if isinstance(g, dict)], bool(body.get("has_more"))
            verdicts.append((scope, verdict))
            if verdict.kind in ("rate_limited", "unavailable"):
                break
        raise _Stop(verdicts)

    async def _cached(self, extra: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], bool]:
        key = (self.real.judge_id, tuple(sorted((k, str(v)) for k, v in extra.items())))
        hit = cache_get(key)
        if hit is not None:
            self.total = _totals.get(key)
            return hit
        if not rate_allow(self.real.judge_id):
            raise _Stop([((self.scopes or ["default"])[0], BR.PlaybackVerdict("rate_limited", "BASTION_RATE_LIMITED"))])
        games, more = await self._page(extra)
        cache_put(key, games, more)
        _totals[key] = self.total = getattr(self, "_page_total", None)
        return games, more

    async def _paged(self, extra: Dict[str, Any], offset: int = 0) -> List[Dict[str, Any]]:
        games, more = await self._cached({**extra, "offset": offset} if offset else dict(extra))
        if not games and more:
            games, _ = await self._cached({**extra, "offset": offset + PAGE})
        return games

    async def search(self, q: str) -> List[Dict[str, Any]]:
        return await self._paged({"q": q})

    async def search_referee(self, name: str, *, video: str = "any", offset: int = 0, role: str = "referee") -> List[Dict[str, Any]]:
        """Mecze z Meczoteki po nazwisku sędziego (`role="delegate"`: delegata). Portal szuka w `q` (próba 28.10), więc trafia
        też drużyny: zostają tylko wiersze, w których `nominees` zawierają tę osobę w tej roli (kolejność słów i polskie znaki
        bez znaczenia). Wiersze bez obsady portalu odpadają (nie ma dowodu)."""
        games = await self._paged({"referee": name, "referee_param": REFEREE_PARAM, "video": video}, offset)
        return [g for g in games if has_person(g, name, role)]

    async def scan(self, *, q: str = "", referee: str = "", role: str = "referee", video: str = "any",
                   d_from: Optional[date] = None, d_to: Optional[date] = None, t_from: Optional[int] = None,
                   t_to: Optional[int] = None, max_pages: int = SCAN_MAX_PAGES) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """Przegląd okresu (opcjonalnie z tekstem lub sędzią): strony po 50 (do `max_pages`), filtr dat/godzin lokalnie.
        Wczesne wyjście, gdy daty wierszy idą malejąco i ostatnia jest już przed początkiem zakresu. `meta.truncated` = były
        jeszcze strony, a limit stron się skończył (wynik niepełny)."""
        extra: Dict[str, Any] = {"video": video, "limit": SCAN_PAGE}
        if referee:
            extra.update(referee=referee, referee_param=REFEREE_PARAM)
        elif q:
            extra["q"] = q
        parts: List[str] = []
        if PORTAL_DATE_PARAMS and (d_from or d_to):
            parts += [f"{k}={v}" for k, v in ((PORTAL_DATE_PARAMS[0], d_from), (PORTAL_DATE_PARAMS[1], d_to)) if v]
        if PORTAL_PLAYED_PARAM and not (d_to and d_to >= date.today()):
            parts.append(f"{PORTAL_PLAYED_PARAM[0]}={PORTAL_PLAYED_PARAM[1]}")  # lista od przeszłości, nie od przyszłości
        if parts:
            extra["portal"] = "&".join(parts)
        q_dates = bool(QUERY_DATE_FORMAT and d_from and d_to and not referee and (d_to - d_from).days < QUERY_DATE_MAX_DAYS)
        if q_dates:
            # Portal zna datę i składnię OR w polu szukania: zakres do 14 dni to jedno zapytanie, total małe.
            days_q = " OR ".join((d_from + timedelta(days=i)).strftime(QUERY_DATE_FORMAT) for i in range((d_to - d_from).days + 1))
            extra["q"] = days_q if not q else f"{q} {days_q}"
        if q or referee or q_dates:
            max_pages = min(max_pages, 5)  # z tekstem lub sędzią total jest małe: czytamy wszystko (do 5 stron)
        elif d_from or d_to:
            # Lista portalu jest posortowana MALEJĄCO po dacie i zaczyna od przyszłości: stron zakresu szukamy binarnie po offsecie.
            found = await self._scan_by_date(extra, d_from, d_to, max_pages)
            if found is not None:
                rows_b, meta_b = found
                out_b = [g for g in rows_b if in_range(g, d_from, d_to, t_from, t_to)]
                return out_b, meta_b
        rows: List[Dict[str, Any]] = []
        days: List[date] = []
        pages, more, truncated = 0, False, False
        for page in range(max(1, max_pages)):
            games, more = await self._cached({**extra, "offset": page * SCAN_PAGE} if page else dict(extra))
            pages += 1
            rows += games
            days += [d for d in (parse_day(g.get("date")) for g in games) if d]
            if not more or not games:
                more = False
                break
            descending = len(days) > 1 and all(days[i] >= days[i + 1] for i in range(len(days) - 1))
            if descending and d_from and days and days[-1] < d_from:
                more = False  # reszta jest starsza niż zakres
                break
        truncated = bool(more)
        out = [g for g in rows if in_range(g, d_from, d_to, t_from, t_to) and (not referee or has_person(g, referee, role))]
        return out, {"pages": pages, "truncated": truncated, "local_filter": True, "mode": "linear", "requests": pages}

    async def _read_page(self, extra: Dict[str, Any], page: int) -> Tuple[List[Dict[str, Any]], bool]:
        return await self._cached({**extra, "offset": page * SCAN_PAGE} if page else dict(extra))

    async def _scan_by_date(self, extra: Dict[str, Any], d_from: Optional[date], d_to: Optional[date],
                            max_pages: int) -> Optional[Tuple[List[Dict[str, Any]], Dict[str, Any]]]:
        """Zakres dat bez tekstu: wyszukiwanie binarne strony, od której dnie są <= `d_to` (log2(total/50) żądań), potem czytanie
        stron aż do dnia < `d_from`. Strona startowa pamiętana 10 min na dzień końca. Zwraca None, gdy nie da się ufać sortowaniu
        (brak `total`, niemonotoniczne daty) - wtedy wołający robi zwykły skan z `truncated`."""
        games0, more0 = await self._read_page(extra, 0)
        total = self.total
        if not games0:
            return [], {"pages": 1, "truncated": False, "local_filter": True, "mode": "binary", "requests": 1}
        if total is None:
            return None
        n_pages = max(1, -(-total // SCAN_PAGE))
        seen: Dict[int, List[Dict[str, Any]]] = {0: games0}
        requests = 1

        def edge(games: List[Dict[str, Any]]) -> Tuple[Optional[date], Optional[date]]:
            ds = [d for d in (parse_day(g.get("date")) for g in games) if d]
            return (ds[0], ds[-1]) if ds else (None, None)

        def monotonic() -> bool:
            prev: Optional[date] = None
            for pg in sorted(seen):
                f, l = edge(seen[pg])
                if f is None:
                    continue
                if (prev is not None and f > prev) or l > f:
                    return False
                prev = l
            return True

        async def page(pg: int) -> List[Dict[str, Any]]:
            nonlocal requests
            if pg not in seen:
                g, _ = await self._read_page(extra, pg)
                seen[pg] = g
                requests += 1
            return seen[pg]

        start = 0
        if d_to is not None:
            f0, _ = edge(games0)
            if f0 is not None and f0 > d_to:
                bkey = (self.real.judge_id, str(extra.get("video")), d_to)
                hit = _bound_cache.get(bkey)
                if hit and time.monotonic() - hit[0] < SEARCH_CACHE_TTL_S and hit[1] < n_pages:
                    start = hit[1]
                else:
                    lo, hi = 1, n_pages  # najmniejsza strona, której PIERWSZY wiersz ma dzień <= d_to (n_pages = żadna)
                    while lo < hi:
                        mid = (lo + hi) // 2
                        f, _ = edge(await page(mid))
                        if f is None:
                            return None
                        if f <= d_to:
                            hi = mid
                        else:
                            lo = mid + 1
                    start = max(lo - 1, 0)  # granica może leżeć w końcówce poprzedniej strony
                    if not monotonic():
                        return None
                    if len(_bound_cache) > 500:
                        _bound_cache.clear()
                    _bound_cache[bkey] = (time.monotonic(), start)
        rows: List[Dict[str, Any]] = []
        done, pg = False, start
        while pg < min(start + max(1, max_pages), n_pages):
            games = await page(pg)
            rows += games
            _, last = edge(games)
            if (last is not None and d_from and last < d_from) or pg >= n_pages - 1 or not games:
                done = True
                break
            pg += 1
        if not monotonic():
            return None
        return rows, {"pages": requests, "truncated": not done, "local_filter": True, "mode": "binary", "requests": requests}



#: Miniatury i długość kaset (z game-context bez embedu): pamięć 6 h, brak wyniku 10 min; najwyżej 12 kaset na odpowiedź.
THUMB_TTL_S = 6 * 3600.0
THUMB_MISS_TTL_S = 600.0
THUMB_LIMIT = 12
THUMB_CONCURRENCY = 4
THUMB_DEADLINE_S = 12.0
_media_cache: Dict[int, Tuple[float, Optional[str], Optional[int]]] = {}


def forget_media_cache() -> None:
    _media_cache.clear()


def _media_hit(item: int, now: float) -> Optional[Tuple[Optional[str], Optional[int]]]:
    hit = _media_cache.get(item)
    if hit is None:
        return None
    ttl = THUMB_TTL_S if (hit[1] or hit[2]) else THUMB_MISS_TTL_S
    if now - hit[0] >= ttl:
        _media_cache.pop(item, None)
        return None
    return hit[1], hit[2]


async def enrich_media(real: Actor, scope: Optional[str], games: Iterable[Dict[str, Any]], limit: int = THUMB_LIMIT) -> None:
    """Miniatura i długość kaset: z game-context (jeśli portal poda), potem NASZA klatka z magazynu BAZY (zadanie w tle:
    `thumb_pending`), plus herby drużyn. Nigdy nie rzuca."""
    games = list(games)
    await _enrich_context_media(real, scope, games, limit)
    try:
        from app.mentor_trybuna_thumbs import attach

        await attach(real, [g for g in games if isinstance(g, dict)][:max(0, limit)])
    except Exception:  # noqa: BLE001
        C.logger.warning("trybuna: miniatury z magazynu nieudane", exc_info=True)
    await attach_crests(games)


_crest_index: Optional[Tuple[float, Dict[str, str], Dict[Tuple[str, ...], str]]] = None
CREST_TTL_S = 3600.0


async def _crests() -> Tuple[Dict[str, str], Dict[Tuple[str, ...], str]]:
    """Indeks herbów klubów (ten sam zbiór `zprp_public_clubs.logo_url`, co na karcie meczu): po nazwie i po rdzeniu nazwy."""
    global _crest_index
    if _crest_index and time.monotonic() - _crest_index[0] < CREST_TTL_S:
        return _crest_index[1], _crest_index[2]
    from app.db import zprp_public_clubs

    by_name: Dict[str, str] = {}
    by_core: Dict[Tuple[str, ...], str] = {}
    try:
        for r in await C.rows(select(zprp_public_clubs.c.name, zprp_public_clubs.c.logo_url).where(zprp_public_clubs.c.logo_url.is_not(None))):
            logo = R.s(r.get("logo_url"))
            if not logo:
                continue
            by_name.setdefault(fold(r.get("name")), logo)
            core = tuple(sorted(team_tokens(r.get("name"))))
            if core:
                by_core.setdefault(core, logo)
    except Exception:  # noqa: BLE001
        C.logger.warning("trybuna: indeks herbów nieczytelny", exc_info=True)
    _crest_index = (time.monotonic(), by_name, by_core)
    return by_name, by_core


def forget_crests() -> None:
    global _crest_index
    _crest_index = None


async def crest_for(name: Any) -> Optional[str]:
    if not R.s(name):
        return None
    by_name, by_core = await _crests()
    return by_name.get(fold(name)) or by_core.get(tuple(sorted(team_tokens(name))))


async def attach_crests(items: Iterable[Dict[str, Any]], pairs: Iterable[Tuple[str, str]] = (("home", "home_crest"), ("away", "away_crest"))) -> None:
    """Dokłada `home_crest` / `away_crest` (url|null) po nazwie drużyny. Nazwa może być napisem albo obiektem {name}."""
    try:
        for it in items:
            if not isinstance(it, dict):
                continue
            for src, dst in pairs:
                if it.get(dst):
                    continue
                value = it.get(src)
                name = value.get("name") if isinstance(value, dict) else value
                it[dst] = await crest_for(name)
    except Exception:  # noqa: BLE001
        C.logger.warning("trybuna: herby nieudane", exc_info=True)


async def _enrich_context_media(real: Actor, scope: Optional[str], games: Iterable[Dict[str, Any]], limit: int = THUMB_LIMIT) -> None:
    """Dokłada `thumbnail_url` i `duration_s` do słowników z `bunny_item_id` (na miejscu). Źródło: miniatura z game-context Bastionu
    (connector `/playback?include_embed=false`, ta sama droga co bilet meczu), pamięć 6 h. Brak danych, brak połączenia, limit czasu
    albo błąd = zostaje null; funkcja nigdy nie rzuca."""
    try:
        from app import mentor_bastion_client as CL
        from app.mentor_bastion import _client, _scope_judge

        targets = [g for g in games if isinstance(g, dict) and g.get("bunny_item_id")][:max(0, limit)]
        now = time.monotonic()
        todo: List[int] = []
        for g in targets:
            item = int(g["bunny_item_id"])
            hit = _media_hit(item, now)
            if hit is not None:
                g["thumbnail_url"] = g.get("thumbnail_url") or hit[0]
                g["duration_s"] = g.get("duration_s") or hit[1]
            elif item not in todo:
                todo.append(item)
        flags = BR.load_flags()
        if not todo or not flags.enabled or not flags.configured:
            return
        scopes = [scope] if scope else BR.candidate_scopes(flags)
        client = _client()
        gate = asyncio.Semaphore(THUMB_CONCURRENCY)

        async def one(item: int) -> None:
            async with gate:
                found: Tuple[Optional[str], Optional[int]] = (None, None)
                for sc in scopes:
                    try:
                        reply = await client.playback(sc, _scope_judge(sc, real), item, include_embed=False)
                    except CL.ConnectorUnavailable:
                        break
                    verdict = BR.classify_playback(reply.status, reply.body)
                    if verdict.kind == "ok":
                        thumb = reply.body.get("thumbnail_url")
                        dur = reply.body.get("duration_s")
                        found = (thumb if isinstance(thumb, str) and thumb.startswith("https://") else None,
                                 int(dur) if isinstance(dur, (int, float)) and not isinstance(dur, bool) and dur > 0 else None)
                        break
                    if verdict.kind in ("rate_limited", "unavailable"):
                        break
                if len(_media_cache) > 2000:
                    _media_cache.clear()
                _media_cache[item] = (time.monotonic(), found[0], found[1])

        try:
            await asyncio.wait_for(asyncio.gather(*(one(i) for i in todo)), THUMB_DEADLINE_S)
        except asyncio.TimeoutError:
            pass
        for g in targets:
            hit = _media_hit(int(g["bunny_item_id"]), time.monotonic())
            if hit is not None:
                g["thumbnail_url"] = g.get("thumbnail_url") or hit[0]
                g["duration_s"] = g.get("duration_s") or hit[1]
    except Exception:  # noqa: BLE001 - miniatura to dodatek
        C.logger.warning("trybuna: miniatury kaset nieudane", exc_info=True)


def _setup(real: Actor) -> Tuple[Optional[Meczoteka], Optional[str]]:
    """(Meczoteka, None) albo (None, stan): `disabled` / `unconfigured`."""
    flags = BR.load_flags()
    if not flags.enabled:
        return None, "disabled"
    scopes = BR.candidate_scopes(flags)
    if not scopes or not flags.configured:
        return None, "unconfigured"
    try:
        client = CL.get_client()
    except CL.ConnectorUnavailable:
        return None, "unconfigured"
    return Meczoteka(client, scopes, real), None


async def _added_items(ctx: Dict[str, Any], match_ids: List[str]) -> Dict[str, List[int]]:
    """Nagrania Bastion już dodane w pokojach tych meczów (nieusunięte)."""
    from app.db import mentor_match_videos as V

    out: Dict[str, List[int]] = {}
    if not match_ids:
        return out
    for row in await C.rows(select(V.c.match_id, V.c.url, V.c.provider).where(V.c.match_id.in_(match_ids))
                            .where(V.c.pair_key == ctx["pair_key"]).where(V.c.deleted_at.is_(None))):
        item = BR.parse_game_url(row.get("url")) if row.get("provider") == BR.PROVIDER else None
        if item:
            out.setdefault(R.s(row["match_id"]), []).append(item)
    return out


async def find_for_card(mz: Meczoteka, card: Mapping[str, Any], added: List[int], q: Optional[str] = None,
                        max_queries: int = MAX_QUERIES) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Kasety dla meczu i użyte zapytania. Po pewnym trafieniu kolejnych zapytań już nie ma."""
    found: List[Dict[str, Any]] = []
    used: List[str] = []
    for query in search_queries(card, q)[:max_queries]:
        used.append(query)
        found += await mz.search(query)
        ranked = rank_games(found, card, added)
        if ranked and ranked[0]["sure"]:
            return ranked, used
    return rank_games(found, card, added), used


# ─── Trasy ──────────────────────────────────────────────────────────────────


class SearchBody(BaseModel):
    q: Optional[str] = Field(default=None, max_length=80)


@router.post("/pairs/{pair_id}/matches/{match_id}/bastion/search")
async def bastion_search(pair_id: str, match_id: str, response: Response, body: Optional[SearchBody] = None,
                         real: Actor = Depends(base_actor), acting: Actor = Depends(mentor_actor)):
    """Archiwista: kasety z Meczoteki dla meczu pokoju (`games` od najpewniejszej) i `best` do biletu „Ten mecz”."""
    from app.mentor_bastion import _playback_failure, berr

    response.headers["Cache-Control"] = "no-store"
    ctx = await C.pair_context(pair_id, acting)
    C.check(ctx, "video")
    card = await C.match_card(ctx, match_id)
    mz, state = _setup(real)
    if state == "disabled":
        raise berr(404, "BASTION_DISABLED", DISABLED_MESSAGE)
    if state == "unconfigured" or mz is None:
        raise berr(503, "BASTION_UNAVAILABLE", UNCONFIGURED_MESSAGE)
    q = R.s((body or SearchBody()).q) or None
    if q and any(ord(ch) < 32 for ch in q):
        raise berr(422, "BAD_QUERY", "Wpisz nazwę drużyny, kod albo datę meczu.")
    added = (await _added_items(ctx, [card["match_id"]])).get(card["match_id"], [])
    try:
        games, used = await find_for_card(mz, card, added, q)
    except _Stop as stop:
        exc = _playback_failure(BR.load_flags(), real, stop.verdicts)
        kind = CODE_KIND.get(exc.detail.get("code"), "unavailable")
        exc.detail["message"] = STATE_MESSAGES[kind]
        raise exc from None
    await enrich_media(real, mz.scope, games)
    return {"games": games, "best": best_of(games), "queries": used, "connection_scope": mz.scope,
            "match": R.slim_match(card)}


class SeasonBody(BaseModel):
    season: str = Field(default="", max_length=20)
    match_ids: Optional[List[str]] = Field(default=None, max_length=SEASON_MAX_MATCHES)
    bastion: bool = True


def _youtube_proposal(stream: Mapping[str, Any]) -> Dict[str, Any]:
    official = stream.get("confidence") == "official"
    confirmed = stream.get("confidence") == "confirmed"
    return {
        "source": "youtube", "key": f"yt:{stream.get('video_id')}", "url": stream.get("url"),
        "title": stream.get("title"), "confidence": 100 if official else 90 if confirmed else 50,
        "sure": official or confirmed, "stream": dict(stream),
    }


def _bastion_proposal(game: Mapping[str, Any]) -> Dict[str, Any]:
    return {"source": "bastion", "key": f"bastion:{game['bunny_item_id']}", "url": game["url"], "title": game.get("title"),
            "confidence": game["confidence"], "sure": game["sure"], "game": dict(game),
            "thumbnail_url": game.get("thumbnail_url"), "duration_s": game.get("duration_s")}


def bastion_state_message(state: str) -> str:
    return {"disabled": DISABLED_MESSAGE, "unconfigured": UNCONFIGURED_MESSAGE}.get(state) or STATE_MESSAGES.get(state, BR.MSG_UNAVAILABLE)


def season_cards(cards: Iterable[Mapping[str, Any]], season: str, match_ids: Optional[List[str]], now: datetime) -> List[Mapping[str, Any]]:
    """Mecze bez nagrania, już rozegrane (dzień meczu minął albo trwa), najnowsze najpierw, najwyżej 40."""
    wanted = {R.s(m) for m in match_ids or [] if R.s(m)}
    today = _warsaw(now)
    out = []
    for c in R.filter_cards(list(cards), season=season):
        if wanted and R.s(c.get("match_id")) not in wanted:
            continue
        if int(((c.get("videos") or {}).get("count")) or 0) > 0:
            continue
        day = card_day(c)
        if day is None or day > today:
            continue
        out.append(c)
    out.sort(key=lambda c: R.s(c.get("scheduled_at")), reverse=True)
    return out[:SEASON_MAX_MATCHES]


@router.post("/pairs/{pair_id}/videos/season-proposals")
async def season_proposals(pair_id: str, response: Response, body: Optional[SeasonBody] = None,
                           real: Actor = Depends(base_actor), acting: Actor = Depends(mentor_actor)):
    """„Wczytaj nagrania sezonu”: jedna lista propozycji (YouTube z portalu + Bastion) dla meczów bez nagrania."""
    from app.mentor_panel_streams import _json_list, visible_rows
    from app.streams import store

    response.headers["Cache-Control"] = "no-store"
    body = body or SeasonBody()
    ctx = await C.pair_context(pair_id, acting)
    C.check(ctx, "video")
    cards = season_cards(await C.enriched_pair_cards(ctx), R.s(body.season), body.match_ids, C.now())
    ids = [R.s(c["match_id"]) for c in cards]

    # YouTube: tylko przypisane już przez portal (zero puli), bez odrzuconych przez parę.
    yt: Dict[str, List[Dict[str, Any]]] = {}
    youtube = {"state": "ok", "message": None}
    try:
        from app.db import mentor_stream_searches as T

        searches = {R.s(r["match_id"]): r for r in await C.rows(select(T).where(and_(T.c.pair_id == ctx["pair_id"], T.c.match_id.in_(ids))))} if ids else {}
        rows = await store.streams_for(ids)
        for mid in ids:
            row = searches.get(mid) or {}
            mine = visible_rows([r for r in rows if R.s(r.get("match_id")) == mid], [], _json_list(row.get("rejected_json")),
                                _json_list(row.get("found_json")))
            if mine:
                yt[mid] = (await store.with_channels(mine))[:2]
    except Exception:  # noqa: BLE001 - YouTube nie zabiera Bastionu
        C.logger.warning("mentor: transmisje sezonu nieczytelne", exc_info=True)
        youtube = {"state": "unavailable", "message": "Nie udało się odczytać transmisji z YouTube. Bastion szuka dalej."}

    # Bastion: kod meczu, potem gospodarz (2 zapytania na mecz), 3 mecze naraz; pierwszy twardy werdykt kończy przebieg.
    bastion = {"state": "ok", "message": None, "scope": None}
    found: Dict[str, Dict[str, Any]] = {}
    if body.bastion and ids:
        mz, state = _setup(real)
        if mz is None:
            bastion = {"state": state or "unconfigured", "message": bastion_state_message(state or "unconfigured"), "scope": None}
        else:
            added = await _added_items(ctx, ids)
            gate = asyncio.Semaphore(SEASON_CONCURRENCY)
            stopped: List[str] = []
            mz.retry_429 = True  # jedno ponowienie po 429
            deadline = time.monotonic() + SEASON_DEADLINE_S
            skipped: List[str] = []

            async def one(card: Mapping[str, Any]) -> None:
                if stopped:
                    return
                async with gate:
                    if stopped:
                        return
                    if time.monotonic() > deadline:  # łączny czas przebiegu minął: reszty nie szukamy
                        skipped.append(R.s(card["match_id"]))
                        return
                    try:
                        games, _ = await find_for_card(mz, card, added.get(R.s(card["match_id"]), []), max_queries=2)
                    except _Stop as stop:
                        kinds = [v.kind for _, v in stop.verdicts]
                        kind = next((k for k in ("rate_limited", "unavailable", "forbidden") if k in kinds), "auth_required")
                        stopped.append(kind)
                        return
                    top = next((g for g in games if not g["added"] and g["confidence"] >= SEASON_MIN and has_code(g)), None)
                    if top:
                        found[R.s(card["match_id"])] = top

            # Pierwszy mecz osobno: ustala połączenie (domyślne/osobiste), reszta równolegle na nim.
            await one(cards[0])
            if not stopped:
                await asyncio.gather(*(one(c) for c in cards[1:]))
            if stopped:
                bastion = {"state": stopped[0], "message": STATE_MESSAGES.get(stopped[0]), "scope": mz.scope,
                           "partial": bool(found)}
            else:
                bastion["scope"] = mz.scope
            if skipped:
                bastion["deadline"] = True
                bastion["partial"] = True
                bastion["skipped"] = len(skipped)

    if found:
        await enrich_media(real, bastion.get("scope"), list(found.values()))
    items = []
    for card in cards:
        mid = R.s(card["match_id"])
        proposals = [_youtube_proposal(s) for s in yt.get(mid, [])]
        if mid in found:
            proposals.append(_bastion_proposal(found[mid]))
        proposals.sort(key=lambda p: -p["confidence"])
        items.append({"match": R.slim_match(card), "proposals": proposals})
    total = sum(len(i["proposals"]) for i in items)
    return {"items": items, "scanned": len(cards), "proposals": total, "youtube": youtube, "bastion": bastion,
            "limit": SEASON_MAX_MATCHES}
