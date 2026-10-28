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
import unicodedata
from datetime import date, datetime, timezone
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


def score_game(game: Mapping[str, Any], card: Mapping[str, Any]) -> Dict[str, Any]:
    """Pewność 0..100 i sygnały. `sure` = zgadza się kod meczu (co do litery), obie drużyny i dzień (wtedy 100).

    Kod: +40 / tylko bez wielkości liter +15 / -15 (różny). Drużyny: obie +40, jedna +15, żadna -10 (kolejność obojętna). Dzień: ten sam +20,
    sąsiedni +10, dalszy -25. Brak danej = 0 punktów i sygnał `null` (nigdy nie zgadujemy)."""
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
    sure = code is True and teams == "both" and day == "same"
    confidence = 100 if sure else max(0, min(99, points))
    return {"confidence": confidence, "sure": sure, "signals": {"code": code, "teams": teams, "date": day}}


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


def best_of(games: List[Mapping[str, Any]]) -> Optional[int]:
    for g in games:
        if not g.get("added") and int(g.get("confidence") or 0) >= BEST_MIN:
            return int(g["bunny_item_id"])
    return None


# ─── Połączenie i zapytania ─────────────────────────────────────────────────


class _Stop(Exception):
    """Werdykt, po którym dalsze zapytania nie mają sensu (brak sesji, limit, awaria)."""

    def __init__(self, verdicts: List[Tuple[str, BR.PlaybackVerdict]]):
        super().__init__("stop")
        self.verdicts = verdicts


class Meczoteka:
    """Jedno połączenie na cały przebieg: pierwsze zapytanie wybiera scope (domyślne -> osobiste), kolejne go używają."""

    def __init__(self, client: CL.ConnectorClient, scopes: List[str], real: Actor):
        self.client, self.scopes, self.real = client, scopes, real
        self.scope: Optional[str] = None

    def _owner(self, scope: str) -> Optional[str]:
        return self.real.judge_id if scope == "personal" else None

    async def _one(self, scope: str, q: str) -> Tuple[BR.PlaybackVerdict, Dict[str, Any]]:
        from app.mentor_bastion import apply_verdict

        params = {"scope": scope, "q": q, "limit": PAGE, "video": "with"}
        owner = self._owner(scope)
        if scope == "personal":
            params["judge_id"] = owner
        try:
            reply = await self.client.request("GET", "/games/search", params=params, timeout=20.0)
        except CL.ConnectorUnavailable:
            return BR.PlaybackVerdict("unavailable", "BASTION_UNAVAILABLE"), {}
        verdict = BR.classify_playback(reply.status, reply.body)
        if verdict.kind == "ok" and not isinstance(reply.body.get("games"), list):
            verdict = BR.PlaybackVerdict("unavailable", "BASTION_BAD_RESPONSE")
        await apply_verdict(scope, owner, verdict)
        return verdict, reply.body

    async def search(self, q: str) -> List[Dict[str, Any]]:
        if self.scope:
            verdict, body = await self._one(self.scope, q)
            if verdict.kind != "ok":
                raise _Stop([(self.scope, verdict)])
            return [g for g in body["games"] if isinstance(g, dict)]
        verdicts: List[Tuple[str, BR.PlaybackVerdict]] = []
        for scope in self.scopes:
            verdict, body = await self._one(scope, q)
            if verdict.kind == "ok":
                self.scope = scope
                return [g for g in body["games"] if isinstance(g, dict)]
            verdicts.append((scope, verdict))
            if verdict.kind in ("rate_limited", "unavailable"):
                break
        raise _Stop(verdicts)


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
            "confidence": game["confidence"], "sure": game["sure"], "game": dict(game)}


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

            async def one(card: Mapping[str, Any]) -> None:
                if stopped:
                    return
                async with gate:
                    if stopped:
                        return
                    try:
                        games, _ = await find_for_card(mz, card, added.get(R.s(card["match_id"]), []), max_queries=2)
                    except _Stop as stop:
                        kinds = [v.kind for _, v in stop.verdicts]
                        kind = next((k for k in ("rate_limited", "unavailable", "forbidden") if k in kinds), "auth_required")
                        stopped.append(kind)
                        return
                    top = next((g for g in games if not g["added"] and g["confidence"] >= SEASON_MIN), None)
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
