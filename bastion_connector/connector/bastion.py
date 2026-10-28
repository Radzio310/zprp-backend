"""Klient odczytu GET /api/game-context z dana sesja. Wewnetrzne API portalu (nie publiczna umowa),
wiec odpowiedz jest walidowana, a bledy mapowane na kody BAZY (handoff 8.1)."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlsplit

from .urlrules import embed_url_ok


@dataclass
class GameResult:
    code: str  # OK | BASTION_AUTH_REQUIRED | BASTION_RESOURCE_FORBIDDEN | BASTION_RATE_LIMITED | BASTION_UNAVAILABLE | BASTION_BAD_RESPONSE | BASTION_EMBED_HOST_NOT_ALLOWED
    http_status: int | None = None
    embed_url: str | None = None
    video_state: str | None = None
    expires_at: int | None = None  # epoch z adresu embed, jezeli ma parametr czasu; inaczej None
    top_keys: list[str] = field(default_factory=list)
    detail: str | None = None
    identity: dict = field(default_factory=dict)  # {id, label, source, viewer_keys}; puste, gdy brak klucza viewer
    match: dict = field(default_factory=dict)  # krotkie podsumowanie meczu z game-context (bilet meczu), bez embedu


_EXPIRY_PARAMS = ("expires", "expire", "token_expires", "exp")


def embed_expiry(url: str) -> int | None:
    try:
        q = parse_qs(urlsplit(url).query)
    except ValueError:
        return None
    for name in _EXPIRY_PARAMS:
        for v in q.get(name, []):
            if v.isdigit() and 1_000_000_000 < int(v) < 4_000_000_000:
                return int(v)
    return None


_ID_KEYS = ("discord_user_id", "discord_id", "user_id", "id", "uid", "sub")
_LABEL_KEYS = ("display_name", "displayName", "global_name", "name", "username", "nickname", "nick")


def _clean(v: Any, limit: int) -> str | None:
    if isinstance(v, bool) or not isinstance(v, (str, int)):
        return None
    t = str(v).strip()
    return t[:limit] if t else None


def extract_identity(body: Any) -> dict:
    """Tozsamosc konta z klucza `viewer` game-context. Publiczne skrypty portalu (game.js, portal.js) czytaja tylko
    `viewer.display_name` (i `user.display_name` z /api/me/sections); stabilnego id nie ujawniaja. Dlatego:
    id z pierwszego znanego pola id, jesli viewer je ma (source `viewer.<pole>`), inaczej odcisk nazwy wyswietlanej
    `dn:<sha256[:16]>` (source `viewer.display_name`; dwie osoby o tej samej nazwie nie sa rozroznialne).
    Zwraca tez NAZWY pol viewer (bez wartosci), zeby dalo sie sprawdzic ksztalt na zywo."""
    v = body.get("viewer") if isinstance(body, dict) else None
    if isinstance(v, dict):
        keys = sorted(str(k) for k in v)[:20]
        idk = next(((k, x) for k in _ID_KEYS if (x := _clean(v.get(k), 128))), None)
        label = next((x for k in _LABEL_KEYS if (x := _clean(v.get(k), 80))), None)
        if idk:
            return {"id": idk[1], "label": label or idk[1], "source": f"viewer.{idk[0]}", "viewer_keys": keys}
        if label:
            return {"id": "dn:" + hashlib.sha256(label.casefold().encode()).hexdigest()[:16], "label": label,
                    "source": "viewer.display_name", "viewer_keys": keys}
        return {"id": None, "label": None, "source": None, "viewer_keys": keys}
    x = _clean(v, 128)
    if x:
        return {"id": x, "label": x, "source": "viewer", "viewer_keys": []}
    return {"id": None, "label": None, "source": None, "viewer_keys": []}


def _norm(k: Any) -> str:
    return "".join(ch for ch in str(k).lower() if ch.isalnum())


def _scalar(v: Any, limit: int = 120) -> str | None:
    if isinstance(v, dict):  # np. {"name": "...", "id": ...}
        for k in ("name", "nazwa", "title", "label", "short_name"):
            if k in v and (x := _scalar(v[k], limit)):
                return x
        return None
    return _clean(v, limit)


def _pick(m: dict, names: tuple) -> str | None:
    by = {_norm(k): v for k, v in m.items()}
    for n in names:
        if n in by and (x := _scalar(by[n])):
            return x
    return None


def summarize_match(body: Any) -> dict:
    """Krotkie podsumowanie klucza `match` z game-context: druzyny, data, kod rozgrywek i identyfikatory ZPRP (Mecz,
    Sezon, Rozgrywki). Ksztalt `match` nie jest potwierdzony publicznie, wiec pola szukamy po kilku nazwach i bierzemy
    tylko skalary (zadnych URL-i, osob ani opisow). `match_keys` = NAZWY pol (bez wartosci), do sprawdzenia ksztaltu na zywo."""
    m = body.get("match") if isinstance(body, dict) else None
    if not isinstance(m, dict):
        return {}
    out = {
        "home": _pick(m, ("home", "hometeam", "hometeamname", "teamhome", "host", "gospodarz", "gospodarze", "zespolgosp", "team1")),
        "away": _pick(m, ("away", "awayteam", "awayteamname", "teamaway", "guest", "gosc", "goscie", "zespolgosc", "team2")),
        "date": _pick(m, ("date", "matchdate", "startsat", "starttime", "scheduledat", "playedat", "datetime", "kickoff", "datafakt", "data")),
        "competition": _pick(m, ("competition", "competitionname", "league", "rozgrywki", "rozgrywkinazwa", "tournament")),
        "code": _pick(m, ("code", "matchcode", "competitioncode", "rozgrywkicode", "numer", "numermeczu", "matchnumber", "kod")),
        "zprp_match_id": _pick(m, ("mecz", "idmecz", "meczid", "zprpmatchid", "zprpid", "matchid")),
        "zprp_season_id": _pick(m, ("sezon", "idsezon", "sezonid", "seasonid", "season")),
        "zprp_competition_id": _pick(m, ("rozgrywki", "idrozgrywki", "rozgrywkiid", "competitionid")),
    }
    out = {k: v for k, v in out.items() if v}
    out["match_keys"] = sorted(str(k) for k in m)[:30]
    return out


def classify(http_status: int, body: Any, embed_suffixes: list[str]) -> GameResult:
    if http_status == 401:
        return GameResult("BASTION_AUTH_REQUIRED", 401)
    if http_status == 403:
        return GameResult("BASTION_RESOURCE_FORBIDDEN", 403)
    if http_status == 429:
        return GameResult("BASTION_RATE_LIMITED", 429)
    if http_status != 200:
        return GameResult("BASTION_UNAVAILABLE", http_status)
    if not isinstance(body, dict):
        return GameResult("BASTION_BAD_RESPONSE", 200, detail="odpowiedz nie jest obiektem JSON")
    video = body.get("video") if isinstance(body.get("video"), dict) else {}
    embed = video.get("embed_url") if isinstance(video.get("embed_url"), str) else None
    res = GameResult("OK", 200, video_state=video.get("state") if isinstance(video.get("state"), str) else None,
                     top_keys=sorted(body.keys())[:20], identity=extract_identity(body), match=summarize_match(body))
    if embed:
        if not embed_url_ok(embed, embed_suffixes):
            host = urlsplit(embed).hostname
            return GameResult("BASTION_EMBED_HOST_NOT_ALLOWED", 200, video_state=res.video_state,
                              top_keys=res.top_keys, detail=f"host embed: {host}", identity=res.identity)
        res.embed_url = embed
        res.expires_at = embed_expiry(embed)
    return res


async def fetch_game_context(req, base_url: str, bunny_item_id: int, embed_suffixes: list[str]) -> GameResult:
    """req = APIRequestContext Playwrighta (browser_context.request albo playwright.request.new_context)."""
    try:
        resp = await req.get(f"{base_url}/api/game-context", params={"bunny_item_id": str(bunny_item_id)},
                             timeout=15000, max_redirects=0)
        try:
            body = await resp.json()
        except Exception:  # noqa: BLE001
            body = None
        return classify(resp.status, body, embed_suffixes)
    except Exception as e:  # noqa: BLE001 - timeout/siec to NIE dowod wygasniecia sesji
        return GameResult("BASTION_UNAVAILABLE", None, detail=type(e).__name__)


# ---------- Meczoteka: GET /api/games (lista meczow, strona /games; ksztalt z publicznego game_library.js) ----------
def _txt(v: Any, limit: int = 120) -> str | None:
    if isinstance(v, bool) or not isinstance(v, (str, int)):
        return None
    t = str(v).strip()
    return t[:limit] if t else None


def _int(v: Any) -> int | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, str) and v.strip().isdigit():
        return int(v.strip())
    return None


REFEREE_PARAMS = ("q", "referee", "referees", "referee_name", "judge", "sedzia")
_REFEREE_KEY_HINTS = ("referee", "judge", "sedzi", "sędzi", "arbiter", "nominee")


def display_name(raw: str) -> str:
    """"RAWICKI Jakub" -> "Jakub Rawicki" (portal: NAZWISKO wielkimi, potem imie). Nazwy bez wielkich czlonow zostaja."""
    words = raw.split()
    sur = [w for w in words if len(w) > 1 and w.isupper()]
    rest = [w for w in words if w not in sur]
    if not sur or not rest:
        return raw
    return " ".join(rest + [w.capitalize() if "-" not in w else "-".join(p.capitalize() for p in w.split("-")) for w in sur])


def _person_name(v: Any, depth: int = 0) -> str | None:
    if isinstance(v, str):
        return _txt(v, 80)
    if isinstance(v, dict):
        full = _txt(v.get("name") or v.get("full_name") or v.get("fullname") or v.get("display_name"), 80)
        if full:
            return full
        first, last = _txt(v.get("first_name") or v.get("firstname"), 40), _txt(v.get("last_name") or v.get("lastname") or v.get("surname"), 40)
        joined = " ".join(x for x in (first, last) if x)
        if joined:
            return joined
        if depth < 2:  # {role, referee|user|person: {...}}
            for k in ("referee", "judge", "user", "person", "profile"):
                if isinstance(v.get(k), dict):
                    nested = _person_name(v[k], depth + 1)
                    if nested:
                        return nested
    return None


def _role_of(raw: Any) -> str:
    r = str(raw or "").lower()
    return "delegate" if ("deleg" in r) else "referee"


def parse_referees(g: dict) -> list[dict]:
    """Obsada wiersza /api/games. POTWIERDZONY ksztalt (proba 28.10): `nominees` = grupy po rolach
    `[{"role":"referees","names":["FABRYCZNY Michal","RAWICKI Jakub"]},{"role":"delegates","names":["TARCZYKOWSKI Jakub"]}]`,
    nazwy "NAZWISKO Imie". Wynik: `{name: "Imie Nazwisko", id, role: referee|delegate, position}`; sedziowie dostaja
    pozycje A, B (z kolejnosci), delegaci D1, D2. Czytamy tez inne klucze z "referee"/"judge"/"sedzi" (napisy, obiekty, listy).
    Bez powtorzen, najwyzej 8."""
    out: list[dict] = []
    seen: set[tuple] = set()
    counters = {"referee": 0, "delegate": 0}

    def put(name: str | None, role: str, pid: Any = None, pos: str | None = None) -> None:
        if not name or len(out) >= 8:
            return
        name = display_name(name)
        if (name.casefold(), role) in seen:
            return
        seen.add((name.casefold(), role))
        counters[role] += 1
        n = counters[role]
        auto = ("A", "B", "C", "D")[n - 1] if role == "referee" and n <= 4 else (f"D{n}" if role == "delegate" else None)
        out.append({"name": name, "id": _txt(pid, 40) if pid is not None else None, "role": role, "position": pos or auto})

    def add(v: Any, role: str = "referee") -> None:
        if isinstance(v, dict) and isinstance(v.get("names"), list):  # grupa {role, names[]}
            grole = _role_of(v.get("role"))
            for n in v["names"]:
                put(_person_name(n), grole)
            return
        pid = pos = None
        if isinstance(v, dict):
            inner = next((v[k] for k in ("referee", "judge", "user", "person") if isinstance(v.get(k), dict)), {})
            pid = v.get("id") if v.get("id") is not None else v.get("judge_id") or v.get("referee_id") or inner.get("id")
            pos = _txt(v.get("position"), 30)
            role = _role_of(v.get("role") or v.get("type") or v.get("function")) if (v.get("role") or v.get("type") or v.get("function")) else role
        put(_person_name(v), role, pid, pos)

    for key, value in g.items():
        k = str(key).lower()
        if not any(h in k for h in _REFEREE_KEY_HINTS) or k.endswith("_id") or k.endswith("_ids"):
            continue
        for item in value if isinstance(value, list) else [value]:
            add(item)
    return out


def normalize_game(g: Any) -> dict | None:
    """Jeden wiersz /api/games -> {bunny_item_id|None, title, home, away, date, competition, code, ...}. Mecz bez nagrania
    (bunny_item_id None) zostaje z video_state; konsumenci pomijaja go tam, gdzie potrzebna jest kaseta."""
    if not isinstance(g, dict):
        return None
    item = _int(g.get("bunny_item_id"))
    item = item if item is not None and item >= 1 else None  # mecz bez nagrania zostaje (kanal: "czeka na nagranie")
    game_id = _int(g.get("id"))
    if item is None and game_id is None and not (g.get("home_team") or g.get("away_team")):
        return None
    home, away = _txt(g.get("home_team")), _txt(g.get("away_team"))
    code = _txt(g.get("game_code"), 40)
    date = _txt(g.get("date"), 40)
    sc = g.get("score") if isinstance(g.get("score"), dict) else {}
    score = None
    if _int(sc.get("full_home")) is not None and _int(sc.get("full_away")) is not None:
        score = f"{_int(sc.get('full_home'))}:{_int(sc.get('full_away'))}"
    title = " - ".join(x for x in (f"{home} - {away}" if home and away else (home or away), code) if x) or f"Mecz {item or game_id}"
    out = {"bunny_item_id": item, "game_id": game_id, "title": title, "home": home, "away": away, "date": date,
           "competition": _txt(g.get("type_name")) or _txt(g.get("series")), "code": code, "score": score,
           "video_state": _txt(g.get("video_state"), 20), "video_coverage": _int(g.get("video_coverage")),
           "thumbnail": None, "duration_s": None, "referees": parse_referees(g),
           "unscheduled": bool(g.get("unscheduled"))}
    return out


def normalize_games(body: Any, limit: int, debug: bool = False) -> dict:
    items = body.get("items") if isinstance(body, dict) else None
    items = items if isinstance(items, list) else []
    games = [n for n in (normalize_game(x) for x in items) if n][:limit]
    paging = body.get("paging") if isinstance(body, dict) and isinstance(body.get("paging"), dict) else {}
    out = {"games": games, "total": _int(paging.get("total")), "has_more": bool(paging.get("has_more"))}
    if debug:  # tylko proba: ksztalt wierszy portalu, liczniki i surowa probka
        first = items[0] if items and isinstance(items[0], dict) else {}
        out.update(row_keys=sorted(str(k) for k in first)[:40], rows_raw=len(items), rows_kept=len(games),
                   raw_sample=[{k: x.get(k) for k in ("id", "bunny_item_id", "video_state", "video_coverage", "nominees", "game_code",
                                                      "home_team", "away_team", "type_name", "date", "unscheduled")}
                               for x in items[:3] if isinstance(x, dict)])
    return out


async def fetch_games(req, base_url: str, q: str, limit: int, offset: int, season_id: int | None, video: str,
                      referee: str = "", referee_param: str = "q") -> tuple[str, int | None, Any]:
    """Zwraca (kod, http, cialo). Kody jak w classify; 200 z nie-obiektem = BASTION_BAD_RESPONSE.
    `referee` = nazwisko sedziego; trafia do parametru `referee_param` (z listy REFEREE_PARAMS, domyslnie zwykle `q`)."""
    params: dict[str, Any] = {"limit": str(limit), "offset": str(offset)}
    if q:
        params["q"] = q
    if referee:
        params[referee_param if referee_param in REFEREE_PARAMS else "q"] = referee
    if season_id is not None:
        params["season_id"] = str(season_id)
    if video in ("with", "without"):
        params["video"] = video
    try:
        resp = await req.get(f"{base_url}/api/games", params=params, timeout=15000, max_redirects=0)
        try:
            body = await resp.json()
        except Exception:  # noqa: BLE001
            body = None
    except Exception as e:  # noqa: BLE001
        return "BASTION_UNAVAILABLE", None, type(e).__name__
    st = resp.status
    if st == 401:
        return "BASTION_AUTH_REQUIRED", st, None
    if st == 403:
        return "BASTION_RESOURCE_FORBIDDEN", st, None
    if st == 429:
        return "BASTION_RATE_LIMITED", st, None
    if st != 200:
        return "BASTION_UNAVAILABLE", st, None
    if not isinstance(body, dict):
        return "BASTION_BAD_RESPONSE", st, None
    return "OK", st, body
