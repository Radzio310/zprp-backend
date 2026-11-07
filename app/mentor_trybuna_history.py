"""Trybuna Mentora - CAŁA historia meczów jednej osoby (sędzia, delegat) z hurtowni ZPRP, stronami.

`GET /mentor-panel/trybuna/referees/history` uzupełnia kartę sędziego (`/trybuna/referees/card`, która pokazuje tylko
8 ostatnich i 5 nadchodzących): te same zasady szukania osoby (numer sędziego albo nazwisko rozwiązane po liście sędziów),
ten sam aktor (`base_actor`) i to samo kryterium meczu (`referee_1/2_id`, `delegate_1/2_id`). Tylko do odczytu.

Każdy wiersz to mecz z rolą osoby, partnerem, pełną obsadą i tanimi sygnałami nagrania:
- `youtube`: transmisja znana portalowi (`match_streams`),
- `proel`: protokół ProEla (`saved_matches`),
- `baza`: mecz jest już w BAZIE (Trybuna moich par albo nagranie w meczu pary),
- `bastion`: kaseta Meczoteki dopasowana do meczu - WYŁĄCZNIE z pamięci karty sędziego (bez nowych zapytań do Bastionu;
  karta otwiera się przed historią, więc pamięć zwykle jest ciepła). `bastion_state` mówi, czy pamięć była.
"""

from __future__ import annotations

import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Tuple

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy import func, or_, select

from app import mentor_bastion_search as S
from app import mentor_panel_core as C
from app import mentor_panel_rules as R
from app import mentor_trybuna_feed as FD
from app import mentor_trybuna_rules as T
from app.db import database, match_streams, mentor_match_videos, mentor_watched_matches, saved_matches, zprp_public_matches
from app.mentor_panel_auth import base_actor

router = APIRouter(prefix="/mentor-panel", tags=["Mentor Trybuna"])
Actor = C.MentorActor
M = zprp_public_matches
W = mentor_watched_matches

#: Strona historii: domyślnie 30, najwyżej 100 wierszy.
PAGE_DEFAULT = 30
PAGE_MAX = 100
ROLE_LABELS = {"referee": "sędzia", "delegate": "delegat"}
_SEASON = re.compile(r"^(\d{4})/(\d{4})$")


def season_bounds(season: str) -> Optional[Tuple[datetime, datetime]]:
    """„2025/2026" -> [1.09.2025, 1.09.2026) w czasie polskim (hurtownia trzyma godzinę bez strefy). Zły zapis -> None."""
    m = _SEASON.match(season or "")
    if not m or int(m.group(2)) != int(m.group(1)) + 1:
        return None
    start = int(m.group(1))
    return datetime(start, 9, 1), datetime(start + 1, 9, 1)


def role_condition(judge_id: str, role: str):
    """Mecze osoby w danej roli (`referee` / `delegate`) albo w obu (pusty napis) - jak w karcie sędziego."""
    refs = [M.c.referee_1_id == judge_id, M.c.referee_2_id == judge_id]
    dels = [M.c.delegate_1_id == judge_id, M.c.delegate_2_id == judge_id]
    return or_(*(refs if role == "referee" else dels if role == "delegate" else refs + dels))


def history_row(r: Mapping[str, Any], me: Mapping[str, Any], now: datetime) -> Dict[str, Any]:
    """Jeden mecz historii: drużyny, wynik, rozgrywki, rola osoby, partner i pełna obsada (bez sygnałów nagrania)."""
    card = R.card_from_public(r)
    crew = T.referees_of_zprp_row(r)
    crew = [x for x in crew if x["role"] in ("referee", "delegate")]
    mine = next((x for x in crew if T.same_referee(x, me)), None)
    role = (mine or {}).get("role") or "referee"
    partner = None
    if role == "referee":
        partner = next(({"name": x["name"], "judge_id": x["judge_id"]} for x in crew
                        if x["role"] == "referee" and x is not mine and not T.same_referee(x, me)), None)
    home, away = card.get("home") or {}, card.get("away") or {}
    hs, as_ = home.get("score"), away.get("score")
    when = r.get("scheduled_at")
    return {
        "zprp_match_id": R.s(r["match_id"]), "date": FD._iso(card.get("scheduled_at")), "season": card.get("season") or None,
        "home": home.get("name"), "away": away.get("name"), "home_score": hs, "away_score": as_,
        "score": f"{hs}:{as_}" if hs is not None and as_ is not None else None, "halftime": card.get("halftime"),
        "competition": card.get("competition_name"), "code": card.get("match_code"), "round": card.get("round_name"),
        "venue_city": card.get("venue_city"), "role": role, "role_label": ROLE_LABELS.get(role, role),
        "position": (mine or {}).get("position"), "partner": partner,
        "referees": [{"name": x["name"], "judge_id": x["judge_id"], "position": x["position"], "role": x["role"]} for x in crew],
        "upcoming": bool(isinstance(when, datetime) and when >= now),
    }


async def fill_names(items: List[Dict[str, Any]]) -> None:
    """Obsada z samym numerem (hurtownia bez nazwiska) dostaje imię i nazwisko z listy sędziów - partner ma być do kliknięcia."""
    bare = {x["judge_id"] for i in items for x in i["referees"] if x.get("judge_id") and re.match(r"^(Sędzia|Delegat) \S+$", x["name"])}
    if not bare:
        return
    who = await C.people(bare)
    for i in items:
        for x in i["referees"] + ([i["partner"]] if i.get("partner") else []):
            full = (who.get(R.s(x.get("judge_id"))) or {}).get("full_name")
            if full and x.get("judge_id") in bare and full != f"Sędzia {x.get('judge_id')}":
                x["name"] = T.display_name(full)


def cached_games(real: Actor, name: str) -> Optional[List[Dict[str, Any]]]:
    """Kasety Meczoteki z pamięci karty sędziego (ten sam klucz co `/trybuna/referees/card`); brak / wygasła = None."""
    hit = S._swr.get(("card", real.judge_id, T.name_key(name), "any"))
    if not hit or time.monotonic() - hit[0] >= S.SWR_TTL_S:
        return None
    value = hit[1]
    games = value[0] if isinstance(value, tuple) and value else value
    return [g for g in games or [] if isinstance(g, dict) and g.get("bunny_item_id")]


def bastion_twin(r: Mapping[str, Any], games: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Najpewniejsza kaseta dla meczu z hurtowni (próg jak przy formie sezonu w karcie)."""
    card = R.card_from_public(r)
    best, best_conf = None, -1
    for g in games:
        try:
            conf = int(S.score_game(g, card)["confidence"])
        except Exception:  # noqa: BLE001 - dziwna kaseta nie psuje historii
            continue
        if conf >= T.AUTO_MIN and conf > best_conf:
            best, best_conf = g, conf
    return best


async def attach_signals(real: Actor, items: List[Dict[str, Any]], raw: Dict[str, Mapping[str, Any]], games: Optional[List[Dict[str, Any]]]) -> None:
    """Dokłada `youtube`, `proel`, `baza`, `bastion` i `has_video` (na miejscu). Każde źródło osobno: błąd jednego zostawia null."""
    ids = [i["zprp_match_id"] for i in items]
    if not ids:
        return
    yt: Dict[str, Dict[str, Any]] = {}
    try:
        for s in await C.rows(select(match_streams).where(match_streams.c.match_id.in_(ids)).where(match_streams.c.platform == "youtube")
                              .where(match_streams.c.hidden.is_(False)).order_by(match_streams.c.starts_at.desc())):
            yt.setdefault(R.s(s["match_id"]), {"url": s.get("url"), "video_id": s.get("video_id"), "title": s.get("title"),
                                               "thumbnail_url": s.get("thumbnail_url"), "official": s.get("confidence") in ("official", "confirmed")})
    except Exception:  # noqa: BLE001
        C.logger.warning("trybuna: historia - transmisje nieczytelne", exc_info=True)
    proel: set = set()
    try:
        proel = {R.s(f["zprp_match_id"]) for f in await C.rows(select(saved_matches.c.zprp_match_id).where(saved_matches.c.zprp_match_id.in_(ids)))}
    except Exception:  # noqa: BLE001
        C.logger.warning("trybuna: historia - protokoły nieczytelne", exc_info=True)
    pairs = await FD._my_pairs(real)
    pair_ids = [p["id"] for p in pairs]
    baza: Dict[str, List[Dict[str, Any]]] = {}
    if pair_ids:
        try:
            for w in await C.rows(select(W.c.pair_id, W.c.match_id, W.c.zprp_match_id).where(W.c.pair_id.in_(pair_ids))
                                  .where(W.c.zprp_match_id.in_(ids)).where(W.c.deleted_at.is_(None))):
                baza.setdefault(R.s(w["zprp_match_id"]), []).append({"pair_id": w["pair_id"], "match_id": w["match_id"], "kind": "trybuna"})
            keys = {"|".join(sorted(R.s(j) for j in p.get("judge_ids") or [])): p["id"] for p in pairs}
            V = mentor_match_videos
            for v in await C.rows(select(V.c.match_id, V.c.pair_key).where(V.c.match_id.in_(ids)).where(V.c.pair_key.in_(list(keys)))
                                  .where(V.c.deleted_at.is_(None))):
                entry = {"pair_id": keys[v["pair_key"]], "match_id": R.s(v["match_id"]), "kind": "pair_match"}
                if entry not in baza.setdefault(R.s(v["match_id"]), []):
                    baza[R.s(v["match_id"])].append(entry)
        except Exception:  # noqa: BLE001
            C.logger.warning("trybuna: historia - mecze BAZY nieczytelne", exc_info=True)
    twins: Dict[str, Dict[str, Any]] = {}
    if games:
        for i in items:
            g = bastion_twin(raw[i["zprp_match_id"]], games)
            if g is not None:
                twins[i["zprp_match_id"]] = g
        got = await FD.watched_by_item(pair_ids, [int(g["bunny_item_id"]) for g in twins.values()])
        marks = {item: mid for (_, item), mid in got.items()}
        twins = {k: FD.game_row(g, marks) for k, g in twins.items()}
    for i in items:
        mid = i["zprp_match_id"]
        b = twins.get(mid)
        i["youtube"] = yt.get(mid)
        i["proel"] = mid in proel
        i["baza"] = baza.get(mid, [])
        i["bastion"] = b
        i["has_video"] = bool(i["youtube"] or i["baza"] or (b and b.get("state") == "video"))
    await S.attach_crests(items)


@router.get("/trybuna/referees/history")
async def referee_history(response: Response, name: str = Query("", max_length=80), judge_id: str = Query("", max_length=20),
                          offset: int = Query(0, ge=0, le=20000), limit: int = Query(PAGE_DEFAULT, ge=1, le=PAGE_MAX),
                          season: str = Query("", max_length=20), role: str = Query("", pattern="^(|referee|delegate)$"),
                          scope: str = Query("past", pattern="^(past|all)$"), real: Actor = Depends(base_actor)):
    """Cała historia meczów osoby z hurtowni ZPRP (najnowsze najpierw), stronami: `offset`/`limit` -> `next_offset` (null = koniec).
    Filtry: `season` („2025/2026"), `role` (`referee` | `delegate`), `scope` (`past` - rozegrane, domyślnie; `all` - też nadchodzące).
    Pierwsza strona (`offset=0`) niesie też `seasons` (liczby meczów w sezonach, przy wybranej roli) i `roles` (liczby w rolach)."""
    response.headers["Cache-Control"] = "no-store"
    name, judge_id = R.plain(name, 80), R.s(judge_id)
    if not name and not judge_id:
        raise C.err(422, "BAD_QUERY", "Podaj nazwisko albo numer sędziego.")
    bounds = None
    if season:
        bounds = season_bounds(season)
        if bounds is None:
            raise C.err(422, "BAD_SEASON", "Sezon zapisz jak 2025/2026.")
    if judge_id and not name:
        who = await C.people([judge_id])
        name = (who.get(judge_id) or {}).get("full_name") or ""
    if not judge_id:
        judge_id = await FD.resolve_judge(name) or ""
    name = T.display_name(name)
    me = {"name": name, "judge_id": judge_id or None}
    out: Dict[str, Any] = {"referee": me, "items": [], "offset": offset, "limit": limit, "next_offset": None, "total": 0,
                           "season": season or None, "role": role or None, "scope": scope, "bastion_state": "none"}
    if not judge_id:
        # Bez numeru sędziego hurtownia nie powie, gdzie ktoś sędziował (jak karta: ZPRP puste, reszta działa).
        out["unresolved"] = True
        return out
    now = FD._naive_local_now()
    cond = [role_condition(judge_id, role)]
    if bounds:
        cond += [M.c.scheduled_at >= bounds[0], M.c.scheduled_at < bounds[1]]
    if scope == "past":
        cond.append(M.c.scheduled_at < now)
    total = int(await database.fetch_val(select(func.count()).select_from(M).where(*cond)) or 0)
    page = await C.rows(select(M).where(*cond).order_by(M.c.scheduled_at.desc().nullslast(), M.c.match_id.desc()).offset(offset).limit(limit))
    raw = {R.s(r["match_id"]): r for r in page}
    items = [history_row(r, me, now) for r in page]
    await fill_names(items)
    games = cached_games(real, name)
    out["bastion_state"] = "cached" if games is not None else "cold"
    await attach_signals(real, items, raw, games)
    out.update({"items": items, "total": total, "next_offset": offset + len(items) if offset + len(items) < total else None})
    if offset == 0:
        # Słupki sezonów i liczby ról: wszystkie mecze osoby (bez filtra sezonu), żeby filtry pokazały, co jest do wyboru.
        base = [role_condition(judge_id, role)] + ([M.c.scheduled_at < now] if scope == "past" else [])
        seasons: Dict[str, int] = {}
        for r in await C.rows(select(M.c.scheduled_at).where(*base)):
            key = R.season_key(R._local_naive_to_utc(r["scheduled_at"])) if r.get("scheduled_at") else ""
            if key:
                seasons[key] = seasons.get(key, 0) + 1
        out["seasons"] = [{"season": s, "matches": n} for s, n in sorted(seasons.items(), reverse=True)]
        roles = {}
        for key in ("referee", "delegate"):
            extra = [M.c.scheduled_at < now] if scope == "past" else []
            roles[key] = int(await database.fetch_val(select(func.count()).select_from(M).where(role_condition(judge_id, key), *extra)) or 0)
        out["roles"] = roles
    out["generated_at"] = datetime.now(timezone.utc).isoformat()
    return out
