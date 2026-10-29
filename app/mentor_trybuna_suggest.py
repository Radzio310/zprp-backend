"""Trybuna: podpowiedzi w trakcie pisania i szukanie osób do obserwowania (runda "lepiej niż Google", 29.10.2026).

Wszystko z LOKALNEJ bazy (hurtownia meczów ZPRP z obsadami, mecze pary i jej Trybuny) - BEZ portalu Bastionu. Indeks (drużyny,
sędziowie, delegaci, kody meczów, rozgrywki) budowany jest z hurtowni raz na 10 min i trzymany w pamięci procesu; samo podpowiadanie
to przejście po kilku tysiącach krótkich wpisów (dziesiątki milisekund). Dopasowanie: bez wielkości liter i polskich znaków,
każde słowo zapytania jest PREFIKSEM jakiegoś słowa wpisu; kody ("SM/3") dopasowują się po zapisie bez ukośnika i spacji ("SM38").
"""

from __future__ import annotations

import logging
import math
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select

from app import mentor_bastion_search as S
from app import mentor_panel_core as C
from app import mentor_panel_rules as R
from app import mentor_trybuna_rules as T
from app.db import mentor_watched_matches, province_judges, zprp_public_matches
from app.mentor_panel_auth import base_actor, mentor_actor

logger = logging.getLogger("app.mentor_panel")
router = APIRouter(prefix="/mentor-panel", tags=["Mentor Trybuna"])
Actor = C.MentorActor

INDEX_TTL_S = 600.0
INDEX_DAYS = 800
MIN_CHARS = 2
KIND_ORDER = {"code": 0, "match": 1, "team": 2, "referee": 3, "competition": 4}
_index: Optional[Tuple[float, Dict[str, Any]]] = None


def forget_index() -> None:
    global _index
    _index = None


#: Nazwy okręgów do WYŚWIETLENIA (w bazie bywają zapisane wielkimi literami albo bez polskich znaków: "SLASKIE", "ŚLĄSKIE").
PROVINCE_NAMES = {
    "DOLNOSLASKIE": "dolnośląskie", "KUJAWSKO_POMORSKIE": "kujawsko-pomorskie", "LODZKIE": "łódzkie", "LUBELSKIE": "lubelskie",
    "LUBUSKIE": "lubuskie", "MALOPOLSKIE": "małopolskie", "MAZOWIECKIE": "mazowieckie", "OPOLSKIE": "opolskie",
    "PODKARPACKIE": "podkarpackie", "PODLASKIE": "podlaskie", "POMORSKIE": "pomorskie", "SLASKIE": "śląskie",
    "SWIETOKRZYSKIE": "świętokrzyskie", "WARMINSKO_MAZURSKIE": "warmińsko-mazurskie", "WIELKOPOLSKIE": "wielkopolskie",
    "ZACHODNIOPOMORSKIE": "zachodniopomorskie",
}


def province_display(value: Any) -> Optional[str]:
    """Okręg do pokazania z polskimi znakami (normalizacja służy tylko do rozpoznania); nieznany zostaje, jak jest."""
    text = R.s(value)
    if not text:
        return None
    from app.exam_live_brand import province_slug

    return PROVINCE_NAMES.get(province_slug(text), text)


def plain_tokens(value: Any) -> List[str]:
    return [w for w in re.split(r"[^0-9a-z]+", S._plain(value)) if w]


def compact(value: Any) -> str:
    return "".join(plain_tokens(value))


def tokens_match(q_tokens: List[str], cand_tokens: List[str]) -> bool:
    """Każde słowo zapytania jest prefiksem jakiegoś słowa wpisu."""
    return bool(q_tokens) and all(any(c.startswith(q) for c in cand_tokens) for q in q_tokens)


def prefix_score(q_plain: str, q_tokens: List[str], cand_plain: str, cand_tokens: List[str]) -> int:
    if cand_plain.startswith(q_plain):
        return 3
    return 2 if cand_tokens and cand_tokens[0].startswith(q_tokens[0]) else 1


async def build_index() -> Dict[str, Any]:
    """Indeks z hurtowni (ostatnie ~2 sezony): drużyny, osoby z obsad (sędziowie / delegaci), kody meczów, rozgrywki."""
    M = zprp_public_matches
    since = datetime.now() - timedelta(days=INDEX_DAYS)
    rows = await C.rows(select(M.c.home_team_name, M.c.away_team_name, M.c.competition_name, M.c.match_code, M.c.scheduled_at,
                               M.c.referee_1_id, M.c.referee_1_name, M.c.referee_2_id, M.c.referee_2_name,
                               M.c.delegate_1_id, M.c.delegate_1_name, M.c.delegate_2_id, M.c.delegate_2_name)
                        .where(M.c.scheduled_at >= since))
    teams: Dict[str, Dict[str, Any]] = {}
    comps: Dict[str, Dict[str, Any]] = {}
    codes: Dict[str, Dict[str, Any]] = {}
    people: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for r in rows:
        for side in ("home_team_name", "away_team_name"):
            name = R.s(r.get(side))
            if name:
                teams.setdefault(name, {"name": name, "count": 0})["count"] += 1
        comp = R.s(r.get("competition_name"))
        if comp:
            comps.setdefault(comp, {"name": comp, "count": 0})["count"] += 1
        code = R.s(r.get("match_code"))
        if code:
            c = codes.get(code)
            if c is None or (r.get("scheduled_at") and (c["when"] is None or r["scheduled_at"] > c["when"])):
                codes[code] = {"code": code, "when": r.get("scheduled_at"), "home": r.get("home_team_name"), "away": r.get("away_team_name"),
                               "count": (c or {"count": 0})["count"]}
            codes[code]["count"] += 1
        for role, slots in (("referee", ("referee_1", "referee_2")), ("delegate", ("delegate_1", "delegate_2"))):
            for slot in slots:
                name, jid = R.s(r.get(f"{slot}_name")), R.s(r.get(f"{slot}_id"))
                if not name or name.lower().startswith(("sędzia ", "delegat ")) and not jid:
                    continue
                key = (role, T.name_key(name))
                p = people.setdefault(key, {"role": role, "name": T.display_name(name), "judge_id": jid or None, "count": 0})
                p["count"] += 1
                p["judge_id"] = p["judge_id"] or jid or None
    for coll, key in ((teams, "name"), (comps, "name")):
        for v in coll.values():
            v["plain"], v["tokens"] = " ".join(plain_tokens(v[key])), plain_tokens(v[key])
    for v in codes.values():
        v["compact"] = compact(v["code"])
    for v in people.values():
        v["plain"], v["tokens"] = " ".join(plain_tokens(v["name"])), plain_tokens(v["name"])
    return {"teams": list(teams.values()), "comps": list(comps.values()), "codes": list(codes.values()), "people": list(people.values())}


async def get_index() -> Dict[str, Any]:
    global _index
    if _index and time.monotonic() - _index[0] < INDEX_TTL_S:
        return _index[1]
    try:
        built = await build_index()
    except Exception:  # noqa: BLE001 - brak hurtowni = puste podpowiedzi, nie błąd
        logger.warning("trybuna: indeks podpowiedzi nieudany", exc_info=True)
        built = {"teams": [], "comps": [], "codes": [], "people": []}
    _index = (time.monotonic(), built)
    return built


def _day(value: Any) -> str:
    d = S.card_day({"scheduled_at": value}) if value else None
    return d.strftime("%d.%m.%Y") if d else ""


async def watched_light(pair_id: str) -> List[Dict[str, Any]]:
    """Lekkie karty meczów z Trybuny pary (z migawki, bez wzbogacania)."""
    found = await C.rows(select(mentor_watched_matches).where(mentor_watched_matches.c.pair_id == pair_id)
                         .where(mentor_watched_matches.c.deleted_at.is_(None)).limit(500))
    return [T.card_from_snapshot(r["match_id"], R.json_value(r.get("card_json"), {}), title=r.get("title")) for r in found]


@router.get("/pairs/{pair_id}/trybuna/suggest")
async def suggest(pair_id: str, q: str = Query("", max_length=80), limit: int = Query(8, ge=1, le=20), actor: Actor = Depends(mentor_actor)):
    """Podpowiedzi w trakcie pisania (z lokalnej bazy, bez portalu): `{items: [{kind: team|referee|code|competition|match, label, sub,
    value, crest|null, match_id?}]}`. `value` wstawia się do pola szukania. `match` = mecz tej pary albo z jej Trybuny (`match_id`).
    Zapytanie krótsze niż 2 znaki zwraca pustą listę."""
    ctx = await C.pair_context(pair_id, actor)
    C.check(ctx, "video")
    q_plain = " ".join(plain_tokens(q))
    q_tokens = plain_tokens(q)
    if len(q_plain.replace(" ", "")) < MIN_CHARS:
        return {"items": []}
    q_compact = compact(q)
    code_like = "/" in q or any(ch.isdigit() for ch in q)
    index = await get_index()
    scored: List[Tuple[Tuple[int, int, int, float], Dict[str, Any]]] = []

    def add(kind: str, score: int, count: int, item: Dict[str, Any]) -> None:
        scored.append(((-score, KIND_ORDER[kind], 0, -math.log1p(count)), {"kind": kind, **item}))

    for t in index["teams"]:
        if tokens_match(q_tokens, t["tokens"]):
            add("team", prefix_score(q_plain, q_tokens, t["plain"], t["tokens"]), t["count"],
                {"label": t["name"], "sub": f"drużyna · {t['count']} meczów", "value": t["name"], "crest": None})
    for p in index["people"]:
        if tokens_match(q_tokens, p["tokens"]):
            add("referee", prefix_score(q_plain, q_tokens, p["plain"], p["tokens"]), p["count"],
                {"label": p["name"], "sub": f"{'delegat' if p['role'] == 'delegate' else 'sędzia'} · {p['count']} meczów", "value": p["name"], "crest": None})
    for c in index["comps"]:
        if tokens_match(q_tokens, c["tokens"]):
            add("competition", prefix_score(q_plain, q_tokens, c["plain"], c["tokens"]), c["count"],
                {"label": c["name"], "sub": f"rozgrywki · {c['count']} meczów", "value": c["name"], "crest": None})
    if code_like and q_compact:
        for c in index["codes"]:
            if c["compact"].startswith(q_compact):
                when = _day(c.get("when"))
                teams = " - ".join(x for x in (c.get("home"), c.get("away")) if x)
                add("code", 3 if c["compact"] == q_compact else 2, c["count"],
                    {"label": c["code"], "sub": " · ".join(x for x in (teams, when) if x), "value": c["code"], "crest": None})
    pair_cards = await C.pair_match_cards(ctx["judge_ids"])
    for card, origin in [(c, "Mecz pary") for c in pair_cards] + [(c, "Trybuna") for c in await watched_light(ctx["pair_id"])]:
        home, away = (card.get("home") or {}).get("name"), (card.get("away") or {}).get("name")
        cand = plain_tokens(f"{home or ''} {away or ''} {card.get('match_code') or ''}")
        if cand and tokens_match(q_tokens, cand):
            label = " - ".join(x for x in (home, away) if x) or card.get("title") or "mecz"
            add("match", 3, 1, {"label": label, "sub": " · ".join(x for x in (_day(card.get("scheduled_at")), card.get("match_code"), origin) if x),
                                "value": card.get("match_code") or home or label, "crest": (card.get("home") or {}).get("logo_url"),
                                "match_id": card["match_id"]})
    scored.sort(key=lambda x: x[0])
    items = [it for _, it in scored[:limit]]
    for it in items:
        if it["kind"] == "team" and not it.get("crest"):
            it["crest"] = await S.crest_for(it["label"])
    return {"items": items}


@router.get("/trybuna/people")
async def people(q: str = Query("", max_length=80), limit: int = Query(20, ge=1, le=50), real: Actor = Depends(base_actor)):
    """Szukanie sędziów i delegatów po nazwisku (do obserwowania), z obsad ZPRP: `[{kind: referee|delegate, name, judge_id|null, province,
    crest|null, matches_count}]` - po liczbie meczów malejąco. `crest` to herb okręgu sędziego (ścieżka względem API)."""
    q_tokens = plain_tokens(q)
    if len("".join(q_tokens)) < MIN_CHARS:
        return []
    found = [p for p in (await get_index())["people"] if tokens_match(q_tokens, p["tokens"])]
    found.sort(key=lambda p: -p["count"])
    found = found[:limit]
    ids = sorted({p["judge_id"] for p in found if p["judge_id"]})
    provinces = {R.s(r["judge_id"]): r.get("province") for r in await C.rows(
        select(province_judges.c.judge_id, province_judges.c.province).where(province_judges.c.judge_id.in_(ids)))} if ids else {}
    from app import exam_live_brand as EB

    out = []
    for p in found:
        prov = provinces.get(p["judge_id"] or "")
        crest = None
        if prov:
            palette = EB.palette_for("province", prov)
            crest = f"/exam-live/assets/img/{EB.crest_name(palette)}" if palette.get("kind") == "province" else None
        out.append({"kind": p["role"], "name": p["name"], "judge_id": p["judge_id"], "province": province_display(prov), "crest": crest,
                    "matches_count": p["count"]})
    return out
