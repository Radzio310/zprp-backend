"""Wiązanie wpisu ręcznego w obsadzie meczu wspólnego z kontem aplikacji (01.11.2026).

Mecz zmigrowany ze starego `myMatches.json` niesie obsadę jako same nazwiska, więc drugi sędzia pary jest wpisem ręcznym
(`judge_id` = NULL) i panel Mentor go nie widzi (karta `my:` wymaga OBU sędziów jako kont). Decyzja właściciela: wpis ręczny
to sam podpis, bez dostępu, więc samo nazwisko NIGDY nie daje dostępu (imiennik!). Wiązanie automatyczne tylko gdy:

- imię i nazwisko po normalizacji (`person_names.person_name_key`: polskie znaki, wielkość liter, dowolna kolejność członów,
  inicjał i Jr/Sr rozróżniają) pasuje dokładnie, co najmniej dwa człony,
- pasujące konto jest zaufanym partnerem któregoś członka obsady z kontem: drugą osobą aktywnej pary mentorskiej albo
  partnerem z dyspozycji (`partner_offtimes`, deklaracja członka), i jest tylko jedno takie konto,
- wpis nie jest świadomą "osobą bez aplikacji" (`no_auto_link`),
- konto nie jest już w obsadzie tego meczu i nie ma blokady "nie dodawaj mnie przez tę osobę" względem autora wpisu.

W pozostałych przypadkach serwer tylko podpowiada konto (`suggestions_for`), a człowiek przypisuje je jawnie (PUT crew/{id}).
Ta sama reguła obowiązuje wszystkie ścieżki: tworzenie, edycja, odczyty, odwrotne wiązanie po koncie i `repair_pair`.

Wiązanie jest idempotentne i bezpieczne przy równoległych wywołaniach (UPDATE warunkowy `judge_id IS NULL`). Zmiana to zwykła
zmiana obsady: rośnie `rev`, wpis w dzienniku (`crew_edit`), odświeżenie paneli par i normalny push „Dodano Cię do meczu".
Wołane przy tworzeniu, dodaniu/edycji wpisu ręcznego, odczycie listy i szczegółów przez członka oraz przy budowie kart pary.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from sqlalchemy import insert, or_, select, update

from app import mentor_panel_core as C
from app import shared_match_notify as N
from app import shared_match_rules as SR
from app.db import (
    database,
    login_records,
    mentoring_pairs,
    partner_offtimes,
    shared_match_blocks,
    shared_match_log,
    shared_match_members,
    shared_matches,
)
from app.person_names import person_name_key, split_name

logger = logging.getLogger("app.shared_match")

M = shared_matches
MM = shared_match_members
s = SR.s

ACCOUNT_TTL_S = 30.0
_index: Optional[Tuple[float, Dict[str, Set[str]], Dict[str, str]]] = None


def reset_account_cache() -> None:
    global _index
    _index = None


def linkable_key(name: Any) -> str:
    """Klucz osoby do wiązania albo "" (puste, jeden człon, same inicjały)."""
    parts, _ = split_name(name)
    return person_name_key(name) if len(parts) >= 2 else ""


def unique_account(name: Any, by_key: Dict[str, Set[str]]) -> Optional[str]:
    """`judge_id` konta, gdy nazwisko pasuje do DOKŁADNIE jednego konta; inaczej None."""
    key = linkable_key(name)
    found = by_key.get(key) if key else None
    return next(iter(found)) if found and len(found) == 1 else None


async def account_index(*, fresh: bool = False) -> Tuple[Dict[str, Set[str]], Dict[str, str]]:
    """(klucz osoby -> zbiór judge_id, judge_id -> pełne nazwisko) z kont aplikacji; krótki cache w pamięci procesu."""
    global _index
    now = time.monotonic()
    if not fresh and _index and now - _index[0] < ACCOUNT_TTL_S:
        return _index[1], _index[2]
    by_key: Dict[str, Set[str]] = {}
    names: Dict[str, str] = {}
    for row in await C.rows(select(login_records.c.judge_id, login_records.c.full_name)):
        jid, full = s(row.get("judge_id")), s(row.get("full_name"))
        key = linkable_key(full)
        if jid and key:
            by_key.setdefault(key, set()).add(jid)
            names[jid] = full
    _index = (now, by_key, names)
    return by_key, names


def _json_list(value: Any) -> List[Any]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return []
    return list(value) if isinstance(value, (list, tuple)) else []


async def trusted_partners(judge_ids: Iterable[Any]) -> Dict[str, Set[str]]:
    """judge_id -> zaufani partnerzy: druga osoba aktywnej pary mentorskiej i partner z dyspozycji (deklaracja TEGO sędziego)."""
    wanted = {s(j) for j in judge_ids if s(j)}
    out: Dict[str, Set[str]] = {j: set() for j in wanted}
    if not wanted:
        return out
    for pair in await C.rows(select(mentoring_pairs.c.judge_ids).where(mentoring_pairs.c.ended_at.is_(None))):
        ids = [s(j) for j in _json_list(pair.get("judge_ids"))]
        if len(ids) == 2 and ids[0] != ids[1]:
            for me, other in ((ids[0], ids[1]), (ids[1], ids[0])):
                if me in wanted:
                    out[me].add(other)
    for row in await C.rows(select(partner_offtimes.c.judge_id, partner_offtimes.c.partner_id)
                            .where(partner_offtimes.c.judge_id.in_(sorted(wanted)))):
        if s(row.get("partner_id")):
            out[s(row["judge_id"])].add(s(row["partner_id"]))
    return out


def trusted_match(name: Any, by_key: Dict[str, Set[str]], trusted: Set[str]) -> Optional[str]:
    """Konto do automatycznego wiązania: dokładne dopasowanie nazwiska ORAZ zaufany partner członka obsady; jedno takie konto."""
    key = linkable_key(name)
    found = {j for j in (by_key.get(key) or set()) if j in trusted} if key else set()
    return next(iter(found)) if len(found) == 1 else None


async def suggestions_for(members: List[Dict[str, Any]]) -> Dict[str, str]:
    """member_id wpisu ręcznego -> judge_id PODPOWIEDZIANEGO konta (dokładne, jednoznaczne nazwisko wśród kont; bez dostępu).

    Pomija konta już będące w obsadzie tego meczu i zablokowane względem autora wpisu. Niczego nie wiąże."""
    out: Dict[str, str] = {}
    try:
        manual = [m for m in members if not s(m.get("judge_id")) and linkable_key(m.get("name"))]
        if not manual:
            return out
        by_key, _ = await account_index()
        present: Dict[str, Set[str]] = {}
        for m in members:
            if s(m.get("judge_id")):
                present.setdefault(s(m["match_id"]), set()).add(s(m["judge_id"]))
        for m in manual:
            jid = unique_account(m.get("name"), by_key)
            if jid and jid not in present.get(s(m["match_id"]), set()) and not await _blocked(jid, s(m.get("added_by"))):
                out[s(m["id"])] = jid
    except Exception:  # noqa: BLE001 - podpowiedź jest dodatkiem
        logger.warning("mecz wspólny: podpowiedź konta nieudana", exc_info=True)
    return out


async def _blocked(judge_id: str, via_judge_id: str) -> bool:
    if not s(via_judge_id):
        return False
    found = await C.one(select(shared_match_blocks.c.judge_id).where(shared_match_blocks.c.judge_id == s(judge_id))
                        .where(shared_match_blocks.c.via_judge_id == s(via_judge_id)))
    return found is not None


async def link_matches(match_ids: Iterable[Any], *, actor_id: str = "", refresh: bool = True) -> List[Dict[str, Any]]:
    """Powiąż wpisy ręczne podanych meczów z kontami. Zwraca listę powiązań `{match_id, member_id, judge_id, name, role}`.

    `actor_id` nie dostaje pusha (to on wywołał odczyt). Nigdy nie rzuca: błąd wiązania nie psuje odczytu."""
    try:
        ids = sorted({s(i) for i in match_ids if s(i)})
        if not ids:
            return []
        manual = await C.rows(select(MM).where(MM.c.match_id.in_(ids)).where(MM.c.judge_id.is_(None)))
        manual = [m for m in manual if linkable_key(m.get("name")) and not m.get("no_auto_link")]
        if not manual:
            return []
        by_key, names = await account_index()
        if not by_key:
            return []
        crew_accounts: Dict[str, Set[str]] = {}
        for row in await C.rows(select(MM.c.match_id, MM.c.judge_id).where(MM.c.match_id.in_(sorted({s(m["match_id"]) for m in manual})))
                                .where(MM.c.judge_id.is_not(None))):
            crew_accounts.setdefault(s(row["match_id"]), set()).add(s(row["judge_id"]))
        partners = await trusted_partners({j for ids_ in crew_accounts.values() for j in ids_})
        candidates: List[Tuple[Dict[str, Any], str]] = []
        for member in manual:
            trusted: Set[str] = set()
            for j in crew_accounts.get(s(member["match_id"]), set()):
                trusted |= partners.get(j, set())
            jid = trusted_match(member.get("name"), by_key, trusted)
            if jid:
                candidates.append((member, jid))
        if not candidates:
            return []
        alive = {s(r["id"]): r for r in await C.rows(select(M).where(M.c.id.in_(sorted({s(m["match_id"]) for m, _ in candidates})))
                                                  .where(M.c.deleted_at.is_(None)))}
        present: Dict[str, Set[str]] = {}
        for row in await C.rows(select(MM.c.match_id, MM.c.judge_id).where(MM.c.match_id.in_(list(alive))).where(MM.c.judge_id.is_not(None))):
            present.setdefault(s(row["match_id"]), set()).add(s(row["judge_id"]))
        linked: List[Dict[str, Any]] = []
        for member, jid in candidates:
            match_id = s(member["match_id"])
            if match_id not in alive or jid in present.setdefault(match_id, set()):
                continue
            if await _blocked(jid, s(member.get("added_by"))):
                continue
            if await _bind(alive[match_id], member, jid, names.get(jid) or s(member.get("name"))):
                present[match_id].add(jid)
                linked.append({"match_id": match_id, "member_id": member["id"], "judge_id": jid, "name": names.get(jid), "role": member["role"]})
        if linked:
            await _announce(linked, alive, actor_id, refresh)
        return linked
    except Exception:  # noqa: BLE001 - wiązanie nie psuje odczytu
        logger.warning("mecz wspólny: wiązanie wpisów ręcznych nieudane", exc_info=True)
        return []


async def _bind(match: Dict[str, Any], member: Dict[str, Any], judge_id: str, account_name: str) -> bool:
    """Podpina konto pod wpis. Prawda tylko wtedy, gdy TO wywołanie go podpięło (wyścig: wygrywa pierwsze)."""
    try:
        async with database.transaction():
            done = await database.fetch_one(
                update(MM).where(MM.c.id == member["id"]).where(MM.c.judge_id.is_(None))
                .values(judge_id=judge_id, name=account_name).returning(MM.c.id))
            if done is None:
                return False
            bumped = await database.fetch_one(
                update(M).where(M.c.id == match["id"]).where(M.c.deleted_at.is_(None))
                .values(rev=M.c.rev + 1, updated_at=C.now()).returning(M.c.rev))
            rev = int(bumped["rev"]) if bumped else int(match.get("rev") or 1)
            await database.execute(insert(shared_match_log).values(
                match_id=match["id"], rev=rev, actor_id="", at=C.now(), action="crew_edit",
                changes_json=C.dumps([{"field": "crew", "from": f"{s(member.get('name'))} (wpis ręczny)",
                                       "to": f"{account_name} (konto w aplikacji)", "member": s(member.get("name"))}])))
        return True
    except Exception:  # noqa: BLE001 - np. wyścig na UniqueConstraint (match_id, judge_id)
        logger.info("mecz wspólny: wpis %s nie został powiązany", member.get("id"), exc_info=True)
        return False


async def _announce(linked: List[Dict[str, Any]], matches: Dict[str, Dict[str, Any]], actor_id: str, refresh: bool) -> None:
    from app.shared_match_pair import refresh_pairs

    by_match: Dict[str, List[Dict[str, Any]]] = {}
    for item in linked:
        by_match.setdefault(item["match_id"], []).append(item)
    for match_id, items in by_match.items():
        row = await C.one(select(M).where(M.c.id == match_id))
        if not row:
            continue
        who = await _adder_name(matches.get(match_id) or row)
        for item in items:
            title, body = N.added(row, who, item["role"])
            await N.send([item["judge_id"]], actor_id, title, body, match_id, "added")
        if refresh:
            referees = [s(m.get("judge_id")) for m in await C.rows(select(MM).where(MM.c.match_id == match_id))
                        if m.get("judge_id") and m.get("role") in SR.REFEREE_ROLES]
            await refresh_pairs(referees, actor_id, match_id)


async def _adder_name(match: Dict[str, Any]) -> str:
    creator = s(match.get("creator_id"))
    if not creator:
        return ""
    row = await C.one(select(login_records.c.full_name).where(login_records.c.judge_id == creator))
    return s((row or {}).get("full_name"))


async def link_for_account(judge_id: str) -> List[Dict[str, Any]]:
    """Odwrotny kierunek: wpisy ręczne, które pasują do konta `judge_id` (żeby sędzia zobaczył mecz od razu po wejściu do aplikacji).

    Wstępny filtr SQL po najdłuższym członie nazwiska (z ogonkami i bez), dokładne rozstrzygnięcie (partner zaufany) robi `link_matches`."""
    try:
        by_key, names = await account_index()
        full = names.get(s(judge_id))
        if not full or not linkable_key(full):
            return []
        parts, _ = split_name(full)
        token = max(parts, key=len)
        original = max((p for p in full.replace(",", " ").split() if len(p) > 1), key=len, default=token)
        patterns = {SR.like_pattern(token), SR.like_pattern(original)}
        conds = [MM.c.name.ilike(p, escape="\\") for p in patterns]
        found = await C.rows(select(MM.c.match_id).where(MM.c.judge_id.is_(None)).where(or_(*conds)).limit(200))
        return await link_matches((f["match_id"] for f in found), actor_id=s(judge_id))
    except Exception:  # noqa: BLE001
        logger.warning("mecz wspólny: wiązanie dla konta nieudane", exc_info=True)
        return []

