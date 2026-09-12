"""
Po zapisie obsady w ZPRP: poprawiamy WŁASNĄ migawkę i sami mówimy o zmianie.

Decyzja użytkownika z 12.09.2026: „puszczenie obsady przez panel i zapisanie do
ZPRP powinno każdorazowo informować o zmianach ten system na serwerze - ale
w taki sposób, aby przejście automatu potem nie zdublowało takiego
powiadomienia".

Jak to działa i dlaczego akurat tak:

  1. WPISUJEMY NOWĄ OBSADĘ DO MIGAWKI (`province_matches.state_json`) i liczymy
     odcisk od nowa. To jest cały sekret braku duplikatu: monitor powiadamia
     wtedy, gdy odcisk świeżego pobrania RÓŻNI SIĘ od zapamiętanego. Skoro
     zapamiętany już niesie tę obsadę, monitor nie ma o czym mówić.
  2. POWIADAMIAMY SAMI, tym samym kanałem (`province_match_events`) i tymi
     samymi słowami, co monitor - `build_change_events` jest importowane, nie
     przepisane. Klucz zdarzenia (`event_key`) liczy się z tych samych członów,
     więc nawet gdyby monitor jednak się odezwał, baza odrzuci powtórkę.
  3. PROWADZIMY REJESTR OBSAD (`province_match_judges`): nowy sędzia dostaje
     wpis i „Dodano nowy mecz", zdjęty - wygaszenie wpisu i „Usunięto Twój
     mecz". Bez tego monitor uznałby nowego sędziego za odkrycie i ogłosił go
     drugi raz, a zdjętemu liczyłby nieobecność przez dwa przebiegi.

Wzorzec: `_sync_slot_holder` z giełdy meczów - ta sama myśl („czynność, która
unieważniła migawkę, sama ja poprawia"), tylko dla całej szóstki gniazd.

⚠ Numer sędziego bierzemy z NASZEJ listy okręgu, nie z formularza ZPRP:
`value` opcji w tamtym formularzu nie jest stałym numerem sędziego.
"""

from __future__ import annotations

import logging
from typing import Any, Iterable, Mapping, Optional

from app.assignment_people import name_key

logger = logging.getLogger(__name__)

#: Gniazdo modułu obsadowego -> gniazdo migawki meczu (`CREW_STATE_FIELDS`).
SLOT_TO_CREW: dict[str, str] = {
    "pierwszy": "sedzia1",
    "drugi": "sedzia2",
    "sekretarz": "sekretarz",
    "czas": "czas",
    "delegat": "delegat",
    "delegat2": "delegat2",
}

#: Gniazdo formularza ZPRP (`SELECT_TO_SLOT`) -> gniazdo modułu obsadowego.
FORM_TO_SLOT: dict[str, str] = {value: key for key, value in SLOT_TO_CREW.items()}


def _s(value: Any) -> str:
    return str(value or "").strip()


def crew_ids(state: Mapping[str, Any]) -> set[str]:
    """Numery sędziów stojących przy meczu. „0" to puste gniazdo, nie człowiek."""
    from app.match_market_rules import crew_judge_ids

    return set(crew_judge_ids(state))


def changes_from_draft(
    drafted: Mapping[str, Any],
    people: Mapping[str, Any],
) -> dict[str, tuple[str, str]]:
    """
    Gniazda wysłane do ZPRP przełożone na `{gniazdo: (numer, nazwisko)}`.

    `drafted` to gniazda modułu obsadowego z numerem sędziego, `people` to nasza
    lista okręgu (numer -> nazwisko). Nazwisko bierze się STĄD, a nie
    z formularza ZPRP - patrz nota na górze pliku.
    """
    out: dict[str, tuple[str, str]] = {}
    for slot, value in drafted.items():
        key = _s(slot)
        if key not in SLOT_TO_CREW:
            continue
        judge_id = _s(value)
        out[key] = (judge_id, _s(people.get(judge_id)) if judge_id else "")
    return out


async def numbers_by_name(province: str, names: Iterable[Any]) -> dict[str, str]:
    """
    Nazwisko -> numer sędziego z listy okręgu.

    ⚠ Klucz liczy `name_key`, bo ZPRP podpisuje opcje „NOWAK Jan", a lista
    okręgu bywa prowadzona jako „Jan Nowak" - to ten sam człowiek.
    """
    wanted = {name_key(name) for name in names if name_key(name)}
    if not wanted:
        return {}
    from sqlalchemy import select

    from app.db import database, province_judges
    from app.settlement_province import spellings

    out: dict[str, str] = {}
    rows = await database.fetch_all(
        select(province_judges.c.judge_id, province_judges.c.full_name).where(
            province_judges.c.province.in_(spellings(province))
        )
    )
    for row in rows:
        key = name_key(row["full_name"])
        if key in wanted and key not in out:
            out[key] = _s(row["judge_id"])
    return out


#: Pola migawki opisujące hale. Ta sama czwórka, na której monitor rozpoznaje
#: „Zmieniono adres hali" - stąd jeden komunikat dla obu dróg.
HALL_FIELDS = ("Hala_nazwa", "Hala_miasto", "Hala_ulica", "Hala_numer")


async def announce_lineup(
    province: str,
    match_id: str,
    changes: Mapping[str, tuple[Any, Any]],
    *,
    actor: Optional[str] = None,
    run_id: Optional[int] = None,
) -> dict:
    """
    Wpisuje zapisana obsadę do migawki i rozsyła powiadomienia.

    `changes` to `{gniazdo: (numer_sedziego, nazwisko)}` - wyłącznie gniazda,
    które faktycznie zmieniliśmy. Pusty numer znaczy „gniazdo zdjęte".
    """
    from app.match_market_rules import with_slot_holder

    # Numer sędziego, gdy panel go nie podal - po nazwisku z listy okręgu.
    missing = [
        _s(name) for judge_id, name in changes.values() if not _s(judge_id) and _s(name)
    ]
    found = await numbers_by_name(province, missing) if missing else {}

    def patch(state: Mapping[str, Any]) -> dict:
        out = dict(state)
        for slot, (judge_id, full_name) in changes.items():
            crew_slot = SLOT_TO_CREW.get(_s(slot))
            if not crew_slot:
                continue
            number = _s(judge_id) or found.get(name_key(full_name), "")
            out = with_slot_holder(out, crew_slot, number, _s(full_name))
        return out

    return await announce_change(province, match_id, patch, actor=actor, run_id=run_id)


async def announce_hall(
    province: str,
    match_id: str,
    hall: Mapping[str, Any],
    *,
    actor: Optional[str] = None,
) -> dict:
    """
    To samo dla HALI: migawka dostaje nowy adres, obsada - powiadomienie.

    Zmiana hali obchodzi sędziów nie mniej niż zmiana składu - to inny dojazd,
    a czasem inne miasto. Monitor ma na to gotowy komunikat („Zmieniono adres
    hali w meczu X"), więc i tu nie piszemy własnego.
    """
    values = {
        "Hala_nazwa": _s(hall.get("name")),
        "Hala_miasto": _s(hall.get("city")),
        "Hala_ulica": _s(hall.get("street") or hall.get("address")),
        "Hala_numer": _s(hall.get("number")),
    }

    def patch(state: Mapping[str, Any]) -> dict:
        out = dict(state)
        for field, value in values.items():
            # Pustego pola NIE wpisujemy: formularz hal nie zawsze rozbija adres
            # na ulice i numer, a nadpisanie pustka skasowałoby to, co wiemy.
            if value:
                out[field] = value
        return out

    return await announce_change(province, match_id, patch, actor=actor)


async def announce_change(
    province: str,
    match_id: str,
    patch: Any,
    *,
    actor: Optional[str] = None,
    run_id: Optional[int] = None,
) -> dict:
    """
    Rdzeń: poprawia migawkę meczu i ogłasza zmianę tak, jak zrobiłby to monitor.

    `patch` dostaje obecny stan i oddaje nowy - dzięki temu ta sama droga obsługuje
    i obsadę, i hale, i cokolwiek jeszcze panel będzie umiał zapisać.

    Całość jest osłonięta: zapis w bazie związku JUŻ przeszedł, więc nieudane
    odświeżenie własnej kopii nie ma prawa zamienić udanego zapisu w błąd.
    Monitor doczyta prawdę przy najbliższym przebiegu.
    """
    from sqlalchemy import and_, func, select, update

    from app.db import database, province_match_judges, province_matches
    from app.match_market_rules import state_dict
    from app.settlement_province import spellings
    from app.province_match_monitor import (
        _create_event,
        _match_details,
        _upsert_assignment,
        build_change_events,
        fingerprint,
    )

    result: dict[str, Any] = {
        "changed": False,
        "events": 0,
        "added": [],
        "removed": [],
        "error": None,
    }
    try:
        row = await database.fetch_one(
            select(
                province_matches.c.state_json,
                province_matches.c.match_code,
                province_matches.c.season,
                province_matches.c.province,
            ).where(
                and_(
                    # Pisownia okręgu w migawce bywa inna niż ta z panelu
                    # („ŚLĄSKIE" i „ŚLĄSKIE") - szukamy po wszystkich, a dalej
                    # piszemy już DOKŁADNIE ta, która stoi w wierszu.
                    province_matches.c.province.in_(spellings(province)),
                    province_matches.c.match_id == _s(match_id),
                )
            )
        )
        if row is None:
            result["error"] = "Meczu nie ma w migawce terminarza okręgu"
            return result
        province = _s(row["province"]) or province

        old = state_dict(row["state_json"])
        if not old:
            result["error"] = "Migawka meczu jest pusta"
            return result

        new = patch(old)
        if new == old:
            return result

        code = _s(new.get("RozgrywkiCode") or row["match_code"])
        new_fp = fingerprint(new)
        await database.execute(
            update(province_matches)
            .where(
                and_(
                    province_matches.c.province == province,
                    province_matches.c.match_id == _s(match_id),
                )
            )
            .values(state_json=new, fingerprint=new_fp, updated_at=func.now())
        )
        result["changed"] = True

        before, after = crew_ids(old), crew_ids(new)
        added = sorted(after - before)
        removed = sorted(before - after)
        stayed = sorted(after & before)
        result["added"], result["removed"] = added, removed

        created = 0
        season = _s(row["season"])
        details = _match_details(new)

        # Rejestr obsad prowadzimy tak samo, jak monitor - razem z jego własnym
        # „Dodano nowy mecz", żeby treść powiadomienia była jedna dla wszystkich.
        for judge_id in added:
            created += await _upsert_assignment(
                province, _s(match_id), judge_id, season, True, new
            )

        for judge_id in removed:
            await database.execute(
                update(province_match_judges)
                .where(
                    and_(
                        province_match_judges.c.province == province,
                        province_match_judges.c.match_id == _s(match_id),
                        province_match_judges.c.judge_id == judge_id,
                    )
                )
                # `missing_runs=2` mówi monitorowi „już policzone" - inaczej
                # doliczyłby swoje dwa przebiegi i ogłosił to samo raz jeszcze.
                .values(active=False, missing_runs=2, updated_at=func.now())
            )
            created += await _create_event(
                province,
                _s(match_id),
                code,
                "assignment_removed",
                f"Usunięto Twój mecz {code}" + (f" • {details}" if details else ""),
                [judge_id],
                new_fp,
            )

        if stayed:
            for event in build_change_events(old, new):
                created += await _create_event(
                    province,
                    _s(match_id),
                    code,
                    event["event_type"],
                    event["body"],
                    stayed,
                    new_fp,
                    previous_state=old,
                )

        # Historia zmian: tylko wtedy, gdy wiemy, z którego przebiegu pochodzą.
        # Ręczna poprawka przy meczu nie ma czego cofać przebiegiem.
        if run_id is not None:
            await _record_changes(province, match_id, code, old, new, run_id, actor)

        result["events"] = created
        logger.info(
            "obsada %s/%s: %s dodanych, %s zdjętych, %s powiadomień (%s)",
            province,
            match_id,
            len(added),
            len(removed),
            created,
            actor or "panel",
        )
        return result
    except Exception as exc:
        logger.exception("obsada: nie udało się ogłosić zmiany w meczu %s", match_id)
        result["error"] = str(exc)
        return result


async def _record_changes(
    province: str,
    match_id: str,
    code: str,
    old: Mapping[str, Any],
    new: Mapping[str, Any],
    run_id: int,
    actor: Optional[str],
) -> int:
    """
    Zapisuje, CO dokładnie zmienił ten przebieg - z osobą, która stała tam przedtem.

    `before_id` jest tu najważniejszy: bez niego cofnięcie umiałoby tylko
    zwolnić gniazdo, a nie przywrócić stan sprzed automatu.

    Osłonięte: obsada w bazie związku już stoi. Brak wpisu w historii odbiera
    możliwość cofnięcia, ale nie unieważnia zapisu - i lepiej powiedzieć o tym
    w logu, niż wywrócić udaną publikację.
    """
    from sqlalchemy import insert

    from app.db import database, province_assignment_changes
    from app.match_market_rules import CREW_STATE_FIELDS

    rows = []
    for slot, (id_field, name_field) in CREW_STATE_FIELDS.items():
        was_id, was_name = _s(old.get(id_field)), _s(old.get(name_field))
        now_id, now_name = _s(new.get(id_field)), _s(new.get(name_field))
        if (was_id, was_name) == (now_id, now_name):
            continue
        rows.append(
            {
                "province": province,
                "run_id": int(run_id),
                "match_id": _s(match_id),
                "match_code": code or None,
                # Gniazdo zapisujemy w słowniku MODUŁU („pierwszy"), nie
                # formularza ZPRP („sedzia1") - cofanie mówi tym samym językiem,
                # co reszta panelu.
                "slot": FORM_TO_SLOT.get(slot, slot),
                "judge_id": now_id or None,
                "judge_name": now_name or None,
                "before_id": was_id or None,
                "before_name": was_name or None,
                "created_by": actor or None,
            }
        )
    if not rows:
        return 0
    try:
        await database.execute_many(insert(province_assignment_changes), rows)
        return len(rows)
    except Exception:
        logger.exception("obsada: nie udało się zapisać historii zmian meczu %s", match_id)
        return 0
