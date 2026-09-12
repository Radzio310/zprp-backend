"""
Po zapisie obsady w ZPRP: poprawiamy WLASNA migawke i sami mowimy o zmianie.

Decyzja uzytkownika z 12.09.2026: „puszczenie obsady przez panel i zapisanie do
ZPRP powinno kazdorazowo informowac o zmianach ten system na serwerze - ale
w taki sposob, aby przejscie automatu potem nie zdublowalo takiego
powiadomienia".

Jak to dziala i dlaczego akurat tak:

  1. WPISUJEMY NOWA OBSADE DO MIGAWKI (`province_matches.state_json`) i liczymy
     odcisk od nowa. To jest caly sekret braku duplikatu: monitor powiadamia
     wtedy, gdy odcisk swiezego pobrania ROZNI SIE od zapamietanego. Skoro
     zapamietany juz niesie te obsade, monitor nie ma o czym mowic.
  2. POWIADAMIAMY SAMI, tym samym kanalem (`province_match_events`) i tymi
     samymi slowami, co monitor - `build_change_events` jest importowane, nie
     przepisane. Klucz zdarzenia (`event_key`) liczy sie z tych samych czlonow,
     wiec nawet gdyby monitor jednak sie odezwal, baza odrzuci powtorke.
  3. PROWADZIMY REJESTR OBSAD (`province_match_judges`): nowy sedzia dostaje
     wpis i „Dodano nowy mecz", zdjety - wygaszenie wpisu i „Usunieto Twoj
     mecz". Bez tego monitor uznalby nowego sedziego za odkrycie i ogloszil go
     drugi raz, a zdjetemu liczylby nieobecnosc przez dwa przebiegi.

Wzorzec: `_sync_slot_holder` z gieldy meczow - ta sama mysl („czynnosc, ktora
uniewaznila migawke, sama ja poprawia"), tylko dla calej szostki gniazd.

⚠ Numer sedziego bierzemy z NASZEJ listy okregu, nie z formularza ZPRP:
`value` opcji w tamtym formularzu nie jest stalym numerem sedziego.
"""

from __future__ import annotations

import logging
from typing import Any, Iterable, Mapping, Optional

from app.assignment_people import name_key

logger = logging.getLogger(__name__)

#: Gniazdo modulu obsadowego -> gniazdo migawki meczu (`CREW_STATE_FIELDS`).
SLOT_TO_CREW: dict[str, str] = {
    "pierwszy": "sedzia1",
    "drugi": "sedzia2",
    "sekretarz": "sekretarz",
    "czas": "czas",
    "delegat": "delegat",
    "delegat2": "delegat2",
}

#: Gniazdo formularza ZPRP (`SELECT_TO_SLOT`) -> gniazdo modulu obsadowego.
FORM_TO_SLOT: dict[str, str] = {value: key for key, value in SLOT_TO_CREW.items()}


def _s(value: Any) -> str:
    return str(value or "").strip()


def crew_ids(state: Mapping[str, Any]) -> set[str]:
    """Numery sedziow stojacych przy meczu. „0" to puste gniazdo, nie czlowiek."""
    from app.match_market_rules import crew_judge_ids

    return set(crew_judge_ids(state))


def changes_from_draft(
    drafted: Mapping[str, Any],
    people: Mapping[str, Any],
) -> dict[str, tuple[str, str]]:
    """
    Gniazda wyslane do ZPRP przelozone na `{gniazdo: (numer, nazwisko)}`.

    `drafted` to gniazda modulu obsadowego z numerem sedziego, `people` to nasza
    lista okregu (numer -> nazwisko). Nazwisko bierze sie STAD, a nie
    z formularza ZPRP - patrz nota na gorze pliku.
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
    Nazwisko -> numer sedziego z listy okregu.

    ⚠ Klucz liczy `name_key`, bo ZPRP podpisuje opcje „NOWAK Jan", a lista
    okregu bywa prowadzona jako „Jan Nowak" - to ten sam czlowiek.
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


#: Pola migawki opisujace hale. Ta sama czworka, na ktorej monitor rozpoznaje
#: „Zmieniono adres hali" - stad jeden komunikat dla obu drog.
HALL_FIELDS = ("Hala_nazwa", "Hala_miasto", "Hala_ulica", "Hala_numer")


async def announce_lineup(
    province: str,
    match_id: str,
    changes: Mapping[str, tuple[Any, Any]],
    *,
    actor: Optional[str] = None,
) -> dict:
    """
    Wpisuje zapisana obsade do migawki i rozsyla powiadomienia.

    `changes` to `{gniazdo: (numer_sedziego, nazwisko)}` - wylacznie gniazda,
    ktore faktycznie zmienilismy. Pusty numer znaczy „gniazdo zdjete".
    """
    from app.match_market_rules import with_slot_holder

    # Numer sedziego, gdy panel go nie podal - po nazwisku z listy okregu.
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

    return await announce_change(province, match_id, patch, actor=actor)


async def announce_hall(
    province: str,
    match_id: str,
    hall: Mapping[str, Any],
    *,
    actor: Optional[str] = None,
) -> dict:
    """
    To samo dla HALI: migawka dostaje nowy adres, obsada - powiadomienie.

    Zmiana hali obchodzi sedziow nie mniej niz zmiana skladu - to inny dojazd,
    a czasem inne miasto. Monitor ma na to gotowy komunikat („Zmieniono adres
    hali w meczu X"), wiec i tu nie piszemy wlasnego.
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
            # na ulice i numer, a nadpisanie pustka skasowaloby to, co wiemy.
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
) -> dict:
    """
    Rdzen: poprawia migawke meczu i oglasza zmiane tak, jak zrobilby to monitor.

    `patch` dostaje obecny stan i oddaje nowy - dzieki temu ta sama droga obsluguje
    i obsade, i hale, i cokolwiek jeszcze panel bedzie umial zapisac.

    Calosc jest oslonieta: zapis w bazie zwiazku JUZ przeszedl, wiec nieudane
    odswiezenie wlasnej kopii nie ma prawa zamienic udanego zapisu w blad.
    Monitor doczyta prawde przy najblizszym przebiegu.
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
                    # Pisownia okregu w migawce bywa inna niz ta z panelu
                    # („ŚLĄSKIE" i „SLASKIE") - szukamy po wszystkich, a dalej
                    # piszemy juz DOKLADNIE ta, ktora stoi w wierszu.
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

        # Rejestr obsad prowadzimy tak samo, jak monitor - razem z jego wlasnym
        # „Dodano nowy mecz", zeby tresc powiadomienia byla jedna dla wszystkich.
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
                # `missing_runs=2` mowi monitorowi „juz policzone" - inaczej
                # doliczylby swoje dwa przebiegi i ogloszil to samo raz jeszcze.
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
