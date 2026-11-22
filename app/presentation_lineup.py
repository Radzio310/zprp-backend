"""Tryb prezentacji - NAKŁADKA OBSADY: kto stoi w gnieździe po udawanym zapisie.

Udawane „Zapisz w ZPRP" (`/zprp/obsada/save`), stolikowy z aplikacji
(`/zprp/obsada/table-officials/save|clear`) i zatwierdzona wymiana na giełdzie
(`/match-market/offers/{id}/approve`) zapisują tu zmianę gniazda: wiersz
`presentation_overlay` rodzaju `lineup`, klucz = numer meczu (IdZawody jest
unikalny w całym ZPRP). Prawdziwa migawka `province_matches` zostaje nietknięta.

Odczyty kont trybu (`app/presentation_sim.py`, nakładki `merge_*`) dostają
prawdziwą odpowiedź z podmienionymi gniazdami - w kształcie, w jakim każda
trasa koduje obsadę:

* migawka (`state_json`): `NrSedzia_{gniazdo}` + `NrSedzia_{gniazdo}_nazwisko`,
* lista Obsady i bootstrap: `crew[gniazdo] = {number, name}` + przeliczony `status`,
* Obsada na żywo: `crew[first|second|...] = {name, key, photo}` + `needs`,
* formularz ZPRP (`match-form`): `slots[sedzia1|...].selected_value` i `options`.

Nazwiska w postaci ZPRP („NAZWISKO Imię", `assignment_board_rules.display_name`).
Pusta osoba (`number` i `name` puste) = gniazdo zwolnione.

Moduł nie importuje `app.db` ani `presentation_sim` na poziomie modułu.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional

from app import presentation_state as PS

log = logging.getLogger("presentation")

KIND = "lineup"
#: Gniazda w słowniku modułu obsadowego (`assignment_rules.SLOTS`).
SLOTS = ("pierwszy", "drugi", "sekretarz", "czas", "delegat", "delegat2")
#: Gniazdo modułu -> etykieta formularza ZPRP / giełdy.
ZPRP_LABEL = {
    "pierwszy": "sedzia1",
    "drugi": "sedzia2",
    "sekretarz": "sekretarz",
    "czas": "czas",
    "delegat": "delegat",
    "delegat2": "delegat2",
}
SELECT_NAME = {slot: f"NrSedzia_{slot}" for slot in SLOTS}
#: Obsada na żywo (`obsada_view_rules.SLOT_MAP`, odwrotnie).
VIEW_SLOT = {
    "pierwszy": "first",
    "drugi": "second",
    "sekretarz": "secretary",
    "czas": "time",
    "delegat": "delegate",
    "delegat2": "delegate2",
}
_ALIASES = {
    **{slot: slot for slot in SLOTS},
    **{label: slot for slot, label in ZPRP_LABEL.items()},
    **{SELECT_NAME[slot].lower(): slot for slot in SLOTS},
    **{view: slot for slot, view in VIEW_SLOT.items()},
    # stolikowy z aplikacji (`table-officials/save`, pole `role`)
    "sekretarz_zawodow": "sekretarz",
    "mierzacy_czas": "czas",
    "timekeeper": "czas",
    "secretary": "sekretarz",
}


def _s(value: Any) -> str:
    return "" if value is None else str(value).strip()


def board_slot(value: Any) -> str:
    """Gniazdo w słowniku modułu z dowolnego zapisu (sedzia1, NrSedzia_drugi, first...)."""
    return _ALIASES.get(_s(value).lower(), "")


def zprp_name(name: Any) -> str:
    text = _s(name)
    if not text:
        return ""
    try:
        from app.assignment_board_rules import display_name

        return display_name(text) or text
    except Exception:  # noqa: BLE001
        return text


def person(number: Any, name: Any) -> Dict[str, str]:
    num = _s(number)
    return {"number": "" if num == "0" else num, "name": zprp_name(name)}


def empty(p: Optional[Mapping[str, Any]]) -> bool:
    return not p or (not _s(p.get("number")) and not _s(p.get("name")))


# ───────────────────────────── zapis i odczyt nakładki ─────────────────────────────


async def record(
    match_id: Any,
    changes: Mapping[str, Mapping[str, Any]],
    *,
    province: Any = "",
    source: str = "",
    account: str = "",
) -> Optional[Dict[str, Any]]:
    """Dopisz zmianę gniazd meczu. `changes` = {gniazdo (dowolny zapis): {number, name}}."""
    mid = _s(match_id)
    clean = {board_slot(k): person(v.get("number"), v.get("name")) for k, v in (changes or {}).items() if board_slot(k)}
    if not mid or not clean:
        return None
    found = await PS.overlay_get(KIND, mid)
    data = dict(found[1]) if found else {"match_id": mid, "province": "", "slots": {}, "log": []}
    if _s(province):
        data["province"] = _canonical(province)
    data["slots"] = {**(data.get("slots") or {}), **clean}
    now = datetime.now(timezone.utc).isoformat()
    data["updated_at"] = now
    data["log"] = (list(data.get("log") or []) + [{"at": now, "source": source, "account": account, "slots": clean}])[-20:]
    if found:
        await PS.overlay_put(found[0], data)
    else:
        await PS.overlay_add(KIND, mid, data)
    return data


async def load() -> Dict[str, Dict[str, Any]]:
    """Wszystkie zmiany obsady trybu: {numer meczu: {match_id, province, slots, updated_at}}."""
    db = PS._db()
    t = db.presentation_overlay
    rows = await db.database.fetch_all(t.select().where(t.c.kind == KIND).order_by(t.c.id))
    out: Dict[str, Dict[str, Any]] = {}
    for r in rows:
        data = PS._loads(r["data_json"], {}) or {}
        if data.get("slots"):
            out[_s(r["key"])] = data
    return out


def _canonical(province: Any) -> str:
    try:
        from app.settlement_province import canonical

        return canonical(province) or _s(province)
    except Exception:  # noqa: BLE001
        return _s(province).upper()


def same_province(a: Any, b: Any) -> bool:
    """Puste = nie wiemy, więc pasuje (numer meczu i tak jest unikalny)."""
    return not _s(a) or not _s(b) or _canonical(a) == _canonical(b)


# ───────────────────────────── kształty obsady ─────────────────────────────


def patch_state(state: Mapping[str, Any], slots: Mapping[str, Mapping[str, Any]]) -> Dict[str, Any]:
    """Migawka meczu (`state_json`) z gniazdami z nakładki - kopia."""
    out = dict(state or {})
    for slot, who in (slots or {}).items():
        slot = board_slot(slot)
        if not slot:
            continue
        out[f"NrSedzia_{slot}"] = _s((who or {}).get("number"))
        out[f"NrSedzia_{slot}_nazwisko"] = _s((who or {}).get("name"))
    return out


def patch_crew(crew: Mapping[str, Any], slots: Mapping[str, Mapping[str, Any]]) -> Dict[str, Any]:
    """`crew` listy Obsady ({gniazdo: {number, name} | None}) z nakładką."""
    out = dict(crew or {})
    for slot, who in (slots or {}).items():
        slot = board_slot(slot)
        if slot:
            out[slot] = None if empty(who) else {"number": _s(who.get("number")), "name": _s(who.get("name"))}
    return out


def crew_state(crew: Mapping[str, Any]) -> Dict[str, Any]:
    state: Dict[str, Any] = {}
    for slot in SLOTS:
        who = crew.get(slot) if isinstance(crew, Mapping) else None
        state[f"NrSedzia_{slot}"] = _s((who or {}).get("number"))
        state[f"NrSedzia_{slot}_nazwisko"] = _s((who or {}).get("name"))
    return state


def patch_assignment_item(item: Dict[str, Any], slots: Mapping[str, Mapping[str, Any]], updated_at: Any = None) -> Dict[str, Any]:
    """Mecz `/province/assignments` (i `bootstrap`): obsada + przeliczony stan obsady."""
    if not isinstance(item, dict):
        return item
    item["crew"] = patch_crew(item.get("crew") or {}, slots)
    try:
        from app import assignment_rules as A

        access = item.get("access") or {}
        state = {**crew_state(item["crew"]), "assignment_access": access}
        item["status"] = A.crew_status(
            state, item.get("code"), item.get("table_by_club") or 0,
            slots=access.get("editable_slots") if access else None,
        )
    except Exception:  # noqa: BLE001 - zostaje stary stan obsady
        log.info("tryb prezentacji: stan obsady bez przeliczenia", exc_info=True)
    if updated_at:
        item["updated_at"] = updated_at
    return item


def patch_view_match(match: Dict[str, Any], slots: Mapping[str, Mapping[str, Any]], updated_at: Any = None) -> Dict[str, Any]:
    """Mecz Obsady na żywo: `crew` po kluczach klienta i `needs`."""
    try:
        from app.obsada_view_rules import judge_key
    except Exception:  # noqa: BLE001
        judge_key = lambda name: _s(name).lower().replace(" ", "-")  # noqa: E731
    crew = dict(match.get("crew") or {})
    needs = dict(match.get("needs") or {})
    wanted: Dict[str, bool] = {}
    try:
        from app import assignment_rules as A

        n = A.crew_needs(match.get("code"))
        wanted = {"first": n["field"] >= 1, "second": n["field"] >= 2, "secretary": n["table"] >= 1, "time": n["table"] >= 2}
    except Exception:  # noqa: BLE001
        pass
    for slot, who in (slots or {}).items():
        slot = board_slot(slot)
        if not slot:
            continue
        key = VIEW_SLOT[slot]
        name = _s((who or {}).get("name"))
        crew[key] = {"name": name, "key": judge_key(name), "photo": None} if name else None
        if key in needs:
            needs[key] = bool((needs.get(key) or wanted.get(key)) and not crew[key])
    match["crew"] = crew
    if needs:
        match["needs"] = needs
    if updated_at:
        match["changed_at"] = updated_at
    return match


def view_names(state: Mapping[str, Any]) -> Dict[str, Optional[str]]:
    """Nazwiska gniazd w kluczach Obsady na żywo (jak `obsada_view_rules._names`)."""
    out: Dict[str, Optional[str]] = {}
    for slot, key in VIEW_SLOT.items():
        name = _s((state or {}).get(f"NrSedzia_{slot}_nazwisko"))
        out[key] = None if (not name or name.strip("- ") == "") else name
    return out


def patch_match_form(form: Dict[str, Any], slots: Mapping[str, Mapping[str, Any]]) -> Dict[str, Any]:
    """Formularz ZPRP meczu: wybrana opcja każdego gniazda z nakładki.

    Numery opcji formularza nie są numerami sędziów - opcję szukamy PO NAZWISKU.
    Gdy osoby nie ma na liście (filtr odległości), dokładamy opcję na górze.
    """
    try:
        from app.match_market_rules import names_match
    except Exception:  # noqa: BLE001
        names_match = lambda a, b: _s(a).lower() == _s(b).lower()  # noqa: E731
    form_slots = form.get("slots") if isinstance(form, dict) else None
    if not isinstance(form_slots, dict):
        return form
    for slot, who in (slots or {}).items():
        slot = board_slot(slot)
        data = form_slots.get(ZPRP_LABEL.get(slot, "")) if slot else None
        if not isinstance(data, dict):
            continue
        options = [dict(o) for o in data.get("options") or [] if isinstance(o, dict)]
        for o in options:
            o["selected"] = False
        if empty(who):
            zero = next((o for o in options if _s(o.get("value")) == "0"), None)
            if zero:
                zero["selected"] = True
            data["selected_value"] = "0" if zero else None
        else:
            name = _s(who.get("name"))
            hit = next((o for o in options if names_match(o.get("name"), name)), None)
            if hit is None:
                hit = {"value": _s(who.get("number")) or name, "name": name, "badges": [], "distance_km": None,
                       "has_match_tag": False, "selected": True, "disabled": False}
                options.insert(0, hit)
            hit["selected"] = True
            data["selected_value"] = _s(hit.get("value"))
        data["options"] = options
    return form


def judge_slots(state: Mapping[str, Any], judge_id: Any, full_name: Any = "") -> List[str]:
    """Gniazda (słownik modułu), w których stoi ten sędzia - numer przed nazwiskiem."""
    try:
        from app.match_market_rules import names_match
    except Exception:  # noqa: BLE001
        names_match = lambda a, b: _s(a).lower() == _s(b).lower()  # noqa: E731
    jid = _s(judge_id)
    out = []
    for slot in SLOTS:
        number = _s((state or {}).get(f"NrSedzia_{slot}"))
        name = _s((state or {}).get(f"NrSedzia_{slot}_nazwisko"))
        if number and number != "0":
            if jid and number == jid:
                out.append(slot)
            continue
        if name and _s(full_name) and names_match(name, full_name):
            out.append(slot)
    return out
