"""Prawa BAZA i zakres sugestii to osobne decyzje. Bez bazy i sieci."""
from __future__ import annotations

from typing import Any, Iterable, Mapping

from app.assignment_rules import FIELD_SLOTS, TABLE_SLOTS, DELEGATE_SLOTS
from app.match_market_rules import league_level, is_managed_by_province
from app.province_clubs_scrape import team_key
from app.settlement_origin import is_other_district

AUTO_SLOTS = (*FIELD_SLOTS, *TABLE_SLOTS)
ALL_SLOTS = (*AUTO_SLOTS, *DELEGATE_SLOTS)
FORM_SLOTS = {"pierwszy": "sedzia1", "drugi": "sedzia2", "sekretarz": "sekretarz",
              "czas": "czas", "delegat": "delegat", "delegat2": "delegat2"}


def node_enabled(node: Any) -> bool:
    """Ukryte formularze/przyciski oraz disabled nie nadają praw."""
    if node is None:
        return False
    for part in [node, *node.parents]:
        if getattr(part, "attrs", None) is None:
            continue
        style = str(part.get("style", "")).lower().replace(" ", "")
        if (part.has_attr("hidden") or part.has_attr("disabled")
                or part.get("aria-hidden") == "true" or part.get("aria-disabled") == "true"
                or "display:none" in style or "visibility:hidden" in style):
            return False
    return True


def schedule_controls(cells: Iterable[Any]) -> dict:
    result = {"referees": False, "hall": False, "date": False}
    for cell in cells:
        for form in cell.find_all("form"):
            action = str(form.get("action", "")).lower()
            key = next((key for key, marker in (("referees", "ustawsedziow"),
                       ("hall", "ustawhale"), ("date", "ustawdate")) if marker in action), None)
            if key and any(node_enabled(b) for b in form.find_all(["button", "input"])
                           if b.name == "button" or b.get("type", "").lower() in {"button", "submit"}):
                result[key] = True
        # Starszy widok otwiera termin przez link albo zdarzenie na komórce.
        for node in [cell, *cell.find_all(["a", "button", "input", "span"])]:
            target = " ".join(str(node.get(k, "")) for k in ("href", "onclick", "ondblclick"))
            if "ustawdate" in target.lower() and node_enabled(node):
                result["date"] = True
    return result


def form_editable(slots: Mapping[str, Any]) -> list[str]:
    return [slot for slot, key in FORM_SLOTS.items()
            if slots.get(key, {}).get("editable") is True]


def own_participant(state: Mapping[str, Any], team_names: Iterable[str], team_ids: Iterable[str] = ()) -> bool:
    ids = set(team_ids)
    for key in ("ID_zespoly_gosp", "ID_zespoly_gosc", "IdZespolGosp", "IdZespolGosc"):
        if str(state.get(key) or "").strip() in ids:
            return True
    names = set(team_names)
    return any(team_key(state.get(key)) in names for key in
               ("ID_zespoly_gosp_ZespolNazwa", "ID_zespoly_gosc_ZespolNazwa"))


def access_for(state: Mapping[str, Any], code: str, *, managed=(), own=(),
               own_team: bool = False, province: str = "") -> dict:
    controls = state.get("assignment_controls")
    modern = isinstance(controls, dict)
    legacy_own = is_managed_by_province(code, managed) and not is_other_district(code, own)
    # Sam prefiks starej migawki nie potwierdza przycisku ani prawa do obsady.
    visible = controls.get("referees") is True if modern else False
    from app.zprp_accounts import normalize_province
    label = team_key(state.get("organizer_label"))
    central = league_level(code) == "central" or label == "departament rozgrywek krajowych"
    organization_provinces = {
        "dolnoslaski": "DOLNOSLASKIE", "kujawsko pomorski": "KUJAWSKO_POMORSKIE",
        "lubelski": "LUBELSKIE", "lubuski": "LUBUSKIE", "lodzki": "LODZKIE",
        "malopolski": "MALOPOLSKIE", "mazowiecki": "MAZOWIECKIE", "warszawsko mazowiecki": "MAZOWIECKIE", "opolski": "OPOLSKIE",
        "podkarpacki": "PODKARPACKIE", "podlaski": "PODLASKIE", "pomorski": "POMORSKIE",
        "slaski": "SLASKIE", "swietokrzyski": "SWIETOKRZYSKIE",
        "warminsko mazurski": "WARMINSKO_MAZURSKIE", "wielkopolski": "WIELKOPOLSKIE",
        "zachodniopomorski": "ZACHODNIOPOMORSKIE"}
    owner = next((value for stem, value in organization_provinces.items() if label.startswith(stem + " ")), "")
    own_organizer = owner == normalize_province(province) if owner else legacy_own
    editable = list(TABLE_SLOTS if central else ALL_SLOTS) if visible else []
    # Ta informacja służy do listy; formularz konkretnego konta rozstrzyga edycję.
    recommended = visible and own_team
    return {
        "manual": bool(visible),
        "editable_slots": editable,
        "auto_slots": [s for s in editable if s in AUTO_SLOTS] if recommended else [],
        "own_team": bool(own_team),
        "recommended": bool(recommended),
        "hall": controls.get("hall") is True if modern else False,
        "date": controls.get("date") is True if modern else False,
        "source": "schedule" if modern else "legacy",
        "organizer": str(state.get("organizer_label") or ("DRK" if central else "")),
        "organizer_kind": "drk" if central else ("own" if own_organizer else "foreign"),
    }


def with_access(state: Mapping[str, Any], access: dict) -> dict:
    return {**state, "assignment_access": access}
