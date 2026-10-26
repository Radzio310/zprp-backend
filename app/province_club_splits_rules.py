"""
Rozbicie klubu na kilka klubów - reguła (moduł-liść, bez bazy i HTTP).

Decyzje właściciela z 26.10.2026 (pamięć `panel-klubow-rozbicie`):
  - rozbić można klub z więcej niż jedną drużyną; każda część ma min. 1 drużynę,
  - część nr 1 to klub MACIERZYSTY (zostaje przy swoim numerze ZPRP i trzyma
    wpłaty oraz wypłaty), części 2+ dostają numer syntetyczny `split:<macierzysty>:<n>`,
  - obciążenia za mecze idą za DRUŻYNĄ (także wcześniejsze w sezonie), bo klub
    drużyny rozstrzyga się na żywo - saldo zawsze wychodzi z podziału,
  - wpłaty i wypłaty zostają w macierzystym, chyba że ręcznie przeniesiono wpis,
  - podział obowiązuje od sezonu, w którym go zrobiono, i dziedziczą go kolejne
    sezony, dopóki ktoś go nie zmieni; "Scal z powrotem" cofa podział od sezonu,
  - synchronizacja z ZPRP nic tu nie cofa: podział to NAKŁADKA na dane z ZPRP
    (osobna tabela), a nie edycja `province_club_teams`.

Przypisanie drużyny to wiersz {parent_club_id, season (od którego sezonu),
team_id, name_key, club_id}. Numer drużyny bywa w innym sezonie inny, więc
drużynę rozpoznajemy po numerze, a gdy go nie ma - po kluczu nazwy; w obu
przypadkach tylko wtedy, gdy ZPRP wciąż trzyma ją w klubie macierzystym.
"""

from __future__ import annotations

import re
from typing import Any, Iterable, Mapping, Optional

from app import club_charges as C
from app.province_clubs_bulk import entry_bucket
from app.settlement_money import money, money_sum

MAX_PARTS = 10
MAX_NAME = 80
PART_PREFIX = "split:"

_ROMAN = ["I", "II", "III", "IV", "V", "VI", "VII", "VIII", "IX", "X"]
_SEASON = re.compile(r"^(\d{4})/(\d{4})$")


def _s(value: Any) -> str:
    return str(value or "").strip()


def season_start(season: Any) -> int:
    match = _SEASON.match(_s(season))
    if not match:
        raise ValueError(f"Nieznany sezon: {season}")
    return int(match.group(1))


def is_part_id(club_id: Any) -> bool:
    return _s(club_id).startswith(PART_PREFIX)


def parent_of_part(club_id: Any) -> str:
    """`split:3608:2` -> `3608` (numer macierzystego bywa z dwukropkiem: bierzemy do ostatniego)."""
    raw = _s(club_id)
    if not raw.startswith(PART_PREFIX):
        return raw
    return raw[len(PART_PREFIX):].rsplit(":", 1)[0]


def part_club_id(parent: str, taken: Iterable[str]) -> str:
    """Pierwszy wolny numer części: split:<macierzysty>:2, :3, ..."""
    used = {_s(item) for item in taken}
    n = 2
    while f"{PART_PREFIX}{parent}:{n}" in used:
        n += 1
    return f"{PART_PREFIX}{parent}:{n}"


def default_names(base: str, count: int) -> list[str]:
    """Nazwa + " (I)", " (II)"... - domyślne nazwy części."""
    base = _s(base)
    return [f"{base} ({_ROMAN[i] if i < len(_ROMAN) else i + 1})".strip() for i in range(count)]


# ---------------------------------------------------------------------------
# Walidacja kreatora
# ---------------------------------------------------------------------------

def validate_plan(
    team_ids: Iterable[str],
    parts: Iterable[Mapping[str, Any]],
    *,
    forbidden: str = "",
) -> list[dict[str, Any]]:
    """
    Plan rozbicia -> lista części (pierwsza = macierzysty) albo ValueError po polsku.

    `team_ids` - drużyny klubu w sezonie. `parts`: [{name, team_ids, expected_in}].
    `forbidden` - powód, dla którego klubu nie wolno rozbijać (budżet, okręg...).
    """
    if forbidden:
        raise ValueError(forbidden)
    teams = [t for t in dict.fromkeys(_s(t) for t in team_ids) if t]
    if len(teams) < 2:
        raise ValueError(
            "Klub ma w tym sezonie jedną drużynę, więc nie ma czego rozdzielać - "
            "rozbić można klub z co najmniej dwiema drużynami."
        )
    plan = list(parts)
    if len(plan) < 2:
        raise ValueError("Rozbicie potrzebuje co najmniej dwóch części.")
    if len(plan) > min(len(teams), MAX_PARTS):
        raise ValueError(
            f"Części może być najwyżej tyle, ile drużyn ({len(teams)}), i nie więcej niż {MAX_PARTS}."
        )
    seen_names: set[str] = set()
    assigned: dict[str, int] = {}
    out: list[dict[str, Any]] = []
    for index, part in enumerate(plan):
        name = _s(part.get("name"))
        if not name:
            raise ValueError(f"Część {index + 1} nie ma nazwy - wpisz nazwę nowego klubu.")
        if len(name) > MAX_NAME:
            raise ValueError(f"Nazwa części {index + 1} jest za długa (limit {MAX_NAME} znaków).")
        low = name.casefold()
        if low in seen_names:
            raise ValueError(f"Dwie części mają tę samą nazwę „{name}” - nadaj im różne nazwy.")
        seen_names.add(low)
        mine = [t for t in dict.fromkeys(_s(t) for t in (part.get("team_ids") or [])) if t]
        for team in mine:
            if team not in teams:
                raise ValueError(f"Drużyna {team} nie należy do tego klubu w tym sezonie.")
            if team in assigned:
                raise ValueError("Ta sama drużyna trafiła do dwóch części - każda drużyna idzie tylko do jednej.")
            assigned[team] = index
        if not mine:
            raise ValueError(
                f"Część „{name}” nie ma żadnej drużyny - każda część musi mieć co najmniej jedną."
            )
        try:
            expected = round(float(part.get("expected_in") or 0), 2)
        except (TypeError, ValueError):
            raise ValueError(f"Oczekiwana wpłata części „{name}” nie jest liczbą.")
        if expected < 0:
            raise ValueError(f"Oczekiwana wpłata części „{name}” nie może być ujemna.")
        out.append({"name": name, "team_ids": mine, "expected_in": expected})
    missing = [t for t in teams if t not in assigned]
    if missing:
        raise ValueError(
            f"{len(missing)} drużyn nie ma przypisanej części - przypisz każdą drużynę do jednej z części."
        )
    return out


# ---------------------------------------------------------------------------
# Przypisania drużyn (dziedziczenie sezonów)
# ---------------------------------------------------------------------------

def effective_maps(rows: Iterable[Mapping[str, Any]], season: str):
    """
    Przypisania obowiązujące w sezonie: dla drużyny wygrywa wiersz z NAJPÓŹNIEJSZYM
    sezonem <= sezon pytania (przy remisie - późniejszy w liście).

    Zwraca (po numerze drużyny, po kluczu nazwy): {team_id: (parent, club)},
    {(parent, name_key): club}. Liczy się też nazwa, bo numer drużyny bywa
    w następnym sezonie inny.
    """
    limit = season_start(season)
    by_id: dict[str, tuple[int, str, str]] = {}
    by_name: dict[tuple[str, str], tuple[int, str]] = {}
    for row in rows:
        try:
            start = season_start(row.get("season"))
        except ValueError:
            continue
        if start > limit:
            continue
        parent, club = _s(row.get("parent_club_id")), _s(row.get("club_id"))
        team, name_key = _s(row.get("team_id")), _s(row.get("name_key"))
        if team and (team not in by_id or start >= by_id[team][0]):
            by_id[team] = (start, parent, club)
        if name_key:
            key = (parent, name_key)
            if key not in by_name or start >= by_name[key][0]:
                by_name[key] = (start, club)
    return (
        {team: (parent, club) for team, (_, parent, club) in by_id.items()},
        {key: club for key, (_, club) in by_name.items()},
    )


def resolve_club(
    zprp_club_id: Any,
    team_id: Any,
    name_key: Any,
    maps,
) -> str:
    """Klub drużyny po uwzględnieniu podziału. Bez przypisania zostaje klub z ZPRP."""
    zprp = _s(zprp_club_id)
    by_id, by_name = maps
    hit = by_id.get(_s(team_id))
    if hit and hit[0] == zprp:
        return hit[1] or zprp
    club = by_name.get((zprp, _s(name_key)))
    if club:
        return club
    # Drużyna już leży w części (ZPRP zmieniło klub na numer części? nie zdarza się) - zostaje.
    return zprp


def split_info(
    groups: Iterable[Mapping[str, Any]],
    active_clubs: Iterable[str],
) -> dict[str, dict[str, Any]]:
    """
    Opis podziału dla każdego klubu uczestniczącego w sezonie.

    `groups`: wiersze {club_id, parent_club_id, part_no, name, expected_in} - także wiersz
    macierzystego (part_no 1). `active_clubs` - kluby z co najmniej jedną drużyną w sezonie.
    Podział jest aktywny w sezonie, gdy jakakolwiek część 2+ ma w nim drużynę.
    """
    active = {_s(c) for c in active_clubs}
    by_parent: dict[str, list[Mapping[str, Any]]] = {}
    for row in groups:
        by_parent.setdefault(_s(row.get("parent_club_id")), []).append(row)
    out: dict[str, dict[str, Any]] = {}
    for parent, rows in by_parent.items():
        rows = sorted(rows, key=lambda r: int(r.get("part_no") or 0))
        parts = [r for r in rows if _s(r.get("club_id")) in active or _s(r.get("club_id")) == parent]
        if not any(_s(r.get("club_id")) != parent and _s(r.get("club_id")) in active for r in rows):
            continue
        members = [
            {
                "club_id": _s(r.get("club_id")),
                "name": _s(r.get("name")),
                "part_no": int(r.get("part_no") or 0),
                "expected_in": float(r.get("expected_in") or 0),
            }
            for r in parts
        ]
        for member in members:
            out[member["club_id"]] = {
                "parent_club_id": parent,
                "role": "parent" if member["club_id"] == parent else "part",
                "part_no": member["part_no"],
                "name": member["name"],
                "expected_in": member["expected_in"],
                "parts": members,
            }
    return out


def overlay_settings(
    settings: Mapping[str, Mapping[str, Any]],
    info: Mapping[str, Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    """
    Ustawienia z nakładką podziału (kopia, wejście zostaje nietknięte).

    Macierzysty dostaje `split_name` (np. „Klub (I)") - surowe `display_name` zostaje,
    żeby zapis ustawień z karty nie wypalił „(I)" na stałe. Część bez własnego
    wiersza ustawień dziedziczy je od macierzystego („Rozlicza się przez okręg" itd.).
    """
    out = {club_id: dict(row) for club_id, row in settings.items()}
    for club_id, item in info.items():
        if item["role"] == "parent":
            out[club_id] = {**out.get(club_id, {}), "split_name": item["name"]}
        elif club_id not in out:
            base = dict(out.get(item["parent_club_id"]) or {})
            base.pop("split_name", None)
            out[club_id] = {**base, "display_name": item["name"]}
        elif not _s(out[club_id].get("display_name")):
            out[club_id] = {**out[club_id], "display_name": item["name"]}
    return out


# ---------------------------------------------------------------------------
# Zmiany podziału (zwracają, co skasować i co wpisać - zapis robi warstwa HTTP)
# ---------------------------------------------------------------------------

def assignment_rows_for_plan(
    parent: str,
    season: str,
    parts: list[Mapping[str, Any]],
    part_ids: list[str],
    names: Mapping[str, str],
) -> list[dict[str, Any]]:
    """
    Wiersze przypisań dla nowego podziału. `parts[0]` zostaje w macierzystym, więc
    wiersze dostają tylko części 2+ - ale też drużyny części 1 dostają wiersz
    „zostań w macierzystym": bez niego starszy wiersz z wcześniejszego podziału
    przeciągnąłby je do dawnej części.
    """
    rows: list[dict[str, Any]] = []
    for index, part in enumerate(parts):
        target = parent if index == 0 else part_ids[index]
        for team in part["team_ids"]:
            rows.append(
                {
                    "parent_club_id": parent,
                    "season": season,
                    "team_id": team,
                    "name_key": _s(names.get(team)),
                    "club_id": target,
                }
            )
    return rows


def move_team(
    rows: Iterable[Mapping[str, Any]],
    *,
    parent: str,
    season: str,
    team_id: str,
    name_key: str,
    to_club_id: str,
    group_clubs: Iterable[str],
    team_counts: Mapping[str, int],
    from_club_id: str,
) -> dict[str, Any]:
    """
    Przeniesienie drużyny między częściami od sezonu: {"delete_where": ..., "insert": row}
    albo ValueError. `team_counts` - ile drużyn ma teraz każda część w tym sezonie.
    """
    clubs = {_s(c) for c in group_clubs}
    if to_club_id not in clubs:
        raise ValueError("Można przenosić tylko do części tego samego klubu.")
    if to_club_id == from_club_id:
        raise ValueError("Drużyna już jest w tej części.")
    if team_counts.get(from_club_id, 0) <= 1:
        raise ValueError(
            "To jedyna drużyna swojej części - część musi mieć co najmniej jedną drużynę. "
            "Użyj „Scal z powrotem”, jeśli część ma zniknąć."
        )
    season_start(season)
    return {
        "delete_same_season": {"team_id": _s(team_id), "season": season, "parent_club_id": parent},
        "insert": {
            "parent_club_id": parent,
            "season": season,
            "team_id": _s(team_id),
            "name_key": _s(name_key),
            "club_id": to_club_id,
        },
    }


def merge_back(
    rows: Iterable[Mapping[str, Any]],
    *,
    parent: str,
    season: str,
    part_id: Optional[str],
    teams: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """
    „Scal z powrotem" od sezonu: wszystkie wiersze rodzica z sezonem >= sezon
    (dla `part_id` - tylko te, które wskazują na część) znikają, a drużyny,
    które w sezonie nadal leżą w scalanej części, dostają wiersz „wróć do macierzystego".

    `teams`: [{team_id, name_key, club_id}] - drużyny z TEGO sezonu z bieżącym klubem.
    Zwraca {"delete_ids": [...], "insert": [...], "entry_clubs": [części, których wpisy wracają]}.
    """
    start = season_start(season)
    rows = [r for r in rows if _s(r.get("parent_club_id")) == parent]
    targets = {_s(part_id)} if part_id else {
        _s(r.get("club_id")) for r in rows if _s(r.get("club_id")) != parent
    }
    targets.discard(parent)
    delete_ids = [
        r["id"]
        for r in rows
        if "id" in r
        and season_start(r.get("season")) >= start
        and (part_id is None or _s(r.get("club_id")) in targets)
    ]
    touched_ids = {_s(r.get("team_id")) for r in rows}
    touched_names = {_s(r.get("name_key")) for r in rows if _s(r.get("name_key"))}
    insert_rows = [
        {
            "parent_club_id": parent,
            "season": season,
            "team_id": _s(t.get("team_id")),
            "name_key": _s(t.get("name_key")),
            "club_id": parent,
        }
        for t in teams
        if _s(t.get("club_id")) in targets
        or (
            part_id is None
            and (_s(t.get("team_id")) in touched_ids or _s(t.get("name_key")) in touched_names)
        )
    ]
    return {"delete_ids": delete_ids, "insert": insert_rows, "entry_clubs": sorted(targets)}


# ---------------------------------------------------------------------------
# Podgląd sald przed i po
# ---------------------------------------------------------------------------

def preview_balances(
    *,
    parent: str,
    part_ids: list[str],
    names: list[str],
    parts: list[Mapping[str, Any]],
    team_charged: Mapping[str, float],
    team_matches: Mapping[str, int],
    entries: Iterable[Mapping[str, Any]],
    entry_moves: Mapping[int, int],
) -> dict[str, Any]:
    """
    Saldo macierzystego PRZED rozbiciem i każdej części PO.

    `team_charged`/`team_matches` - obciążenia i liczba meczów na drużynę; `entries` -
    wpisy macierzystego z sezonu; `entry_moves` - {id wpisu: numer części (od 0)};
    brak w mapie = zostaje w macierzystym. Wpis przeniesiony do części 0 zostaje.
    """
    entries = list(entries)
    all_charged = money_sum(team_charged.values())
    buckets_all = {"in": 0.0, "out": 0.0, "settled": 0.0}
    for row in entries:
        bucket = entry_bucket(row.get("kind"), row.get("source"))
        buckets_all[bucket] = money_sum((buckets_all[bucket], row.get("amount") or 0))
    before = {
        "club_id": parent,
        "paid_in": money(buckets_all["in"]),
        "paid_out": money(buckets_all["out"]),
        "settled": money(buckets_all["settled"]),
        "charged": all_charged,
        "balance": C.balance(
            paid_in=buckets_all["in"] + buckets_all["settled"],
            paid_out=buckets_all["out"],
            charged=all_charged,
        ),
    }
    after: list[dict[str, Any]] = []
    for index, part in enumerate(parts):
        mine = [
            row for row in entries if int(entry_moves.get(int(row.get("id") or 0), 0)) == index
        ]
        buckets = {"in": 0.0, "out": 0.0, "settled": 0.0}
        for row in mine:
            bucket = entry_bucket(row.get("kind"), row.get("source"))
            buckets[bucket] = money_sum((buckets[bucket], row.get("amount") or 0))
        charged = money_sum(team_charged.get(t, 0) for t in part["team_ids"])
        after.append(
            {
                "club_id": parent if index == 0 else part_ids[index],
                "name": names[index],
                "teams": len(part["team_ids"]),
                "matches": sum(int(team_matches.get(t, 0)) for t in part["team_ids"]),
                "paid_in": money(buckets["in"]),
                "paid_out": money(buckets["out"]),
                "settled": money(buckets["settled"]),
                "charged": charged,
                "expected_in": part.get("expected_in", 0),
                "balance": C.balance(
                    paid_in=buckets["in"] + buckets["settled"],
                    paid_out=buckets["out"],
                    charged=charged,
                ),
            }
        )
    return {"before": before, "after": after}


def validate_entry_moves(
    entries: Iterable[Mapping[str, Any]],
    moves: Mapping[Any, Any],
    parts_count: int,
) -> dict[int, int]:
    """Przeniesienia wpisów: {id: część} -> sprawdzone; ValueError dla obcych wpisów albo części."""
    ids = {int(row["id"]) for row in entries}
    out: dict[int, int] = {}
    for raw_id, raw_part in moves.items():
        try:
            entry_id, part = int(raw_id), int(raw_part)
        except (TypeError, ValueError):
            raise ValueError("Przeniesienie wpisu ma niepoprawny numer.")
        if entry_id not in ids:
            raise ValueError("Nie można przenieść wpisu, który nie należy do tego klubu w tym sezonie.")
        if part < 0 or part >= parts_count:
            raise ValueError("Wpis wskazuje nieistniejącą część.")
        if part != 0:
            out[entry_id] = part
    return out
