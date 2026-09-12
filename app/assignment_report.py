"""
Raport z przebiegu automatu - to, co obsadowy ma zobaczyć po naciśnięciu guzika.

MODUŁ-LIŚĆ: bez bazy i sieci. Dostaje gotowy plan i mecze, oddaje słownik, który
tak samo dobrze wchodzi do odpowiedzi HTTP, jak do szablonu PDF.

Użytkownik poprosił o trzy rzeczy wprost: KTO ile ma meczów w zakresie, oraz
ŚREDNI, NAJWIĘKSZY i NAJMNIEJSZY przejazd. Reszta jest po to, żeby dało się
zobaczyć, czy plan jest dobry: ile gniazd zostało pustych i dlaczego, jak
rozkłada się obciążenie i ile meczów dostała każda rozgrywka.

⚠ Kilometry liczymy W JEDNA STRONĘ - tak, jak podaje je tabela odległości.
Rozliczenia mnożą je przez dwa (`R.ROUND_TRIP`), bo płacą za drogę tam i z
powrotem; tutaj chodzi o to, jak daleko sędzia ma na mecz.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Optional, Sequence

from app.assignment_auto import Gap, MatchNeed, Plan, Proposal
from app.assignment_people import Judge

#: Podpisy gniazd dla człowieka - te same słowa, co w panelu.
SLOT_LABELS: dict[str, str] = {
    "pierwszy": "sędzia I",
    "drugi": "sędzia II",
    "sekretarz": "sekretarz",
    "czas": "mierzący czas",
    "delegat": "delegat",
    "delegat2": "drugi delegat",
}


def slot_label(slot: Any) -> str:
    key = str(slot or "").strip()
    return SLOT_LABELS.get(key, key)


def _round(value: Optional[float], places: int = 1) -> Optional[float]:
    return None if value is None else round(float(value), places)


def why_without_km(reasons: Iterable[Any]) -> list[str]:
    """
    Uzasadnienie BEZ samej odległości.

    Kilometry stoją w planie osobno (znaczek „12 km" przy nazwisku), więc
    powtórzone w uzasadnieniu czytają się jak zacinająca się płyta: „12 km ·
    dzień preferowany 12 km". Lista `reasons` zostaje pełna - to z niej żyje
    tekst raportu.
    """
    out: list[str] = []
    for reason in reasons or ():
        text = str(reason or "").strip()
        if not text:
            continue
        head = text[:-3].strip() if text.endswith(" km") else ""
        if head and head.replace(".", "", 1).isdigit():
            continue
        out.append(text)
    return out


def _spread(values: Sequence[float]) -> dict:
    """Suma, średnia, największy i najmniejszy - albo same puste pola."""
    if not values:
        return {"total": 0.0, "avg": None, "max": None, "min": None, "count": 0}
    return {
        "total": _round(sum(values)),
        "avg": _round(sum(values) / len(values)),
        "max": _round(max(values)),
        "min": _round(min(values)),
        "count": len(values),
    }


def _judge_line(judge: Optional[Judge], judge_id: str, name: str) -> dict:
    return {
        "judge_id": judge_id,
        "name": name or judge_id,
        "city": judge.city if judge else "",
        "matches": 0,
        "slots": {},
        "days": [],
        "km_values": [],
        "unknown_km": 0,
        "badges": sorted(judge.badges) if judge else [],
        "league": bool(judge and judge.league),
        "central": bool(judge and judge.central),
    }


def build_report(
    plan: Plan,
    needs: Sequence[MatchNeed],
    *,
    judges: Mapping[str, Judge] | None = None,
    window: Optional[dict] = None,
    load_before: Mapping[str, int] | None = None,
) -> dict:
    """
    Liczby z jednego przebiegu automatu.

    `load_before` to mecze, które sędzia MIAŁ już w zakresie przed przebiegiem -
    bez tego „równy podział" wyglądałby na równy tylko w obrębie nowych obsad,
    a sędzia z pięciu meczami stałby obok tego z zerem jako równi.
    """
    people = dict(judges or {})
    before = dict(load_before or {})
    by_match = {need.match_id: need for need in needs}

    lines: dict[str, dict] = {}
    for item in plan.proposals:
        line = lines.get(item.judge_id)
        if line is None:
            line = _judge_line(people.get(item.judge_id), item.judge_id, item.judge_name)
            line["before"] = int(before.get(item.judge_id, 0))
            lines[item.judge_id] = line
        line["matches"] += 1
        line["slots"][item.slot] = line["slots"].get(item.slot, 0) + 1
        if item.km is None:
            line["unknown_km"] += 1
        else:
            line["km_values"].append(float(item.km))
        need = by_match.get(item.match_id)
        day = need.day.isoformat() if need and need.day else None
        if day and day not in line["days"]:
            line["days"].append(day)

    judge_rows: list[dict] = []
    for line in lines.values():
        km = _spread(line.pop("km_values"))
        days = sorted(line.pop("days"))
        judge_rows.append(
            {
                **line,
                "days": days,
                "km": km,
                "total": int(line.get("before", 0)) + line["matches"],
            }
        )
    # Najpierw ci z największa liczba meczów - tam najłatwiej zobaczyć przechył.
    judge_rows.sort(key=lambda row: (-row["total"], -row["matches"], row["name"]))

    all_km = [float(item.km) for item in plan.proposals if item.km is not None]
    totals_km = _spread(all_km)
    totals_km["unknown"] = sum(1 for item in plan.proposals if item.km is None)

    per_competition: dict[str, dict] = {}
    for need in needs:
        key = need.code.split("/")[0] if "/" in need.code else need.code
        entry = per_competition.setdefault(
            key, {"key": key, "matches": 0, "filled": 0, "gaps": 0}
        )
        entry["matches"] += 1
    for item in plan.proposals:
        key = item.code.split("/")[0] if "/" in item.code else item.code
        per_competition.setdefault(key, {"key": key, "matches": 0, "filled": 0, "gaps": 0})
        per_competition[key]["filled"] += 1
    for item in plan.gaps:
        key = item.code.split("/")[0] if "/" in item.code else item.code
        per_competition.setdefault(key, {"key": key, "matches": 0, "filled": 0, "gaps": 0})
        per_competition[key]["gaps"] += 1

    counts = [row["total"] for row in judge_rows]
    slots_open = sum(len(need.field_needed) + len(need.table_needed) for need in needs)

    return {
        "window": window or {},
        "matches": len(needs),
        "slots": slots_open,
        "filled": len(plan.proposals),
        "gaps": len(plan.gaps),
        "judges_used": len(judge_rows),
        "rounds": {
            "first": sum(1 for item in plan.proposals if item.round_no <= 1),
            "later": sum(1 for item in plan.proposals if item.round_no > 1),
        },
        "travel": totals_km,
        "balance": {
            "max": max(counts) if counts else 0,
            "min": min(counts) if counts else 0,
            "spread": (max(counts) - min(counts)) if counts else 0,
        },
        "judges": judge_rows,
        "competitions": sorted(
            per_competition.values(), key=lambda entry: (-entry["gaps"], entry["key"])
        ),
        "gaps_detail": [
            {
                "match_id": item.match_id,
                "code": item.code,
                "slot": item.slot,
                "slot_label": slot_label(item.slot),
                "reason": item.reason,
                "day": (
                    by_match[item.match_id].day.isoformat()
                    if by_match.get(item.match_id) and by_match[item.match_id].day
                    else None
                ),
            }
            for item in plan.gaps
        ],
    }


def taken_slots(need: Optional[MatchNeed]) -> list[dict]:
    """
    Kto już stoi przy tym meczu - gniazda, których automat nie tykał.

    To NIE jest luka w planie: obsadzamy wyłącznie puste gniazda (decyzja
    użytkownika), więc zajęte trzeba pokazać osobno, żeby nie wyglądało na
    przeoczenie.
    """
    if need is None:
        return []
    out: list[dict] = []
    for group, people in (("field", need.crew_field), ("table", need.crew_table)):
        for judge in people:
            if not judge or not judge.name:
                continue
            out.append({"group": group, "name": judge.name, "judge_id": judge.judge_id})
    return out


def plan_rows(plan: Plan, needs: Sequence[MatchNeed]) -> list[dict]:
    """
    PEŁNY obraz meczu, nie same propozycje.

    Panel musi pokazać trzy rzeczy naraz, inaczej obsadowy nie wie, co się
    stało: kogo automat właśnie postawił, KTO JUŻ STAŁ w gnieździe (i dlatego
    automat go nie tknął) oraz które gniazdo zostało puste i dlaczego. Sama
    lista propozycji wygląda przy meczu dzieci tak, jakby automat zapomniał
    o sędzim boiskowym - a on po prostu już tam był.
    """
    by_match = {need.match_id: need for need in needs}
    gaps_by_match: dict[str, list[Gap]] = {}
    for item in plan.gaps:
        gaps_by_match.setdefault(item.match_id, []).append(item)
    # Karta powstaje dla KAŻDEGO meczu z listy, także dla takiego, w którym
    # automat nikogo nie postawił - bo właśnie tam trzeba pokazać powód.
    grouped: dict[str, dict] = {
        need.match_id: {
            "match_id": need.match_id,
            "code": need.code,
            "day": need.day.isoformat() if need.day else None,
            "time": need.moment.strftime("%H:%M") if need.moment else "",
            "city": need.host_city,
            "hall": need.hall,
            "host": need.host,
            "guest": need.guest,
            "slots": [],
            "taken": taken_slots(need),
            "gaps": [
                {
                    "slot": gap.slot,
                    "slot_label": slot_label(gap.slot),
                    "reason": gap.reason,
                }
                for gap in gaps_by_match.get(need.match_id, ())
            ],
        }
        for need in needs
    }
    for item in plan.proposals:
        entry = grouped.get(item.match_id)
        if entry is None:
            continue
        entry["slots"].append(
            {
                "slot": item.slot,
                "slot_label": slot_label(item.slot),
                "judge_id": item.judge_id,
                "name": item.judge_name,
                "km": _round(item.km),
                "reasons": item.reasons,
                "why": why_without_km(item.reasons),
                "round": item.round_no,
            }
        )
    for entry in grouped.values():
        entry["slots"].sort(key=lambda row: list(SLOT_LABELS).index(row["slot"]))
    return sorted(
        grouped.values(),
        key=lambda entry: (entry["day"] is None, entry["day"] or "", entry["time"], entry["code"]),
    )
