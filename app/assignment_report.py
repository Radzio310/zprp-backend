"""
Raport z przebiegu automatu - to, co obsadowy ma zobaczyc po nacisnieciu guzika.

MODUL-LISC: bez bazy i sieci. Dostaje gotowy plan i mecze, oddaje slownik, ktory
tak samo dobrze wchodzi do odpowiedzi HTTP, jak do szablonu PDF.

Uzytkownik poprosil o trzy rzeczy wprost: KTO ile ma meczow w zakresie, oraz
SREDNI, NAJWIEKSZY i NAJMNIEJSZY przejazd. Reszta jest po to, zeby dalo sie
zobaczyc, czy plan jest dobry: ile gniazd zostalo pustych i dlaczego, jak
rozklada sie obciazenie i ile meczow dostala kazda rozgrywka.

⚠ Kilometry liczymy W JEDNA STRONE - tak, jak podaje je tabela odleglosci.
Rozliczenia mnoza je przez dwa (`R.ROUND_TRIP`), bo placa za droge tam i z
powrotem; tutaj chodzi o to, jak daleko sedzia ma na mecz.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Optional, Sequence

from app.assignment_auto import Gap, MatchNeed, Plan, Proposal
from app.assignment_people import Judge

#: Podpisy gniazd dla czlowieka - te same slowa, co w panelu.
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
    Uzasadnienie BEZ samej odleglosci.

    Kilometry stoja w planie osobno (znaczek „12 km" przy nazwisku), wiec
    powtorzone w uzasadnieniu czytaja sie jak zacinajaca sie plyta: „12 km ·
    dzien preferowany 12 km". Lista `reasons` zostaje pelna - to z niej zyje
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
    """Suma, srednia, najwiekszy i najmniejszy - albo same puste pola."""
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

    `load_before` to mecze, ktore sedzia MIAL juz w zakresie przed przebiegiem -
    bez tego „rowny podzial" wygladalby na rowny tylko w obrebie nowych obsad,
    a sedzia z pieciu meczami stalby obok tego z zerem jako rowni.
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
    # Najpierw ci z najwieksza liczba meczow - tam najlatwiej zobaczyc przechyl.
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


def plan_rows(plan: Plan, needs: Sequence[MatchNeed]) -> list[dict]:
    """Propozycje pogrupowane po meczu - do panelu i do tabeli w PDF."""
    by_match = {need.match_id: need for need in needs}
    grouped: dict[str, dict] = {}
    for item in plan.proposals:
        need = by_match.get(item.match_id)
        entry = grouped.setdefault(
            item.match_id,
            {
                "match_id": item.match_id,
                "code": item.code,
                "day": need.day.isoformat() if need and need.day else None,
                "time": need.moment.strftime("%H:%M") if need and need.moment else "",
                "city": need.host_city if need else "",
                "hall": need.hall if need else "",
                "host": need.host if need else "",
                "guest": need.guest if need else "",
                "slots": [],
            },
        )
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
