"""
Wiersze listy przejazdów zebrane w grupy sędziów - pod PDF „Przejazdy".

MODUŁ-LIŚĆ: bez bazy i sieci, żeby reguła chodziła w teście.

Decyzja użytkownika z 23.09.2026: na liście kosztów przejazdów każdy sędzia
ma swoje wyjazdy jeden pod drugim, a pod nimi wiersz „Razem" z sumą
kilometrów i kwotą do wypłaty - także przy jednym wyjeździe, żeby kwota
osoby zawsze stała w tym samym miejscu. Lp numeruje SĘDZIÓW, nie wyjazdy.

Kolejność grup to kolejność pierwszego wyjazdu sędziego na wejściu (silnik
rozliczeń sortuje już po nazwisku), a wyjazdy w grupie zostają w swojej
kolejności. Sędzia rozsiany po liście i tak trafia do jednej grupy.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping


def group_by_judge(rows: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """
    Grupy `{lp, judge_id, name, trips, total_km, total_amount}`.

    Wiersz potrzebuje pól `judge_id`, `name`, `total_km`, `amount`; reszta
    przechodzi do `trips` bez zmian.
    """
    groups: dict[str, dict[str, Any]] = {}
    for row in rows:
        key = str(row.get("judge_id") or row.get("name") or "").strip()
        group = groups.get(key)
        if group is None:
            group = groups[key] = {
                "judge_id": row.get("judge_id"),
                "name": row.get("name"),
                "trips": [],
            }
        group["trips"].append(dict(row))

    out: list[dict[str, Any]] = []
    for lp, group in enumerate(groups.values(), start=1):
        trips = group["trips"]
        out.append(
            {
                **group,
                "lp": lp,
                "total_km": sum(float(t.get("total_km") or 0) for t in trips),
                # Suma groszy liczona raz i zaokrąglona raz - tak samo jak RAZEM.
                "total_amount": round(sum(float(t.get("amount") or 0) for t in trips), 2),
            }
        )
    return out
