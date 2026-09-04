# app/training_spk_report.py
#
# Raport wyników sprawdzianu SPK - liczby i tabele dla szablonu PDF.
#
# CZYSTY MODUŁ, jak wszystko przy tym szkoleniu: decyzje (kogo liczyć, jak
# grupować, co pokazać) zapadają tutaj i dają się sprawdzić testem; szablon
# HTML tylko rysuje, a WeasyPrint tylko drukuje.
#
# TE SAME REGUŁY CO ZESTAWIENIE W PANELU (`summarize_by_province`):
#   • liczy się NAJLEPSZE podejście sędziego, nie średnia z wszystkich prób -
#     wytrwałość w ćwiczeniu nie może obniżać wyniku,
#   • nauka w aplikacji (guided) nie wchodzi do rankingu ani do średnich
#     okręgów - prowadzenie za rękę gwarantuje niemal komplet zdarzeń i w
#     porównaniu okręgów mówiłaby nieprawdę.
#
# ALE NIE ZNIKA. Wykluczona z liczb, nauka dostaje WŁASNĄ SEKCJĘ: nazwisko,
# okręg, wynik, data. Bez niej raport z okresu, w którym wszyscy ćwiczyli
# prowadzeni za rękę, wychodził pusty - „0 sędziów" przy pełnej tabeli podejść
# w panelu. Raport ma pokazywać, co się wydarzyło, a rozdzielać dopiero
# w rubrykach.
#
# RAPORT OKRĘGOWY TO TEN SAM RAPORT NA MNIEJSZYCH DANYCH - nie osobny szablon.
# Dwa szablony rozjadą się przy pierwszej poprawce; filtr wystarcza.

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.zprp_accounts import normalize_province

MODE_LABEL = {
    "video": "pełne nagranie",
    "condensed": "skrót od 2. połowy",
    "slides": "prezentacja",
    "guided": "nauka w aplikacji",
}

#: Podpis pod nazwą okręgu, gdy nie ma go w danych podejścia.
NO_PROVINCE = "bez okręgu"

#: Slug (tak trzyma je baza) → nazwa z polskimi znakami. Ta sama lista, co
#: `PROVINCE_NAMES` w aplikacji: raport i panel mają mówić „ŁÓDZKIE", a nie
#: „LODZKIE" - slug jest kluczem technicznym, nie nazwą do czytania.
PROVINCE_NAMES = {
    "DOLNOSLASKIE": "Dolnośląskie",
    "KUJAWSKO_POMORSKIE": "Kujawsko-pomorskie",
    "LUBELSKIE": "Lubelskie",
    "LUBUSKIE": "Lubuskie",
    "LODZKIE": "Łódzkie",
    "MALOPOLSKIE": "Małopolskie",
    "MAZOWIECKIE": "Mazowieckie",
    "OPOLSKIE": "Opolskie",
    "PODKARPACKIE": "Podkarpackie",
    "PODLASKIE": "Podlaskie",
    "POMORSKIE": "Pomorskie",
    "SLASKIE": "Śląskie",
    "SWIETOKRZYSKIE": "Świętokrzyskie",
    "WARMINSKO_MAZURSKIE": "Warmińsko-mazurskie",
    "WIELKOPOLSKIE": "Wielkopolskie",
    "ZACHODNIOPOMORSKIE": "Zachodniopomorskie",
}


def _clean_name(run: Dict[str, Any]) -> str:
    return str(run.get("judgeName") or "").strip() or "(bez nazwiska)"


def _province_of(run: Dict[str, Any]) -> str:
    return str(run.get("province") or "").strip().upper()


def _display_province(value: str) -> str:
    """Nazwa okręgu do czytania: `LODZKIE` → `Łódzkie`.

    Nieznany slug wraca z podkreśleniami zamienionymi na dywizy, a nie pusty:
    lepiej pokazać dziwną nazwę niż zgubić wiersz z wynikami.
    """
    raw = str(value or "").strip().upper()
    if not raw:
        return NO_PROVINCE
    return PROVINCE_NAMES.get(raw) or raw.replace("_", "-").capitalize()


def crest_slug(value: str) -> str:
    """Nazwa pliku herbu bez rozszerzenia - ta sama, co w aplikacji.

    Aplikacja trzyma herby jako `dolnoslaskie.png`, a `normalize_province`
    oddaje `DOLNOSLASKIE`, więc jedno wynika z drugiego. Dzięki temu panel i
    PDF pokazują ten sam herb i nie ma drugiej listy do utrzymania.
    """
    return normalize_province(value).lower()


def _best_scored_runs(runs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Najlepsze OCENIANE podejście każdego sędziego (bez nauki w aplikacji)."""
    best: Dict[str, Dict[str, Any]] = {}
    for run in runs:
        if run.get("score") is None or run.get("mode") == "guided":
            continue
        key = str(run.get("judgeId") or run.get("runId"))
        current = best.get(key)
        if current is None or run["score"] > current["score"]:
            best[key] = run
    return sorted(best.values(), key=lambda r: (-r["score"], _clean_name(r)))


def _median(scores: List[float]) -> float:
    ordered = sorted(scores)
    middle = len(ordered) // 2
    if len(ordered) % 2 == 1:
        return ordered[middle]
    return round((ordered[middle - 1] + ordered[middle]) / 2, 1)


def _grade_buckets(scores: List[float]) -> List[Dict[str, Any]]:
    """Rozkład ocen - dokładnie progi `grade()` z oceny podejścia."""
    buckets = [
        ("wzorowo", lambda s: s >= 95),
        ("bardzo dobrze", lambda s: 85 <= s < 95),
        ("dobrze", lambda s: 70 <= s < 85),
        ("są braki", lambda s: 50 <= s < 70),
        ("do powtórzenia", lambda s: s < 50),
    ]
    total = len(scores) or 1
    out = []
    for label, match in buckets:
        count = sum(1 for s in scores if match(s))
        out.append(
            {
                "label": label,
                "count": count,
                "percent": round(100 * count / total),
                # Słupek nie może zniknąć przy jednym podejściu na pięć progów -
                # zero rysujemy jako kreskę, a nie jako nic.
                "width": max(2, round(100 * count / total)) if count else 0,
            }
        )
    return out


def _date_label(value: Any) -> str:
    """`2026-09-04T18:21:00+00:00` → `04.09`. Pusto, gdy nie ma czego czytać."""
    raw = str(value or "").strip()
    if not raw:
        return ""
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).strftime("%d.%m")
    except ValueError:
        return ""


def report_context(
    runs: List[Dict[str, Any]],
    *,
    province: Optional[str] = None,
    generated_by: str = "",
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Wszystko, czego potrzebuje szablon raportu - i nic ponad to."""
    wanted = normalize_province(province) if province else ""
    pool = [r for r in runs if not wanted or _province_of(r) == wanted]

    best = _best_scored_runs(pool)
    scores = [r["score"] for r in best]
    scored_attempts = [
        r for r in pool if r.get("score") is not None and r.get("mode") != "guided"
    ]

    ranking = [
        {
            "place": i + 1,
            "judgeName": _clean_name(r),
            "province": _display_province(_province_of(r)),
            "crest": crest_slug(_province_of(r)),
            "score": r["score"],
            "mode": MODE_LABEL.get(str(r.get("mode") or ""), str(r.get("mode") or "")),
            "attempt": r.get("attempt") or 1,
            "date": _date_label(r.get("endedAt")),
        }
        for i, r in enumerate(best)
    ]

    by_province: List[Dict[str, Any]] = []
    if not wanted:
        grouped: Dict[str, List[float]] = {}
        for run in best:
            grouped.setdefault(_province_of(run), []).append(run["score"])
        for name, values in grouped.items():
            by_province.append(
                {
                    "province": _display_province(name),
                    "crest": crest_slug(name),
                    "judges": len(values),
                    "avg": round(sum(values) / len(values), 1),
                    "median": _median(values),
                    "best": max(values),
                }
            )
        by_province.sort(key=lambda x: (-x["avg"], x["province"]))
        top = by_province[0]["avg"] if by_province else 0
        for row in by_province:
            row["width"] = round(100 * row["avg"] / top) if top else 0

    # NAUKA W APLIKACJI - poza liczbami, ale nie poza raportem (patrz nagłówek).
    guided = [
        {
            "judgeName": _clean_name(r),
            "province": _display_province(_province_of(r)),
            "crest": crest_slug(_province_of(r)),
            "score": r.get("score"),
            "attempt": r.get("attempt") or 1,
            "date": _date_label(r.get("endedAt")),
        }
        for r in sorted(
            (r for r in pool if r.get("mode") == "guided"),
            key=lambda r: (-(r.get("score") or 0), _clean_name(r)),
        )
    ]

    stamp = (now or datetime.now(timezone.utc)).astimezone()
    return {
        "title": "Sprawdzian SPK/1",
        "subtitle": "Superpuchar - szkolenie stałe",
        "scope": _display_province(wanted) if wanted else "cała Polska",
        "scopeCrest": crest_slug(wanted) if wanted else "",
        "isProvince": bool(wanted),
        "generatedAt": stamp.strftime("%d.%m.%Y, %H:%M"),
        "generatedBy": str(generated_by or "").strip(),
        "year": stamp.strftime("%Y"),
        "judges": len(best),
        "attempts": len(scored_attempts),
        "guidedAttempts": len(guided),
        "avg": round(sum(scores) / len(scores), 1) if scores else None,
        "median": _median(scores) if scores else None,
        "best": max(scores) if scores else None,
        "worst": min(scores) if scores else None,
        "gradeBuckets": _grade_buckets(scores) if scores else [],
        "ranking": ranking,
        "byProvince": by_province,
        "guided": guided,
        # Raport bez ani jednej liczby ma powiedzieć to wprost, a nie wyjść
        # jako strony pustych tabel.
        "empty": not ranking and not guided,
    }
