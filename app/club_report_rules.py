"""
Kreator raportu finansów klubów - czyste reguły (bez bazy, bez HTTP).

Wyciąg klubu za okres: saldo otwarcia, mecze (obciążenia), wpłaty i wypłaty,
saldo zamknięcia i podsumowanie per kategoria. Te same liczby idą do podglądu
na żywo, do PDF-a i do Excela - wszystkie trzy wołają `build_statement`.

Zasady (20.10.2026, prośba okręgu śląskiego):
- Saldo otwarcia i zamknięcia są ZAWSZE salda całego klubu w sezonie - filtr
  kategorii zawęża tabelę meczów, a nie saldo. Mecze spoza wybranych kategorii
  stoją na wyciągu jedną linią, żeby równanie otwarcie - mecze + wpłaty =
  zamknięcie zgadzało się co do grosza.
- Okres nie wychodzi poza sezon: sezony to osobne księgi („Rozlicz sezon"
  zeruje saldo). Zakres sięgający dalej przycinamy i MÓWIMY o tym w `notes`.
- Kategoria raportu = szczebel + płeć z numeru rozgrywek. `category_label`
  silnika stawek nie zna płci („Junior" to JM i JK), a okręg chce presetów
  „Juniorzy + juniorki", „Tylko młodzież".
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from typing import Any, Iterable, Mapping, Optional, Sequence

from app import settlement_rates as R
from app.settlement_money import money, money_sum

# ---------------------------------------------------------------------------
# Kategorie
# ---------------------------------------------------------------------------

YOUTH = "youth"
SENIOR = "senior"
OTHER = "other"


@dataclass(frozen=True)
class Category:
    key: str
    label: str
    group: str
    #: "M" chłopcy/mężczyźni, "K" dziewczęta/kobiety, "" bez płci.
    gender: str
    order: int


#: Kolejność = kolejność chipów i wierszy podsumowania (od najmłodszych).
CATEGORIES: tuple[Category, ...] = (
    Category("DZM", "Dzieci - chłopcy", YOUTH, "M", 10),
    Category("DZK", "Dzieci - dziewczęta", YOUTH, "K", 11),
    Category("MLM1213", "Młodzicy mł.", YOUTH, "M", 20),
    Category("MLK1213", "Młodziczki mł.", YOUTH, "K", 21),
    Category("MLM", "Młodzicy", YOUTH, "M", 30),
    Category("MLK", "Młodziczki", YOUTH, "K", 31),
    Category("JMM", "Juniorzy mł.", YOUTH, "M", 40),
    Category("JMK", "Juniorki mł.", YOUTH, "K", 41),
    Category("JM", "Juniorzy", YOUTH, "M", 50),
    Category("JK", "Juniorki", YOUTH, "K", 51),
    Category("IIIM", "III liga mężczyzn", SENIOR, "M", 60),
    Category("IIIK", "III liga kobiet", SENIOR, "K", 61),
    Category("IIM", "II liga mężczyzn", SENIOR, "M", 70),
    Category("IIK", "II liga kobiet", SENIOR, "K", 71),
    Category("IM", "I liga mężczyzn", SENIOR, "M", 80),
    Category("IK", "I liga kobiet", SENIOR, "K", 81),
    Category("SUPM", "Superliga / LC mężczyzn", SENIOR, "M", 90),
    Category("SUPK", "Superliga / LC kobiet", SENIOR, "K", 91),
    Category("CUP", "Puchary", OTHER, "", 100),
    Category("OTHER", "Inne (sparingi, mecze ręczne)", OTHER, "", 110),
)

BY_KEY: dict[str, Category] = {item.key: item for item in CATEGORIES}

#: Prefiks rozgrywek (`settlement_rates.competition_prefix`) -> kategoria raportu.
_PREFIX_TO_KEY = {
    "DZM": "DZM", "DZK": "DZK",
    "MLM1213": "MLM1213", "MLK1213": "MLK1213",
    "MLM": "MLM", "MLK": "MLK",
    "JMM": "JMM", "JMK": "JMK", "JM": "JM", "JK": "JK",
    "IIIM": "IIIM", "IIIK": "IIIK",
    "IIM": "IIM", "IIK": "IIK",
    "IM": "IM", "IK": "IK",
    "LCM": "SUPM", "LCK": "SUPK", "OSM": "SUPM", "OSK": "SUPK",
    "SM": "SUPM", "SK": "SUPK", "BSM": "SUPM", "BSK": "SUPK",
    "MP": "CUP", "PP": "CUP",
}


def report_category(code: Any) -> str:
    """Klucz kategorii raportu z numeru rozgrywek („JMK/3" -> „JMK")."""
    if R.is_provincial_cup(code) or R.is_cup_competition(code):
        return "CUP"
    prefix = R.competition_prefix(code)
    key = _PREFIX_TO_KEY.get(prefix)
    if key:
        return key
    # „IIM4/2" - II liga powierzona okręgowi ma cyfrę grupy za prefiksem.
    value = R.code_key(code)
    if value.startswith("IIM"):
        return "IIM"
    if value.startswith("IIK"):
        return "IIK"
    return "OTHER"


def category_label(key: str) -> str:
    hit = BY_KEY.get(key)
    return hit.label if hit else key


#: Presety chipów: klucz, napis i reguła doboru kategorii.
PRESETS: tuple[tuple[str, str], ...] = (
    ("all", "Wszystkie kategorie"),
    ("youth", "Tylko młodzież"),
    ("no-senior", "Bez seniorów"),
    ("juniors", "Juniorzy + juniorki"),
    ("boys", "Chłopcy i mężczyźni"),
    ("girls", "Dziewczęta i kobiety"),
    ("senior", "Tylko seniorzy"),
)


def preset_keys(preset: str) -> list[str]:
    """Kategorie presetu w kolejności chipów."""
    picks: list[str] = []
    for item in CATEGORIES:
        if preset == "all":
            ok = True
        elif preset == "youth":
            ok = item.group == YOUTH
        elif preset == "no-senior":
            ok = item.group != SENIOR
        elif preset == "juniors":
            ok = item.key in ("JM", "JK", "JMM", "JMK")
        elif preset == "boys":
            ok = item.gender == "M"
        elif preset == "girls":
            ok = item.gender == "K"
        elif preset == "senior":
            ok = item.group == SENIOR
        else:
            ok = False
        if ok:
            picks.append(item.key)
    return picks


def presets_json() -> list[dict]:
    return [{"key": key, "label": label, "keys": preset_keys(key)} for key, label in PRESETS]


def scope_label(selected: Optional[Iterable[str]]) -> str:
    """Napis zakresu na dokumencie: nazwa presetu albo lista kategorii."""
    if selected is None:
        return "Wszystkie kategorie"
    wanted = [key for key in (item.key for item in CATEGORIES) if key in set(selected)]
    if not wanted:
        return "Żadna kategoria"
    for key, label in PRESETS:
        if preset_keys(key) == wanted:
            return label
    return ", ".join(category_label(key) for key in wanted)


# ---------------------------------------------------------------------------
# Okres
# ---------------------------------------------------------------------------

def clamp_range(
    season_from: date,
    season_to: date,
    date_from: Optional[date],
    date_to: Optional[date],
) -> tuple[date, date, list[str]]:
    """Zakres raportu przycięty do sezonu - z notką, gdy coś przycięto."""
    notes: list[str] = []
    start = date_from or season_from
    end = date_to or season_to
    if start > end:
        start, end = end, start
        notes.append("Daty „od” i „do” były zamienione - odwróciłem je.")
    if start < season_from:
        notes.append(
            f"Początek przycięty do startu sezonu ({pl_date(season_from)}) - "
            "poprzedni sezon to osobna księga."
        )
        start = season_from
    if end > season_to:
        notes.append(f"Koniec przycięty do końca sezonu ({pl_date(season_to)}).")
        end = season_to
    if start > end:
        # Cały zakres poza sezonem - pokazujemy pusty dzień startu sezonu.
        start = end = season_from
    return start, end, notes


def pl_date(value: Optional[date]) -> str:
    return value.strftime("%d.%m.%Y") if value else "-"


def _as_date(value: Any) -> Optional[date]:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    text = str(value or "")[:10]
    try:
        return date.fromisoformat(text) if len(text) == 10 else None
    except ValueError:
        return None


def entry_day(row: Mapping[str, Any], fallback: date) -> date:
    """Dzień wpisu: data wpłaty, a bez niej dzień zapisu; bez obu - start sezonu."""
    return _as_date(row.get("day")) or _as_date(row.get("created_at")) or fallback


# ---------------------------------------------------------------------------
# Wyciąg
# ---------------------------------------------------------------------------

SEASON_CLOSE_SOURCE = "season-close"

SOURCE_LABELS = {
    "manual": "wpis ręczny",
    "excel": "import z Excela",
    "bulk": "akcja grupowa",
    "invoice": "faktura",
    SEASON_CLOSE_SOURCE: "rozliczenie sezonu",
}


def _field(row: Any, name: str, default: Any = None) -> Any:
    if isinstance(row, Mapping):
        return row.get(name, default)
    return getattr(row, name, default)


def _referees(row: Any) -> tuple[str, str]:
    """(para boiskowych, stolik) - nazwiska z obsady meczu."""
    field, table = [], []
    for share in _field(row, "referees", []) or []:
        role = str(_field(share, "role", "") or "")
        name = str(_field(share, "name", "") or "").strip()
        if not name:
            continue
        if role.startswith(R.ROLE_FIELD):
            field.append(name)
        elif role.startswith(R.ROLE_TABLE):
            table.append(name)
    return " / ".join(field), " / ".join(table)


def _teams(row: Any) -> str:
    host = str(_field(row, "host_name", "") or "").strip()
    guest = str(_field(row, "guest_name", "") or "").strip()
    if host and guest:
        return f"{host} - {guest}"
    return str(_field(row, "teams", "") or "").strip() or host or str(_field(row, "team_name", "") or "")


def match_line(row: Any) -> dict:
    """Jeden mecz na wyciągu - kształt wspólny dla PDF, Excela i podglądu."""
    day = _as_date(_field(row, "day"))
    key = report_category(_field(row, "code", ""))
    field, table = _referees(row)
    return {
        "match_key": str(_field(row, "match_key", "") or ""),
        "day": day.isoformat() if day else None,
        "date_label": pl_date(day),
        "code": str(_field(row, "code", "") or ""),
        "category": key,
        "category_label": category_label(key),
        "teams": _teams(row),
        "team_name": str(_field(row, "team_name", "") or ""),
        "city": str(_field(row, "city", "") or ""),
        "field": field,
        "table": table,
        "gross": money(_field(row, "gross", 0) or 0),
        "travel": money(_field(row, "travel", 0) or 0),
        "amount": money(_field(row, "amount", 0) or 0),
    }


def build_statement(
    *,
    charges: Sequence[Any],
    entries: Sequence[Mapping[str, Any]],
    pending: Sequence[Mapping[str, Any]],
    season_from: date,
    date_from: date,
    date_to: date,
    categories: Optional[Iterable[str]] = None,
) -> dict:
    """
    Wyciąg jednego klubu (albo wspólnego budżetu) za okres.

    `charges` - wiersze obciążeń klubu ze statusem `charged` (filtr statusu
    robi wołający, bo tam jest słownik statusów). `categories=None` = wszystkie.
    """
    wanted = None if categories is None else set(categories)

    opening_charges: list[float] = []
    opening_paid: list[float] = []
    matches: list[dict] = []
    other_amounts: list[float] = []
    other_count = 0
    period_charges: list[float] = []

    for row in charges:
        day = _as_date(_field(row, "day")) or season_from
        amount = float(_field(row, "amount", 0) or 0)
        if day < date_from:
            opening_charges.append(amount)
            continue
        if day > date_to:
            continue
        period_charges.append(amount)
        line = match_line(row)
        if wanted is None or line["category"] in wanted:
            matches.append(line)
        else:
            other_amounts.append(amount)
            other_count += 1

    lines: list[dict] = []
    paid_in, paid_out, settled = [], [], []
    for row in entries:
        day = entry_day(row, season_from)
        amount = float(row.get("amount") or 0)
        source = str(row.get("source") or "")
        out = str(row.get("kind") or "").strip().lower().startswith("out")
        signed = -amount if out else amount
        if day < date_from:
            opening_paid.append(signed)
            continue
        if day > date_to:
            continue
        if source == SEASON_CLOSE_SOURCE:
            settled.append(amount if not out else -amount)
            kind_label = "Rozliczenie sezonu"
        elif out:
            paid_out.append(amount)
            kind_label = "Wypłata"
        else:
            paid_in.append(amount)
            kind_label = "Wpłata"
        lines.append(
            {
                "id": row.get("id"),
                "day": day.isoformat(),
                "date_label": pl_date(day),
                "kind": "out" if out else "in",
                "kind_label": kind_label,
                "description": str(row.get("description") or "").strip(),
                "source": source,
                "source_label": SOURCE_LABELS.get(source, source or "wpis"),
                "team_name": str(row.get("team_name") or ""),
                "amount": money(amount),
                "signed": money(signed),
            }
        )
    lines.sort(key=lambda item: (item["day"], item.get("id") or 0))
    matches.sort(key=lambda item: (item["day"] or "", item["match_key"]))

    open_invoices = []
    for item in pending:
        day = _as_date(item.get("issue_date"))
        if day and date_from <= day <= date_to:
            open_invoices.append({**item, "date_label": pl_date(day)})
    open_invoices.sort(key=lambda item: (item.get("issue_date") or "", item.get("id") or 0))

    opening = money_sum((money_sum(opening_paid), -money_sum(opening_charges)))
    charged_all = money_sum(period_charges)
    charged_scope = money_sum(line["amount"] for line in matches)
    charged_other = money_sum(other_amounts)
    paid_in_sum = money_sum(paid_in)
    paid_out_sum = money_sum(paid_out)
    settled_sum = money_sum(settled)
    # W groszach - równanie na wyciągu ma się zgadzać co do grosza.
    closing = money_sum((opening, -charged_all, paid_in_sum, settled_sum, -paid_out_sum))

    by_cat: dict[str, dict] = {}
    for line in matches:
        bucket = by_cat.setdefault(
            line["category"],
            {"key": line["category"], "label": line["category_label"], "matches": 0, "amount": 0.0},
        )
        bucket["matches"] += 1
        bucket["amount"] = money_sum((bucket["amount"], line["amount"]))
    order = {item.key: item.order for item in CATEGORIES}
    summary = sorted(by_cat.values(), key=lambda item: order.get(item["key"], 999))
    for item in summary:
        item["share"] = round(item["amount"] / charged_scope, 4) if charged_scope else 0.0

    return {
        "opening": opening,
        "closing": closing,
        "charged": charged_all,
        "charged_scope": charged_scope,
        "charged_other": charged_other,
        "other_count": other_count,
        "paid_in": paid_in_sum,
        "paid_out": paid_out_sum,
        "settled": settled_sum,
        "pending_in": money_sum(item.get("amount") or 0 for item in open_invoices),
        "matches": matches,
        "entries": lines,
        "pending": open_invoices,
        "by_category": summary,
    }


def category_counts(charges: Iterable[Any], date_from: date, date_to: date, season_from: date) -> dict[str, dict]:
    """Ile meczów i za ile w każdej kategorii okresu - liczniki na chipach."""
    out: dict[str, dict] = {}
    for row in charges:
        day = _as_date(_field(row, "day")) or season_from
        if day < date_from or day > date_to:
            continue
        key = report_category(_field(row, "code", ""))
        bucket = out.setdefault(key, {"matches": 0, "amount": 0.0})
        bucket["matches"] += 1
        bucket["amount"] = money_sum((bucket["amount"], float(_field(row, "amount", 0) or 0)))
    return out


def season_months(charges: Iterable[Any], season_from: date, categories: Optional[Iterable[str]] = None) -> list[dict]:
    """Dwanaście miesięcy sezonu (wrzesień - sierpień): mecze i kwota w zakresie kategorii."""
    wanted = None if categories is None else set(categories)
    keys = []
    year, month = season_from.year, season_from.month
    for _ in range(12):
        keys.append((year, month))
        month += 1
        if month > 12:
            year, month = year + 1, 1
    buckets = {key: {"matches": 0, "amount": 0.0} for key in keys}
    for row in charges:
        day = _as_date(_field(row, "day"))
        if not day or (day.year, day.month) not in buckets:
            continue
        if wanted is not None and report_category(_field(row, "code", "")) not in wanted:
            continue
        bucket = buckets[(day.year, day.month)]
        bucket["matches"] += 1
        bucket["amount"] = money_sum((bucket["amount"], float(_field(row, "amount", 0) or 0)))
    return [
        {"month": f"{y:04d}-{m:02d}", "matches": buckets[(y, m)]["matches"], "amount": buckets[(y, m)]["amount"]}
        for y, m in keys
    ]


def categories_json(counts: Mapping[str, Mapping[str, Any]]) -> list[dict]:
    """Wszystkie kategorie z licznikami - pusta też, żeby chip mówił „0"."""
    return [
        {
            "key": item.key,
            "label": item.label,
            "group": item.group,
            "gender": item.gender,
            "matches": int((counts.get(item.key) or {}).get("matches", 0)),
            "amount": money((counts.get(item.key) or {}).get("amount", 0)),
        }
        for item in CATEGORIES
    ]


def safe_file_part(value: str, limit: int = 48) -> str:
    """Kawałek nazwy pliku bez znaków, których nie lubi Windows ani ZIP."""
    import re
    import unicodedata

    folded = unicodedata.normalize("NFKD", str(value or "")).replace("ł", "l").replace("Ł", "L")
    ascii_only = folded.encode("ascii", "ignore").decode()
    cleaned = re.sub(r"[^A-Za-z0-9]+", "_", ascii_only).strip("_")
    return (cleaned or "klub")[:limit]
