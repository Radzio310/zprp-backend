"""
Ręczne mecze z rachunkiem (np. SPARING) - cała reguła wyceny.

Decyzje użytkownika z 23.09.2026:
  - mecz dopisany z karty klubu „działa jak wypłata, ale tworzy mecz z
    rachunkiem": trafia do OBCIĄŻEŃ klubu (nie do wpłat/wypłat) i jednocześnie
    do rozliczeń SĘDZIÓW jak zwykły mecz - ryczałt i przejazd w miesiącu dnia
    meczu, w zestawieniu ekwiwalentów, na liście przejazdów i w „Moich
    rozliczeniach" w aplikacji,
  - kwota to RYCZAŁT ZA MECZ NA SĘDZIEGO, osobno boiskowy i stolikowy.
    Domyślnie z tabeli okręgu obowiązującej w dniu meczu (numer bez kategorii,
    np. „SPARING", liczy się jak „Inne"); wartości można zmienić,
  - przełącznik brutto/netto: podana kwota netto jest zamieniana na brutto
    DOKŁADNĄ odwrotnością `settlement_rates.net_parts` (patrz `gross_from_net`),
  - przejazd sędziego = km w jedną stronę (miasto domowe -> miasto meczu) x 2
    x stawka za km okręgu (Śląsk 0,70 zł). Przełącznik „zwrot za dojazd"
    wyłącza przejazdy całej obsadzie,
  - rachunek klubu = suma ryczałtów + przejazdy.

JEDEN RACHUNEK, DWIE STRONY. Rekord ręcznego meczu zamienia się tu na zwykłe
obsady silnika (`settlement_engine.Assignment`) z GOTOWĄ kwotą
(`fixed_gross`, `fixed_travel`) zamiast stawki z tabeli. Z tych obsad liczy się
i miesiąc sędziego (KUP i podatek od sumy miesiąca - `settle_period`), i wiersz
obciążenia klubu (`charge_rows`) - więc kwoty po obu stronach nie mają jak się
rozjechać.

MODUŁ-LIŚĆ: bez bazy i sieci, żeby cała reguła chodziła w teście.
"""

from __future__ import annotations

import json
import re
from datetime import date, datetime, time
from typing import Any, Iterable, Optional
from zoneinfo import ZoneInfo

from app import club_charges as C
from app import settlement_engine as E
from app import settlement_rates as R

#: Prefiks klucza meczu. Terminarz okręgu ma „d:", lista sędziego „o:".
KEY_PREFIX = "manual:"
#: `origin` obsady z ręcznego meczu - po nim silnik i statystyki go poznają.
ORIGIN = "manual"
#: Numer meczu, gdy nikt go nie podał.
DEFAULT_CODE = "SPARING"

FIELD = "field"
TABLE = "table"
ROLE_OF = {FIELD: R.ROLE_FIELD, TABLE: R.ROLE_TABLE}

MODE_GROSS = "gross"
MODE_NET = "net"

#: Godzina meczu bez podanej godziny - środek dnia, żeby żadna strefa czasowa
#: nie przesunęła meczu na inny dzień (a więc na inny miesiąc rozliczenia).
DEFAULT_TIME = time(12, 0)
WARSAW = ZoneInfo("Europe/Warsaw")

#: Ostatnia deska, gdy okręg nie ma żadnej tabeli stawek (ani własnej, ani
#: gałęzi „okręgowe" tabeli centralnej). Tylko podpowiedź - pole jest edytowalne.
FALLBACK_FEES = {FIELD: 117, TABLE: 77}

#: Źródła kilometrów - te same słowa co w rozliczeniu (`settlement_distances`),
#: plus ręczne wpisanie.
KM_SOURCES = ("same-city", "table", "google", "manual", "none")


def _s(value: Any) -> str:
    return str(value if value is not None else "").strip()


def _num(value: Any) -> Optional[float]:
    if value is None or value == "":
        return None
    try:
        out = float(str(value).replace(",", "."))
    except (TypeError, ValueError):
        return None
    return out if out == out else None  # NaN


def is_manual_key(match_key: Any) -> bool:
    return _s(match_key).startswith(KEY_PREFIX)


def match_key(record_id: Any) -> str:
    return f"{KEY_PREFIX}{record_id}"


def record_id_of(key: Any) -> Optional[int]:
    text = _s(key)
    if not text.startswith(KEY_PREFIX):
        return None
    try:
        return int(text[len(KEY_PREFIX):])
    except ValueError:
        return None


def normalize_role(value: Any) -> str:
    """„field" / „table" - przyjmuje też pełne nazwy ról z rozliczeń."""
    text = _s(value).lower()
    if text in (TABLE, "stolik", "stolikowy") or text.startswith("sędzia stolik") or text.startswith("sedzia stolik"):
        return TABLE
    return FIELD


def clean_code(value: Any) -> str:
    """Numer meczu jak wpisany; pusto = „SPARING"."""
    text = " ".join(_s(value).split())
    return text[:40] or DEFAULT_CODE


def club_season(day: Optional[date]) -> str:
    """
    Sezon panelu klubów dla dnia meczu - ta sama granica co
    `province_clubs.season_range` (1.09 - 31.08), bo to ona decyduje, w którym
    sezonie karta klubu pokaże mecz.
    """
    if day is None:
        return ""
    start = day.year if day.month >= 9 else day.year - 1
    return f"{start}/{start + 1}"


def parse_time(value: Any) -> Optional[time]:
    match = re.match(r"^\s*(\d{1,2})[:.](\d{2})", _s(value))
    if not match:
        return None
    hour, minute = int(match.group(1)), int(match.group(2))
    if hour > 23 or minute > 59:
        return None
    return time(hour, minute)


def match_instant(day: date, match_time: Any = None) -> datetime:
    """Dzień i godzina meczu w czasie POLSKIM jako chwila ze strefą."""
    return datetime.combine(day, parse_time(match_time) or DEFAULT_TIME, tzinfo=WARSAW)


# ---------------------------------------------------------------------------
# Brutto / netto
# ---------------------------------------------------------------------------

def net_of(gross: float) -> int:
    """Netto jednego ryczałtu - wprost z `settlement_rates.net_parts`."""
    return int(R.net_parts(round(float(gross or 0)))["net"])


def gross_from_net(net: float) -> int:
    """
    Najmniejsze CAŁKOWITE brutto, którego netto (`net_parts`) jest >= podanego.

    Odwrotność liczona dokładnie, przeszukaniem, a nie wzorem: `net_parts`
    zaokrągla koszty i podatek do złotówki i ma próg 200 zł (KUP 20% dopiero
    POWYŻEJ 200 zł, podatek 12% od reszty), więc wzór odwrotny myliłby się
    o złotówkę przy zaokrągleniach.

    ⚠ Luka przy progu: brutto 200 zł daje 176 zł netto, a 201 zł już 182 zł
    (od 201 zł wchodzą koszty uzyskania). Netto 177-181 zł nie da się więc
    uzyskać DOKŁADNIE - dostaje brutto 201 zł, a wycena mówi, ile wyjdzie netto
    naprawdę (`net_of`). Brutto jest całkowite, bo rozliczenie sędziego i tak
    zaokrągla ryczałt do złotówki.
    """
    target = round(float(net or 0))
    if target <= 0:
        return 0
    # Netto to co najmniej ~84% brutto (0.88 poniżej progu, 0.904 powyżej),
    # więc brutto nie przekroczy 1.2 x netto + zapas na zaokrąglenia.
    low = max(1, int(target * 0.95) - 2)
    high = int(target * 1.25) + 10
    for gross in range(low, high + 1):
        if net_of(gross) >= target:
            return gross
    return high


def fee_gross(amount: Any, mode: str) -> int:
    """Ryczałt z formularza (brutto albo netto) -> brutto całkowite."""
    value = _num(amount) or 0.0
    if value <= 0:
        return 0
    if _s(mode) == MODE_NET:
        return gross_from_net(value)
    return int(round(value))


# ---------------------------------------------------------------------------
# Podpowiedzi z tabel okręgu
# ---------------------------------------------------------------------------

def _content(version: Any) -> Any:
    if version is None:
        return None
    return version.get("content") if isinstance(version, dict) else getattr(version, "content", None)


def default_fee(
    code: Any,
    role: str,
    day: date,
    *,
    central_versions: Iterable[Any],
    province_versions: Iterable[Any],
    distance_km: float = 10.0,
) -> tuple[int, str]:
    """
    Domyślny ryczałt brutto dla roli - (kwota, skąd).

    Kolejność: numer meczu rozpoznany przez `calculate_gross` (np. „S/JmM/12"),
    potem kategoria „Inne" z tabeli okręgu z dnia meczu (tak liczy się numer
    bez kategorii, np. „SPARING"), potem gałąź „okręgowe" tabeli centralnej,
    a na końcu stała podpowiedź. Źródło idzie do ekranu, żeby było widać, czy
    kwota pochodzi z tabeli, czy jest zgadnięta.
    """
    role_name = ROLE_OF.get(role, R.ROLE_FIELD)
    central = _content(R.pick_version(list(central_versions or []), day))
    provincial = _content(R.pick_version(list(province_versions or []), day))
    km = float(distance_km or 0)

    text = clean_code(code)
    if text != DEFAULT_CODE:
        hit = R.calculate_gross(
            code=text,
            role=role_name,
            distance_km=km,
            when=day,
            central_book=central,
            province_content=provincial,
        )
        if hit > 0:
            return int(round(hit)), "code"

    other = R.provincial_gross(provincial, km, "Inne", role_name, day)
    if other > 0:
        return int(round(other)), "province"
    fallback = R.district_fallback(central, km, role_name)
    if fallback > 0:
        return int(round(fallback)), "central"
    return FALLBACK_FEES.get(role, FALLBACK_FEES[FIELD]), "fallback"


def km_rate(
    code: Any,
    province: str,
    day: date,
    *,
    central_versions: Iterable[Any],
    province_versions: Iterable[Any],
) -> float:
    """Stawka za km (w jedną stronę) - ta sama funkcja co w rozliczeniu."""
    central = _content(R.pick_version(list(central_versions or []), day))
    provincial = _content(R.pick_version(list(province_versions or []), day))
    return float(
        R.kilometer_rate(
            code=clean_code(code),
            province=province,
            province_content=provincial,
            central_book=central,
            when=day,
        )
    )


# ---------------------------------------------------------------------------
# Wycena
# ---------------------------------------------------------------------------

def price_officials(
    officials: Iterable[dict],
    *,
    field_fee: int,
    table_fee: int,
    rate: float,
    travel_enabled: bool,
) -> list[dict]:
    """
    Obsada z kwotami: ryczałt z roli, przejazd z km x 2 x stawka.

    Każdy wiersz: judge_id, name, role (field|table), home_city, km_one_way,
    km_source, fee_gross, travel. Przejazd liczy `settlement_rates.travel_pln`
    - ta sama funkcja co dla meczów z terminarza, do grosza.
    """
    out: list[dict] = []
    for raw in officials or []:
        role = normalize_role(raw.get("role"))
        km = _num(raw.get("km_one_way"))
        km = max(0.0, round(km, 1)) if km is not None else None
        source = _s(raw.get("km_source")) or ("none" if km is None else "manual")
        if source not in KM_SOURCES:
            source = "manual"
        travel = R.travel_pln(km, rate) if (travel_enabled and km) else 0.0
        out.append(
            {
                "judge_id": _s(raw.get("judge_id")),
                "name": _s(raw.get("name")),
                "role": role,
                "home_city": _s(raw.get("home_city")),
                "km_one_way": km,
                "km_source": source,
                "fee_gross": int(field_fee if role == FIELD else table_fee),
                "travel": float(travel),
            }
        )
    # Boiskowi przed stolikowymi - kolejność rachunku i listy w karcie klubu.
    out.sort(key=lambda item: (0 if item["role"] == FIELD else 1))
    return out


def totals_of(priced: Iterable[dict]) -> dict:
    items = list(priced)
    gross = sum(int(item["fee_gross"]) for item in items)
    travel = round(sum(float(item["travel"]) for item in items), 2)
    return {
        "officials": len(items),
        "field": sum(1 for item in items if item["role"] == FIELD),
        "table": sum(1 for item in items if item["role"] == TABLE),
        "gross": gross,
        "travel": travel,
        "km": round(sum(float(item["km_one_way"] or 0) for item in items if item["travel"]) * R.ROUND_TRIP, 1),
        "total": round(gross + travel, 2),
    }


def problems(
    *,
    day: Optional[date],
    city: Any,
    officials: Iterable[dict],
    field_fee: int,
    table_fee: int,
    travel_enabled: bool,
) -> list[str]:
    """
    Czego brakuje do zapisu - każdy brak własnym zdaniem, nigdy cicha blokada.
    Pusta lista = można zapisać.
    """
    items = list(officials or [])
    out: list[str] = []
    if day is None:
        out.append("Wybierz dzień meczu.")
    if not _s(city):
        out.append("Podaj miasto meczu.")
    if not items:
        out.append("Dodaj co najmniej jednego sędziego.")
    if any(not item.get("judge_id") for item in items):
        out.append("Każdy sędzia musi być wybrany z listy okręgu.")
    seen: set[tuple[str, str]] = set()
    for item in items:
        key = (_s(item.get("judge_id")), normalize_role(item.get("role")))
        if key[0] and key in seen:
            out.append(f"{item.get('name') or key[0]} jest dodany dwa razy w tej samej roli.")
        seen.add(key)
    roles = {normalize_role(item.get("role")) for item in items}
    if FIELD in roles and field_fee <= 0:
        out.append("Podaj ryczałt boiskowego większy od zera.")
    if TABLE in roles and table_fee <= 0:
        out.append("Podaj ryczałt stolikowego większy od zera.")
    if travel_enabled:
        missing = [
            item.get("name") or item.get("judge_id") or "sędzia"
            for item in items
            if _num(item.get("km_one_way")) is None
        ]
        if missing:
            out.append(
                "Brak kilometrów dla: " + ", ".join(str(name) for name in missing)
                + ". Wpisz je albo wyłącz zwrot za dojazd."
            )
    return out


# ---------------------------------------------------------------------------
# Rekord -> obsady silnika -> wiersz obciążenia
# ---------------------------------------------------------------------------

def officials_of(record: dict) -> list[dict]:
    """Obsada z rekordu - JSON trzymany w kolumnie tekstowej."""
    raw = record.get("officials")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw or "[]")
        except ValueError:
            raw = []
    return [item for item in (raw or []) if isinstance(item, dict)]


def _teams_label(club_name: str) -> str:
    """
    Napis „drużyn" przy obsadzie - sama nazwa klubu, BEZ „ - ".

    ⚠ Separator „ - " oznacza dla `club_charges.host_from_teams` parę
    „Gospodarz - Gość". Bez niego gospodarz jest pusty, więc most
    `settlement_club_scope` nie przeniesie ręcznego meczu do rozliczenia
    klubu płacącego samemu - sędziom płaci okręg, a klub oddaje to okręgowi.
    """
    return " ".join(_s(club_name).replace(" - ", " ").split())


def _totals(record: dict) -> dict:
    raw = record.get("totals")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw or "{}")
        except ValueError:
            raw = {}
    return raw if isinstance(raw, dict) else {}


def _km_rate_of(record: dict) -> Optional[float]:
    """Stawka za km zapisana przy wycenie - idzie do kolumny „stawka" listy przejazdów."""
    value = _num(_totals(record).get("km_rate"))
    return value if value and value > 0 else None


def assignments_of(record: dict, *, club_name: str = "") -> list[E.Assignment]:
    """Rekord ręcznego meczu jako zwykłe obsady silnika z gotową kwotą."""
    day = record.get("day")
    if isinstance(day, datetime):
        day = day.date()
    if not isinstance(day, date):
        day = R.as_date(day)
    if day is None:
        return []
    when = match_instant(day, record.get("match_time"))
    key = match_key(record.get("id"))
    code = clean_code(record.get("code"))
    city = _s(record.get("city"))
    travel_enabled = bool(record.get("travel_enabled", True))
    out: list[E.Assignment] = []
    for item in officials_of(record):
        judge_id = _s(item.get("judge_id"))
        if not judge_id:
            continue
        km = _num(item.get("km_one_way"))
        travel = float(item.get("travel") or 0) if travel_enabled else 0.0
        out.append(
            E.Assignment(
                match_key=key,
                judge_id=judge_id,
                judge_name=_s(item.get("name")),
                match_at=when,
                match_code=code,
                role=ROLE_OF[normalize_role(item.get("role"))],
                origin=ORIGIN,
                city=city,
                home_city=_s(item.get("home_city")),
                teams=_teams_label(club_name),
                distance_km=km if travel_enabled else None,
                distance_source=_s(item.get("km_source")) or None,
                fixed_gross=float(item.get("fee_gross") or 0),
                fixed_travel=travel,
                fixed_km_rate=_km_rate_of(record),
            )
        )
    return out


def charge_rows(
    records: Iterable[dict],
    settled: Iterable[Any],
    *,
    judge_names: Optional[dict[str, str]] = None,
    club_names: Optional[dict[str, str]] = None,
) -> list[C.ChargeRow]:
    """
    Wiersze obciążeń z ręcznych meczów - z obsad JUŻ przeliczonych przez silnik.

    Bierzemy przeliczone (`SettledMatch`), a nie surowe rekordy, bo silnik
    zastosował już zakres sezonu i przełącznik przyszłych meczów - karta klubu
    i rozliczenie sędziego widzą więc dokładnie te same mecze.

    Status zawsze `charged`: ręczny mecz dopisuje się świadomie z karty
    konkretnego klubu, więc ani rozpoznawanie gospodarza, ani „rozlicza się
    przez okręg" go nie dotyczy. Klub oddaje okręgowi to, co okręg wypłaca
    sędziom.
    """
    judge_names = judge_names or {}
    club_names = club_names or {}
    by_id = {int(record["id"]): record for record in records if record.get("id") is not None}
    grouped: dict[str, C.ChargeRow] = {}
    for item in settled:
        record_id = record_id_of(getattr(item, "match_key", ""))
        record = by_id.get(record_id) if record_id is not None else None
        if record is None:
            continue
        row = grouped.get(item.match_key)
        if row is None:
            club_id = _s(record.get("club_id"))
            name = club_names.get(club_id, "")
            row = C.ChargeRow(
                match_key=item.match_key,
                match_at=item.match_at,
                day=item.day,
                code=item.match_code,
                category="Mecz ręczny",
                city=item.city,
                host_name=name,
                team_id="",
                team_name="",
                club_id=club_id,
                status=C.CHARGED,
                teams=_s(record.get("note")),
                manual_id=record_id,
            )
            grouped[item.match_key] = row
        row.referees.append(
            C.RefereeShare(
                judge_id=item.judge_id,
                name=judge_names.get(item.judge_id, ""),
                role=item.role,
                gross=int(item.gross or 0),
                travel=float(item.travel or 0),
            )
        )
    out: list[C.ChargeRow] = []
    for row in grouped.values():
        row.referees.sort(key=lambda share: (share.role, share.name, share.judge_id))
        row.gross = sum(int(share.gross or 0) for share in row.referees)
        row.travel = round(sum(float(share.travel or 0) for share in row.referees), 2)
        row.amount = round(row.gross + row.travel, 2)
        out.append(row)
    return out


def record_json(record: dict) -> dict:
    """Rekord do edycji w kreatorze."""
    day = record.get("day")
    totals = _totals(record)

    def iso(value: Any) -> Optional[str]:
        return value.isoformat() if hasattr(value, "isoformat") else (value or None)

    return {
        "id": record.get("id"),
        "match_key": match_key(record.get("id")),
        "club_id": _s(record.get("club_id")),
        "season": _s(record.get("season")),
        "day": iso(day),
        "match_time": _s(record.get("match_time")) or None,
        "code": clean_code(record.get("code")),
        "city": _s(record.get("city")),
        "distance_source": _s(record.get("distance_source")) or None,
        "travel_enabled": bool(record.get("travel_enabled", True)),
        "rate_mode": _s(record.get("rate_mode")) or MODE_GROSS,
        "field_fee": record.get("field_fee"),
        "table_fee": record.get("table_fee"),
        "officials": officials_of(record),
        "totals": totals or {},
        "note": _s(record.get("note")),
        "created_by": _s(record.get("created_by")) or None,
        "created_at": iso(record.get("created_at")),
        "updated_by": _s(record.get("updated_by")) or None,
        "updated_at": iso(record.get("updated_at")),
    }
