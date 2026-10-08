"""
Kara za nieobecność naliczana w sezonie - MODUŁ-LIŚĆ (bez bazy i sieci).

Decyzje Radka z 07.10.2026:
  - kara rośnie z każdą bombą sędziego w sezonie: 1. = 60 zł, 2. = 90 zł,
    3. = 120 zł, 4. = 150 zł i dalej co 30 zł, bez górnej granicy,
  - kwota startowa i krok są ustawiane PER OKRĘG (domyślnie 60 i 30) - liczy
    się skala okręgu, w którego rejestrze stoi bomba,
  - liczą się wyłącznie CZYNNE bomby, po kolei wg daty meczu; cofnięcie albo
    unieważnienie przelicza resztę NA ŻYWO (było 60/90/120, unieważniona
    druga -> 60/90),
  - kara wpisana ręcznie (inna kwota albo „bez kary") zmienia tylko tę bombę,
    a bomba DALEJ liczy się jako kolejna w sezonie (2. ręcznie 0 zł, 3. nadal
    120 zł); „Przywróć automatyczną" wraca do skali.

Kolejność liczymy dla SĘDZIEGO w sezonie, niezależnie od tego, który okręg
prowadzi wpis (okręg bomby to okręg autora, a rozliczenie i tak szuka jej po
sędzim we wszystkich okręgach - `province_settlements._active_bombs`).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Mapping, Optional

from app.match_bombs_rules import counts_to_stats, name_parts
from app.settlement_money import money
from app.zprp_accounts import normalize_province

DEFAULT_START = 60.0
DEFAULT_STEP = 30.0
#: Większa kwota (startowa, krok albo kara) to pomyłka w polu - ta sama granica
#: co przy karze wpisywanej ręcznie (`match_bombs.MAX_PENALTY`).
MAX_AMOUNT = 10000.0

MODE_AUTO = "auto"
MODE_MANUAL = "manual"

_FAR = datetime.max.replace(tzinfo=timezone.utc)


@dataclass(frozen=True)
class Scale:
    """Skala kar okręgu: kwota pierwszej bomby i przyrost za każdą kolejną."""

    start: float = DEFAULT_START
    step: float = DEFAULT_STEP
    #: Okręg zapisał własną skalę (False = domyślna 60 / +30).
    custom: bool = False

    def as_dict(self) -> Dict[str, Any]:
        return {"start": self.start, "step": self.step, "custom": self.custom}


DEFAULT_SCALE = Scale()


@dataclass(frozen=True)
class Effective:
    """Kara bomby tak, jak liczy ją rozliczenie i pokazuje rejestr."""

    #: Kwota w zł; None = bez kary (także bomba, która się nie liczy).
    amount: Optional[float]
    #: True = z skali okręgu, False = wpisana ręcznie.
    auto: bool
    #: Która to czynna bomba sędziego w sezonie (1, 2, 3...); None = nie liczy się.
    ordinal: Optional[int]


def _s(value: Any) -> str:
    return str(value or "").strip()


def _num(value: Any, label: str) -> float:
    try:
        amount = round(float(value), 2)
    except (TypeError, ValueError):
        raise ValueError(f"{label} musi być kwotą w złotych.")
    if amount != amount or amount < 0:
        raise ValueError(f"{label} nie może być ujemna.")
    if amount > MAX_AMOUNT:
        raise ValueError(f"{label} powyżej {int(MAX_AMOUNT)} zł wygląda na pomyłkę w polu.")
    return amount


def normalize_scale(start: Any, step: Any) -> Scale:
    """Skala z formularza - albo odmowa zdaniem, co poprawić."""
    return Scale(
        start=_num(start, "Kara za pierwszą nieobecność"),
        step=_num(step, "Przyrost za kolejną nieobecność"),
        custom=True,
    )


def scale_from_row(row: Optional[Mapping[str, Any]]) -> Scale:
    """Skala z wiersza `province_bomb_penalty_scale`; brak wiersza = domyślna."""
    if not row:
        return DEFAULT_SCALE
    try:
        return normalize_scale(row.get("start"), row.get("step"))
    except ValueError:
        return DEFAULT_SCALE


def amount_for(ordinal: int, scale: Scale = DEFAULT_SCALE) -> float:
    """Kara n-tej bomby w sezonie: start + krok × (n - 1)."""
    n = max(1, int(ordinal))
    return money(min(MAX_AMOUNT, scale.start + scale.step * (n - 1)))


def subject_key(row: Mapping[str, Any]) -> str:
    """Kto dostał bombę - numer sędziego, a bez numeru nazwisko bez kolejności członów.

    „DRAB Krzysztof" i „Krzysztof DRAB" to ten sam człowiek (ZPRP i lista
    okręgu piszą nazwisko w różnej kolejności).
    """
    judge_id = _s(row.get("subject_judge_id"))
    if judge_id:
        return f"id:{judge_id}"
    return "n:" + " ".join(sorted(name_parts(row.get("subject_name"))))


def _aware(value: Any) -> Optional[datetime]:
    if not isinstance(value, datetime):
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def order_key(row: Mapping[str, Any]) -> tuple:
    """Kolejność bomb w sezonie: data meczu, potem chwila wpisu, potem numer wpisu.

    Mecz bez daty idzie na koniec (brak `data_fakt` to luka w bazie związku).
    """
    return (
        _aware(row.get("match_at")) or _FAR,
        _aware(row.get("created_at")) or _FAR,
        int(row.get("id") or 0),
    )


def ordinals(rows: Iterable[Mapping[str, Any]]) -> Dict[int, int]:
    """Numer kolejny każdej CZYNNEJ bomby sędziego w jej sezonie (1, 2, 3...)."""
    groups: Dict[tuple, list] = {}
    for row in rows:
        if not counts_to_stats(row.get("status")) or row.get("id") is None:
            continue
        groups.setdefault((row.get("season"), subject_key(row)), []).append(row)
    out: Dict[int, int] = {}
    for items in groups.values():
        for n, row in enumerate(sorted(items, key=order_key), start=1):
            out[int(row["id"])] = n
    return out


def is_manual(row: Mapping[str, Any]) -> bool:
    return _s(row.get("penalty_mode")) == MODE_MANUAL


def _stored(row: Mapping[str, Any]) -> Optional[float]:
    try:
        amount = money(float(row.get("penalty") or 0))
    except (TypeError, ValueError):
        return None
    return amount if amount > 0 else None


def effective(row: Mapping[str, Any], ordinal: Optional[int], scale: Scale) -> Effective:
    """Kara tej bomby: ręczna wygrywa, inaczej skala okręgu wg numeru kolejnego."""
    manual = is_manual(row)
    if not counts_to_stats(row.get("status")) or not ordinal:
        # Nieczynny wpis nie zdejmuje z wypłaty, więc i kara się nie liczy;
        # ręczną kwotę pokazujemy dalej (rejestr dopisuje „nie liczy się").
        return Effective(_stored(row) if manual else None, not manual, None)
    if manual:
        return Effective(_stored(row), False, ordinal)
    return Effective(amount_for(ordinal, scale), True, ordinal)


def preview_ordinal(
    rows: Iterable[Mapping[str, Any]],
    *,
    key: str,
    season: Optional[int],
    match_at: Optional[datetime],
) -> int:
    """Którą bombą w sezonie byłby nowy wpis o meczu z `match_at`.

    Nowy wpis powstaje „teraz", więc przy tej samej dacie meczu staje za
    istniejącymi - tak samo, jak ustawi go `ordinals` po zapisie.
    """
    when = _aware(match_at) or _FAR
    before = 0
    for row in rows:
        if not counts_to_stats(row.get("status")):
            continue
        if row.get("season") != season or subject_key(row) != key:
            continue
        if order_key(row)[0] <= when:
            before += 1
    return before + 1


def province_key(value: Any) -> str:
    """Okręg skali - ten sam slug, którym bomby zapisują okręg („SLASKIE")."""
    return normalize_province(value) or _s(value).upper()


def effective_from_pool(
    rows: Iterable[Mapping[str, Any]],
    pool: Iterable[Mapping[str, Any]],
    scales: Mapping[str, Scale],
) -> Dict[int, Effective]:
    """Kara każdej bomby z `rows`, numerowana w puli czynnych bomb sezonu.

    Pula to czynne bomby tych sezonów ze WSZYSTKICH okręgów (kolejność liczy
    się dla sędziego), a kwota bierze się z skali okręgu, w którego rejestrze
    stoi dana bomba.
    """
    numbers = ordinals(pool)
    out: Dict[int, Effective] = {}
    for row in rows:
        if row.get("id") is None:
            continue
        bomb_id = int(row["id"])
        scale = scales.get(province_key(row.get("province")), DEFAULT_SCALE)
        out[bomb_id] = effective(row, numbers.get(bomb_id), scale)
    return out
