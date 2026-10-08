"""
Bomby z Rejestru nieobecności w rozliczeniu okręgu.

MODUŁ-LIŚĆ: bez bazy i sieci, żeby cała reguła chodziła w teście.

Decyzje użytkownika z 06.10.2026:
  - czynna bomba (status „active") ZDEJMUJE sędziego z wypłaty za ten mecz:
    okręg mu nie płaci, a klub gospodarza za niego nie jest obciążany. Mecz
    zostaje na liście sędziego - oznaczony, z kwotą, która przepadła,
  - cofnięcie albo unieważnienie bomby przywraca kwotę (liczymy na żywo, nic
    nie księgujemy),
  - opcjonalna KARA (kwota przy bombie) to potrącenie od kwoty do wypłaty
    PO podatku: brutto, koszty i podatek zostają bez zmian. Rodzaj kar
    okręg ustali później - na razie kwotę wpisuje człowiek.

Kara schodzi z ekwiwalentu NETTO z wypłaty okręgu w okresie meczu z bombą,
najwyżej do zera: zwrot kosztów przejazdu to nie wynagrodzenie, a ujemna
wypłata nie ma sensu na zestawieniu. Czego nie dało się potrącić, zostaje
widoczne jako „do potrącenia" - nie przechodzi samo na kolejny miesiąc.

Powiązanie bomby z obsadą:
  - bomba z ekranu meczu niesie numer meczu ZPRP (`match_id`) i numer
    zgłoszonego sędziego - para (mecz, sędzia) wystarcza,
  - bomba dopisana RĘCZNIE przez komisję (`manual:` zamiast numeru meczu,
    gdy meczu nie dało się rozpoznać przy zapisie) wiąże się po sędzim i dniu
    meczu w czasie polskim; numer meczu z wpisu zawęża wybór, a godzina
    rozstrzyga, gdy sędzia miał tego dnia kilka meczów. Niejednoznaczna -
    zostaje tylko w rejestrze, zamiast zdjąć sędziemu zły mecz.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from typing import Any, Iterable, Mapping, Optional
from zoneinfo import ZoneInfo

from app import settlement_rates as R
from app.match_bombs_rules import same_person
from app.settlement_money import money

_PL = ZoneInfo("Europe/Warsaw")

#: Przedrostek numeru meczu bomby, której przy zapisie nie powiązano z meczem.
MANUAL_MATCH_PREFIX = "manual:"

#: Ile może się różnić godzina z ręcznego wpisu od godziny meczu, żeby wpis
#: wskazał ten mecz spośród kilku tego samego dnia.
TIME_TOLERANCE = timedelta(minutes=90)

#: Powód w liście „Poza rozliczeniem okręgu" - patrz `province_settlements`.
REASON_BOMB = "bomb"
REASON_LABEL = "zgłoszona nieobecność (Rejestr nieobecności) - okręg nie wypłaca"
#: Bomba bez obsady w rozliczeniu (07.10.2026) - np. sędziego zdjęto z obsady
#: w ZPRP po nieobecności albo dzień we wpisie ręcznym nie trafia w mecz.
REASON_UNLINKED_LABEL = "zgłoszona nieobecność - meczu nie ma w rozliczeniu okręgu (nic nie przepadło, liczy się kara)"


@dataclass(frozen=True)
class BombRef:
    """Czynna bomba w kształcie potrzebnym rozliczeniu."""

    bomb_id: int
    match_id: str
    judge_id: str
    subject_name: str
    match_at: Optional[datetime]
    match_code: str
    penalty: float
    note: str
    source: str
    label: str
    created_at: Optional[datetime] = None
    #: Kara z skali okręgu (True) czy wpisana ręcznie (False) - od 07.10.2026.
    penalty_auto: bool = True
    #: Która to czynna bomba sędziego w sezonie (z niej kwota z skali).
    penalty_ordinal: Optional[int] = None


def _s(value: Any) -> str:
    return str(value or "").strip()


def _utc(value: Any) -> Optional[datetime]:
    if not isinstance(value, datetime):
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def pl_day(value: Any) -> Optional[date]:
    """Dzień w czasie polskim - `match_at` w bazie to prawdziwy UTC."""
    when = _utc(value)
    return when.astimezone(_PL).date() if when else None


def bomb_from_row(row: Mapping[str, Any]) -> BombRef:
    """Wiersz `match_bombs` -> `BombRef`."""
    teams = " - ".join(x for x in (_s(row.get("host_team")), _s(row.get("guest_team"))) if x)
    try:
        penalty = money(float(row.get("penalty") or 0))
    except (TypeError, ValueError):
        penalty = 0.0
    return BombRef(
        bomb_id=int(row.get("id") or 0),
        match_id=_s(row.get("match_id")),
        judge_id=_s(row.get("subject_judge_id")),
        subject_name=_s(row.get("subject_name")),
        match_at=_utc(row.get("match_at")),
        match_code=_s(row.get("match_code")),
        penalty=max(0.0, penalty),
        note=_s(row.get("note")),
        source=_s(row.get("source")) or "crew",
        label=_s(row.get("match_label")) or teams,
        created_at=_utc(row.get("created_at")),
        penalty_auto=_s(row.get("penalty_mode")) != "manual",
        penalty_ordinal=row.get("penalty_ordinal"),
    )


def match_id_of(match_key: Any) -> str:
    """„d:194144" / „o:194144" -> „194144"."""
    text = _s(match_key)
    return text.split(":", 1)[1] if ":" in text else text


def _same_code(a: Any, b: Any) -> bool:
    left, right = R.code_key(a), R.code_key(b)
    return bool(left and right and left == right)


def _is_subject(bomb: BombRef, judge_id: str, names: Mapping[str, str]) -> bool:
    if bomb.judge_id:
        return bomb.judge_id == judge_id
    # Wpis bez numeru (sędzia spoza listy okręgu w chwili zgłoszenia) - po nazwisku.
    return bool(bomb.subject_name) and same_person(bomb.subject_name, names.get(judge_id, ""))


def match_bombs(
    bombs: Iterable[BombRef],
    assignments: Iterable[Any],
    *,
    names: Optional[Mapping[str, str]] = None,
) -> dict[tuple[str, str], BombRef]:
    """
    Które obsady zdejmuje bomba: (klucz meczu, numer sędziego) -> bomba.

    `assignments` to obsady okręgu (`settlement_engine.Assignment` albo cokolwiek
    z polami `match_key`, `judge_id`, `match_at`, `match_code`).
    """
    names = names or {}
    items = list(assignments)
    by_match: dict[str, list[Any]] = {}
    by_judge_day: dict[tuple[str, date], list[Any]] = {}
    for item in items:
        by_match.setdefault(match_id_of(item.match_key), []).append(item)
        day = pl_day(item.match_at)
        if day is not None:
            by_judge_day.setdefault((_s(item.judge_id), day), []).append(item)

    hits: dict[tuple[str, str], BombRef] = {}
    for bomb in bombs:
        if bomb.match_id and not bomb.match_id.startswith(MANUAL_MATCH_PREFIX):
            # Bomba z numerem meczu: obsada tego sędziego przy tym meczu.
            for item in by_match.get(bomb.match_id, ()):
                judge_id = _s(item.judge_id)
                if _is_subject(bomb, judge_id, names):
                    hits.setdefault((item.match_key, judge_id), bomb)
            continue
        hit = _manual_hit(bomb, by_judge_day, names)
        if hit is not None:
            hits.setdefault((hit.match_key, _s(hit.judge_id)), bomb)
    return hits


def _manual_hit(
    bomb: BombRef,
    by_judge_day: Mapping[tuple[str, date], list[Any]],
    names: Mapping[str, str],
) -> Optional[Any]:
    day = pl_day(bomb.match_at)
    if day is None:
        return None
    candidates = [
        item
        for (judge_id, when), items in by_judge_day.items()
        if when == day and _is_subject(bomb, judge_id, names)
        for item in items
    ]
    if bomb.match_code:
        coded = [item for item in candidates if _same_code(item.match_code, bomb.match_code)]
        if coded:
            candidates = coded
    if len(candidates) == 1:
        return candidates[0]
    if len(candidates) > 1 and bomb.match_at is not None:
        close = [
            item
            for item in candidates
            if _utc(item.match_at) is not None
            and abs(_utc(item.match_at) - bomb.match_at) <= TIME_TOLERANCE
        ]
        if len(close) == 1:
            return close[0]
    return None


def unlinked(
    bombs: Iterable[BombRef],
    hits: Mapping[tuple[str, str], BombRef],
    judges: Iterable[str],
) -> list[BombRef]:
    """
    Czynne bomby NASZYCH sędziów, których nie dało się powiązać z obsadą.

    Zgłoszenie z 07.10.2026: komisja dopisała Krzysztofowi Drabowi trzy bomby
    na 03.10, a tego dnia nie miał w rozliczeniu żadnego meczu - bomby
    zostawały tylko w rejestrze, razem z karą. Teraz wchodzą do okresu po
    swojej dacie (`match_at`) jako wiersz „meczu nie ma w rozliczeniu": nic
    nie przepada, ale kara schodzi z wypłaty i wpis jest widoczny.
    """
    linked = {bomb.bomb_id for bomb in hits.values()}
    ours = {_s(j) for j in judges}
    return [
        bomb
        for bomb in bombs
        if bomb.bomb_id not in linked and bomb.judge_id and bomb.judge_id in ours and bomb.match_at
    ]


def split_bombed(
    assignments: Iterable[Any], hits: Mapping[tuple[str, str], BombRef]
) -> tuple[list[Any], list[tuple[Any, BombRef]]]:
    """Obsady do wypłaty i obsady zdjęte bombą (z bombą obok)."""
    payable: list[Any] = []
    bombed: list[tuple[Any, BombRef]] = []
    for item in assignments:
        bomb = hits.get((item.match_key, _s(item.judge_id)))
        if bomb is None:
            payable.append(item)
        else:
            bombed.append((item, bomb))
    return payable, bombed


def penalty_due(bombed: Iterable[tuple[Any, BombRef]]) -> dict[str, float]:
    """Suma kar na sędziego - każda bomba liczy się RAZ, nawet przy dwóch rolach."""
    seen: set[int] = set()
    out: dict[str, float] = {}
    for item, bomb in bombed:
        if bomb.bomb_id in seen or bomb.penalty <= 0:
            continue
        seen.add(bomb.bomb_id)
        judge_id = _s(item.judge_id)
        out[judge_id] = money(out.get(judge_id, 0) + bomb.penalty)
    return out


def apply_penalty(net: float, due: float) -> tuple[float, float]:
    """
    Ile kary schodzi z wypłaty, a ile zostaje do potrącenia.

    Potrącamy z ekwiwalentu NETTO, najwyżej do zera (patrz opis modułu).
    """
    due = money(max(0.0, float(due or 0)))
    applied = money(min(due, max(0.0, float(net or 0))))
    return applied, money(due - applied)


def apply_penalties(entries: Iterable[Any], bomb_rows: Iterable[Mapping[str, Any]]) -> dict[str, dict]:
    """
    Kary z wierszy bomb okresu na wpisach sedziow (`JudgeSettlement`).

    Kazda bomba liczy sie RAZ (sedzia w dwoch rolach przy jednym meczu ma jedna
    bombe). Kara schodzi z ekwiwalentu netto (`apply_penalty`), `total` wpisu
    maleje o to, co potracono; czego nie bylo z czego potracic - `penalty_left`.
    Zwraca {sedzia: {due, applied, left}} - takze dla sedziow bez wpisu.
    """
    due: dict[str, float] = {}
    seen: set[int] = set()
    for row in bomb_rows:
        bomb_id = int(row.get("bomb_id") or 0)
        amount = float(row.get("penalty") or 0)
        if bomb_id in seen or amount <= 0:
            continue
        seen.add(bomb_id)
        judge_id = _s(row.get("judge_id"))
        due[judge_id] = money(due.get(judge_id, 0) + amount)
    out: dict[str, dict] = {}
    by_judge = {_s(entry.judge_id): entry for entry in entries}
    for judge_id, amount in due.items():
        entry = by_judge.get(judge_id)
        applied, left = apply_penalty(entry.net if entry is not None else 0, amount)
        if entry is not None:
            entry.penalty = applied
            entry.penalty_left = left
            entry.total = round(entry.total - applied, 2)
        out[judge_id] = {"due": amount, "applied": applied, "left": left}
    return out
