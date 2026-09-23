"""
Alerty mailowe o saldzie klubów w Rozliczeniach BAZA_web - same reguły.

Decyzje użytkownika (23.09.2026):
  - ustawienia należą do KONTA (VIP albo sędzia-administrator) w danym okręgu,
    domyślnie wszystko wyłączone,
  - alert dotyczy BUDŻETU klubu, który rozlicza się przez okręg
    (`settles_via_district`) i ma w sezonie choć jedną wpłatę (`paid_in > 0`) -
    klub, który jeszcze nic nie wpłacił, nie „spada" poniżej progu, tylko
    w ogóle nie zaczął, i codzienny mail o nim byłby szumem,
  - warunek: saldo < próg,
  - RAZ przy przekroczeniu: kolejny mail o tym samym budżecie dopiero wtedy,
    gdy saldo wróci do progu (albo wyżej) i znowu spadnie,
  - częstotliwość sprawdzania: 4, 8, 12 albo 24 godziny.

Tempo wydawania (do treści maila): suma obciążeń z ostatnich 28 dni
(mecze ze statusem „charged", dzień meczu w oknie (dziś - 28 dni, dziś]).
  - średnio na mecz = suma / liczba meczów,
  - średnio na tydzień = suma / 4,
  - „wystarczy na ok. N meczów" = floor(saldo / średnio na mecz),
  - „wystarczy na ok. N tygodni" = floor(saldo / średnio na tydzień).
Bez meczów w oknie tempa nie zgadujemy - mail mówi wprost, że w ostatnich
4 tygodniach nie było obciążeń. Saldo ujemne = „klub jest na minusie".

MODUŁ-LIŚĆ: bez bazy i sieci, żeby reguły chodziły w teście.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from typing import Any, Iterable, Mapping, Optional

#: Dozwolone odstępy między sprawdzeniami, w godzinach.
INTERVALS: tuple[int, ...] = (4, 8, 12, 24)
DEFAULT_INTERVAL = 24
DEFAULT_THRESHOLD = 500.0
MAX_THRESHOLD = 1_000_000.0
MAX_EMAILS = 10
#: Okno, z którego liczymy tempo wydawania.
PACE_WINDOW_DAYS = 28
#: Pętla chodzi co 15 minut - bez tego luzu 4 h zamieniałyby się w 4 h 15 min.
DUE_SLACK = timedelta(minutes=5)

SEASON_CLOSE_SOURCE = "season-close"

_EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$")


class AlertRuleError(ValueError):
    """Zła wartość ustawień - komunikat nadaje się wprost na ekran."""


# ---------------------------------------------------------------------------
# Konto i walidacja ustawień
# ---------------------------------------------------------------------------

def _s(value: Any) -> str:
    return str(value if value is not None else "").strip()


def account_key(payload: Mapping[str, Any]) -> str:
    """
    Klucz konta z tokenu: numer sędziego („judge:1234") albo login VIP.

    Sędzia i VIP to dwa różne światy logowania - ten sam napis nie może
    oznaczać raz loginu, raz numeru, więc numer dostaje przedrostek.
    """
    judge_id = _s(payload.get("judge_id"))
    if judge_id:
        return f"judge:{judge_id}"
    return _s(payload.get("sub"))


def normalize_interval(value: Any) -> int:
    try:
        hours = int(value)
    except (TypeError, ValueError):
        raise AlertRuleError("Częstotliwość sprawdzania musi być liczbą godzin.") from None
    if hours not in INTERVALS:
        allowed = ", ".join(f"{item} h" for item in INTERVALS)
        raise AlertRuleError(f"Częstotliwość sprawdzania może wynosić tylko: {allowed}.")
    return hours


def normalize_threshold(value: Any) -> float:
    try:
        amount = float(str(value).replace(",", ".").replace(" ", ""))
    except (TypeError, ValueError):
        raise AlertRuleError("Próg musi być kwotą w złotych, np. 500.") from None
    if math.isnan(amount) or math.isinf(amount):
        raise AlertRuleError("Próg musi być kwotą w złotych, np. 500.")
    if amount <= 0:
        raise AlertRuleError("Próg musi być większy od zera.")
    if amount > MAX_THRESHOLD:
        raise AlertRuleError("Próg nie może przekraczać 1 000 000 zł.")
    return round(amount, 2)


def is_valid_email(value: Any) -> bool:
    text = _s(value)
    return len(text) <= 254 and bool(_EMAIL_RE.match(text))


def normalize_emails(values: Iterable[Any]) -> list[str]:
    """
    Lista adresów bez powtórzeń (wielkość liter bez znaczenia), w kolejności
    wpisania. Pierwszy zły adres zatrzymuje zapis z nazwą tego adresu.
    """
    seen: set[str] = set()
    clean: list[str] = []
    for raw in values or []:
        text = _s(raw)
        if not text:
            continue
        if not is_valid_email(text):
            raise AlertRuleError(f"Adres „{text}” nie wygląda na poprawny e-mail.")
        low = text.lower()
        if low in seen:
            continue
        seen.add(low)
        clean.append(text)
    if len(clean) > MAX_EMAILS:
        raise AlertRuleError(f"Można podać najwyżej {MAX_EMAILS} adresów.")
    return clean


@dataclass(frozen=True)
class AlertSettings:
    enabled: bool
    threshold: float
    interval_hours: int
    emails: list[str]


def validate_settings(*, enabled: Any, threshold: Any, interval_hours: Any, emails: Iterable[Any]) -> AlertSettings:
    """Całe ustawienia naraz. Włączony alert bez adresu nie miałby dokąd iść."""
    clean = normalize_emails(emails)
    settings = AlertSettings(
        enabled=bool(enabled),
        threshold=normalize_threshold(threshold),
        interval_hours=normalize_interval(interval_hours),
        emails=clean,
    )
    if settings.enabled and not clean:
        raise AlertRuleError("Włączony alert potrzebuje co najmniej jednego adresu e-mail.")
    return settings


# ---------------------------------------------------------------------------
# Harmonogram
# ---------------------------------------------------------------------------

def is_due(last_check_at: Optional[datetime], interval_hours: int, now: datetime) -> bool:
    """Czy minął odstęp od ostatniego sprawdzenia. Nigdy nie sprawdzane = teraz."""
    if last_check_at is None:
        return True
    return now - last_check_at >= timedelta(hours=interval_hours) - DUE_SLACK


def next_check_at(last_check_at: Optional[datetime], interval_hours: int, now: datetime) -> datetime:
    """Kiedy najpóźniej pójdzie następne sprawdzenie (pętla chodzi co 15 minut)."""
    if last_check_at is None:
        return now
    return max(now, last_check_at + timedelta(hours=interval_hours))


# ---------------------------------------------------------------------------
# Wybór budżetów i „raz przy przekroczeniu"
# ---------------------------------------------------------------------------

def _money(value: Any) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def watched_budgets(budgets: Mapping[str, Mapping[str, Any]]) -> dict[str, Mapping[str, Any]]:
    """Budżety pod obserwacją: rozliczane przez okręg i z co najmniej jedną wpłatą."""
    return {
        budget_id: budget
        for budget_id, budget in budgets.items()
        if bool(budget.get("settles_via_district", True)) and _money(budget.get("paid_in")) > 0
    }


@dataclass
class AlertDecision:
    #: Budżety, o których trzeba teraz napisać (spadły poniżej progu).
    alert: list[str] = field(default_factory=list)
    #: Budżety, które wróciły do progu - ich stan „mail poszedł" gaśnie.
    rearm: list[str] = field(default_factory=list)
    #: Poniżej progu, ale mail już poszedł wcześniej - milczymy.
    still_below: list[str] = field(default_factory=list)


def decide(
    budgets: Mapping[str, Mapping[str, Any]],
    alerted: Iterable[str],
    threshold: float,
) -> AlertDecision:
    """
    Kto dostaje mail, a komu gasimy znacznik.

    `alerted` = budżety, o których mail już poszedł i saldo od tamtej pory nie
    wróciło do progu. Budżet, który zniknął z obserwacji (przestał rozliczać się
    przez okręg), też gaśnie - gdy wróci, zaczyna od czystej karty.
    """
    watched = watched_budgets(budgets)
    already = set(alerted)
    decision = AlertDecision()
    for budget_id in sorted(watched):
        below = _money(watched[budget_id].get("balance")) < threshold
        if below and budget_id in already:
            decision.still_below.append(budget_id)
        elif below:
            decision.alert.append(budget_id)
        elif budget_id in already:
            decision.rearm.append(budget_id)
    decision.rearm.extend(sorted(item for item in already if item not in watched))
    return decision


# ---------------------------------------------------------------------------
# Treść: ostatnia wpłata i tempo wydawania
# ---------------------------------------------------------------------------

def _as_date(value: Any) -> Optional[date]:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    text = _s(value)
    if len(text) >= 10:
        try:
            return date.fromisoformat(text[:10])
        except ValueError:
            return None
    return None


def last_payment(entries: Iterable[Mapping[str, Any]]) -> Optional[tuple[Optional[date], float]]:
    """
    Najnowsza wpłata: (dzień, kwota). Wypłaty i zapis „rozliczenie sezonu"
    (to nie pieniądze od klubu, tylko księgowe zamknięcie) się nie liczą.
    """
    best: Optional[tuple[date, int, float]] = None
    for row in entries:
        if _s(row.get("source")) == SEASON_CLOSE_SOURCE:
            continue
        if _s(row.get("kind")).lower().startswith("out"):
            continue
        amount = _money(row.get("amount"))
        if amount <= 0:
            continue
        day = _as_date(row.get("day")) or date.min
        rank = (day, int(row.get("id") or 0), amount)
        if best is None or rank[:2] > best[:2]:
            best = rank
    if best is None:
        return None
    return (best[0] if best[0] != date.min else None, round(best[2], 2))


@dataclass(frozen=True)
class Pace:
    negative: bool
    #: Obciążenia z okna (28 dni) - suma i liczba meczów.
    window_total: float
    window_matches: int
    per_match: Optional[float]
    per_week: Optional[float]
    matches_left: Optional[int]
    weeks_left: Optional[int]


def spending_pace(
    balance: float,
    charges: Iterable[tuple[Any, Any]],
    today: date,
    window_days: int = PACE_WINDOW_DAYS,
) -> Pace:
    """`charges` = pary (dzień meczu, kwota) obciążeń budżetu. Wzór w opisie modułu."""
    start = today - timedelta(days=window_days)
    total = 0.0
    count = 0
    for day_raw, amount_raw in charges:
        day = _as_date(day_raw)
        amount = _money(amount_raw)
        if day is None or amount <= 0 or not (start < day <= today):
            continue
        total += amount
        count += 1
    per_match = round(total / count, 2) if count else None
    per_week = round(total / (window_days / 7), 2) if count else None
    negative = balance < 0
    matches_left = weeks_left = None
    if not negative and per_match:
        matches_left = int(balance // per_match)
    if not negative and per_week:
        weeks_left = int(balance // per_week)
    return Pace(
        negative=negative,
        window_total=round(total, 2),
        window_matches=count,
        per_match=per_match,
        per_week=per_week,
        matches_left=matches_left,
        weeks_left=weeks_left,
    )


# ---------------------------------------------------------------------------
# Napisy
# ---------------------------------------------------------------------------

def plural(count: int, one: str, few: str, many: str) -> str:
    """Polska odmiana liczebnika: 1 klub, 2 kluby, 5 klubów, 22 kluby, 12 klubów."""
    n = abs(int(count))
    if n == 1:
        return one
    if 2 <= n % 10 <= 4 and not 12 <= n % 100 <= 14:
        return few
    return many


def format_pln(amount: Any, *, sign: bool = False) -> str:
    """„1 234,50 zł" - spacja tysięcy nierozdzielająca, grosze tylko gdy są."""
    value = _money(amount)
    negative = value < 0
    value = abs(value)
    whole = int(value)
    cents = int(round((value - whole) * 100))
    if cents == 100:
        whole, cents = whole + 1, 0
    text = f"{whole:,}".replace(",", " ")
    if cents:
        text += f",{cents:02d}"
    prefix = "-" if negative else ("+" if sign and value > 0 else "")
    return f"{prefix}{text} zł"


def province_title(display_name: str) -> str:
    """„ŚLĄSKIE" -> „Śląskie", „KUJAWSKO-POMORSKIE" -> „Kujawsko-Pomorskie"."""
    return "-".join(part[:1].upper() + part[1:].lower() for part in _s(display_name).split("-"))


def subject_line(province_display: str, count: int, threshold: float) -> str:
    name = province_title(province_display)
    word = plural(count, "klub", "kluby", "klubów")
    return f"{name}: {count} {word} poniżej {format_pln(threshold)}"


def pace_sentence(pace: Pace) -> str:
    if pace.negative:
        return "Klub jest na minusie - obciążenia przekroczyły wpłaty."
    if not pace.window_matches:
        return "W ostatnich 4 tygodniach nie było obciążeń - tempa nie da się ocenić."
    parts = []
    if pace.matches_left is not None:
        parts.append(f"ok. {pace.matches_left} {plural(pace.matches_left, 'mecz', 'mecze', 'meczów')}")
    if pace.weeks_left is not None:
        parts.append(f"ok. {pace.weeks_left} {plural(pace.weeks_left, 'tydzień', 'tygodnie', 'tygodni')}")
    return "Przy obecnym tempie wystarczy na " + " / ".join(parts) + "."
