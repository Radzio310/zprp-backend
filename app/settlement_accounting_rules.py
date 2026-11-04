"""
Plik księgowej (04.11.2026) - sama reguła, bez bazy i sieci.

SKĄD TO SIĘ WZIĘŁO. Księgowa okręgu (Karolina Golec) wczytuje ryczałty
sędziowskie do programu kadrowo-płacowego enova365 z własnego skoroszytu:
zakładka „dane do importu" (kod osoby, okres, numer dokumentu, data wypłaty,
kwota brutto i kolumny kontrolne KUP, podstawa, podatek, do wypłaty) zasila
zakładkę „Import" (kolumny enova: Class, Definicja:Symbol, Pracownik:Kod,
Data, Wydzial:Kod, Seria, Opis, Tytul, Okres, Wartosc, Element:Nazwa,
RodzajRozliczenia). Dane przepisywała ręcznie z list od Wojtka. Teraz do
każdego zestawienia - szkicu i oficjalnego - BAZA wydaje gotowy skoroszyt.

DECYZJE UŻYTKOWNIKA (04.11.2026):
  - Formuła podatku to ustawienie okręgu: „baza" (KUP, podstawa i podatek do
    pełnych złotych, `settlement_rates._tax_parts`) albo „arkusz" (formuła
    z arkusza księgowej: KUP 20% z groszami, podstawa z groszami, podatek
    ROUND(podstawa x 12%, 0)). Przy ok. 3% kwot wychodzi 1 zł różnicy
    (brutto 318 zł: 30 zł albo 31 zł) - Excel zaznacza takie wiersze.
  - Numer dokumentu: wzór do wyboru - sezonowy „SL/2026_27/14" albo
    kalendarzowy „14/S/2026", jak dotąd u księgowej.
  - Kod osoby w enova: słownik okręgu z podpowiedzią - NAZWISKO, a przy
    zbieżności nazwisk NAZWISKO+IMIĘ obcięte do 15 znaków (PYTLIKALEKSANDR).
  - Okres = okres rozliczenia, Data = jego ostatni dzień, data wypłaty
    wybierana przy generowaniu.
  - Szkic: pełny skoroszyt, ale oznaczony SZKIC i z pustą kolumną Opis
    w zakładce Import, żeby nie wszedł do enova przypadkiem.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date
from decimal import ROUND_HALF_UP, Decimal
from typing import Any, Iterable, Optional

# ---------------------------------------------------------------------------
# Podatek
# ---------------------------------------------------------------------------

#: Formuła BAZA: KUP, podstawa i podatek do pełnych złotych.
FORMULA_BAZA = "baza"
#: Formuła arkusza księgowej: KUP i podstawa z groszami, podatek do złotówki.
FORMULA_SHEET = "arkusz"
#: Formuła enova: KUP z groszami, podstawa do pełnych złotych (zrzuty enova
#: w zakładce „Uwagi" skoroszytu księgowej: koszty uzyskania 780,06). Podatek
#: zawsze równy formule BAZA - różni się tylko zapis KUP i podstawy.
FORMULA_ENOVA = "enova"
FORMULAS = (FORMULA_BAZA, FORMULA_ENOVA, FORMULA_SHEET)

#: Próg, do którego koszty uzyskania nie przysługują (brutto <= 200 zł).
THRESHOLD = Decimal("200")


def _dec(value: Any) -> Decimal:
    try:
        number = Decimal(str(float(value or 0)))
    except (TypeError, ValueError, ArithmeticError):
        return Decimal("0")
    if not number.is_finite():
        return Decimal("0")
    return number.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def _whole(value: Decimal) -> int:
    """Do pełnych złotych, połówka w górę (jak Excel ROUND i ordynacja)."""
    return int(value.quantize(Decimal("1"), rounding=ROUND_HALF_UP))


def _f(value: Decimal) -> float:
    return float(value) + 0.0


def tax_parts(gross: Any, formula: str = FORMULA_BAZA) -> dict:
    """
    Rachunek jednego wiersza: brutto -> KUP, podstawa, podatek, do wypłaty.

    „baza" daje dokładnie to samo, co `settlement_rates._tax_parts`, a więc
    ekran rozliczeń. „arkusz" - to, co liczą formuły w skoroszycie księgowej
    (=IF(H<=200,0,H*0.2), =H-I, =ROUND(J*0.12,0), =H-K).
    """
    g = _dec(gross)
    exact_costs = (g * Decimal("0.2")).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP) if g > THRESHOLD else Decimal("0")
    if formula == FORMULA_SHEET:
        # Dokładnie jak Excel: KUP i podstawa bez zaokrąglenia (228,274), tylko
        # podatek ROUND(...; 0). Na ekran i do pliku - do grosza.
        raw_costs = g * Decimal("0.2") if g > THRESHOLD else Decimal("0")
        raw_taxable = g - raw_costs
        tax = _whole(raw_taxable * Decimal("0.12")) if raw_taxable > 0 else 0
        costs = raw_costs.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
        taxable = raw_taxable.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    elif formula == FORMULA_ENOVA:
        costs = exact_costs
        taxable = Decimal(_whole(g - costs))
        tax = _whole(taxable * Decimal("0.12")) if taxable > 0 else 0
    else:
        costs = Decimal(_whole(g * Decimal("0.2"))) if g > THRESHOLD else Decimal("0")
        taxable = Decimal(_whole(g - costs))
        tax = _whole(taxable * Decimal("0.12")) if taxable > 0 else 0
    return {
        "gross": _f(g),
        "costs": _f(costs),
        "taxable": _f(taxable),
        "tax": int(tax),
        "net": _f(g - Decimal(tax)),
    }


def other_formula(formula: str) -> str:
    """Formuła, z którą porównujemy podatek w pliku (zaznaczone wiersze)."""
    return FORMULA_ENOVA if formula == FORMULA_SHEET else FORMULA_SHEET


def formula_of(value: Any) -> str:
    text = str(value or "").strip().lower()
    return text if text in FORMULAS else FORMULA_BAZA


def formula_label(formula: str) -> str:
    if formula == FORMULA_SHEET:
        return "jak arkusz księgowej (KUP i podstawa z groszami)"
    if formula == FORMULA_ENOVA:
        return "jak enova (KUP z groszami, podstawa do pełnych złotych)"
    return "BAZA (KUP i podstawa do pełnych złotych)"


def formula_short(formula: str) -> str:
    """Do dopisku przy wierszu: „wg arkusza: podatek 31 zł"."""
    return {FORMULA_SHEET: "wg arkusza", FORMULA_ENOVA: "wg enova"}.get(formula, "wg BAZA")


def excel_formulas(formula: str, row: int) -> dict[str, str]:
    """Formuły kolumn kontrolnych w zakładce „dane do importu" (I-L)."""
    h = f"H{row}"
    if formula == FORMULA_ENOVA:
        return {
            "I": f"=IF({h}<=200,0,ROUND({h}*0.2,2))",
            "J": f"=ROUND({h}-I{row},0)",
            "K": f"=ROUND(J{row}*0.12,0)",
            "L": f"={h}-K{row}",
        }
    if formula == FORMULA_SHEET:
        return {
            "I": f"=IF({h}<=200,0,{h}*0.2)",
            "J": f"={h}-I{row}",
            "K": f"=ROUND(J{row}*0.12,0)",
            "L": f"={h}-K{row}",
        }
    return {
        "I": f"=IF({h}<=200,0,ROUND({h}*0.2,0))",
        "J": f"=ROUND({h}-I{row},0)",
        "K": f"=ROUND(J{row}*0.12,0)",
        "L": f"={h}-K{row}",
    }


# ---------------------------------------------------------------------------
# Kod osoby w enova
# ---------------------------------------------------------------------------

#: Kod pracownika w enova ma u księgowej najwyżej 15 znaków (PYTLIKALEKSANDR).
CODE_MAX = 15

_CODE_STRIP = re.compile(r"[^0-9A-ZĄĆĘŁŃÓŚŹŻ]")


def _code_part(text: str) -> str:
    return _CODE_STRIP.sub("", str(text or "").upper())


def split_name(display_name: str) -> tuple[str, str]:
    """„KOWALSKA-NOWAK Anna Maria" -> („KOWALSKA-NOWAK", „Anna Maria")."""
    from app.settlement_engine import split_judge_name

    parts = split_judge_name(display_name)
    if parts is None:
        return str(display_name or "").strip(), ""
    return parts[0].upper(), parts[1]


def code_base(surname: str) -> str:
    return _code_part(surname)[:CODE_MAX]


def code_long(surname: str, given: str) -> str:
    first = (given or "").split()
    return (_code_part(surname) + _code_part(first[0] if first else ""))[:CODE_MAX]


def normalize_code(value: Any) -> str:
    """Kod wpisany ręcznie: wersaliki, bez spacji i znaków spoza alfabetu."""
    return _code_part(value)[:CODE_MAX]


@dataclass
class CodePick:
    code: str
    #: „saved" - ze słownika okręgu, „suggested" - z reguły, do potwierdzenia.
    source: str
    #: Inni ludzie z tym samym kodem (po nazwisku) - wymaga decyzji człowieka.
    conflict_with: list[str] = field(default_factory=list)


def suggest_codes(people: Iterable[tuple[str, str]], saved: dict[str, str]) -> dict[str, CodePick]:
    """
    Kody dla wszystkich osób okręgu: [(judge_id, „NAZWISKO Imię")] -> CodePick.

    Reguła księgowej: samo NAZWISKO, a gdy w okręgu jest więcej osób o tym
    nazwisku - NAZWISKO+IMIĘ (obcięte do 15 znaków). Kod ze słownika wygrywa
    zawsze. Dwie osoby z tym samym kodem to konflikt - ekran go pokazuje.
    """
    people = [(str(j), str(n or "")) for j, n in people]
    by_surname: dict[str, int] = {}
    split: dict[str, tuple[str, str]] = {}
    for judge_id, name in people:
        surname, given = split_name(name)
        split[judge_id] = (surname, given)
        key = code_base(surname)
        by_surname[key] = by_surname.get(key, 0) + 1

    out: dict[str, CodePick] = {}
    for judge_id, _name in people:
        surname, given = split[judge_id]
        if saved.get(judge_id):
            out[judge_id] = CodePick(normalize_code(saved[judge_id]), "saved")
            continue
        base = code_base(surname)
        code = code_long(surname, given) if by_surname.get(base, 0) > 1 else base
        out[judge_id] = CodePick(code, "suggested")

    holders: dict[str, list[str]] = {}
    for judge_id, pick in out.items():
        if pick.code:
            holders.setdefault(pick.code, []).append(judge_id)
    for code, ids in holders.items():
        if len(ids) > 1:
            for judge_id in ids:
                out[judge_id].conflict_with = [other for other in ids if other != judge_id]
    return out


# ---------------------------------------------------------------------------
# Numeracja
# ---------------------------------------------------------------------------

#: „SL/2026_27/14" - ciągła w sezonie (sierpień-lipiec), jak dotąd w BAZA.
SCHEME_SEASON = "season"
#: „14/S/2026" - ciągła w roku kalendarzowym wydania, jak u księgowej.
SCHEME_CALENDAR = "calendar"
SCHEMES = (SCHEME_SEASON, SCHEME_CALENDAR)

#: Wyróżnik rodzaju w numerze kalendarzowym („14/S/2026", „3/P/2026").
DEFAULT_MARKS = {"zestawienie": "S", "przejazdy": "P"}


def scheme_of(value: Any) -> str:
    text = str(value or "").strip().lower()
    return text if text in SCHEMES else SCHEME_SEASON


def mark_of(value: Any, kind: str) -> str:
    text = re.sub(r"[^0-9A-Za-ząćęłńóśźżĄĆĘŁŃÓŚŹŻ]", "", str(value or "")).upper()[:4]
    return text or DEFAULT_MARKS.get(kind, "S")


# ---------------------------------------------------------------------------
# Daty i okres
# ---------------------------------------------------------------------------

def pl_date(value: Optional[date]) -> str:
    return value.strftime("%d.%m.%Y") if value else ""


def period_text(date_from: Optional[date], date_to: Optional[date], *, enova: bool = False) -> str:
    """
    Okres w zakładce „dane do importu" - „01.06.2026…30.06.2026" (wielokropek,
    jak u księgowej). `enova=True` - zapis, który przyjmuje enova w kolumnie
    Okres zakładki Import: trzy kropki („01.06.2026...30.06.2026").
    """
    if not date_from or not date_to:
        return ""
    joint = "..." if enova else "…"
    return f"{pl_date(date_from)}{joint}{pl_date(date_to)}"


def parse_day(value: Any) -> Optional[date]:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return date.fromisoformat(text[:10])
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Wiersze skoroszytu
# ---------------------------------------------------------------------------

@dataclass
class SheetRow:
    judge_id: str
    name: str
    surname: str
    given: str
    code: str
    code_source: str
    code_conflict: bool
    #: Litera części puli („A") albo pusty napis; `part_of` - z ilu części.
    part: str
    part_of: int
    gross: float
    costs: float
    taxable: float
    tax: int
    net: float
    #: Podatek według drugiej formuły - gdy inny niż `tax`, wiersz jest
    #: zaznaczony w pliku i na ekranie.
    other_tax: int

    @property
    def differs(self) -> bool:
        return int(self.other_tax) != int(self.tax)

    def note(self, other_label: str) -> str:
        bits: list[str] = []
        if self.part and self.part_of > 1:
            bits.append(f"lista {self.part} (z {self.part_of})")
        if self.code_conflict:
            bits.append("ten sam kod co inna osoba - popraw w Ustawieniach")
        elif self.code_source != "saved":
            bits.append("kod podpowiedziany - potwierdź")
        if self.differs:
            bits.append(f"{other_label}: podatek {self.other_tax} zł")
        return " · ".join(bits)


def sheet_rows(
    items: Iterable[dict],
    codes: dict[str, CodePick],
    formula: str,
) -> list[SheetRow]:
    """
    Pozycje dokumentu (KAŻDA część puli osobno - każda to odrębny rachunek
    i odrębna umowa w enova) -> wiersze skoroszytu.

    Kwoty kontrolne bierzemy z pozycji, jeśli je niesie (to, co stoi na PDF);
    brakujące liczymy z brutto tą samą formułą.
    """
    out: list[SheetRow] = []
    alt = other_formula(formula)
    for item in items:
        judge_id = str(item.get("judge_id") or "")
        name = str(item.get("name") or judge_id)
        surname, given = split_name(name)
        gross = item.get("gross") or 0
        own = tax_parts(gross, formula)
        if item.get("tax") is not None and item.get("costs") is not None:
            own = {
                "gross": float(_dec(gross)),
                "costs": float(_dec(item.get("costs"))),
                "taxable": float(_dec(item.get("taxable") if item.get("taxable") is not None else own["taxable"])),
                "tax": int(item.get("tax") or 0),
                "net": float(_dec(item.get("net") if item.get("net") is not None else own["net"])),
            }
        elif item.get("net") is not None:
            # Stary wpis rejestru bez KUP: podatek = brutto - netto.
            tax = _whole(_dec(gross) - _dec(item.get("net")))
            if tax != own["tax"] and tax >= 0:
                own = {**own, "tax": tax, "net": float(_dec(item.get("net")))}
        pick = codes.get(judge_id) or CodePick(code_base(surname), "suggested")
        out.append(
            SheetRow(
                judge_id=judge_id,
                name=name,
                surname=surname,
                given=given,
                code=pick.code,
                code_source=pick.source,
                code_conflict=bool(pick.conflict_with),
                part=str(item.get("part") or ""),
                part_of=int(item.get("part_of") or 0),
                gross=own["gross"],
                costs=own["costs"],
                taxable=own["taxable"],
                tax=int(own["tax"]),
                net=own["net"],
                other_tax=int(tax_parts(gross, alt)["tax"]),
            )
        )
    return out


def totals(rows: Iterable[SheetRow]) -> dict:
    rows = list(rows)

    def cents(values: Iterable[float]) -> float:
        return float(sum(_dec(v) for v in values)) + 0.0

    return {
        "rows": len(rows),
        "people": len({r.judge_id for r in rows}),
        "gross": cents(r.gross for r in rows),
        "costs": cents(r.costs for r in rows),
        "taxable": cents(r.taxable for r in rows),
        "tax": sum(int(r.tax) for r in rows),
        "net": cents(r.net for r in rows),
        "differs": sum(1 for r in rows if r.differs),
        "unconfirmed": sum(1 for r in rows if r.code_source != "saved" and not r.code_conflict),
        "conflicts": sum(1 for r in rows if r.code_conflict),
    }


def file_name(number: str, *, draft: bool, period_tag: str) -> str:
    """„ksiegowa_14_S_2026.xlsx", szkic: „SZKIC_ksiegowa_06_2026.xlsx"."""
    if draft:
        return f"SZKIC_ksiegowa_{period_tag}.xlsx".replace("__", "_")
    safe = re.sub(r"[^0-9A-Za-z_-]+", "_", number).strip("_")
    return f"ksiegowa_{safe}.xlsx"


#: Stałe kolumn zakładki Import - jak w skoroszycie księgowej. Do zmiany
#: w Ustawieniach (Księgowość → Import enova), gdyby enova u niej się zmieniła.
ENOVA_DEFAULTS = {
    "class": "Umowa",
    "definition": "RS",
    "department": "FIRMA",
    "series": "EX",
    "title": "BRAK UBEZPIECZEŃ",
    "element": "PIT-11.5.Działalność wyk. osobiście",
    "settlement": "KwotaDoWypłaty",
}

#: Klauzula ze starych list - domyślny tekst stopki PDF (decyzja 04.11.2026:
#: „tylko klauzula na samym dole"). Do zmiany w Ustawieniach.
CONSENT_DEFAULT = (
    "Wyrażam zgodę na przetwarzanie moich danych osobowych zawartych w umowie zgodnie "
    "z ustawą o ochronie danych osobowych (Dz.U. z 2002 r. nr 101, poz. 926 z późn. zm.)"
)

#: Ustawienia „Księgowość" okręgu - domyślne.
EXTRA_DEFAULTS = {
    "tax_formula": FORMULA_BAZA,
    "number_scheme": SCHEME_SEASON,
    "number_marks": dict(DEFAULT_MARKS),
    "show_consent": True,
    "consent_text": CONSENT_DEFAULT,
    "enova": dict(ENOVA_DEFAULTS),
}


def clean_extra(raw: Any) -> dict:
    """Ustawienia z bazy albo z żądania -> pełny, bezpieczny słownik."""
    data = raw if isinstance(raw, dict) else {}
    marks_in = data.get("number_marks") if isinstance(data.get("number_marks"), dict) else {}
    enova_in = data.get("enova") if isinstance(data.get("enova"), dict) else {}
    consent = str(data.get("consent_text") or "").strip()[:600] or CONSENT_DEFAULT
    return {
        "tax_formula": formula_of(data.get("tax_formula")),
        "number_scheme": scheme_of(data.get("number_scheme")),
        "number_marks": {kind: mark_of(marks_in.get(kind), kind) for kind in DEFAULT_MARKS},
        "show_consent": bool(data.get("show_consent", True)),
        "consent_text": consent,
        "enova": {
            key: (str(enova_in.get(key) or "").strip()[:80] or default)
            for key, default in ENOVA_DEFAULTS.items()
        },
    }
