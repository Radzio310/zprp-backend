"""
Modul obsadowego - kim jest sedzia i kto moze z kim stanac przy meczu.

MODUL-LISC: bez bazy i sieci, zeby regula chodzila w tescie.

Skad wiemy, kim jest sedzia (decyzje uzytkownika z 11.09.2026):
  - UPRAWNIENIA DO SZCZEBLI z formularza obsady ZPRP, litery w nawiasach przy
    nazwisku: (SL) Superliga, (LC) ligi centralne, (PP) Puchar Polski,
    (MP) Mistrzostwa Polski, (I) (II) (III) ligi, (Mł) mlodziez. „Sedzia
    ligowy" to (II) i wyzej. „Licencja A" to sedzia CENTRALNY boiskowy, czyli
    (I), (LC) albo (SL).
  - ODZNAKI OKREGU, bo baza zwiazku bywa nieaktualna: „Ligowcy" (aktywny
    ligowiec - to ona rozstrzyga, czy ktos NAPRAWDE dzis sedziuje ligi),
    „Stolikowi" (preferowani na stoliki okregowe), „Mlodzi" (nigdy dwoje
    razem w jednej parze, najlepiej doswiadczony z mlodym).

Kryteria stolikow ligowych (te same slowa, co uzytkownik):
  - Superliga i ligi centralne: min. 1 sedzia ligowy albo delegat, druga osoba
    z licencja A; preferowani dwaj ligowcy albo delegaci,
  - I i II liga: min. 1 osoba z licencja A,
  - stoliki okregowe: bez wymogu, ale najpierw sedziowie z odznaka „Stolikowi".
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

from app import settlement_rates as R

#: „Sedzia ligowy" to uprawnienie do II ligi i wyzej.
LEAGUE_LETTERS = frozenset({"II", "I", "LC", "SL"})
#: „Licencja A" - sedzia centralny boiskowy.
CENTRAL_LETTERS = frozenset({"I", "LC", "SL"})

#: Odznaki okregu, po ktorych automat rozpoznaje ludzi.
BADGE_LEAGUE = "Ligowcy"
BADGE_TABLE = "Stolikowi"
BADGE_YOUNG = "Młodzi"
BADGE_DELEGATE = "Delegaci"

#: Rozgrywki, w ktorych stolik ma wymagania (prefiksy z numeru meczu).
SUPERLEAGUE_PREFIXES = frozenset({"SM", "SK", "OSM", "OSK"})
CENTRAL_LEAGUE_PREFIXES = frozenset({"LCM", "LCK"})
LEAGUE_TABLE_PREFIXES = frozenset({"IM", "IK", "IIM", "IIK"})


def fold(value: Any) -> str:
    """
    Napis bez ogonkow i wielkosci liter - do porownywania odznak i liter.

    ⚠ „ł" NIE jest „l" z ogonkiem, tylko osobnym znakiem, wiec rozklad NFD go
    nie tyka - trzeba go podmienic recznie. Bez tego uprawnienie „(Mł)" raz
    zapisywaloby sie jako „MŁ", raz jako „ML", a odznaka „Młodzi" nie pasowalaby
    do „Mlodzi". Ta sama poprawka, co w tabeli odleglosci (`_strip_dia`).
    """
    text = str(value or "").strip().lower().replace("ł", "l")
    text = unicodedata.normalize("NFD", text)
    return "".join(ch for ch in text if unicodedata.category(ch) != "Mn")


def letter_key(value: Any) -> str:
    """Litera uprawnienia w jednym zapisie: „Mł" i „ML" to to samo."""
    return fold(value).upper().replace(" ", "")


def name_key(value: Any) -> str:
    """
    Klucz nazwiska niezalezny od kolejnosci czlonow.

    ZPRP podpisuje opcje „NOWAK Jan", a lista sedziow okregu bywa prowadzona
    jako „Jan Nowak" - to ten sam czlowiek i ma miec ten sam klucz. Ta sama
    mysl, co `names_match` w gieldzie, tylko w postaci klucza, bo uprawnienia
    z formularza zapisujemy do tabeli, a tabela potrzebuje czegos stalego.
    Inicjaly („J.") odpadaja - nie odrozniaja nikogo, a psuja porownanie.
    """
    cleaned = "".join(ch if ch.isalnum() else " " for ch in fold(value))
    parts = sorted(part for part in cleaned.split() if len(part) > 1)
    return " ".join(parts)


@dataclass
class Judge:
    """Sedzia okregu widziany przez automat."""

    judge_id: str
    name: str
    city: str = ""
    #: Litery z formularza ZPRP, np. {"MP", "II", "III", "ML"}.
    letters: frozenset[str] = frozenset()
    #: Odznaki okregu, znormalizowane przez `fold`.
    badges: frozenset[str] = frozenset()
    #: Rola z listy ZPRP: sedzia / delegat / stolikowy.
    roles: frozenset[str] = frozenset()
    #: Ustawienia z modulu obsadowego.
    needs_experienced: bool = False
    preferred_days: frozenset[int] = frozenset()
    #: Ile meczow ma juz w oknie - do rownego podzialu.
    load: int = 0

    def has_badge(self, name: str) -> bool:
        return fold(name) in self.badges

    def has_letter(self, letter: str) -> bool:
        return letter_key(letter) in self.letters

    @property
    def league(self) -> bool:
        """Sedzia ligowy: (II) i wyzej ALBO odznaka „Ligowcy"."""
        return self.has_badge(BADGE_LEAGUE) or any(
            letter_key(letter) in self.letters for letter in LEAGUE_LETTERS
        )

    @property
    def central(self) -> bool:
        """Licencja A: sedzia centralny boiskowy - (I), (LC) albo (SL)."""
        return any(letter_key(letter) in self.letters for letter in CENTRAL_LETTERS)

    @property
    def young(self) -> bool:
        return self.has_badge(BADGE_YOUNG)

    @property
    def table_specialist(self) -> bool:
        return self.has_badge(BADGE_TABLE)

    @property
    def delegate(self) -> bool:
        return self.has_badge(BADGE_DELEGATE) or "delegat" in {fold(r) for r in self.roles}


def make_judge(
    judge_id: Any,
    name: Any,
    *,
    city: Any = "",
    letters: Iterable[Any] = (),
    badges: Iterable[Any] = (),
    roles: Iterable[Any] = (),
    needs_experienced: bool = False,
    preferred_days: Iterable[int] = (),
    load: int = 0,
) -> Judge:
    return Judge(
        judge_id=str(judge_id or "").strip(),
        name=str(name or "").strip(),
        city=str(city or "").strip(),
        letters=frozenset(letter_key(letter) for letter in letters if str(letter or "").strip()),
        badges=frozenset(fold(badge) for badge in badges if str(badge or "").strip()),
        roles=frozenset(str(role or "").strip() for role in roles if str(role or "").strip()),
        needs_experienced=bool(needs_experienced),
        preferred_days=frozenset(int(day) for day in preferred_days if day is not None),
        load=int(load or 0),
    )


def table_rule(code: Any) -> dict[str, int]:
    """
    Czego wymaga STOLIK w tych rozgrywkach.

    `league_or_delegate` i `central` to minimalna liczba osob przy stoliku
    z danym uprawnieniem. Rozgrywki okregowe nie wymagaja niczego.
    """
    prefix = R.competition_prefix(code)
    if prefix in SUPERLEAGUE_PREFIXES or prefix in CENTRAL_LEAGUE_PREFIXES:
        return {"league_or_delegate": 1, "central": 1}
    if prefix in LEAGUE_TABLE_PREFIXES:
        return {"central": 1}
    return {}


def table_pair_ok(people: Iterable[Judge], code: Any) -> tuple[bool, str]:
    """Czy taki stolik spelnia wymagania szczebla. Zwraca powod odmowy."""
    rule = table_rule(code)
    if not rule:
        return True, ""
    crew = [judge for judge in people if judge]
    if rule.get("league_or_delegate") and sum(
        1 for judge in crew if judge.league or judge.delegate
    ) < rule["league_or_delegate"]:
        return False, "stolik bez sędziego ligowego ani delegata"
    if rule.get("central") and sum(1 for judge in crew if judge.central) < rule["central"]:
        return False, "stolik bez osoby z licencją A"
    return True, ""


def pair_ok(
    judge: Judge,
    partner: Optional[Judge],
    *,
    blocked: Iterable[tuple[str, str]] = (),
) -> tuple[bool, str]:
    """
    Czy tych dwoje moze stanac razem w jednym meczu.

    Trzy twarde zasady: nie ten sam czlowiek, nie para „nigdy razem", nie dwoje
    mlodych. Do tego znacznik „wymaga doswiadczonego partnera" - wtedy drugi
    musi miec licencje A (sedzia centralny boiskowy).
    """
    if partner is None:
        return True, ""
    if judge.judge_id and judge.judge_id == partner.judge_id:
        return False, "ten sam sędzia"
    pairs = {(str(a), str(b)) for a, b in blocked}
    if (judge.judge_id, partner.judge_id) in pairs or (partner.judge_id, judge.judge_id) in pairs:
        return False, "para wykluczona przez okręg"
    if judge.young and partner.young:
        return False, "dwoje młodych sędziów"
    if judge.needs_experienced and not partner.central:
        return False, f"{judge.name} wymaga partnera z licencją A"
    if partner.needs_experienced and not judge.central:
        return False, f"{partner.name} wymaga partnera z licencją A"
    return True, ""


def prefers_day(judge: Judge, weekday: Optional[int]) -> bool:
    """
    Czy to jeden z dni, ktore sedzia woli.

    Brak wskazanych dni znaczy „kazdy dzien pasuje" - inaczej pierwszy obieg
    automatu omijalby wszystkich, ktorzy nic nie wybrali.
    """
    if not judge.preferred_days or weekday is None:
        return True
    return int(weekday) in judge.preferred_days


def is_local(judge: Judge, host_city: Any) -> bool:
    """Sedzia z miasta gospodarza - unikamy, ale nie zakazujemy."""
    city = fold(host_city)
    return bool(city) and fold(judge.city) == city
