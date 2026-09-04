# app/match_market_notify.py
#
# Treści powiadomień giełdy meczów - jedno miejsce na wszystkie zdania.
#
# Powiadomienie push czyta się na zablokowanym ekranie, jednym spojrzeniem, i
# musi wtedy powiedzieć CAŁĄ rzecz: kto, co i z którym meczem. Wcześniej treści
# powstawały ze sklejenia technicznej etykiety z czasownikiem, więc wychodziło
# „IIM4/1 · sędzia 1 przejmuje Krzysztof WITKOWICZ" - zdanie, w którym numer
# meczu udaje podmiot, a człowiek stoi na końcu jak dopisek.
#
# ZASADY, które ten moduł wymusza:
#
#  1. PODMIOTEM JEST CZŁOWIEK, nie mecz. „Krzysztof WITKOWICZ przejmuje Twój
#     mecz IIM4/1", nigdy odwrotnie.
#  2. Rola odmienia się razem z przyimkiem. „jako sędzia 1", ale „na sędziego 1"
#     - stąd dwa słowniki form, a nie jedna etykieta wciskana wszędzie.
#  3. Zdanie składa się także wtedy, gdy czegoś brakuje. Nie znamy nazwiska,
#     terminu ani drużyn? Powiadomienie zostaje poprawne, tylko krótsze - nigdy
#     nie zostawia po sobie dziury w rodzaju „przejmuje ." albo podwójnej kropki.
#
# Moduł jest LIŚCIEM: bez bazy, bez sieci, bez FastAPI. Wszystkie zdania dają
# się sprawdzić testem, zamiast czytać je pierwszy raz na czyimś telefonie.

from __future__ import annotations

from datetime import datetime
from typing import Any, Mapping, Optional

from app.match_market_rules import SLOT_LABELS

#: Rola po „jako" - mianownik, ten sam co na kaflu.
#:
#: „zgłasza się jako sędzia 1", „prowadzisz jako sekretarz".
SLOT_AS = dict(SLOT_LABELS)

#: Rola po „na" - biernik.
#:
#: „szuka kogoś na sędziego 1", „na mierzącego czas". Bez tego wychodziło
#: „szuka kogoś na sędzia 1", co widać od pierwszego spojrzenia.
SLOT_FOR: dict[str, str] = {
    "sedzia1": "sędziego 1",
    "sedzia2": "sędziego 2",
    "sekretarz": "sekretarza",
    "czas": "mierzącego czas",
}

#: Miesiące w dopełniaczu - „12 września", nie „12 wrzesień".
_MONTHS = (
    "stycznia", "lutego", "marca", "kwietnia", "maja", "czerwca",
    "lipca", "sierpnia", "września", "października", "listopada", "grudnia",
)
_WEEKDAYS = ("pon.", "wt.", "śr.", "czw.", "pt.", "sob.", "niedz.")


def _s(value: Any) -> str:
    return str(value or "").strip()


def slot_as(slot: Any) -> str:
    """Rola po „jako"; nieznane gniazdo oddajemy bez zmiany."""
    key = _s(slot)
    return SLOT_AS.get(key, key)


def slot_for(slot: Any) -> str:
    """Rola po „na"; nieznane gniazdo oddajemy bez zmiany."""
    key = _s(slot)
    return SLOT_FOR.get(key, SLOT_AS.get(key, key))


def judge(name: Any, fallback: str = "Sędzia") -> str:
    """Nazwisko albo uczciwe zastępstwo - nigdy pustka w środku zdania."""
    return _s(name) or fallback


def match_of(offer: Mapping[str, Any]) -> str:
    """„mecz IIM4/1" albo samo „mecz", gdy numeru nie znamy."""
    code = _s(offer.get("match_code"))
    return f"mecz {code}" if code else "mecz"


def match_gen(offer: Mapping[str, Any]) -> str:
    """„meczu IIM4/1" - po „obsada", po „wymiany" i po „w".

    Osobna forma, bo „obsada mecz IIM4/1" widać od pierwszego spojrzenia. To
    ta sama zasada, co przy rolach: przyimek albo rządzący rzeczownik wybiera
    przypadek, więc form musi być tyle, ile potrzeb.
    """
    code = _s(offer.get("match_code"))
    return f"meczu {code}" if code else "meczu"


def _capitalize(text: str) -> str:
    """Wielka litera na początku zdania - BEZ ruszania reszty.

    `str.capitalize()` sprowadza ogon do małych liter, więc „mecz IIM4/1"
    wychodziło jako „Mecz iim4/1" - numer meczu przestawał być numerem.
    """
    return text[:1].upper() + text[1:] if text else text


def when_of(offer: Mapping[str, Any]) -> str:
    """„sob. 12 września, 14:00" albo pusto.

    Termin jest w powiadomieniu ważniejszy niż nazwy drużyn: sędzia najpierw
    pyta „czy mam wtedy czas". Pusto, gdy mecz nie ma jeszcze terminu - i to
    jest odpowiedź sama w sobie, więc nie zmyślamy.
    """
    raw = offer.get("match_at")
    stamp: Optional[datetime]
    if isinstance(raw, datetime):
        stamp = raw
    elif _s(raw):
        try:
            stamp = datetime.fromisoformat(_s(raw).replace("Z", "+00:00"))
        except ValueError:
            stamp = None
    else:
        stamp = None
    if not stamp:
        return ""
    return (
        f"{_WEEKDAYS[stamp.weekday()]} {stamp.day} {_MONTHS[stamp.month - 1]}, "
        f"{stamp.hour:02d}:{stamp.minute:02d}"
    )


def teams_of(snapshot: Optional[Mapping[str, Any]]) -> str:
    """„MKS Mysłowice - Hutnik Kraków" albo pusto.

    Kolejność jest NOMINALNA, taka jak w stanie meczu - to samo, co pokazuje
    lista giełdy. Powiadomienie nie jest miejscem na rozstrzyganie zamiany
    gospodarza; ma pomóc rozpoznać mecz, nie zastąpić protokół.
    """
    state = snapshot or {}
    host = _s(state.get("ID_zespoly_gosp_ZespolNazwa"))
    guest = _s(state.get("ID_zespoly_gosc_ZespolNazwa"))
    if host and guest:
        return f"{host} - {guest}"
    return host or guest


def _join(*parts: str) -> str:
    """Zdania w jeden akapit - puste człony wypadają bez śladu.

    To ten mechanizm sprawia, że brak terminu albo brak nazwiska skraca
    powiadomienie, a nie psuje je podwójną kropką ani wiszącym przecinkiem.
    """
    out = []
    for part in parts:
        text = _s(part)
        if not text:
            continue
        # Każdy człon staje SAMODZIELNYM zdaniem, więc dostaje wielką literę -
        # inaczej termin wchodził jako „sob. 12 września" w środku akapitu i
        # czytał się jak urwana myśl.
        text = _capitalize(text)
        if not text.endswith((".", "!", "?", ":")):
            text = f"{text}."
        out.append(text)
    return " ".join(out)


# ─────────────────────────── treści ───────────────────────────
#
# Każda funkcja oddaje (tytuł, treść). Tytuł mówi RODZAJ sprawy i jest krótki,
# bo na zablokowanym ekranie bywa jedyną widoczną linijką.


def offer_created(offer: Mapping[str, Any], giver_name: Any) -> tuple[str, str]:
    """Nowa oferta - do sędziów okręgu."""
    who = judge(giver_name)
    return (
        "🔁 Mecz do wzięcia",
        _join(
            f"{who} szuka zastępstwa na {match_of(offer)} "
            f"na {slot_for(offer.get('slot'))}",
            when_of(offer),
            teams_of(offer.get("match_snapshot")),
        ),
    )


def offer_withdrawn(offer: Mapping[str, Any], giver_name: Any) -> tuple[str, str]:
    """Oferta zabrana z giełdy - do tych, którzy się na nią zgłosili."""
    who = judge(giver_name)
    return (
        "↩️ Mecz wrócił do właściciela",
        _join(
            f"{who} zabrał {match_of(offer)} z giełdy i poprowadzi go sam",
            "Twoje zgłoszenie jest już nieaktualne",
        ),
    )


def claim_created(offer: Mapping[str, Any], claimer_name: Any) -> tuple[str, str]:
    """Ktoś się zgłosił - do obsadowych okręgu."""
    who = judge(claimer_name)
    return (
        "🙋 Zgłoszenie na mecz",
        _join(
            f"{who} zgłasza się na {match_of(offer)} "
            f"jako {slot_as(offer.get('slot'))}",
            when_of(offer),
            "Czeka na Twoją decyzję",
        ),
    )


def offer_rejected(
    offer: Mapping[str, Any], giver_name: Any, reason: Any = ""
) -> tuple[str, str]:
    """Obsadowy odrzucił wymianę - do oddającego i do chętnych."""
    who = _s(giver_name)
    head = (
        f"Obsada {match_gen(offer)} zostaje bez zmian - prowadzi go {who}"
        if who
        else f"Obsada {match_gen(offer)} zostaje bez zmian"
    )
    return ("🚫 Wymiana odrzucona", _join(head, _s(reason) and f"Powód: {_s(reason)}"))


def apply_failed(offer: Mapping[str, Any], message: Any) -> tuple[str, str]:
    """Zapis w bazie związku nie przeszedł - do obsadowego, który go puścił."""
    return (
        "⚠️ Wymiana niezapisana",
        _join(
            f"Nie udało się zapisać wymiany {match_gen(offer)} w bazie związku",
            _s(message),
        ),
    )


def taker_won(offer: Mapping[str, Any], taker_name: Any = "") -> tuple[str, str]:
    """Wymiana zapisana - do tego, kto mecz przejął."""
    return (
        "✅ Masz nowy mecz",
        _join(
            f"Prowadzisz {match_of(offer)} jako {slot_as(offer.get('slot'))}",
            when_of(offer),
            teams_of(offer.get("match_snapshot")),
            "Obsada jest już zapisana w bazie związku",
        ),
    )


def giver_released(offer: Mapping[str, Any], taker_name: Any) -> tuple[str, str]:
    """Wymiana zapisana - do tego, kto mecz oddał.

    To powiadomienie brzmiało najgorzej z całej giełdy („IIM4/1 · sędzia 1
    przejmuje Krzysztof WITKOWICZ"), bo numer meczu stał na miejscu podmiotu.
    Teraz zdanie zaczyna człowiek, który mecz przejmuje.
    """
    who = judge(taker_name)
    return (
        "✅ Mecz oddany",
        _join(
            f"{who} przejmuje Twój {match_of(offer)} "
            f"jako {slot_as(offer.get('slot'))}",
            when_of(offer),
            "Obsada jest już zmieniona w bazie związku - nie musisz tam być",
        ),
    )


def crew_changed(
    offer: Mapping[str, Any], taker_name: Any, giver_name: Any = ""
) -> tuple[str, str]:
    """Wymiana zapisana - do POZOSTAŁEJ obsady meczu.

    Ci ludzie niczego nie oddawali ani nie brali, ale w sobotę staną przy tym
    samym stoliku - i dowiedzieć się o zmianie partnera mają prawo od razu.
    Zdanie jest nazwowe („Nowy sędzia 1: ..."), bo forma narzędnika roli
    („sędzią 1", „mierzącym czas") byłaby trzecią tabelą odmiany na jedno
    powiadomienie, a każda taka tabela to kolejne miejsce na literówkę.
    """
    who = judge(taker_name)
    before = _s(giver_name)
    return (
        "🔁 Zmiana w Twoim meczu",
        _join(
            f"Nowy {slot_as(offer.get('slot'))} w {match_gen(offer)}: {who}",
            before and f"Wcześniej: {before}",
            when_of(offer),
        ),
    )


def claim_lost(offer: Mapping[str, Any]) -> tuple[str, str]:
    """Wymiana zapisana komuś innemu - do pozostałych chętnych."""
    return (
        "🔁 Mecz zajęty",
        _join(
            f"{_capitalize(match_of(offer))} poprowadzi kto inny",
            "Twoje zgłoszenie nie zostało wybrane",
        ),
    )
