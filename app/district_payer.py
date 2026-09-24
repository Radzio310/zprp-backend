"""
Okręg jako płatnik - „klub", którym jest sam okręg (dla Śląska: ŚlZPR).

Decyzje użytkownika z 24.09.2026:
  - w panelu klubów jest JEDEN dodatkowy płatnik na województwo: sam okręg.
    Część meczów i wpłat nie należy do żadnego klubu, tylko do okręgu,
  - działa NA TYCH SAMYCH ZASADACH co klub: wpłaty i wypłaty
    (`province_club_entries`), ręczne mecze (`province_manual_charges`),
    faktury, a mecz z terminarza przenosi się na niego tym samym wyjątkiem na
    meczu co na inną drużynę (`province_match_overrides.team_id = OKREG`),
  - ale jest OSOBNO od klubów: nie wchodzi do sum „kluby razem", do
    „Rozlicz sezon", do wspólnych budżetów ani do alertu salda. Ma własne
    podsumowanie i własny kafel na górze listy, zawsze - także bez meczów,
  - nazwę da się zmienić tym samym mechanizmem co nazwę klubu
    (`province_clubs.display_name` dla numeru `OKREG`).

Numer płatnika jest ZAREZERWOWANY i taki sam w każdym województwie - okręg
rozróżnia kolumna `province`, jak przy każdym klubie. Numery klubów z ZPRP są
liczbowe, a ręczne mają prefiks „manual:", więc „OKREG" z niczym się nie zderzy.

Rozliczenia sędziów (decyzja do komentarza w `settlement_club_scope`): mecz
przeniesiony na okręg ma status `charged` na koncie okręgu, a nie `club-off`,
więc zostaje w zestawieniu okręgu - sędziom płaci okręg jak zawsze. Zmienia
się tylko to, KTO jest obciążony (okręg zamiast klubu gospodarza).

MODUŁ-LIŚĆ: bez bazy i sieci, żeby regułę dało się sprawdzić testem.
"""

from __future__ import annotations

from typing import Any, Iterable

from app.settlement_province import canonical, display

#: Zarezerwowany numer płatnika „okręg" - w każdym województwie ten sam.
DISTRICT_PAYER_ID = "OKREG"

#: Skróty związków okręgowych, które znamy na pewno. Reszta dostaje nazwę
#: z województwa („Okręg MAZOWIECKIE") i można ją zmienić w panelu.
SHORT_NAMES: dict[str, str] = {
    "SLASKIE": "ŚlZPR",
}


def _s(value: Any) -> str:
    return str(value if value is not None else "").strip()


def is_district_payer(club_id: Any) -> bool:
    return _s(club_id).upper() == DISTRICT_PAYER_ID


def default_label(province: Any) -> str:
    """Nazwa płatnika bez własnej: skrót związku albo „Okręg <WOJEWÓDZTWO>"."""
    key = canonical(province)
    if key in SHORT_NAMES:
        return SHORT_NAMES[key]
    name = display(province)
    return f"Okręg {name}" if name else "Okręg"


def label(province: Any, display_name: Any = None) -> str:
    """Nazwa nadana w panelu wygrywa z domyślną."""
    return _s(display_name) or default_label(province)


def without_district(club_ids: Iterable[Any]) -> list[str]:
    """Numery klubów bez płatnika-okręgu - do wszystkiego, co liczy „kluby"."""
    return [_s(item) for item in club_ids if _s(item) and not is_district_payer(item)]


def refuse_reason(club_ids: Iterable[Any], action: str) -> str:
    """
    Opis odmowy, gdy akcja dla klubów dostała płatnika-okręg. Pusto = można.

    Zero cichych blokad: zamiast po cichu go pominąć, mówimy wprost dlaczego.
    """
    if any(is_district_payer(item) for item in club_ids):
        return (
            f"{action} nie dotyczy okręgu jako płatnika - okręg ma własne konto "
            "i nie wchodzi do akcji dla klubów."
        )
    return ""
