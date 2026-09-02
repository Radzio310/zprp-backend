# app/extra_report_scope.py
#
# Który okręg czyta raport z TEGO meczu.
#
# PO CO. Adresaci dodatkowego raportu byli dotąd przypisani do kategorii
# rozgrywek i tylko do niej. Dla Superligi to wystarcza - jest jedna w kraju.
# Dla rozgrywek od II ligi w dół nie wystarcza wcale: prowadzą je związki
# wojewódzkie, więc „II liga mężczyzn" to osiem różnych skrzynek, a nie jedna,
# a liga juniorów to szesnaście. Przy jednym adresie na kategorię raport z
# meczu młodzieżowego w Katowicach jechał tam, gdzie ktoś wpisał pierwszy
# adres - albo nie jechał nigdzie.
#
# SKĄD BIERZEMY OKRĘG. Z publicznego API rozgrywek, z tego samego zapytania,
# którym i tak sprawdzamy obsadę meczu: `pokaz_mecze_szczegoly.php` oddaje przy
# każdym meczu pola `NrWZPR` i `NazwaWZPR` - związek PROWADZĄCY te rozgrywki.
# Sprawdzone na żywym API: mecz `IIM4/1` (sezon 2025/2026) wraca z
# `NazwaWZPR = "ŚLĄSKIE"`, a lista rozgrywek daje komplet, zgodny z regulaminem
# ZPRP: grupy II ligi 1-4 prowadzą kolejno Dolnośląski/Wielkopolski, Pomorski,
# Mazowiecki i Śląski.
#
# CZEGO ŚWIADOMIE NIE ROBIMY. Nie zaszywamy tabeli „grupa → okręg". Przydział
# grup jest ustaleniem na sezon i zmienia się; tabela w kodzie zestarzałaby się
# po cichu, a raport poszedłby do cudzego związku. Nie czytamy też okręgu z
# województwa KLUBU (`ID_zespoly_gosp_ZespolNrWoj`) - to inne pole i inna
# odpowiedź: klub z Opola gra w grupie prowadzonej przez Wielkopolskę.

from __future__ import annotations

import logging
from typing import Any, Dict, FrozenSet, Optional

from httpx import AsyncClient

from app.zprp_accounts import normalize_province

logger = logging.getLogger(__name__)

DETAILS_URL = "https://rozgrywki.zprp.pl/api/pokaz_mecze_szczegoly.php"

#: Kategorie, w których o adresata pyta się OKRĘG, a nie centrala.
#:
#: „Od II ligi w dół" - II i III liga oraz wszystkie rozgrywki młodzieżowe.
#: Wyżej (I liga, Liga Centralna, Superliga, Superpuchar) rozgrywki prowadzi
#: ZPRP i jedna skrzynka na kategorię jest właściwą odpowiedzią. Puchar Polski
#: i mistrzostwa Polski zostają poza tym zbiorem świadomie: to rozgrywki
#: centralne, choć grają w nich drużyny z okręgów.
#:
#: Lustro `PROVINCE_SCOPED_CATEGORIES` w `BAZA/utils/extraReportScope.ts`.
PROVINCE_SCOPED_CATEGORIES: FrozenSet[str] = frozenset(
    {
        "IIM",
        "IIK",
        "IIIM",
        "IIIK",
        "JM",
        "JK",
        "JmM",
        "JmK",
        "MłM",
        "MłK",
        "MłM1213",
        "MłK1213",
    }
)


def is_province_scoped(category: Any) -> bool:
    """Czy dla tej kategorii pytamy o adresata okręg.

    Porównanie jest DOKŁADNE, nie przez „zaczyna się od". Kategorie różnią się
    między sobą jedną literą („IIM" i „IIIM"), a rozpoznawanie po prefiksie
    wpuściłoby III ligę tam, gdzie miała być II - ten sam błąd, który
    `extractCategory` po stronie aplikacji musi omijać kolejnością listy.
    """
    return str(category or "").strip() in PROVINCE_SCOPED_CATEGORIES


def province_from_match(match: Optional[Dict[str, Any]]) -> str:
    """Slug okręgu prowadzącego rozgrywki tego meczu, albo pusty napis.

    Pusty wynik znaczy „nie wiemy", nie „brak okręgu" - i wołający ma go
    traktować jako brak wiedzy: lepiej wysłać raport samym adresatom
    kategorii niż nie wysłać go wcale.
    """
    if not isinstance(match, dict):
        return ""
    return normalize_province(match.get("NazwaWZPR"))


async def fetch_match_province(match_id: Any, *, timeout: float = 12.0) -> str:
    """Okręg prowadzący, prosto z publicznego API rozgrywek.

    Awaria sieci kończy się pustym napisem, a nie wyjątkiem: adresaci to
    wygoda przy wysyłce raportu, a nie warunek jego istnienia. Sędzia, któremu
    ZPRP akurat nie odpowiada, ma dostać listę z samych kategorii i móc
    wysłać raport, zamiast oglądać błąd.
    """
    mid = str(match_id or "").strip()
    if not mid.isdigit():
        return ""
    try:
        async with AsyncClient(timeout=timeout) as client:
            resp = await client.get(DETAILS_URL, params={"Zawody": mid})
            resp.raise_for_status()
            payload = resp.json()
        rows = payload.get("0") if isinstance(payload, dict) else None
        match = rows[0] if isinstance(rows, list) and rows else None
        return province_from_match(match)
    except Exception:  # noqa: BLE001 — patrz nota w docstringu
        logger.warning("nie udało się ustalić okręgu meczu %s", mid, exc_info=True)
        return ""
