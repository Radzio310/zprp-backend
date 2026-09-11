"""
Miasto meczu z publicznego API rozgrywek - jedno zrodlo prawdy dla odleglosci.

Skad wzial sie problem: terminarz na baza.zprp.pl podaje hale JEDNYM napisem,
w atrybucie `title` odsylacza do map („Hala Widowiskowo-Sportowa im. Ryszarda
Matuszaka, Glogow, Wita Stwosza 1"). Scraper dzieli go po przecinkach i zgaduje,
ktora czesc jest miastem - a przy dwuczlonowej nazwie hali, przy braku
przecinka albo przy adresie bez miasta „miastem" zostawala nazwa obiektu. Do
tabeli odleglosci taki napis nie pasowal do niczego, wiec dojazd szedl do Google
jako „Hala Sportowa MOSiR" i wracal z przypadkowa liczba kilometrow. Na Liscie
kosztow przejazdow widac to od razu: trasa „Bystra-Hala Sportowa-Bystra".

Publiczne API meczu (`pokaz_mecze_szczegoly.php?Zawody=<id>`) podaje to samo
rozbite na pola:

    "Hala_nazwa":  "Hala Widowiskowo-Sportowa im. Ryszarda Matuszaka",
    "Hala_miasto": "Głogów",
    "Hala_ulica":  "Wita Stwosza",
    "Hala_numer":  "1",

Bierzemy stad `Hala_miasto` i nie zgadujemy niczego.

MODUL-LISC: rozbior odpowiedzi i czyszczenie napisow bez bazy i bez wlasnych
polaczen - siec dostaje gotowego klienta.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Optional

logger = logging.getLogger(__name__)

DETAILS_URL = "https://rozgrywki.zprp.pl/api/pokaz_mecze_szczegoly.php"

#: Slowa, po ktorych poznajemy, ze w polu „miasto" wyladowala nazwa obiektu.
_VENUE_WORDS = (
    "hala", "sala", "arena", "centrum", "osir", "mosir", "kompleks", "obiekt",
    "szkol", "liceum", "gimnazjum", "akademia", "klub", "boisko", "im.", "ul.",
    "aleja", "aleje", "os.", "osiedle",
)


def pretty_city(raw: Any) -> str:
    """
    Miasto do pokazania i do porownan: bez kodu pocztowego i bez ogona po przecinku.

    „43-360 Bystra, ul. Szczyrkowska 1" -> „Bystra". Zapis oryginalny (ogonki,
    wielkie litery) ZOSTAJE - dopasowaniem do tabeli odleglosci zajmuje sie
    `settlement_distances.normalize_city`, a na wydruku ma stac ludzka nazwa.
    """
    text = str(raw or "").split(",")[0]
    text = re.sub(r"\b\d{2}-\d{3}\b", " ", text)
    text = re.sub(r"\s+", " ", text).strip(" .,-")
    return text


def looks_like_city(value: Any) -> bool:
    """
    Czy to w ogole wyglada na miejscowosc, a nie na nazwe hali albo adres.

    Uzywane TYLKO jako droga awaryjna, gdy API nie odpowie: lepiej zostawic mecz
    bez dojazdu - widac go wtedy jako „brak dojazdu" i wiadomo, co uzupelnic -
    niz wyslac do Google „Hala Sportowa im. Kogos" i zaplacic za kilometry,
    ktorych nikt nie przejechal.
    """
    text = pretty_city(value)
    if len(text) < 3:
        return False
    lowered = f" {text.lower()} "
    if any(word in lowered for word in _VENUE_WORDS):
        return False
    if re.search(r"\d", text):
        return False
    # Miejscowosci bywaja dwu- i trzyczlonowe („Siemianowice Śląskie",
    # „Dąbrowa Górnicza"), ale nie piecioczlonowe.
    return len(text.split()) <= 4


def _records(payload: Any) -> list[dict]:
    """
    Dwa ksztalty tej samej odpowiedzi: `{"0": [...]}` i gola lista `[[{...}]]`.

    Ta sama pulapka, co w monitorze meczow okregu - swiezy mecz bez protokolu
    wraca druga postacia.
    """
    if isinstance(payload, dict):
        for value in payload.values():
            if isinstance(value, list) and value and isinstance(value[0], dict):
                return [item for item in value if isinstance(item, dict)]
        return [payload] if payload.get("Hala_miasto") or payload.get("Hala_nazwa") else []
    if isinstance(payload, list):
        flat: list[dict] = []
        for item in payload:
            if isinstance(item, dict):
                flat.append(item)
            elif isinstance(item, list):
                flat.extend(x for x in item if isinstance(x, dict))
        return flat
    return []


def venue_from_payload(payload: Any) -> dict[str, str]:
    """`{city, hall, street, number}` z odpowiedzi API; puste napisy, gdy brak."""
    for record in _records(payload):
        city = pretty_city(record.get("Hala_miasto"))
        hall = str(record.get("Hala_nazwa") or "").strip()
        if city or hall:
            return {
                "city": city,
                "hall": hall,
                "street": str(record.get("Hala_ulica") or "").strip(),
                "number": str(record.get("Hala_numer") or "").strip(),
            }
    return {"city": "", "hall": "", "street": "", "number": ""}


async def fetch_details_payload(client: Any, match_id: Any, *, timeout: float = 20.0) -> Any:
    """
    Surowa odpowiedz API jednego meczu. `None` = nie udalo sie zapytac.

    Jedno zapytanie niesie i hale, i obsade z nazwiskami - pobieranie okregu
    bierze z niego oba (patrz `settlement_names_rules.officials_from_payload`).
    Klucza nie potrzeba - to samo publiczne API, ktorym monitor meczow okregu
    dobiera obsade.
    """
    key = str(match_id or "").strip()
    if client is None or not key:
        return None
    try:
        response = await client.get(DETAILS_URL, params={"Zawody": key}, timeout=timeout)
        response.raise_for_status()
        return response.json()
    except Exception as exc:
        logger.debug("[settlement] szczegoly meczu %s: %s", key, exc)
        return None


async def fetch_venue(
    client: Any, match_id: Any, *, timeout: float = 20.0
) -> Optional[dict[str, str]]:
    """Hala jednego meczu z publicznego API. `None` = nie udalo sie zapytac."""
    payload = await fetch_details_payload(client, match_id, timeout=timeout)
    if payload is None:
        return None
    venue = venue_from_payload(payload)
    return venue if (venue["city"] or venue["hall"]) else None
