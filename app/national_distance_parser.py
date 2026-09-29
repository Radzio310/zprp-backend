"""Czyste parsery ryczałtu ZPRP - bez bazy danych i efektów ubocznych."""

from __future__ import annotations

import re
import unicodedata
from typing import Optional
from urllib.parse import parse_qs, urlparse

import pymupdf
from pydantic import BaseModel

_ZPRP_HOSTS = {"baza.zprp.pl", "www.baza.zprp.pl"}
_SOURCE_PATH = "/sedzia_ryczalt_pdf.php"


class ParsedSettlement(BaseModel):
    judge_city: str
    venue_city: str
    one_way_km: int
    round_trip_km: int


def normalize_city_key(value: str) -> str:
    text_value = unicodedata.normalize("NFKD", str(value or ""))
    text_value = "".join(ch for ch in text_value if not unicodedata.combining(ch))
    text_value = text_value.replace("Ł", "L").replace("ł", "l").lower()
    return re.sub(r"[^a-z0-9]+", " ", text_value).strip()


def clean_city(value: Optional[str]) -> str:
    city = re.sub(r"\s+", " ", str(value or "")).strip(" ,.;:-\n\r\t")
    city = re.sub(r"\s+\d{2}-\d{3}.*$", "", city).strip()
    return city[:120]


def validate_settlement_candidate(
    *,
    url: str,
    settlement_id_hint: Optional[str] = None,
    match_id_hint: Optional[str] = None,
    match_code: Optional[str] = None,
    judge_city: Optional[str] = None,
    venue_city: Optional[str] = None,
) -> dict[str, str]:
    parsed = urlparse(url)
    host = parsed.hostname.lower() if parsed.hostname else ""
    path = parsed.path.lower().rstrip("/")
    if parsed.scheme not in {"", "https"} or (host and host not in _ZPRP_HOSTS):
        raise ValueError("Nieobsługiwany adres ryczałtu")
    if path != _SOURCE_PATH:
        raise ValueError("Nieobsługiwany adres ryczałtu")

    query = parse_qs(parsed.query)
    settlement_id = str((query.get("Id") or [settlement_id_hint or ""])[0]).strip()
    match_id = str((query.get("IdZawody") or [match_id_hint or ""])[0]).strip()
    if not settlement_id.isdigit() or not match_id.isdigit():
        raise ValueError("Adres ryczałtu nie zawiera poprawnych identyfikatorów")
    if settlement_id_hint and str(settlement_id_hint) != settlement_id:
        raise ValueError("Id ryczałtu nie zgadza się z adresem")
    if match_id_hint and str(match_id_hint) != match_id:
        raise ValueError("IdZawody nie zgadza się z adresem")

    return {
        "source_key": f"{settlement_id}:{match_id}",
        "settlement_id": settlement_id,
        "match_id": match_id,
        "path": "/sedzia_ryczalt_PDF.php",
        "match_code": clean_city(match_code),
        "judge_city": clean_city(judge_city),
        "venue_city": clean_city(venue_city),
    }


def _usable_pdf_city(value: str) -> bool:
    return bool(value and len(value) >= 2 and "�" not in value and normalize_city_key(value))


def read_pdf_text(data: bytes) -> str:
    if not data.startswith(b"%PDF-"):
        raise ValueError("ZPRP nie zwrócił pliku PDF")
    try:
        with pymupdf.open(stream=data, filetype="pdf") as document:
            return "\n".join(page.get_text("text") for page in document)
    except Exception as exc:  # noqa: BLE001 - źródło jest zewnętrzne
        raise ValueError("Nie udało się odczytać ryczałtu PDF") from exc


def parse_settlement_pdf(
    data: bytes,
    *,
    judge_city_hint: Optional[str] = None,
    venue_city_hint: Optional[str] = None,
) -> ParsedSettlement:
    """Wydobywa dwa miasta i dystans, odrzucając niejednoznaczny dokument."""

    raw = read_pdf_text(data).replace("\xa0", " ")
    compact = re.sub(r"[ \t]+", " ", raw)

    judge_match = re.search(r"zam\.\s*([^\n\r]+)", compact, flags=re.IGNORECASE)
    venue_match = re.search(
        r"Miejsce\s+rozgrywania\s+zawod.{0,4}:\s*([^\n\r]+)",
        compact,
        flags=re.IGNORECASE,
    )
    distance_match = re.search(
        r"Przejazd\s*2x\s*([0-9]+(?:[.,][0-9]+)?)\s*=\s*"
        r"([0-9]+(?:[.,][0-9]+)?)\s*km",
        compact,
        flags=re.IGNORECASE,
    )
    if not distance_match:
        raise ValueError("Ryczałt nie zawiera czytelnego pola przejazdu 2x")

    pdf_judge_city = clean_city(judge_match.group(1) if judge_match else "")
    pdf_venue_city = clean_city(venue_match.group(1) if venue_match else "")
    judge_hint = clean_city(judge_city_hint)
    venue_hint = clean_city(venue_city_hint)

    judge_city = pdf_judge_city if _usable_pdf_city(pdf_judge_city) else judge_hint
    venue_city = pdf_venue_city if _usable_pdf_city(pdf_venue_city) else venue_hint
    if not judge_city or not venue_city:
        raise ValueError("Nie udało się jednoznacznie odczytać obu miejscowości")

    one_way = int(round(float(distance_match.group(1).replace(",", "."))))
    round_trip = int(round(float(distance_match.group(2).replace(",", "."))))
    if one_way < 0 or one_way > 1000 or round_trip < 0 or round_trip > 2000:
        raise ValueError("Odległość w ryczałcie jest poza dopuszczalnym zakresem")
    if abs(round_trip - one_way * 2) > 2:
        raise ValueError("Pole przejazdu w ryczałcie jest niespójne")

    return ParsedSettlement(
        judge_city=judge_city,
        venue_city=venue_city,
        one_way_km=one_way,
        round_trip_km=round_trip,
    )

