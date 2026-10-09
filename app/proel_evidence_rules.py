"""Mecz jako materiał dowodowy - reguły bez bazy i bez sieci.

Administrator oznacza mecz w Dzienniku meczu jako WAŻNY. Od tej chwili:

1. Nic z historii meczu nie wygasa - migawki, wersje przegrane w sporze,
   kopia w koszu. Dobowy limit migawek przestaje obowiązywać: sprawa, która
   się toczy, potrzebuje KAŻDEJ wersji, a nie co dwudziestej.
2. Zapisu meczu nie da się usunąć - ani pojedynczo, ani grupowo. Odmowa
   mówi wprost, dlaczego (zero cichych blokad).
3. Przy oznaczeniu powstaje TECZKA: komplet zapisu zamrożony na tę chwilę,
   z sumą SHA-256. Teczek nie kasuje nic - ani sprzątanie, ani zdjęcie
   oznaczenia. To jest ten „pełny zapis", który można przekazać dalej.

Zdjęcie oznaczenia wymaga PIN-u administratora i przywraca zwykłą retencję
liczoną OD CHWILI zdjęcia, a nie od powstania wersji - inaczej najbliższe
sprzątanie skasowałoby całą historię w ciągu godziny od jednego dotknięcia.

Format teczki jest TEN SAM co `tools/raport_dowodowy/zrzut.py`: pobraną
teczkę można od razu zamienić w raport (`raport.py --z-pliku teczka.json.gz`).
"""
from __future__ import annotations

import base64
import datetime as dt
import decimal
import gzip
import hashlib
import json
import re
import zlib
from typing import Any, Dict, List, Optional, Tuple

#: Uzasadnienie ma być zdaniem, nie esejem - leci do dziennika i do teczki.
REASON_MAX = 500

#: Wersja formatu teczki - ta sama rodzina co `zrzut.py` (WERSJA = 1).
PACKAGE_FORMAT = 1

DELETE_REFUSED_MESSAGE = (
    "Ten mecz jest oznaczony jako materiał dowodowy - jego zapisu nie da się "
    "usunąć. Oznaczenie zdejmuje administrator w Dzienniku meczu."
)
NOT_HELD_MESSAGE = "Ten mecz nie jest oznaczony jako materiał dowodowy."
UNKNOWN_MATCH_MESSAGE = (
    "Nie ma śladu takiego meczu - ani zapisu, ani dziennika, ani wersji. "
    "Sprawdź numer (wielkość liter ma znaczenie)."
)

#: Dni, przez które wersja przegrana w sporze i kopia w koszu żyją po zdjęciu
#: oznaczenia - tyle samo, co przy powstaniu (`proel_archive.py`).
RELEASE_ARCHIVE_DAYS = 365


def normalize_reason(raw: Any) -> str:
    """Uzasadnienie bez zbędnych spacji, przycięte do `REASON_MAX`."""
    text = re.sub(r"\s+", " ", str(raw or "")).strip()
    return text[:REASON_MAX]


def jawne(v: Any) -> Any:
    """Wartość z bazy jako coś, co da się zapisać w JSON-ie.

    Kolumny binarne rozpakowujemy (migawki to zlib, protokoły PDF gzip), żeby
    teczka była czytelna bez wiedzy o tym, jak serwer trzyma dane. Bliźniak:
    `_jawne` w `tools/raport_dowodowy/zrzut.py` - formaty muszą się zgadzać.
    """
    if isinstance(v, (dt.datetime, dt.date)):
        if isinstance(v, dt.datetime) and v.tzinfo is None:
            v = v.replace(tzinfo=dt.timezone.utc)
        return v.isoformat()
    if isinstance(v, decimal.Decimal):
        return str(v)
    if isinstance(v, memoryview):
        v = bytes(v)
    if isinstance(v, bytes):
        for fn in (zlib.decompress, gzip.decompress):
            try:
                tekst = fn(v).decode("utf-8")
            except Exception:  # noqa: BLE001 - to nie ten format, próbujemy dalej
                continue
            try:
                return json.loads(tekst)
            except ValueError:
                return tekst
        return {"_bajty_base64": base64.b64encode(v).decode("ascii")}
    if isinstance(v, str) and v[:1] in "{[":
        try:
            return json.loads(v)
        except ValueError:
            return v
    return v


def jawny_wiersz(row: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if row is None:
        return None
    return {k: jawne(v) for k, v in dict(row).items()}


def build_package(
    *,
    match_number: str,
    mecz: Optional[Dict[str, Any]],
    stan: Optional[Dict[str, Any]],
    migawki: List[Dict[str, Any]],
    dziennik: List[Dict[str, Any]],
    historia_sporow: List[Dict[str, Any]],
    usuniete: List[Dict[str, Any]],
    protokoly_pdf: List[Dict[str, Any]],
    teczka: Dict[str, Any],
    now: dt.datetime,
) -> Tuple[bytes, str, Dict[str, int]]:
    """Teczka jako bajty gzip + jej SHA-256 + liczniki do listy.

    `mecz` bywa `None`: oznaczyć można też mecz usunięty - wtedy zapis leży
    w `usuniete`, a teczka mówi o tym licznikiem, nie dziurą.
    """
    zrzut = {
        "narzedzie": {"nazwa": "app/proel_evidence.py", "wersja": PACKAGE_FORMAT},
        "wykonano": jawne(now),
        "klucz": match_number,
        "teczka": {k: jawne(v) for k, v in teczka.items()},
        "mecz": jawny_wiersz(mecz),
        "stan": jawny_wiersz(stan),
        "migawki": [jawny_wiersz(r) for r in migawki],
        "dziennik": [jawny_wiersz(r) for r in dziennik],
        "historia_sporow": [jawny_wiersz(r) for r in historia_sporow],
        "usuniete": [jawny_wiersz(r) for r in usuniete],
        "protokoly_pdf": [jawny_wiersz(r) for r in protokoly_pdf],
    }
    raw = json.dumps(zrzut, ensure_ascii=False, default=str).encode("utf-8")
    # `mtime=0`: ta sama treść daje te same bajty, więc ta sama suma.
    paczka = gzip.compress(raw, 9, mtime=0)
    counts = {
        "migawki": len(migawki),
        "dziennik": len(dziennik),
        "spory": len(historia_sporow),
        "usuniete": len(usuniete),
        "pdf": len(protokoly_pdf),
        "zapis": 1 if mecz is not None else 0,
        "bajty_json": len(raw),
    }
    return paczka, hashlib.sha256(paczka).hexdigest(), counts


def has_any_trace(counts: Dict[str, int]) -> bool:
    """Czy jest co chronić - inaczej literówka w numerze tworzyłaby pustą teczkę."""
    return any(counts.get(k) for k in ("zapis", "migawki", "dziennik", "usuniete", "spory", "pdf"))


def package_filename(match_number: str, package_id: int) -> str:
    """„teczka_SK-24_nr3.json.gz" - bez ukośnika, który rozjechałby ścieżkę."""
    safe = re.sub(r"[^A-Za-z0-9]+", "-", str(match_number or "")).strip("-") or "mecz"
    return f"teczka_{safe}_nr{int(package_id)}.json.gz"


def package_doc(package_id: int) -> str:
    """Znak w podpisanym adresie - token otwiera JEDNĄ teczkę, nie wszystkie."""
    return f"evidence:{int(package_id)}"


def hold_view(row: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Oznaczenie do odpowiedzi API (daty jako ISO)."""
    if row is None:
        return None
    d = dict(row)

    def iso(v: Any) -> Optional[str]:
        return jawne(v) if v is not None else None

    return {
        "match_number": d.get("match_number"),
        "active": d.get("released_at") is None,
        "reason": d.get("reason") or "",
        "marked_at": iso(d.get("marked_at")),
        "marked_by": d.get("marked_by_name") or d.get("marked_by_judge") or "",
        "released_at": iso(d.get("released_at")),
        "released_by": d.get("released_by_name") or d.get("released_by_judge") or "",
        "release_reason": d.get("release_reason") or "",
    }


def package_view(row: Dict[str, Any]) -> Dict[str, Any]:
    d = dict(row)
    return {
        "id": int(d["id"]),
        "match_number": d.get("match_number"),
        "created_at": jawne(d.get("created_at")),
        "created_by": d.get("created_by_name") or d.get("created_by_judge") or "",
        "reason": d.get("reason") or "",
        "sha256": d.get("sha256") or "",
        "bytes": int(d.get("payload_bytes") or 0),
        "counts": jawne(d.get("counts_json")) or {},
    }
