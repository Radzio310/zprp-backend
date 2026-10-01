"""Publiczne liczby BAZY dla strony bazaapp.online - reguły liczenia.

Strona produktu jest statyczna (Hostinger) i pobiera te liczby `fetch`-em
prosto z przeglądarki, bez logowania. Dlatego wychodzą stąd WYŁĄCZNIE sumy:
żadnego numeru sędziego, nazwiska, numeru meczu ani nazwy klubu.

Moduł-LIŚĆ: bez bazy, bez routera. `app.db` łączy się z Postgresem już przy
imporcie (create_all w module), więc gdyby reguła mieszkała przy endpoincie,
jej test wymagałby żywej bazy. Endpoint (`app/public_stats.py`) tylko czyta
wiersze i woła funkcje stąd.

Co liczymy i dlaczego tak:

* sędziowie - wiersze `login_records` (jeden na numer sędziego, który choć raz
  zalogował się do BAZY);
* aktywni w 30 dni - świeższy z dwóch znaczników: `last_login_at` (zapis
  logowania) i `last_open_at` (ostatnie otwarcie aplikacji);
* okręgi - województwa tych sędziów, sprowadzone do 16 kanonicznych nazw
  (aplikacja zapisuje raz „ŚLĄSKIE", raz „SLASKIE"), oraz osobno okręgi
  z włączonym panelem (`active_provinces.enabled`);
* mecze ProEla - bez szkoleniowych i testowych (klucz `T-.../NUMER`, flaga
  `isTest`, pochodzenie `training`, ćwiczenie z kursokonferencji) - ta sama
  reguła, co w `app/proel_training_key.py`;
* zatwierdzone protokoły - mecze oficjalne ze statusem `approved`.
"""

from __future__ import annotations

import json
import unicodedata
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, Mapping, Optional

from app.proel_training_key import blob_is_training, is_training_key

#: Jak długo żyje policzona odpowiedź. Liczby na stronie produktu nie muszą być
#: co do minuty, a każde odświeżenie strony nie może czytać całej tabeli.
CACHE_TTL_S = 10 * 60

#: Po nieudanym liczeniu kolejna próba najwcześniej po tylu sekundach. Bez
#: tego przy leżącej bazie każde wejście na stronę produktu dokładałoby cztery
#: nieudane zapytania i cztery ślady w logach.
RETRY_AFTER_FAILURE_S = 60

#: Okno „aktywnych" sędziów.
ACTIVE_WINDOW_DAYS = 30

#: 16 województw w zapisie bez ogonków - klucz porównania.
PROVINCES = (
    "DOLNOSLASKIE",
    "KUJAWSKO-POMORSKIE",
    "LUBELSKIE",
    "LUBUSKIE",
    "LODZKIE",
    "MALOPOLSKIE",
    "MAZOWIECKIE",
    "OPOLSKIE",
    "PODKARPACKIE",
    "PODLASKIE",
    "POMORSKIE",
    "SLASKIE",
    "SWIETOKRZYSKIE",
    "WARMINSKO-MAZURSKIE",
    "WIELKOPOLSKIE",
    "ZACHODNIOPOMORSKIE",
)

#: Klucz porównania -> nazwa do pokazania: wielkie litery z polskimi znakami.
PROVINCE_NAMES = {
    "DOLNOSLASKIE": "DOLNOŚLĄSKIE",
    "KUJAWSKO-POMORSKIE": "KUJAWSKO-POMORSKIE",
    "LUBELSKIE": "LUBELSKIE",
    "LUBUSKIE": "LUBUSKIE",
    "LODZKIE": "ŁÓDZKIE",
    "MALOPOLSKIE": "MAŁOPOLSKIE",
    "MAZOWIECKIE": "MAZOWIECKIE",
    "OPOLSKIE": "OPOLSKIE",
    "PODKARPACKIE": "PODKARPACKIE",
    "PODLASKIE": "PODLASKIE",
    "POMORSKIE": "POMORSKIE",
    "SLASKIE": "ŚLĄSKIE",
    "SWIETOKRZYSKIE": "ŚWIĘTOKRZYSKIE",
    "WARMINSKO-MAZURSKIE": "WARMIŃSKO-MAZURSKIE",
    "WIELKOPOLSKIE": "WIELKOPOLSKIE",
    "ZACHODNIOPOMORSKIE": "ZACHODNIOPOMORSKIE",
}

#: Kolejność liter polskiego alfabetu - do sortowania nazw (Ł po L, Ś po S).
_POLISH_ORDER = "-AĄBCĆDEĘFGHIJKLŁMNŃOÓPQRSŚTUVWXYZŹŻ"

#: Pola liczbowe odpowiedzi w stałej kolejności. Każde jest liczbą całkowitą
#: albo `None`, gdy jego źródło jeszcze nigdy się nie udało.
FIELDS = (
    "judges",
    "active_judges_30d",
    "provinces",
    "panel_provinces",
    "proel_matches",
    "proel_protocols",
    "protocol_pdfs",
)

#: Pola-listy (nazwy województw, nie dane osobowe). Ta sama zasada co przy
#: liczbach: lista albo `None`, gdy jej źródło jeszcze nigdy się nie udało.
LIST_FIELDS = ("panel_province_list",)


def canonical_province(value: Any) -> str:
    """Województwo w kanonicznym zapisie albo "" dla śmieci.

    Zdejmuje ogonki (ł nie rozkłada się w NFD, więc idzie osobno), przedrostek
    „WOJ." i nadmiarowe spacje wokół dywizu.
    """
    text = str(value or "").strip().upper()
    if not text:
        return ""
    text = text.replace("Ł", "L")
    text = unicodedata.normalize("NFD", text)
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Mn")
    for prefix in ("WOJEWODZTWO ", "WOJ. ", "WOJ."):
        if text.startswith(prefix):
            text = text[len(prefix):]
    text = "-".join(part.strip() for part in text.split("-"))
    text = " ".join(text.split())
    return text if text in PROVINCES else ""


def _aware(value: Any) -> Optional[datetime]:
    """Znacznik czasu ze strefą (naiwny traktujemy jako UTC)."""
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def summarize_judges(rows: Iterable[Mapping[str, Any]], now: datetime) -> Dict[str, int]:
    """Sędziowie, aktywni w oknie i liczba okręgów - z wierszy `login_records`.

    Wiersz: `judge_id`, `province`, `last_login_at`, `last_open_at`.
    """
    now = _aware(now) or datetime.now(timezone.utc)
    cutoff = now - timedelta(days=ACTIVE_WINDOW_DAYS)
    seen: set = set()
    active = 0
    provinces: set = set()
    for row in rows:
        judge_id = str(row.get("judge_id") or "").strip()
        if not judge_id or judge_id in seen:
            continue
        seen.add(judge_id)
        stamps = [
            s
            for s in (_aware(row.get("last_login_at")), _aware(row.get("last_open_at")))
            if s is not None
        ]
        if stamps and max(stamps) >= cutoff:
            active += 1
        province = canonical_province(row.get("province"))
        if province:
            provinces.add(province)
    return {
        "judges": len(seen),
        "active_judges_30d": active,
        "provinces": len(provinces),
    }


def display_province(value: Any) -> str:
    """Województwo do pokazania („ŚLĄSKIE") albo "" dla śmieci."""
    return PROVINCE_NAMES.get(canonical_province(value), "")


def _polish_key(name: str) -> tuple:
    return tuple(
        _POLISH_ORDER.index(ch) if ch in _POLISH_ORDER else len(_POLISH_ORDER) + ord(ch)
        for ch in name
    )


def sort_provinces(names: Iterable[str]) -> list:
    """Nazwy województw w porządku polskiego alfabetu (ŁÓDZKIE po LUBUSKIE)."""
    return sorted(names, key=_polish_key)


def panel_province_list(rows: Iterable[Mapping[str, Any]]) -> list:
    """Województwa z włączonym panelem - z wierszy `active_provinces`.

    Nazwy z polskimi znakami, posortowane. Ten sam okręg zapisany dwiema
    pisowniami („ŚLĄSKIE" i „SLASKIE") występuje raz.
    """
    enabled = set()
    for row in rows:
        if not row.get("enabled"):
            continue
        name = display_province(row.get("province"))
        if name:
            enabled.add(name)
    return sort_provinces(enabled)


def count_panel_provinces(rows: Iterable[Mapping[str, Any]]) -> int:
    """Liczba okręgów z włączonym panelem - z wierszy `active_provinces`."""
    return len(panel_province_list(rows))


def summarize_panel(rows: Iterable[Mapping[str, Any]]) -> Dict[str, Any]:
    """Sekcja panelu: liczba i lista z jednego odczytu tabeli."""
    names = panel_province_list(rows)
    return {"panel_provinces": len(names), "panel_province_list": names}


def _as_mapping(value: Any) -> Dict[str, Any]:
    """`matchConfig` z bazy: słownik albo surowy napis JSON (asyncpg bez kodeka)."""
    if isinstance(value, (bytes, bytearray)):
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError:
            return {}
    if isinstance(value, str):
        try:
            value = json.loads(value) if value.strip() else {}
        except ValueError:
            return {}
    return dict(value) if isinstance(value, Mapping) else {}


def is_official_match(key: Any, config: Any) -> bool:
    """Czy wiersz `proel_matches` to prawdziwy mecz, a nie ćwiczenie lub test."""
    if not str(key or "").strip() or is_training_key(key):
        return False
    return not blob_is_training({"matchConfig": _as_mapping(config)})


def summarize_matches(rows: Iterable[Mapping[str, Any]]) -> Dict[str, int]:
    """Mecze oficjalne i zatwierdzone protokoły - z wierszy `proel_matches`.

    Wiersz: `match_number`, `status`, `config` (samo `data_json->'matchConfig'`,
    żeby nie ciągnąć z bazy całego przebiegu meczu).
    """
    matches = 0
    approved = 0
    for row in rows:
        if not is_official_match(row.get("match_number"), row.get("config")):
            continue
        matches += 1
        if str(row.get("status") or "").strip().lower() == "approved":
            approved += 1
    return {"proel_matches": matches, "proel_protocols": approved}


def _clean_list(value: Any) -> Optional[list]:
    if not isinstance(value, (list, tuple)):
        return None
    return [str(item) for item in value]


def merge_sections(
    fresh: Mapping[str, Any],
    previous: Optional[Mapping[str, Any]],
) -> Dict[str, Any]:
    """Składa odpowiedź z sekcji, z których część mogła się nie udać.

    Sekcja, która padła, przychodzi jako brak klucza - wtedy bierzemy wartość
    z poprzedniej odpowiedzi, a gdy jej nie ma, `None`. Jedna niedostępna
    tabela nie może zgasić całej strony produktu.
    """
    prev = previous or {}
    out: Dict[str, Any] = {}
    for field in FIELDS:
        if field in fresh and fresh[field] is not None:
            out[field] = int(fresh[field])
        else:
            value = prev.get(field)
            out[field] = int(value) if isinstance(value, int) else None
    for field in LIST_FIELDS:
        value = _clean_list(fresh.get(field))
        out[field] = value if value is not None else _clean_list(prev.get(field))
    return out


def build_payload(
    fresh: Mapping[str, Any],
    previous: Optional[Mapping[str, Any]],
    now: datetime,
) -> Dict[str, Any]:
    """Gotowa odpowiedź: liczby + `updated_at` w ISO (UTC)."""
    payload: Dict[str, Any] = dict(merge_sections(fresh, previous))
    payload["updated_at"] = (_aware(now) or datetime.now(timezone.utc)).astimezone(
        timezone.utc
    ).isoformat()
    payload["stale"] = False
    return payload


class StatsCache:
    """Ostatnia odpowiedź i jej wiek. Czas podaje wołający (test bez zegara)."""

    def __init__(
        self,
        ttl_s: float = CACHE_TTL_S,
        retry_after_s: float = RETRY_AFTER_FAILURE_S,
    ) -> None:
        self.ttl_s = ttl_s
        self.retry_after_s = retry_after_s
        self._payload: Optional[Dict[str, Any]] = None
        self._stored_at: Optional[float] = None
        self._failed_at: Optional[float] = None

    def fresh(self, now_s: float) -> Optional[Dict[str, Any]]:
        """Odpowiedź, jeśli jeszcze nie wygasła."""
        if self._payload is None or self._stored_at is None:
            return None
        if now_s - self._stored_at >= self.ttl_s:
            return None
        return self._payload

    def last(self) -> Optional[Dict[str, Any]]:
        """Ostatnia znana odpowiedź bez względu na wiek."""
        return self._payload

    def stale(self) -> Optional[Dict[str, Any]]:
        """Ostatnia odpowiedź oznaczona jako nieświeża - na wypadek awarii bazy."""
        if self._payload is None:
            return None
        return {**self._payload, "stale": True}

    def put(self, payload: Dict[str, Any], now_s: float) -> None:
        self._payload = payload
        self._stored_at = now_s
        self._failed_at = None

    def mark_failure(self, now_s: float) -> None:
        """Zapamiętuje nieudane liczenie - początek przerwy przed kolejną próbą."""
        self._failed_at = now_s

    def in_backoff(self, now_s: float) -> bool:
        """Czy trwa jeszcze przerwa po nieudanym liczeniu."""
        return self._failed_at is not None and now_s - self._failed_at < self.retry_after_s
