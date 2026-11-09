"""Zapisane stany zakładek „Raporty i podsumowania ZPRP" (10.11.2026) - reguły, bez bazy i sieci.

Zakładki BAZA_web (Terminarz, Rozgrywki, Statystyki, Sędziowie i delegaci) pokazują
przy wejściu ostatni zapisany stan okręgu zamiast logować się do baza.zprp.pl za
każdym razem. Stan powstaje:

  - automatycznie, kontem okręgu z serwera (`zprp_accounts`, rola `sync`):
    lista sędziów przy synchronizacji niedyspozycji (co 2 h), reszta nocą raz na dobę,
  - ręcznie, gdy ktoś z okręgu kliknie odświeżenie - nadpisuje stan dla całego okręgu
    (decyzja właściciela, 10.11.2026), także w okręgach bez konta na serwerze.

Kształt `payload` to DOKŁADNIE odpowiedź odpowiedniej trasy `/zprp/*` - zakładka
nie odróżnia stanu zapisanego od świeżego. Klucz (`key`) opisuje parametry trasy.
"""

from __future__ import annotations

import datetime as _dt
import re
from typing import Any, Dict, Optional
from zoneinfo import ZoneInfo

WARSAW = ZoneInfo("Europe/Warsaw")

#: Rodzaj -> trasa, z której pochodzi kształt danych, i opis klucza.
KINDS: Dict[str, str] = {
    "officials": "/zprp/sedziowie/scrape (klucz pusty)",
    "schedule_meta": "/zprp/terminarz/meta (klucz: sezon albo pusty = bieżący)",
    "schedule_full": "/zprp/terminarz/scrape (klucz: sezon)",
    "schedule_slim": "/zprp/terminarz/scrape_slim (klucz: sezon::kategoria::rozgrywki)",
    "competitions_meta": "/zprp/rozgrywki/meta (klucz pusty)",
    "competitions_lite": "/zprp/rozgrywki/scrape_lite (klucz: sezon)",
    "stats_table": "/zprp/statystyki/tabela (klucz: sezon::rozgrywki, puste = domyślne)",
    "stats_teams": "/zprp/statystyki/druzyn (klucz: sezon::rozgrywki)",
    "stats_scorers": "/zprp/statystyki/strzelec (klucz: sezon::rozgrywki)",
}

SOURCE_AUTO = "auto"
SOURCE_MANUAL = "manual"

#: Nocne okno odświeżania (czas polski) i minimalny odstęp między przebiegami.
NIGHT_FROM_HOUR = 3
NIGHT_TO_HOUR = 6
NIGHTLY_MIN_GAP = _dt.timedelta(hours=20)

#: Stan starszy niż tyle jest w zakładce oznaczony jako nieaktualny.
STALE_AFTER = {
    "officials": _dt.timedelta(hours=6),
}
STALE_DEFAULT = _dt.timedelta(hours=36)

MAX_PAYLOAD_BYTES = 25 * 1024 * 1024

_KEY_RE = re.compile(r"^[0-9A-Za-z_|:.\- ]{0,120}$")


def valid_kind(kind: Any) -> bool:
    return str(kind or "") in KINDS


def clean_key(key: Any) -> Optional[str]:
    """Klucz z parametrów trasy; None, gdy wygląda podejrzanie (zła długość, znaki)."""
    text = str(key if key is not None else "").strip()
    if not _KEY_RE.fullmatch(text):
        return None
    # „::" i „" to ten sam domyślny wybór - jeden zapis zamiast dwóch.
    if text.replace(":", "") == "":
        return ""
    return text


def stats_key(season_id: Any, id_rozgr: Any) -> str:
    season = str(season_id or "").strip()
    rozgr = str(id_rozgr or "").strip()
    return "" if not season and not rozgr else f"{season}::{rozgr}"


def newest_season(meta: Dict[str, Any]) -> str:
    """Najnowszy sezon z meta rozgrywek - lustro `pickNewestSeasonIdFromMeta` w zakładce."""
    seasons = ((meta or {}).get("filters") or {}).get("Filtr_sezon") or []
    values = [str(s.get("value") or "").strip() for s in seasons if isinstance(s, dict)]
    values = [v for v in values if v and v not in ("---", "0")]
    numeric = [v for v in values if v.isdigit()]
    if numeric:
        return max(numeric, key=int)
    if values:
        return values[0]
    return str((meta or {}).get("Filtr_sezon_selected") or "").strip()


def is_stale(kind: str, fetched_at: Optional[_dt.datetime], now: _dt.datetime) -> bool:
    if not fetched_at:
        return True
    if fetched_at.tzinfo is None:
        fetched_at = fetched_at.replace(tzinfo=_dt.timezone.utc)
    return now - fetched_at > STALE_AFTER.get(kind, STALE_DEFAULT)


def nightly_due(last_auto: Optional[_dt.datetime], now: _dt.datetime) -> bool:
    """Czy pora na nocny przebieg: nigdy nie było - od razu; inaczej w oknie 3-6 i nie częściej niż co 20 h."""
    if last_auto is None:
        return True
    if last_auto.tzinfo is None:
        last_auto = last_auto.replace(tzinfo=_dt.timezone.utc)
    if now - last_auto < NIGHTLY_MIN_GAP:
        return False
    local = now.astimezone(WARSAW)
    return NIGHT_FROM_HOUR <= local.hour < NIGHT_TO_HOUR or now - last_auto > _dt.timedelta(hours=30)


def officials_payload(officials: Dict[str, Dict[str, Any]], *, base_url: str, entry_href: str, summary: Dict[str, Any], fetched_at: str) -> Dict[str, Any]:
    """Lista z synchronizacji niedyspozycji w kształcie odpowiedzi `/zprp/sedziowie/scrape`."""
    return {
        "fetched_at": fetched_at,
        "base_url": base_url,
        "entry_href": entry_href,
        "paging": {},
        "officials": officials,
        "summary": {"officials_total": len(officials), **summary},
    }
