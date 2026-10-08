"""Prognoza rozliczenia - przyszle mecze z telefonu sedziego. Lisc bez bazy.

„Moje rozliczenie" z przelacznikiem przyszlych ma pokazac, ile wyjdzie takze
w miesiacach, ktore dopiero nadejda. Serwer zna jednak tylko obsady ze swojej
tabeli, a ta synchronizuje sie raz na dobe i nie siega nastepnego sezonu.
Telefon ma wlasna, swieza liste meczow z ZPRP - wysyla przyszle, a serwer
dokleja te, ktorych nie zna, i liczy je TYM SAMYM silnikiem (decyzja
uzytkownika z 29.09.2026). Dzieki temu prognoza nie ma drugiego zestawu
regul w aplikacji.

Co wolno dokleic - te same granice, co przy synchronizacji list sedziow:
  * tylko mecze PRZYSZLE (rozegrane zna juz serwer; ich brak to sprawa
    synchronizacji, nie prognozy),
  * stolik zawsze (stoliki spoza okregu tez sa rozliczeniem okregu),
  * boiskowy i delegat - na meczu rozgrywek okregowych (takze innego
    okregu, jak synchronizacja od 06.10.2026) albo centralnym (centralny
    wypadnie w silniku jako obsada ZPRP i pokaze sie bez kwoty).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable, Optional

from app import settlement_origin as O
from app import settlement_rates as R

FORECAST_ORIGIN = "forecast"
#: Klucz prognozy: przedrostek + IdZawody. Obsady z synchronizacji maja postac
#: „<zrodlo>:<IdZawody>", wiec po czesci za dwukropkiem rozpoznajemy mecz,
#: ktory serwer juz zna.
FORECAST_PREFIX = "f:"
MAX_FORECAST_MATCHES = 400


def match_id_of(key: Any) -> str:
    return str(key or "").split(":", 1)[-1].strip()


def role_of(raw: Any) -> str:
    text = R.strip_dia(str(raw or "")).lower()
    if "deleg" in text:
        return R.ROLE_DELEGATE
    if "stolik" in text or "sekret" in text or "mierz" in text or "czas" in text:
        return R.ROLE_TABLE
    return R.ROLE_FIELD


def parse_when(raw: Any) -> Optional[datetime]:
    """ISO z telefonu. Bez strefy = UTC (telefon wysyla `toISOString`)."""
    text = str(raw or "").strip()
    if not text:
        return None
    try:
        when = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return when if when.tzinfo else when.replace(tzinfo=timezone.utc)


def may_forecast(code: Any, role: str, own_prefixes: Iterable[str]) -> bool:
    """
    Te same granice co synchronizacja BIEZACEGO sezonu (`counts_this_season`,
    06.10.2026): mecz rozgrywek okregowych - takze innego okregu - wchodzi
    w kazdej roli; zdejmuje go tylko czlowiek. Do 08.10.2026 prognoza odrzucala
    boiskowego na meczu innego okregu, a panel ten sam mecz po synchronizacji
    wyplacal.
    """
    if role == R.ROLE_TABLE or O.counts_this_season(code):
        return True
    return not O.is_other_district(code, own_prefixes)


def pick_forecast(
    items: Iterable[dict],
    *,
    known_ids: set[str],
    own_prefixes: Iterable[str],
    now: datetime,
) -> list[dict]:
    """Surowe mecze z telefonu -> te, ktore wolno dokleic (juz znormalizowane)."""
    out: list[dict] = []
    seen: set[str] = set()
    own = set(own_prefixes)
    for raw in list(items)[:MAX_FORECAST_MATCHES]:
        match_id = match_id_of(raw.get("match_id") or raw.get("match_key"))
        if not match_id or match_id in known_ids or match_id in seen:
            continue
        when = parse_when(raw.get("when"))
        if when is None or when <= now:
            continue
        code = str(raw.get("code") or "").strip()
        role = role_of(raw.get("role"))
        if not code or not may_forecast(code, role, own):
            continue
        seen.add(match_id)
        out.append(
            {
                "match_key": FORECAST_PREFIX + match_id,
                "match_at": when,
                "code": code,
                "role": role,
                "city": str(raw.get("city") or "").strip(),
                "hall": str(raw.get("hall") or "").strip(),
                "teams": str(raw.get("teams") or "").strip(),
                "round_text": raw.get("round") or None,
                "series_text": raw.get("series") or None,
            }
        )
    return out
