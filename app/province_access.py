# app/province_access.py
#
# Kto może pisać po okręgu.
#
# Liść bez bazy - wołający podaje to, co odczytał, a tu zapada sama decyzja.
# Dzięki temu reguła chodzi w teście bez Postgresa i widać ją w całości w
# jednym miejscu, zamiast rozsypanej po endpointach. Kształt wzorowany na
# `app/match_market_access.py`.
#
# PO CO TO POWSTAŁO. Ogłoszenia okręgowe i niedyspozycje przyjmowały zapis od
# każdego, kto znał adres: `POST /silesia/announcements/create` nie sprawdzał
# nikogo, `DELETE /silesia/announcements/{id}` kasował po samym numerze, a
# `POST /silesia/offtimes/set` nadpisywał niedyspozycje DOWOLNEGO sędziego.
# Uprawnienia Masterów żyły wyłącznie w aplikacji, czyli po stronie, której
# serwer nie ma powodu wierzyć.
#
# RÓŻNICA WOBEC `match_market_access.normalize_province`. Tam województwa
# porównuje się po samym `upper()`, bo obie strony biorą je z tej samej
# kolumny. Tutaj nie: nazwa okręgu przy ogłoszeniu przychodzi z telefonu, a
# lista Masterów z panelu admina - jedna strona potrafi napisać „DOLNOSLASKIE",
# druga „DOLNOŚLĄSKIE". Ogonki zdejmujemy więc do porównania, żeby Master nie
# tracił uprawnień przez sposób zapisu.

from __future__ import annotations

import json
import unicodedata
from typing import Any, Iterable, List, Optional

#: Rodzaje uprawnień okręgowych - te same nazwy, co w panelu admina i w
#: `BAZA/utils/silesia/masters.ts`. Jeden słownik pojęć na całą aplikację.
MASTER_NEWS = "news"
MASTER_CALENDAR = "calendar"
MASTER_MATCH = "match"
MASTER_TEACH = "teach"

MASTER_KINDS = (MASTER_NEWS, MASTER_CALENDAR, MASTER_MATCH, MASTER_TEACH)


def normalize_province(value: Any) -> str:
    """Województwo do porównania: wielkie litery, bez ogonków, bez spacji."""
    text = str(value or "").strip().upper()
    if not text:
        return ""
    stripped = unicodedata.normalize("NFD", text)
    return "".join(ch for ch in stripped if unicodedata.category(ch) != "Mn")


def judge_ids(raw: Any) -> List[str]:
    """Numery sędziów z każdego kształtu, w jakim leżą w bazie.

    Kolumna `judges` jest JSONB, ale pod `databases`/asyncpg bez kodeka potrafi
    wrócić SUROWYM NAPISEM - dokładnie ta pułapka wyłożyła kiedyś obsadowego z
    odznaką w giełdzie (patrz `match_market_access.badge_names`). Numery
    sprowadzamy do napisów, bo tak porównuje je cała aplikacja.
    """
    value = raw
    if isinstance(value, (bytes, bytearray)):
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError:
            return []
    if isinstance(value, str) and value.strip():
        try:
            value = json.loads(value)
        except ValueError:
            return []
    if isinstance(value, dict):
        # Kształt `{numer: true}` - wyłączone wpisy nie są uprawnieniem.
        value = [k for k, v in value.items() if v]
    out: List[str] = []
    for item in value if isinstance(value, (list, tuple, set)) else []:
        text = str(item or "").strip()
        if text and text not in out:
            out.append(text)
    return out


def is_app_admin(judge_id: Any, admin_ids: Optional[Iterable[Any]]) -> bool:
    """Czy numer jest na globalnej liście administratorów aplikacji."""
    wanted = str(judge_id or "").strip()
    if not wanted:
        return False
    return wanted in judge_ids(list(admin_ids or []))


def master_ids_for_province(
    rows: Iterable[Any], province: Any
) -> List[str]:
    """Numery Masterów dla województwa z wierszy tabeli `*_masters`.

    `rows` to cokolwiek z kluczami `province` i `judges` - wiersz bazy, słownik
    albo obiekt `_mapping`. Porównanie idzie przez `normalize_province`, więc
    zapis z ogonkami i bez trafia na tę samą listę.
    """
    wanted = normalize_province(province)
    if not wanted:
        return []
    for row in rows or []:
        data = row
        mapping = getattr(row, "_mapping", None)
        if mapping is not None:
            data = mapping
        try:
            row_province = data["province"]
            row_judges = data["judges"]
        except (TypeError, KeyError):
            row_province = getattr(row, "province", None)
            row_judges = getattr(row, "judges", None)
        if normalize_province(row_province) != wanted:
            continue
        return judge_ids(row_judges)
    return []


def may_write_province(
    *,
    judge_id: Any,
    master_judge_ids: Optional[Iterable[Any]] = None,
    admin_ids: Optional[Iterable[Any]] = None,
) -> bool:
    """Czy ten człowiek może pisać po tym okręgu w tej kategorii.

    Administrator przechodzi zawsze - tak samo, jak w aplikacji. Poza nim
    liczy się wyłącznie obecność na liście Masterów TEGO województwa; nazwa
    okręgu podana w żądaniu nie ma tu nic do rzeczy poza wyborem listy, którą
    wołający już odczytał.
    """
    actor = str(judge_id or "").strip()
    if not actor:
        return False
    if is_app_admin(actor, admin_ids):
        return True
    return actor in judge_ids(list(master_judge_ids or []))


def may_write_offtimes(
    *,
    judge_id: Any,
    target_judge_id: Any,
    master_judge_ids: Optional[Iterable[Any]] = None,
    admin_ids: Optional[Iterable[Any]] = None,
) -> bool:
    """Czy wolno zapisać niedyspozycje pod ten numer sędziego.

    Po SWOICH pisze każdy zalogowany - to jego kalendarz i jego decyzja.
    Po cudzych wyłącznie Calendar Master okręgu albo administrator: panel
    „Calendar Master" istnieje właśnie po to, żeby ktoś mógł wpisać
    niedyspozycję za kolegę, który nie ma jak.
    """
    actor = str(judge_id or "").strip()
    target = str(target_judge_id or "").strip()
    if not actor:
        return False
    if target and actor == target:
        return True
    return may_write_province(
        judge_id=actor,
        master_judge_ids=master_judge_ids,
        admin_ids=admin_ids,
    )
