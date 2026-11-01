"""Reguły meczów wspólnych - LIŚĆ: bez bazy, bez sieci, bez FastAPI (31.10.2026).

Kontrakt: `docs/mecze-wspolne-api.md`. Wszystko, co daje się rozstrzygnąć na samych danych (klucz duplikatu, kolejny numer
serii, różnica pól do dziennika, ranking sugestii, uprawnienia do obsady), mieszka tu i ma test jednostkowy.
"""

from __future__ import annotations

import json
import re
import unicodedata
from datetime import date, datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
from zoneinfo import ZoneInfo

WARSAW = ZoneInfo("Europe/Warsaw")

#: Role obsady: sędziowie, stolik, delegat.
ROLES: Tuple[str, ...] = ("sedzia1", "sedzia2", "czas", "sekretarz", "delegat")
ROLE_LABELS: Dict[str, str] = {
    "sedzia1": "sędzia 1", "sedzia2": "sędzia 2", "czas": "mierzący czas", "sekretarz": "sekretarz", "delegat": "delegat",
}
#: Role, które tworzą parę sędziowską w panelu Mentor.
REFEREE_ROLES: Tuple[str, ...] = ("sedzia1", "sedzia2")

MAX_MEMBERS = 12
MAX_EXTRA_BYTES = 20_000
MAX_TEXT = 200

#: Pola treści meczu, które edytuje każdy członek (z `PUT /shared-matches/{id}`).
EDITABLE_FIELDS: Tuple[str, ...] = ("code", "competition", "home_name", "away_name", "match_at", "hall", "city")


def s(value: Any) -> str:
    return str(value if value is not None else "").strip()


def clean_text(value: Any, limit: int = MAX_TEXT) -> Optional[str]:
    """Tekst przycięty i bez znaków sterujących; pusty = None."""
    text = "".join(ch for ch in s(value) if ch == " " or (ch.isprintable() and ch not in "\r\n\t"))
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit] or None


def clean_role(value: Any) -> str:
    role = s(value).lower()
    if role not in ROLES:
        raise ValueError(f"Nieznana rola obsady: {s(value) or '(pusta)'}.")
    return role


def role_label(role: Any) -> str:
    return ROLE_LABELS.get(s(role), s(role))


def is_zprp_id(value: Any) -> bool:
    """Prawdziwe `IdZawody` to czysta liczba (syntetyczne identyfikatory ręcznych meczów nie są nim)."""
    text = s(value)
    return text.isdigit() and 0 < len(text) <= 12


def clean_proel_key(value: Any) -> Optional[str]:
    text = s(value)
    if not text:
        return None
    if len(text) > 80 or any(ord(ch) < 32 for ch in text):
        raise ValueError("Klucz protokołu ProEla jest nieprawidłowy.")
    return text


def clean_score(value: Any, field: str = "wynik") -> Optional[int]:
    if value is None or s(value) == "":
        return None
    if isinstance(value, bool):
        raise ValueError(f"Pole {field} musi być liczbą.")
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        raise ValueError(f"Pole {field} musi być liczbą.") from None
    if not 0 <= number <= 199:
        raise ValueError(f"Pole {field} musi być w zakresie 0-199.")
    return number


def clean_extra(value: Any) -> Dict[str, Any]:
    if value in (None, ""):
        return {}
    if not isinstance(value, Mapping):
        raise ValueError("Pole extra musi być obiektem.")
    raw = json.dumps(value, ensure_ascii=False, default=str)
    if len(raw.encode("utf-8")) > MAX_EXTRA_BYTES:
        raise ValueError("Pole extra jest za duże (limit 20 kB).")
    return dict(value)


def parse_match_at(value: Any) -> Optional[datetime]:
    """ISO 8601 -> data ze strefą (UTC). Bez strefy = czas polski (tak podaje go aplikacja)."""
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        moment = value
    else:
        text = s(value).replace("Z", "+00:00")
        if len(text) == 10:
            text += "T00:00:00"
        try:
            moment = datetime.fromisoformat(text.replace(" ", "T"))
        except ValueError:
            raise ValueError("Data meczu ma nieprawidłowy format (oczekiwano ISO 8601).") from None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=WARSAW)
    return moment.astimezone(timezone.utc)


def date_key(moment: Optional[datetime]) -> Optional[str]:
    """Dzień meczu po polsku (YYYY-MM-DD)."""
    if moment is None:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(WARSAW).date().isoformat()


_PL = str.maketrans({"ł": "l", "Ł": "L"})


def fold(value: Any) -> str:
    """Nazwa do porównań: bez ogonków, wielkości liter, znaków interpunkcyjnych i spacji."""
    text = unicodedata.normalize("NFKD", s(value).translate(_PL))
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    return "".join(ch for ch in text.lower() if ch.isalnum())


def teams_key(home: Any, away: Any) -> Optional[str]:
    """Klucz pary drużyn niezależny od kolejności; brak którejkolwiek nazwy = brak klucza (nie ma czego porównywać)."""
    a, b = fold(home), fold(away)
    if not a or not b:
        return None
    return "|".join(sorted((a, b)))


def duplicate_key(home: Any, away: Any, moment: Optional[datetime]) -> Optional[Tuple[str, str]]:
    day, teams = date_key(moment), teams_key(home, away)
    return (day, teams) if day and teams else None


# ─── Seria meczów ───────────────────────────────────────────────────────────

_SERIES = re.compile(r"^(?P<base>.*?[^\d\s/\-_.])(?P<sep>[\s/\-_.]*)(?P<num>\d{1,4})$")


def split_series(code: Any) -> Tuple[str, str, Optional[int]]:
    """„EHF/1" -> („EHF", „/", 1); „EHF" -> („EHF", „", None)."""
    text = s(code)
    found = _SERIES.match(text)
    if not found or not found.group("base").strip():
        return text, "", None
    return found.group("base").strip(), found.group("sep") or "/", int(found.group("num"))


def next_series_code(code: Any, existing: Iterable[Any] = ()) -> Optional[str]:
    """Kolejny numer serii: EHF/1 -> EHF/2; EHF (bez numeru) -> EHF/2. Pomija zajęte numery.

    Kod, który jest samym numerem („12") albo pusty, nie tworzy serii - zwraca None (powtórzony mecz zostaje bez kodu).
    """
    base, sep, number = split_series(code)
    if not base or base.replace(" ", "").isdigit():
        return None
    taken = {s(c).casefold() for c in existing}
    sep = sep or "/"
    n = (number or 1) + 1
    for _ in range(10_000):
        candidate = f"{base}{sep}{n}"
        if candidate.casefold() not in taken:
            return candidate
        n += 1
    return None


# ─── Różnice do dziennika ───────────────────────────────────────────────────


def _plain(value: Any) -> Any:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return value


def diff_fields(old: Mapping[str, Any], new: Mapping[str, Any], fields: Iterable[str]) -> List[Dict[str, Any]]:
    """Lista {field, from, to} tylko dla pól, które się zmieniły."""
    out = []
    for field in fields:
        before, after = _plain(old.get(field)), _plain(new.get(field))
        if before in ("", None) and after in ("", None):
            continue
        if before != after:
            out.append({"field": field, "from": before, "to": after})
    return out


# ─── Uprawnienia ────────────────────────────────────────────────────────────


def may_remove_member(*, actor_id: str, creator_id: str, member_judge_id: Optional[str]) -> bool:
    """Innych z obsady usuwa tylko twórca. Siebie nikt nie „usuwa" - ukrywa mecz (twórca nie znika z własnego meczu)."""
    if s(actor_id) != s(creator_id):
        return False
    return s(member_judge_id) != s(creator_id)


def may_change_role(*, actor_id: str, creator_id: str, member_judge_id: Optional[str]) -> bool:
    """Rolę zmienia twórca (każdemu) albo członek (sobie)."""
    return s(actor_id) == s(creator_id) or (bool(s(member_judge_id)) and s(actor_id) == s(member_judge_id))


def revision_conflict(base_rev: Any, current_rev: Any) -> bool:
    """True, gdy zapis szedłby na nieaktualnej wersji."""
    try:
        return int(base_rev) != int(current_rev)
    except (TypeError, ValueError):
        return True


# ─── Sugestie ───────────────────────────────────────────────────────────────


def rank_partners(counts: Mapping[str, int], *, exclude: Iterable[str] = (), limit: int = 5) -> List[Tuple[str, int]]:
    """Najczęstsi wspólni partnerzy: malejąco po liczbie, przy remisie po identyfikatorze (stabilnie)."""
    skip = {s(x) for x in exclude}
    ranked = sorted(((j, n) for j, n in counts.items() if s(j) and s(j) not in skip and n > 0), key=lambda kv: (-kv[1], kv[0]))
    return ranked[:limit]


def merge_suggestions(groups: Sequence[Tuple[str, Iterable[str]]], *, limit: int = 8) -> List[Dict[str, Any]]:
    """Grupy (powód, [judge_id]) w jedną listę bez powtórzeń; osoba dostaje powód z NAJWCZEŚNIEJSZEJ grupy."""
    seen: Dict[str, Dict[str, Any]] = {}
    for reason, ids in groups:
        for judge_id in ids:
            key = s(judge_id)
            if not key:
                continue
            if key in seen:
                seen[key]["reasons"].append(reason)
            else:
                seen[key] = {"judge_id": key, "reason": reason, "reasons": [reason]}
    return list(seen.values())[:limit]


def like_pattern(text: Any) -> str:
    """Wzorzec do `ILIKE ... ESCAPE '\\\\'` bez znaków specjalnych LIKE."""
    raw = s(text)[:60]
    return "%" + raw.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
