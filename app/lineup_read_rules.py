"""Reguły odczytu składów z protokołu („Wczytaj składy", 02.11.2026) - LIŚĆ: bez bazy, bez sieci, bez FastAPI.

Kontrakt: `docs/mecze-wspolne-api.md` (sekcja „Wczytaj składy"). Decyzje: pamięć `wczytaj-sklady-decyzje`.

Dwie gałęzie odczytu (PDF z warstwą tekstową: `app/lineup_pdf_parse.py`; zdjęcie albo skan: model z wizją w
`app/lineup_read.py`) schodzą się TUTAJ: wspólna normalizacja i walidacja. Do aplikacji nie wychodzi nic spoza schematu:
każde pole jest przepuszczane przez czyszczenie (długość, znaki), a nazwiska i funkcje dodatkowo przez whitelistę znaków -
tekst wpisany na zdjęciu („ignoruj poprzednie polecenia") nie przejdzie jako „nazwisko".

Zasada nadrzędna: nieczytelne = None, nigdy zgadywanie.
"""

from __future__ import annotations

import re
from datetime import date
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

# ─── Limity wejścia ─────────────────────────────────────────────────────────

MAX_IMAGE_BYTES = 12 * 1024 * 1024
MAX_PDF_BYTES = 16 * 1024 * 1024
MAX_FILES = 4
MAX_PAGES = 4
#: Odczyty z modelem (kosztują) na konto na dobę - decyzja właściciela.
AI_DAILY_LIMIT = 20
#: Odczyt PDF-a bez AI jest tani, więc limit jest tylko bezpiecznikiem przed pętlą w kliencie.
TEXT_DAILY_LIMIT = 300
#: PDF z mniejszą liczbą znaków na stronie to skan (stopka daje ok. 230 znaków).
MIN_TEXT_CHARS = 400

MAX_PLAYERS = 30
STAFF_SLOTS = ("A", "B", "C", "D", "E")
LOW_CONFIDENCE = 0.7
CHECK_KEYS = ("pdf_text", "vision")


class LineupError(Exception):
    """Błąd do pokazania użytkownikowi: status HTTP, kod maszynowy i zdanie po polsku."""

    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


def s(value: Any) -> str:
    return str(value if value is not None else "").strip()


# ─── Typ pliku i rozmiar ────────────────────────────────────────────────────

_HEIC_BRANDS = (b"heic", b"heix", b"hevc", b"hevx", b"heim", b"heis", b"mif1", b"msf1", b"avif")


def detect_kind(data: bytes) -> str:
    """`jpeg` | `png` | `pdf` | `heic` | `` (nieznany) - po pierwszych bajtach, nie po rozszerzeniu ani nagłówku klienta."""
    head = bytes(data[:16])
    if head.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if head.startswith(b"%PDF-"):
        return "pdf"
    if head[4:8] == b"ftyp" and head[8:12] in _HEIC_BRANDS:
        return "heic"
    return ""


def check_upload(data: bytes) -> str:
    """Zwraca rodzaj pliku albo rzuca `LineupError` (pusty, za duży, nieobsługiwany, HEIC)."""
    if not data:
        raise LineupError(422, "EMPTY_FILE", "Plik jest pusty.")
    kind = detect_kind(data)
    if kind == "heic":
        raise LineupError(
            415, "HEIC_UNSUPPORTED",
            "Format HEIC nie jest obsługiwany. Zrób zdjęcie jako JPEG (Aparat -> Formaty -> Najbardziej zgodne) albo użyj skanera dokumentów.",
        )
    if not kind:
        raise LineupError(415, "UNSUPPORTED_TYPE", "Obsługiwane są pliki PDF, JPEG i PNG.")
    limit = MAX_PDF_BYTES if kind == "pdf" else MAX_IMAGE_BYTES
    if len(data) > limit:
        raise LineupError(413, "FILE_TOO_LARGE", f"Plik jest za duży (limit {limit // (1024 * 1024)} MB dla {'PDF' if kind == 'pdf' else 'zdjęcia'}).")
    return kind


# ─── Pojedyncze pola ────────────────────────────────────────────────────────

_CTRL = re.compile(r"[\x00-\x1f\x7f​-‏‪-‮⁠﻿]")
_WS = re.compile(r"\s+")


def clean_text(value: Any, limit: int = 120) -> Optional[str]:
    """Tekst bez znaków sterujących i podwójnych spacji, przycięty; pusty = None."""
    if value is None or isinstance(value, (bool, dict, list)):
        return None
    text = _WS.sub(" ", _CTRL.sub(" ", str(value))).strip()
    return text[:limit] or None


_NAME_OK = re.compile(r"^[^\W\d_](?:[^\W\d_]|[ .'\-’])*$", re.UNICODE)


def _is_upper_token(token: str) -> bool:
    letters = [c for c in token if c.isalpha()]
    return bool(letters) and all(c.isupper() for c in letters)


def _cap(token: str) -> str:
    """Imię: `JAN` -> `Jan`, `ANNA-MARIA` -> `Anna-Maria`; wpis w mieszanej wielkości zostaje, jak jest."""
    if not _is_upper_token(token):
        return token
    return "-".join(part[:1].upper() + part[1:].lower() for part in token.split("-"))


def split_name(raw: Any) -> Optional[Dict[str, Any]]:
    """`NAZWISKO Imię` z dowolnego zapisu: {name, surname, given, ambiguous} albo None, gdy to nie wygląda na osobę.

    Nazwisko wieloczłonowe (`VAN DER BERG Jan`, `NOWAK-KOWALSKI Anna`) = wszystkie człony wielkimi literami na początku.
    Kolejność „Imię NAZWISKO" jest odwracana. Zapis samymi wielkimi literami bierze ostatni człon za imię (i oznacza to jako
    niejednoznaczne przy 3+ członach). Znaki spoza liter, spacji, kropki, apostrofu i myślnika odrzucają całość (None).
    """
    text = clean_text(raw, 80)
    if not text or not _NAME_OK.match(text):
        return None
    tokens = text.split(" ")
    if len(tokens) == 1:
        return {"name": tokens[0].upper(), "surname": tokens[0].upper(), "given": "", "ambiguous": True}
    upper = [_is_upper_token(t) for t in tokens]
    lead = 0
    while lead < len(tokens) and upper[lead]:
        lead += 1
    ambiguous = False
    if lead == len(tokens):
        sur, giv = tokens[:-1], tokens[-1:]
        ambiguous = len(tokens) > 2
    elif lead > 0:
        sur, giv = tokens[:lead], tokens[lead:]
    else:
        tail = len(tokens)
        while tail > 0 and upper[tail - 1]:
            tail -= 1
        if tail < len(tokens):
            sur, giv = tokens[tail:], tokens[:tail]
        else:
            sur, giv = tokens[:1], tokens[1:]
            ambiguous = True
    surname = " ".join(t.upper() for t in sur)
    given = " ".join(_cap(t) for t in giv)
    return {"name": f"{surname} {given}".strip(), "surname": surname, "given": given, "ambiguous": ambiguous}


def clean_number(value: Any) -> Optional[int]:
    """Numer zawodnika 1-99; wszystko inne (0, 100+, tekst, bool, ułamek) to None."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, float):
        if not value.is_integer():
            return None
        value = int(value)
    text = s(value)
    if not re.fullmatch(r"\d{1,2}", text):
        return None
    number = int(text)
    return number if 1 <= number <= 99 else None


_LICENSE = re.compile(r"(?<!\w)(?:(?P<cat>[A-Za-z]{1,2})\s*)?(?P<num>\d{4}/(?:\d{4}|\d{2}))(?!\d)")


def find_license(text: Any) -> Optional[Dict[str, Any]]:
    """Licencja z tekstu: `NNNN/RR` albo `NNNN/RRRR` z opcjonalnym prefiksem kategorii (`B 0544/2026`).

    Zwraca {license, category, number, start, end} - `start`/`end` to położenie w tekście, żeby wołający mógł odciąć resztę
    (funkcję) bez zgadywania. None, gdy w tekście nie ma licencji.
    """
    match = _LICENSE.search(s(text))
    if not match:
        return None
    category = (match.group("cat") or "").upper() or None
    number = match.group("num")
    return {"license": f"{category} {number}" if category else number, "category": category, "number": number,
            "start": match.start(), "end": match.end()}


def clean_license(value: Any) -> Optional[Dict[str, Any]]:
    """Licencja z pola, które ma zawierać TYLKO licencję. Cokolwiek poza wzorcem = None (nie zgadujemy)."""
    text = clean_text(value, 30)
    found = find_license(text) if text else None
    if not found or found["start"] != 0 or found["end"] != len(text or ""):
        return None
    return {k: found[k] for k in ("license", "category", "number")}


def clean_function(value: Any) -> Optional[str]:
    text = clean_text(value, 40)
    if not text or re.fullmatch(r"[-_. ]+", text):
        return None
    if not re.fullmatch(r"[^\W_](?:[^\W_]|[ .'\-/])*", text, re.UNICODE):
        return None
    return text.upper() if _is_upper_token(text.replace(" ", "")) else text


def clean_confidence(value: Any, default: float = 0.0) -> float:
    if isinstance(value, bool) or value is None:
        return default
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    if number != number:  # NaN
        return default
    return round(min(1.0, max(0.0, number)), 2)


def clean_bool(value: Any) -> Optional[bool]:
    return value if isinstance(value, bool) else None


_DATE = re.compile(r"^\s*(\d{1,2})[.\-/ ](\d{1,2})[.\-/ ](\d{4})\s*$")
_ISO = re.compile(r"^\s*(\d{4})-(\d{2})-(\d{2})\s*$")


def clean_date(value: Any) -> Optional[str]:
    """Data jako `RRRR-MM-DD`; nieistniejący dzień (31.02) i rok spoza 2000-2100 = None."""
    text = s(value)
    match = _ISO.match(text)
    parts = (match.group(1), match.group(2), match.group(3)) if match else None
    if parts is None:
        match = _DATE.match(text)
        if not match:
            return None
        parts = (match.group(3), match.group(2), match.group(1))
    try:
        day = date(int(parts[0]), int(parts[1]), int(parts[2]))
    except ValueError:
        return None
    return day.isoformat() if 2000 <= day.year <= 2100 else None


def clean_time(value: Any) -> Optional[str]:
    match = re.fullmatch(r"\s*(\d{1,2})[:.](\d{2})\s*", s(value))
    if not match or int(match.group(1)) > 23 or int(match.group(2)) > 59:
        return None
    return f"{int(match.group(1)):02d}:{match.group(2)}"


def clean_zprp_id(value: Any) -> Optional[str]:
    """IdZawody tylko jako cyfry (jak `is_zprp_id`); „IMD/54" i wszystko inne to nie IdZawody."""
    if isinstance(value, bool):
        return None
    text = s(value)
    return text if text.isdigit() and 0 < len(text) <= 12 else None


_MATCH_NO = re.compile(r"^[\w/.\- ]{1,30}$", re.UNICODE)


def clean_match_number(value: Any) -> Optional[str]:
    """Numer meczu tak, jak wydrukowano (wielkość liter ma znaczenie: JmK != JMK). Nie jest kluczem."""
    text = clean_text(value, 200)
    return text if text and len(text) <= 30 and _MATCH_NO.match(text) else None


# ─── Wiersze ────────────────────────────────────────────────────────────────


def _row_source(value: Any, default: str) -> str:
    return value if value in CHECK_KEYS else default


def normalize_player(raw: Any, *, source: str) -> Optional[Dict[str, Any]]:
    """Wiersz zawodnika w kształcie wyjściowym; None, gdy w wierszu nie ma ani numeru, ani nazwiska (nic do pokazania)."""
    if not isinstance(raw, dict):
        return None
    number = clean_number(raw.get("number"))
    person = split_name(raw.get("name"))
    if number is None and person is None:
        return None
    confidence = clean_confidence(raw.get("confidence"), 0.0)
    if number is None or person is None:
        confidence = min(confidence, 0.4)
    elif person["ambiguous"]:
        confidence = min(confidence, 0.6)
    return {
        "number": number, "name": person["name"] if person else None,
        "surname": person["surname"] if person else None, "given": person["given"] if person else None,
        "confidence": confidence, "checked": clean_bool(raw.get("checked")),
        "source": _row_source(raw.get("source"), source),
    }


def normalize_staff(raw: Any, *, source: str) -> Optional[Dict[str, Any]]:
    """Osoba A-E. Wiersz bez nazwiska nie jest osobą (puste miejsce w tabeli)."""
    if not isinstance(raw, dict):
        return None
    person = split_name(raw.get("name"))
    if person is None:
        return None
    lic = clean_license(raw.get("license"))
    function = clean_function(raw.get("function"))
    if lic is None and raw.get("license"):
        # Model albo parser skleił funkcję z licencją („TRENER B 0544/2026") - rozdzielamy deterministycznie.
        found = find_license(raw.get("license"))
        if found:
            lic = {k: found[k] for k in ("license", "category", "number")}
    slot = s(raw.get("slot")).upper()
    confidence = clean_confidence(raw.get("confidence"), 0.0)
    if person["ambiguous"]:
        confidence = min(confidence, 0.6)
    return {
        "slot": slot if slot in STAFF_SLOTS else None, "name": person["name"], "surname": person["surname"], "given": person["given"],
        "function": function, "license": lic["license"] if lic else None,
        "license_category": lic["category"] if lic else None, "license_number": lic["number"] if lic else None,
        "confidence": confidence, "source": _row_source(raw.get("source"), source),
    }


def dedupe_numbers(team: str, players: List[Dict[str, Any]], warnings: List[Dict[str, Any]]) -> None:
    """Powtórzony numer w składzie (model `clashedNumber` z aplikacji): pierwszy zostaje, kolejny traci numer i niesie
    `clashed_number`, a w `warnings` ląduje DUPLICATE_NUMBER. Numeru nie zgadujemy ani nie przesuwamy."""
    seen: Dict[int, int] = {}
    for index, player in enumerate(players):
        number = player.get("number")
        if number is None:
            continue
        if number in seen:
            warnings.append({"code": "DUPLICATE_NUMBER", "team": team, "number": number, "rows": [seen[number], index]})
            player["clashed_number"] = number
            player["number"] = None
            player["confidence"] = min(player["confidence"], 0.4)
        else:
            seen[number] = index
    names: Dict[str, int] = {}
    for index, player in enumerate(players):
        key = s(player.get("name")).lower()
        if not key:
            continue
        if key in names:
            warnings.append({"code": "DUPLICATE_PLAYER", "team": team, "rows": [names[key], index]})
        else:
            names[key] = index


def unreadable_fields(team: str, rows: List[Dict[str, Any]], people: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Puste pola wierszy (indeksy względem podanych list) - liczone od nowa po scaleniu plików, bo indeksy się przesuwają."""
    out: List[Dict[str, Any]] = []
    for index, row in enumerate(rows):
        for field in ("number", "name"):
            if row.get(field) is None and not (field == "number" and row.get("clashed_number")):
                out.append({"team": team, "kind": "player", "index": index, "field": field})
    for index, person in enumerate(people):
        if not person["function"]:
            out.append({"team": team, "kind": "staff", "index": index, "field": "function"})
    return out


def normalize_team(team: str, name: Any, players: Iterable[Any], staff: Iterable[Any], *, source: str,
                   warnings: List[Dict[str, Any]], unreadable: List[Dict[str, Any]]) -> Dict[str, Any]:
    rows = [p for p in (normalize_player(raw, source=source) for raw in (players or ())) if p]
    if len(rows) > MAX_PLAYERS:
        warnings.append({"code": "TOO_MANY_ROWS", "team": team, "limit": MAX_PLAYERS})
        rows = rows[:MAX_PLAYERS]
    people = [p for p in (normalize_staff(raw, source=source) for raw in (staff or ())) if p][: len(STAFF_SLOTS)]
    dedupe_numbers(team, rows, warnings)
    unreadable.extend(unreadable_fields(team, rows, people))
    return {"name": clean_text(name, 80), "players": rows, "staff": people}


_ROLE_ORDER = ("sedzia1", "sedzia2", "czas", "sekretarz", "delegat")


def normalize_officials(raw: Any) -> List[Dict[str, Any]]:
    """Sędziowie i obsada stolika jako PODPOWIEDŹ (nic nie wpisuje się samo). Role jak w `shared_match_rules.ROLES`."""
    out: List[Dict[str, Any]] = []
    used: set = set()
    for item in (raw if isinstance(raw, (list, tuple)) else [])[:8]:
        if not isinstance(item, dict):
            continue
        role = s(item.get("role")).lower()
        person = split_name(item.get("name"))
        if role not in _ROLE_ORDER or role in used or person is None:
            continue
        used.add(role)
        out.append({"role": role, "name": person["name"]})
    out.sort(key=lambda x: _ROLE_ORDER.index(x["role"]))
    return out


def normalize_header(raw: Any) -> Dict[str, Any]:
    raw = raw if isinstance(raw, dict) else {}
    marks = raw.get("competition")
    competition: Optional[Dict[str, Any]] = None
    if isinstance(marks, dict):
        def labels(key: str) -> List[str]:
            items = marks.get(key)
            return [t for t in (clean_text(i, 30) for i in (items if isinstance(items, list) else [])[:10]) if t]

        sex = clean_text(marks.get("sex"), 1)
        competition = {"stage": labels("stage"), "sex": sex if sex in ("K", "M") else None, "age": labels("age")}
        if not (competition["stage"] or competition["sex"] or competition["age"]):
            competition = None
    return {
        "match_number": clean_match_number(raw.get("match_number")),
        "zprp_match_id": clean_zprp_id(raw.get("zprp_match_id")),
        "home_name": clean_text(raw.get("home_name"), 80), "away_name": clean_text(raw.get("away_name"), 80),
        "date": clean_date(raw.get("date")), "time": clean_time(raw.get("time")),
        "hall": clean_text(raw.get("hall"), 100), "address": clean_text(raw.get("address"), 140),
        "competition": competition,
    }


def build_result(*, source: str, pages: int, header: Any, home: Dict[str, Any], away: Dict[str, Any], officials: Any,
                 checks_detectable: Optional[bool] = None) -> Dict[str, Any]:
    """Wspólny kształt odpowiedzi obu gałęzi. `home`/`away`: {name, players, staff} jeszcze przed normalizacją wierszy."""
    warnings: List[Dict[str, Any]] = []
    unreadable: List[Dict[str, Any]] = []
    src = source if source in CHECK_KEYS else "pdf_text"
    head = normalize_header(header)
    teams = {}
    for key, part in (("home", home), ("away", away)):
        part = part if isinstance(part, dict) else {}
        teams[key] = normalize_team(key, part.get("name") or head.get(f"{key}_name"), part.get("players"), part.get("staff"),
                                    source=src, warnings=warnings, unreadable=unreadable)
        head[f"{key}_name"] = head.get(f"{key}_name") or teams[key]["name"]
    if not (teams["home"]["players"] or teams["away"]["players"]):
        raise LineupError(422, "NOT_A_PROTOCOL", "Na tym pliku nie widać protokołu zawodów ZPRP ze składami.")
    for key in ("home", "away"):
        if not teams[key]["players"]:
            warnings.append({"code": "EMPTY_TEAM", "team": key})
    return {
        "ok": True, "source": src, "pages": int(pages), "header": head, "home": teams["home"], "away": teams["away"],
        "officials": normalize_officials(officials), "warnings": warnings, "unreadable": unreadable,
        #: Czy w pliku dało się wiarygodnie wykryć zielone ptaszki przy zawodnikach (None = nie wiadomo, `checked` jest wtedy null).
        "checks_detectable": checks_detectable,
        "low_confidence_count": sum(1 for t in teams.values() for r in (*t["players"], *t["staff"]) if r["confidence"] < LOW_CONFIDENCE),
    }


def merge_results(parts: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """Łączy wyniki z kilku plików/stron jednego protokołu: nagłówek z pierwszej strony, która go ma, wiersze dopisane,
    identyczne (numer + nazwisko) pominięte."""
    if len(parts) == 1:
        return parts[0]
    base = dict(parts[0])
    base["header"] = dict(base["header"])
    for part in parts[1:]:
        for key, value in part["header"].items():
            if base["header"].get(key) in (None, "") and value not in (None, ""):
                base["header"][key] = value
        for team in ("home", "away"):
            merged = {"name": base[team]["name"] or part[team]["name"], "players": list(base[team]["players"]), "staff": list(base[team]["staff"])}
            have = {(p.get("number"), p.get("name")) for p in merged["players"]}
            merged["players"] += [p for p in part[team]["players"] if (p.get("number"), p.get("name")) not in have]
            have_s = {s(p.get("name")) for p in merged["staff"]}
            merged["staff"] += [p for p in part[team]["staff"] if s(p.get("name")) not in have_s]
            base[team] = merged
        known = {o["role"] for o in base["officials"]}
        base["officials"] = base["officials"] + [o for o in part["officials"] if o["role"] not in known]
        base["pages"] = int(base["pages"]) + int(part["pages"])
        if base["source"] != part["source"]:
            base["source"] = "mixed"
        if part.get("checks_detectable"):
            base["checks_detectable"] = True
    # Powtórna kontrola po scaleniu - numery z różnych stron też mogą się powtarzać.
    warnings: List[Dict[str, Any]] = [w for w in base["warnings"] if w.get("code") not in ("DUPLICATE_NUMBER", "DUPLICATE_PLAYER")]
    for team in ("home", "away"):
        dedupe_numbers(team, base[team]["players"], warnings)
    base["warnings"] = warnings
    base["unreadable"] = [u for team in ("home", "away") for u in unreadable_fields(team, base[team]["players"], base[team]["staff"])]
    base["low_confidence_count"] = sum(1 for team in ("home", "away") for r in (*base[team]["players"], *base[team]["staff"])
                                       if r["confidence"] < LOW_CONFIDENCE)
    return base


# ─── Zgodność z meczem ZPRP ─────────────────────────────────────────────────

_PL = str.maketrans({"ł": "l", "Ł": "L"})


def fold(value: Any) -> str:
    import unicodedata

    text = unicodedata.normalize("NFKD", s(value).translate(_PL))
    return "".join(ch for ch in text.lower() if ch.isalnum() and not unicodedata.combining(ch))


def compare_with_zprp(row: Optional[Dict[str, Any]], *, home: Any, away: Any, day: Any) -> Dict[str, Any]:
    """Czy mecz ZPRP z bazy zgadza się z meczem ręcznym. NIC nie łączy - to tylko werdykt do pokazania w pytaniu o połączenie.

    `row`: wiersz `zprp_public_matches` (czas lokalny polski, bez strefy). Drużyny porównujemy bez wielkości liter, ogonków
    i interpunkcji, a nazwa jest „zgodna", gdy jedna zawiera drugą (ZPRP dopisuje człony: `ASPR Zawadzkie` vs `ASPR Zawadzkie II`
    to NIE jest zgodność, ale `Zawadzkie` w `ASPR Zawadzkie` tak - dlatego wymagamy zawierania w jedną stronę ze skróceniem
    najwyżej do połowy). Zamienione strony (gość jako gospodarz) są osobno oznaczone.
    """
    if not row:
        return {"found": False, "verdict": "not_found"}

    def same(a: Any, b: Any) -> bool:
        x, y = fold(a), fold(b)
        if not x or not y:
            return False
        if x == y:
            return True
        short, long_ = (x, y) if len(x) <= len(y) else (y, x)
        return short in long_ and len(short) * 2 >= len(long_) and not _has_tail_marker(long_, short)

    r_home, r_away = row.get("home_team_name"), row.get("away_team_name")
    home_ok, away_ok = same(home, r_home), same(away, r_away)
    swapped = (not (home_ok and away_ok)) and same(home, r_away) and same(away, r_home)
    when = row.get("scheduled_at")
    zprp_day = when.date().isoformat() if hasattr(when, "date") else None
    want_day = clean_date(day)
    date_ok = bool(zprp_day and want_day and zprp_day == want_day)
    if home_ok and away_ok and date_ok:
        verdict = "match"
    elif swapped and date_ok:
        verdict = "swapped"
    else:
        verdict = "mismatch"
    return {
        "found": True, "verdict": verdict, "home_ok": home_ok, "away_ok": away_ok, "date_ok": date_ok, "swapped": swapped,
        "match": {
            "zprp_match_id": s(row.get("match_id")), "home_name": r_home, "away_name": r_away, "date": zprp_day,
            "time": when.strftime("%H:%M") if hasattr(when, "strftime") else None,
            "competition": row.get("competition_name"), "match_code": row.get("match_code"),
        },
    }


_TAIL = re.compile(r"(ii|iii|iv|v|b|c|u\d+|mlodziez|juniorzy|kobiety)$")


def _has_tail_marker(long_: str, short: str) -> bool:
    """`zawadzkieii` zawiera `zawadzkie`, ale to druga drużyna klubu, nie ta sama."""
    rest = long_.replace(short, "", 1)
    return bool(rest) and bool(_TAIL.fullmatch(rest))


# ─── Zapis składu we wspólnym meczu ─────────────────────────────────────────

#: Skład to ok. 32 zawodników i 10 osób (~5 kB); resztę z 20 kB zostawiamy innym polom `extra`.
MAX_LINEUP_BYTES = 12_000


def clean_lineup(value: Any) -> Optional[Dict[str, Any]]:
    """Walidacja składu do zapisu w `extra.lineup`. Odrzuca wszystko spoza schematu (rzuca ValueError, nic nie poprawia
    po cichu). None / pusty = skasowanie składu."""
    import json

    if value in (None, "", {}):
        return None
    if not isinstance(value, dict):
        raise ValueError("Skład musi być obiektem.")
    out: Dict[str, Any] = {"v": 1}
    for key in ("home", "away"):
        team = value.get(key)
        if not isinstance(team, dict):
            raise ValueError(f"Skład: brak drużyny {key}.")
        players = []
        for raw in (team.get("players") or [])[:MAX_PLAYERS]:
            if not isinstance(raw, dict):
                raise ValueError("Skład: zły wiersz zawodnika.")
            person = split_name(raw.get("name")) if raw.get("name") not in (None, "") else None
            if raw.get("name") not in (None, "") and person is None:
                raise ValueError("Skład: nazwisko zawiera niedozwolone znaki.")
            number = clean_number(raw.get("number"))
            if raw.get("number") not in (None, "", 0) and number is None:
                raise ValueError("Skład: numer zawodnika musi być z zakresu 1-99.")
            if number is None and person is None:
                continue
            row: Dict[str, Any] = {"number": number, "name": person["name"] if person else None}
            clashed = clean_number(raw.get("clashed_number"))
            if clashed is not None and number is None:
                row["clashed_number"] = clashed  # powód pustego numeru (ten sam numer ma inny zawodnik) idzie dalej do stolika
            if raw.get("checked") is not None:
                row["checked"] = bool(clean_bool(raw.get("checked")))
            if raw.get("confidence") is not None:
                row["confidence"] = clean_confidence(raw.get("confidence"))
            players.append(row)
        staff = []
        for raw in (team.get("staff") or [])[: len(STAFF_SLOTS)]:
            if not isinstance(raw, dict):
                raise ValueError("Skład: zły wiersz osoby.")
            person = split_name(raw.get("name"))
            if person is None:
                raise ValueError("Skład: nazwisko osoby jest puste albo ma niedozwolone znaki.")
            lic = clean_license(raw.get("license")) if raw.get("license") else None
            if raw.get("license") and lic is None:
                raise ValueError("Skład: numer licencji ma zły format (NNNN/RR, opcjonalnie z kategorią).")
            slot = s(raw.get("slot")).upper()
            staff.append({"slot": slot if slot in STAFF_SLOTS else None, "name": person["name"], "function": clean_function(raw.get("function")),
                          "license": lic["license"] if lic else None})
        out[key] = {"name": clean_text(team.get("name"), 80), "players": players, "staff": staff}
    for key in ("source", "read_at"):
        if value.get(key) is not None:
            out[key] = clean_text(value.get(key), 40)
    if len(json.dumps(out, ensure_ascii=False).encode("utf-8")) > MAX_LINEUP_BYTES:
        raise ValueError("Skład jest za duży.")
    return out


def lineup_counts(lineup: Optional[Dict[str, Any]]) -> Tuple[int, int, int]:
    """(zawodnicy gospodarzy, zawodnicy gości, osoby) - do dziennika i pusha, żeby nigdy nie niosły nazwisk."""
    if not isinstance(lineup, dict):
        return (0, 0, 0)
    home, away = lineup.get("home") or {}, lineup.get("away") or {}
    return (len(home.get("players") or []), len(away.get("players") or []),
            len(home.get("staff") or []) + len(away.get("staff") or []))
