"""
Archiwum meczów okręgu - reguły budowy sezonu, bez bazy i bez sieci.

PORT 1:1 tego, co dziś składa przeglądarka w Statystykach okręgowych
(BAZA_web, decyzja użytkownika z 16.09.2026: „wspólne źródło na serwerze,
liczenie jak dziś"):

  - `utils/province-stats/toSlim.ts`     -> `to_slim`, `enrich_with_details`,
  - `utils/province-stats/outside.ts`    -> `collect_outside_candidates`,
                                            `row_to_slim`, `details_to_slim`,
  - `utils/province-stats/normalize.ts`  -> pomocnicze,
  - `api/zprp-public/provinceCascade.ts` -> `filter_province_competitions`,
                                            `resolve_wzpr_code`.

Serwer oddaje sezon w KSZTAŁCIE `ProvinceDataset`, a ekran liczy dalej swoim
kodem. Każda różnica w tym pliku to inna liczba na ekranie, więc zgodność
pilnuje test porównujący wynik z kodem TypeScript na prawdziwych meczach.

Pułapki JavaScriptu, które trzeba było odtworzyć, żeby liczby się zgadzały:
  - `Date.parse("2026-09-20T16:45:00")` liczy w czasie LOKALNYM (Warszawa),
    ale `Date.parse("2026-09-20")` - bez godziny - w UTC,
  - `a ?? b` bierze `b` tylko dla null, a `a || b` także dla 0 i pustego napisu,
  - `Number("")` to 0, a nie NaN (czasy time-outów „00:19:" dają liczby),
  - pole `undefined` znika z JSON-a - tutaj klucza po prostu nie ma.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import math
import re
import unicodedata
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple
from zoneinfo import ZoneInfo

from app.settlement_rates import is_test_competition

#: Wersja kształtu meczu w archiwum. Podbicie = przebudowa wszystkich sezonów.
ARCHIVE_SCHEMA = 1
#: `CACHE_SCHEMA` z `utils/province-stats/statsCache.ts` - ekran odrzuca inny.
CLIENT_SCHEMA = 2

WARSAW = ZoneInfo("Europe/Warsaw")

ROLE_FIELD: Dict[str, str] = {
    "first": "NrSedzia_pierwszy",
    "second": "NrSedzia_drugi",
    "secretary": "NrSedzia_sekretarz",
    "timer": "NrSedzia_czas",
    "delegate": "NrSedzia_delegat",
    "delegate2": "NrSedzia_delegat2",
}

#: Kolejność pól obsady na stronie sędziego -> nasze role (`outside.ts`).
ROW_ROLE: Tuple[Tuple[str, str], ...] = (
    ("referee1", "first"),
    ("referee2", "second"),
    ("secretary", "secretary"),
    ("timekeeper", "timer"),
    ("delegate", "delegate"),
)

#: Pola, które dokłada faza szczegółów - przy meczu bez zmian przenosimy je
#: ze starej wersji zamiast pytać API drugi raz.
DETAIL_KEYS = ("cat", "sex", "to", "roster", "compName", "wzpr", "wzprName")


# ---------------------------------------------------------------------------
# JavaScript w Pythonie
# ---------------------------------------------------------------------------


def js_str(value: Any) -> str:
    """`String(v ?? "").trim()`."""
    if value is None:
        return ""
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value).strip()


def _clean_number(value: float) -> Any:
    """Liczba tak, jak zapisałby ją JSON w przeglądarce (12, nie 12.0)."""
    if isinstance(value, float) and value.is_integer() and abs(value) < 2**53:
        return int(value)
    return value


def js_number(value: Any) -> Optional[float]:
    """`Number(v)` - `None`, gdy wychodzi NaN albo nieskończoność."""
    if value is None:
        return 0.0
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if isinstance(value, (int, float)):
        number = float(value)
    else:
        text = str(value).strip()
        if text == "":
            return 0.0
        try:
            number = float(text)
        except ValueError:
            return None
        if text.lower() in ("nan", "inf", "-inf", "infinity", "-infinity", "+inf"):
            return None
    return number if math.isfinite(number) else None


def num(value: Any) -> Any:
    """`num` z `normalize.ts`: null i pusty napis to brak, reszta przez `Number`."""
    if value is None or value == "":
        return None
    number = js_number(value)
    return None if number is None else _clean_number(number)


def int_or0(value: Any) -> int:
    number = num(value)
    # `Math.round` zaokrąga połówki w górę (także ujemne: -2.5 -> -2).
    return 0 if number is None else int(math.floor(float(number) + 0.5))


def parse_zprp_ms(raw: Any) -> Optional[int]:
    """`parseZprpDate`: „RRRR-MM-DD GG:MM:SS" -> milisekundy.

    Z godziną - czas lokalny (tak liczy przeglądarka w Polsce), bez godziny -
    UTC, bo tak `Date.parse` czyta samą datę.
    """
    text = js_str(raw)
    if not text:
        return None
    iso = text.replace(" ", "T", 1)
    match = re.fullmatch(r"(\d{4})-(\d{2})-(\d{2})", iso)
    try:
        if match:
            moment = datetime(int(match.group(1)), int(match.group(2)), int(match.group(3)), tzinfo=timezone.utc)
            return int(moment.timestamp() * 1000)
        match = re.fullmatch(
            r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,3}))?)?",
            iso,
        )
        if not match:
            return None
        millis = int((match.group(7) or "0").ljust(3, "0"))
        moment = datetime(
            int(match.group(1)),
            int(match.group(2)),
            int(match.group(3)),
            int(match.group(4)),
            int(match.group(5)),
            int(match.group(6) or 0),
            millis * 1000,
            tzinfo=WARSAW,
        )
        return int(round(moment.timestamp() * 1000))
    except ValueError:
        return None


def local_parts(ms: Optional[int]) -> Tuple[Optional[int], Optional[int]]:
    """(`getDay()`, `getHours()`) w Warszawie; niedziela to 0."""
    if ms is None:
        return None, None
    moment = datetime.fromtimestamp(ms / 1000, tz=WARSAW)
    return (moment.isoweekday() % 7, moment.hour)


_COMBINING = re.compile("[" + chr(0x300) + "-" + chr(0x36F) + "]")


def strip_diacritics(text: str) -> str:
    return _COMBINING.sub("", unicodedata.normalize("NFD", text or ""))


def is_placeholder_name(raw: Any) -> bool:
    text = js_str(raw)
    return not text or bool(re.fullmatch(r"[-\s—–_.]*", text))


def clean_ref_id(raw: Any) -> Optional[str]:
    text = js_str(raw)
    if not text or not re.fullmatch(r"\d+", text) or int(text) <= 0:
        return None
    return text


def _title_token(token: str) -> str:
    if "-" in token:
        return "-".join(_title_token(part) for part in token.split("-") if part)
    return token[:1].upper() + token[1:].lower()


def pretty_person_name(raw: Any) -> str:
    """„NAZWISKO Imię" -> „Imię Nazwisko" (`prettyPersonName`)."""
    text = re.sub(r"\s+", " ", "" if raw is None else str(raw)).strip()
    if not text or is_placeholder_name(text):
        return ""
    parts = [part for part in text.split(" ") if part]
    if len(parts) == 1:
        return _title_token(parts[0])
    letters = re.sub(r"[^A-Za-z]", "", strip_diacritics(parts[0]))
    if letters and letters == letters.upper():
        last = _title_token(parts[0])
        first = " ".join(_title_token(part) for part in parts[1:])
        return f"{first} {last}".strip()
    return " ".join(_title_token(part) for part in parts)


_FOLD = {"ł": "l", "Ł": "l", "ø": "o", "Ø": "o", "đ": "d", "Đ": "d", "ß": "s"}


def fold_for_search(text: Any) -> str:
    out = []
    for ch in "" if text is None else str(text):
        mapped = _FOLD.get(ch)
        if mapped:
            out.append(mapped)
            continue
        folded = (unicodedata.normalize("NFD", ch)[:1] or ch).lower()
        out.append(folded if len(folded) == 1 else ch)
    return "".join(out)


def name_key(raw: Any) -> str:
    """Nazwisko do porównań: bez ogonków, małymi, człony posortowane."""
    folded = fold_for_search(raw)
    tokens = re.sub(r"[^a-z0-9]+", " ", folded).strip().split(" ")
    return " ".join(sorted(token for token in tokens if token))


def timeout_seconds(raw: Any) -> Optional[int]:
    text = js_str(raw)
    if not text:
        return None
    parts = [js_number(part) for part in text.split(":")]
    if any(part is None for part in parts):
        return None
    if len(parts) >= 3:
        return _clean_number(parts[1] * 60 + parts[2])
    if len(parts) == 2:
        return _clean_number(parts[0] * 60 + parts[1])
    return None


def normalize_province(text: Any) -> str:
    folded = strip_diacritics(js_str(text)).replace("ł", "l").replace("Ł", "L").upper()
    return re.sub(r"[^A-Z]", "", folded)


def as_rows(payload: Any) -> List[dict]:
    """`asRows`: API oddaje słownik „1", „2"... albo listę."""
    if not payload:
        return []
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        return [item for item in payload.values() if isinstance(item, dict)]
    return []


#: Ślad ISO-8859-2 przeczytanego jako UTF-8: bajt C3-C5 i bajt kontynuacji.
#: Budowane z kodów, żeby w źródle nie stały niewidoczne znaki.
_MOJIBAKE = re.compile("[" + chr(0xC3) + "-" + chr(0xC5) + "][" + chr(0x80) + "-" + chr(0xBF) + "]")


def decode_api_bytes(raw: bytes) -> Any:
    """JSON z publicznego API: część odpowiedzi to UTF-8, część surowe ISO-8859-2.

    `pokaz_rozgrywki.php` oddaje bajty ISO-8859-2 bez deklaracji - jak w
    `api/zprp-public/httpDecoded.ts`, najpierw ścisły UTF-8, a przy śladach
    „krzaków" ISO-8859-2.
    """
    text: Optional[str] = None
    try:
        candidate = raw.decode("utf-8")
        if not re.search(_MOJIBAKE, candidate):
            text = candidate
    except UnicodeDecodeError:
        text = None
    if text is None:
        text = raw.decode("iso-8859-2", errors="replace")
    text = text.strip()
    if not text or text == "null":
        return None
    return json.loads(text)


# ---------------------------------------------------------------------------
# Rozgrywki okręgu
# ---------------------------------------------------------------------------

_STATIC_WZPR = {"SLASKIE": "12", "DOLNOSLASKIE": "1"}


def resolve_wzpr_code(competitions: Iterable[dict], province: Any) -> Optional[str]:
    want = normalize_province(province)
    if not want:
        return None
    for item in competitions:
        if item.get("NazwaWZPR") and normalize_province(item.get("NazwaWZPR")) == want:
            return js_str(item.get("NrWZPR")) or None
    return _STATIC_WZPR.get(want)


def filter_province_competitions(competitions: Iterable[dict], code: str) -> List[dict]:
    return [
        item
        for item in competitions
        if js_str(item.get("NrWZPR")) == js_str(code)
        and js_str(item.get("Wystartowano")) == "1"
        and not is_test_competition(js_str(item.get("code")))
    ]


def competition_entry(item: dict) -> dict:
    teams = js_number(item.get("IleZespolow") if item.get("IleZespolow") is not None else 0)
    entry = {
        "id": item.get("Id_rozgrywki"),
        "code": item.get("code_export"),
        "name": item.get("Nazwa"),
        "sex": item.get("Plec"),
        "teams": _clean_number(teams) if teams else 0,
    }
    if item.get("Kategoria") is not None:
        entry["category"] = item.get("Kategoria")
    return entry


def series_label(series: dict) -> str:
    """`String(s.Nazwa ?? s.Nr ?? "")`."""
    for key in ("Nazwa", "Nr"):
        if series.get(key) is not None:
            return str(series.get(key))
    return ""


# ---------------------------------------------------------------------------
# Mecz
# ---------------------------------------------------------------------------


def _comp_from_code(code: str) -> str:
    index = code.rfind("/")
    return code[:index] if index > 0 else code


def to_slim(row: dict, *, origin: str, round_name: str = "", series: str = "") -> dict:
    """`toSlimMatch` - wiersz meczu z API do postaci archiwum."""
    ts = parse_zprp_ms(row.get("data_fakt"))
    if ts is None:
        ts = parse_zprp_ms(row.get("data_prop"))
    dow, hour = local_parts(ts)

    refs: Dict[str, str] = {}
    ref_names: Dict[str, str] = {}
    for role, field in ROLE_FIELD.items():
        judge = clean_ref_id(row.get(field))
        raw_name = js_str(row.get(f"{field}_nazwisko"))
        if judge:
            refs[role] = judge
        if not is_placeholder_name(raw_name):
            ref_names[role] = pretty_person_name(raw_name)

    def js_num0(value: Any) -> float:
        number = num(value)
        return 0 if number is None else number

    ot_h = js_num0(row.get("dogrywka_1_full_gosp")) + js_num0(row.get("dogrywka_2_full_gosp"))
    ot_a = js_num0(row.get("dogrywka_1_full_gosc")) + js_num0(row.get("dogrywka_2_full_gosc"))
    code = js_str(row.get("RozgrywkiCode"))

    slim: Dict[str, Any] = {
        "id": js_str(row.get("Id")),
        "comp": _comp_from_code(code),
        "code": code,
        "ts": ts,
        "tsProp": parse_zprp_ms(row.get("data_prop")),
        "dow": dow,
        "hour": hour,
        "origin": origin,
    }
    if round_name:
        slim["round"] = round_name
    if series:
        slim["series"] = series
    slim.update(
        {
            "refs": refs,
            "refNames": ref_names,
            "homeId": js_str(row.get("ID_zespoly_gosp")),
            "awayId": js_str(row.get("ID_zespoly_gosc")),
            "home": js_str(row.get("ID_zespoly_gosp_ZespolNazwa")),
            "away": js_str(row.get("ID_zespoly_gosc_ZespolNazwa")),
            "homeWoj": js_str(row.get("ID_zespoly_gosp_ZespolNrWoj")),
            "awayWoj": js_str(row.get("ID_zespoly_gosc_ZespolNrWoj")),
            "hall": js_str(row.get("Hala_nazwa")),
            "city": js_str(row.get("Hala_miasto")),
            "gH": num(row.get("wynik_gosp_full")),
            "gA": num(row.get("wynik_gosc_full")),
            "htH": num(row.get("wynik_gosp_pol")),
            "htA": num(row.get("wynik_gosc_pol")),
            "otH": _clean_number(ot_h) if ot_h else None,
            "otA": _clean_number(ot_a) if ot_a else None,
            "psH": num(row.get("dogrywka_karne_gosp")),
            "psA": num(row.get("dogrywka_karne_gosc")),
            "penTakenH": num(row.get("karne_ile_gosp")),
            "penGoalH": num(row.get("karne_bramki_gosp")),
            "penTakenA": num(row.get("karne_ile_gosc")),
            "penGoalA": num(row.get("karne_bramki_gosc")),
            "winner": js_str(row.get("zwyciezca")),
            "draw": js_str(row.get("czy_remis")) == "1",
            "punH": int_or0(row.get("KaryGosp")),
            "punA": int_or0(row.get("KaryGosc")),
            "spect": num(row.get("widzowie")),
            "withdrawn": js_str(row.get("wycofany")) == "1" or bool(js_str(row.get("wycofany_ID_zespoly"))),
            "walkover": bool(js_str(row.get("walkower_ID_zespoly"))),
            "swapped": js_str(row.get("zamiana")) == "1",
            "protoOk": js_str(row.get("protokol_zatwierdz")) == "1",
            "hasComment": bool(js_str(row.get("komentarz"))),
            "hasStream": bool(js_str(row.get("transmisja"))),
        }
    )
    return slim


def details_from_payload(payload: Any) -> Optional[dict]:
    """Odpowiedź `pokaz_mecze_szczegoly.php` -> {match, gosp, gosc, gospOsoby, goscOsoby}.

    Dwa kształty tej samej odpowiedzi: obiekt `{"0": [...], "gosp": ...}` albo
    goła lista `[[{...}]]` dla meczu bez składów.
    """
    if isinstance(payload, list):
        bucket = payload[0] if payload else None
        extra: dict = {}
    elif isinstance(payload, dict):
        bucket = payload.get("0")
        extra = payload
    else:
        return None
    match = bucket[0] if isinstance(bucket, list) and bucket else bucket
    if not isinstance(match, dict):
        return None

    def part(key: str) -> Any:
        value = extra.get(key)
        return value if value is not None else {}

    return {
        "match": match,
        "gosp": part("gosp"),
        "gosc": part("gosc"),
        "gospOsoby": part("gosp_osoby"),
        "goscOsoby": part("gosc_osoby"),
    }


def _players(roster: Any) -> List[dict]:
    if isinstance(roster, dict):
        values = roster.values()
    elif isinstance(roster, list):
        values = roster
    else:
        values = []
    return [player for player in values if isinstance(player, dict)]


def _count(value: Any) -> int:
    if isinstance(value, dict):
        return len(value)
    if isinstance(value, list):
        return len(value)
    return 0


def _age_at(birth: Any, at_ms: Optional[int]) -> Optional[float]:
    born = parse_zprp_ms(f"{birth} 00:00:00") if birth else None
    if born is None or at_ms is None:
        return None
    years = (at_ms - born) / (365.25 * 24 * 3600 * 1000)
    return years if 4 < years < 70 else None


def _agg_side(roster: Any, at_ms: Optional[int]) -> dict:
    players = _players(roster)
    totals = dict(played=0, scorers=0, top=0, warn=0, sus=0, red=0, blu=0, penA=0, penG=0)
    age_sum = 0.0
    age_count = 0
    for player in players:
        goals = int_or0(player.get("bramki"))
        if js_str(player.get("wyjscie")) == "1":
            totals["played"] += 1
        if goals > 0:
            totals["scorers"] += 1
        if goals > totals["top"]:
            totals["top"] = goals
        totals["warn"] += int_or0(player.get("upomnienie"))
        totals["sus"] += int_or0(player.get("2minuty"))
        totals["red"] += int_or0(player.get("dyskwalifikacja"))
        totals["blu"] += int_or0(player.get("kd"))
        totals["penA"] += int_or0(player.get("karne_liczba"))
        totals["penG"] += int_or0(player.get("karne_bramki"))
        age = _age_at(player.get("dataUr"), at_ms)
        if age is not None:
            age_sum += age
            age_count += 1
    totals["n"] = len(players)
    totals["age"] = age_sum / age_count if age_count else None
    return totals


def _round1(value: Optional[float]) -> Optional[float]:
    if value is None:
        return None
    return _clean_number(math.floor(value * 10 + 0.5) / 10)


def extract_details(det: dict, at_ms: Optional[int]) -> dict:
    """Z odpowiedzi szczegółów tylko to, czego używa `enrichWithDetails`.

    Zapisujemy ten wyciąg obok meczu - wtedy mecz, który się nie zmienił, da się
    wzbogacić ponownie bez pytania API.
    """
    match = det.get("match") or {}
    home = _agg_side(det.get("gosp"), at_ms)
    away = _agg_side(det.get("gosc"), at_ms)
    return {
        "at": at_ms,
        "match": {
            key: match.get(key)
            for key in (
                "Kategoria",
                "Plec",
                "Nazwa",
                "NrWZPR",
                "NazwaWZPR",
                "widzowie",
                "Hala_nazwa",
                "Hala_miasto",
                "karne_ile_gosc",
                "karne_ile_gosp",
                "timeout1_gosp",
                "timeout2_gosp",
                "timeout3_gosp",
                "timeout1_gosc",
                "timeout2_gosc",
                "timeout3_gosc",
            )
            if key in match
        },
        "roster": {
            "nH": home["n"],
            "nA": away["n"],
            "playedH": home["played"],
            "playedA": away["played"],
            "scorersH": home["scorers"],
            "scorersA": away["scorers"],
            "topH": home["top"],
            "topA": away["top"],
            "warnH": home["warn"],
            "warnA": away["warn"],
            "susH": home["sus"],
            "susA": away["sus"],
            "redH": home["red"],
            "redA": away["red"],
            "bluH": home["blu"],
            "bluA": away["blu"],
            "penAH": home["penA"],
            "penGH": home["penG"],
            "penAA": away["penA"],
            "penGA": away["penG"],
            "ageH": _round1(home["age"]),
            "ageA": _round1(away["age"]),
            "offH": _count(det.get("gospOsoby")),
            "offA": _count(det.get("goscOsoby")),
        },
    }


def apply_details(slim: dict, extract: dict) -> dict:
    """`enrichWithDetails` na zapisanym wyciągu."""
    match = extract.get("match") or {}
    timeouts = [
        timeout_seconds(match.get(key))
        for key in (
            "timeout1_gosp",
            "timeout2_gosp",
            "timeout3_gosp",
            "timeout1_gosc",
            "timeout2_gosc",
            "timeout3_gosc",
        )
    ]
    out = dict(slim)
    for key in DETAIL_KEYS:
        out.pop(key, None)

    category = js_str(match.get("Kategoria"))
    sex = js_str(match.get("Plec"))
    if category:
        out["cat"] = category
    if sex:
        out["sex"] = sex
    if any(value is not None for value in timeouts):
        out["to"] = timeouts
    out["roster"] = extract.get("roster")

    for key, field in (("compName", "Nazwa"), ("wzpr", "NrWZPR"), ("wzprName", "NazwaWZPR")):
        value = js_str(match.get(field)) or slim.get(key)
        if value:
            out[key] = value

    out["spect"] = slim.get("spect") if slim.get("spect") is not None else num(match.get("widzowie"))
    out["hall"] = slim.get("hall") or js_str(match.get("Hala_nazwa"))
    out["city"] = slim.get("city") or js_str(match.get("Hala_miasto"))
    out["penTakenA"] = (
        slim.get("penTakenA") if slim.get("penTakenA") is not None else num(match.get("karne_ile_gosc"))
    )
    out["penTakenH"] = (
        slim.get("penTakenH") if slim.get("penTakenH") is not None else num(match.get("karne_ile_gosp"))
    )
    return out


def enrich_with_details(slim: dict, det: dict) -> dict:
    return apply_details(slim, extract_details(det, slim.get("ts")))


# ---------------------------------------------------------------------------
# Mecze spoza okręgu
# ---------------------------------------------------------------------------


class OutsideCollector:
    """`collectOutsideCandidates` podawane sędzia po sędzim.

    Serwer pobiera listy sędziów po kolei i od razu je tu wrzuca - trzymanie
    pełnych list ~200 sędziów z kilku sezonów naraz to dziesiątki megabajtów,
    a potrzebny jest tylko pierwszy wiersz każdego meczu i kto go prowadził.
    """

    def __init__(self, known_ids: Iterable[str], officials: Dict[str, dict]):
        self.known = set(known_ids)
        self.officials = officials
        self.out: Dict[str, dict] = {}
        self.skipped = 0

    def add(self, ref_id: str, rows: Iterable[dict]) -> None:
        own = name_key((self.officials.get(ref_id) or {}).get("name") or "")
        for row in rows or []:
            match_id = js_str((row or {}).get("IdZawody"))
            if not re.fullmatch(r"\d+", match_id):
                self.skipped += 1
                continue
            if match_id in self.known:
                continue
            entry = self.out.get(match_id)
            if entry is None:
                entry = {"id": match_id, "row": row, "contributors": {}}
                self.out[match_id] = entry
            if own:
                officials_row = row.get("officials") or {}
                for key, role in ROW_ROLE:
                    if name_key(officials_row.get(key)) == own:
                        entry["contributors"][ref_id] = role
                        break

    def result(self) -> Tuple[List[dict], int]:
        return list(self.out.values()), self.skipped


def collect_outside_candidates(
    by_referee: Iterable[Tuple[str, List[dict]]],
    known_ids: set,
    officials: Dict[str, dict],
) -> Tuple[List[dict], int]:
    """`collectOutsideCandidates`: unikalne mecze z list sędziów, bez własnych."""
    collector = OutsideCollector(known_ids, officials)
    for ref_id, rows in by_referee:
        collector.add(ref_id, rows)
    return collector.result()


def row_to_slim(candidate: dict) -> dict:
    """`rowToSlim`: mecz z listy sędziego, gdy szczegóły są nieosiągalne."""
    row = candidate["row"] or {}
    ts = parse_zprp_ms(row.get("data_fakt"))
    dow, hour = local_parts(ts)

    ref_names: Dict[str, str] = {}
    officials_row = row.get("officials") or {}
    for key, role in ROW_ROLE:
        pretty = pretty_person_name(officials_row.get(key) or "")
        if pretty:
            ref_names[role] = pretty
    refs: Dict[str, str] = {}
    for ref_id, role in candidate["contributors"].items():
        refs[role] = ref_id

    code = js_str(row.get("match_code"))
    result = row.get("result") or {}
    full = result.get("full")
    half = result.get("half")
    shootout = result.get("penalties")
    spect = js_number(((row.get("spectators") or {}).get("count")) or 0)
    teams = row.get("teams") or {}
    venue = ((row.get("hall") or {}).get("venue")) or {}

    def side(score: Any, key: str) -> Any:
        return score.get(key) if isinstance(score, dict) else None

    winner = ""
    if isinstance(full, dict):
        if full.get("host") > full.get("guest"):
            winner = "1"
        elif full.get("guest") > full.get("host"):
            winner = "2"

    return {
        "id": candidate["id"],
        "comp": code[: code.rfind("/")] if "/" in code else code,
        "code": code,
        "ts": ts,
        "tsProp": None,
        "dow": dow,
        "hour": hour,
        "origin": "outside",
        "refs": refs,
        "refNames": ref_names,
        "homeId": "",
        "awayId": "",
        "home": js_str(teams.get("host")),
        "away": js_str(teams.get("guest")),
        "homeWoj": "",
        "awayWoj": "",
        "hall": js_str(venue.get("name")),
        "city": js_str(venue.get("city")),
        "gH": side(full, "host"),
        "gA": side(full, "guest"),
        "htH": side(half, "host"),
        "htA": side(half, "guest"),
        "otH": None,
        "otA": None,
        "psH": side(shootout, "host"),
        "psA": side(shootout, "guest"),
        "penTakenH": None,
        "penGoalH": None,
        "penTakenA": None,
        "penGoalA": None,
        "winner": winner,
        "draw": isinstance(full, dict) and full.get("host") == full.get("guest"),
        "punH": 0,
        "punA": 0,
        "spect": _clean_number(spect) if spect is not None and spect > 0 else None,
        "withdrawn": False,
        "walkover": False,
        "swapped": bool(result.get("host_swapped")),
        "protoOk": False,
        "hasComment": False,
        "hasStream": False,
    }


def details_to_slim(candidate: dict, det: dict) -> dict:
    """`detailsToSlim`: szczegóły wygrywają, wiersz listy tylko uzupełnia."""
    enriched = enrich_with_details(to_slim(det["match"], origin="outside"), det)
    from_row = row_to_slim(candidate)
    return {
        **enriched,
        "id": candidate["id"],
        "hall": enriched.get("hall") or from_row["hall"],
        "city": enriched.get("city") or from_row["city"],
        "spect": enriched.get("spect") if enriched.get("spect") is not None else from_row["spect"],
        "refNames": {**from_row["refNames"], **enriched.get("refNames", {})},
        "refs": {**from_row["refs"], **enriched.get("refs", {})},
    }


# ---------------------------------------------------------------------------
# Kiedy pytać o szczegóły drugi raz
# ---------------------------------------------------------------------------

#: Pola wiersza meczu, których zmiana znaczy „szczegóły są nieaktualne".
_FRESHNESS_KEYS = (
    "ts",
    "gH",
    "gA",
    "htH",
    "htA",
    "psH",
    "psA",
    "refs",
    "protoOk",
    "withdrawn",
    "walkover",
    "home",
    "away",
)


def needs_details(fresh: dict, stored: Optional[dict], stored_extract: Optional[dict], now_ms: int) -> bool:
    """Czy mecz bieżącego sezonu trzeba zapytać o szczegóły ponownie.

    Zamknięty mecz (zatwierdzony protokół, nic się nie zmieniło) ma szczegóły
    na zawsze. Pytamy, gdy: nie mamy wyciągu, zmienił się wynik/obsada/termin,
    albo mecz już się odbył, a protokół czeka - składy i kary jeszcze dochodzą.
    """
    if not stored or not stored_extract:
        return True
    if any(fresh.get(key) != stored.get(key) for key in _FRESHNESS_KEYS):
        return True
    ts = fresh.get("ts")
    if ts is not None and ts <= now_ms and not fresh.get("protoOk"):
        return True
    return False


# ---------------------------------------------------------------------------
# Sezon do wysłania
# ---------------------------------------------------------------------------


def dataset_payload(
    *,
    province: str,
    wzpr_code: str,
    season_id: str,
    season_name: str,
    fetched_at_ms: int,
    competitions: List[dict],
    matches: List[dict],
    counters: dict,
    outside_stage: str,
    outside_scanned: int,
    outside_total: int,
) -> dict:
    """`ProvinceDataset` bez sędziów - listę sędziów ekran dostaje osobno i świeżą."""
    return {
        "schema": CLIENT_SCHEMA,
        "province": province,
        "wzprCode": wzpr_code,
        "seasonId": season_id,
        "seasonName": season_name,
        "fetchedAt": fetched_at_ms,
        "stage": "full",
        "outsideStage": outside_stage,
        "outsideScanned": outside_scanned,
        "outsideTotal": outside_total,
        "competitions": competitions,
        "matches": matches,
        "counters": counters,
    }


def pack(payload: Any) -> Tuple[bytes, str]:
    """JSON -> gzip + ETag. `mtime=0`, żeby ten sam sezon dawał te same bajty."""
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    packed = gzip.compress(raw, compresslevel=6, mtime=0)
    return packed, hashlib.sha1(raw).hexdigest()


# ---------------------------------------------------------------------------
# Harmonogram
# ---------------------------------------------------------------------------


def plan_builds(
    catalog: Dict[str, Any],
    rows: Dict[str, dict],
    *,
    current: int,
    now: datetime,
    max_age: timedelta,
    oldest: int,
    batch: int,
) -> List[Any]:
    """Co budować w tym obiegu: najpierw bieżący sezon, potem zaległe zamknięte.

    Bieżący - gdy go nie ma, jest starszy niż `max_age` albo zbudowany starszym
    schematem. Zamknięte - nigdy niezbudowane albo starszym schematem, od
    najnowszych (to po nie najczęściej sięga porównanie sezonów), po `batch`
    w jednym obiegu, żeby jedna pętla nie trwała godzinami.
    """
    by_start: Dict[int, Any] = {}
    for season in catalog.values():
        if season.id and oldest <= season.start <= current:
            known = by_start.get(season.start)
            if known is None or int(season.id) > int(known.id):
                by_start[season.start] = season

    def outdated(row: Optional[dict]) -> bool:
        return not row or not row.get("built_at") or int(row.get("schema") or 0) < ARCHIVE_SCHEMA

    plan: List[Any] = []
    head = by_start.get(current)
    if head is not None:
        row = rows.get(head.id)
        if outdated(row) or now - row["built_at"] > max_age:
            plan.append(head)
    backlog = [
        by_start[start]
        for start in sorted(by_start, reverse=True)
        if start != current and outdated(rows.get(by_start[start].id))
    ]
    return plan + backlog[: max(0, batch)]
