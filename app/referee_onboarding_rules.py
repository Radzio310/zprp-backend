"""Kreator nowych sędziów na baza.zprp.pl (09.11.2026) - reguły, bez bazy i sieci.

Panel okręgowy BAZA_web (Lista sędziów okręgowych -> „Dodaj nowego sędziego na
baza.zprp.pl") zakłada osoby w ZPRP formularzem `?a=sedzia&b=dodaj`. Ten moduł
wie, jak ten formularz wygląda i jak go wypełnić:

  - `parse_add_page`     - czy konto ma formularz NOWY, kod województwa (ukryte
                           pole `woj`) i lista osób z selecta „Dwójka sędziowska z"
                           (tam ZPRP wypisuje sędziów - używamy jej do duplikatów),
  - `has_new_button`     - czy lista „Sędziowie i Delegaci" ma przycisk NOWY,
  - `normalize_person` / `validate_person` / `build_form` - dane osoby -> pola POST,
  - `match_candidates` / `classify_duplicate` - czy ta osoba już jest w ZPRP,
  - `detect_result`      - co ZPRP odpowiedział po „ZAPISZ".

Strona ZPRP jest w iso-8859-2; kodowanie bajtów robi trasa (`_form_urlencoded_bytes`),
tutaj są same napisy. MODUŁ-LIŚĆ: test w `tests/test_referee_onboarding_rules.py`.
"""

from __future__ import annotations

import datetime as _dt
import re
import unicodedata
from typing import Any, Dict, Iterable, List, Optional

from bs4 import BeautifulSoup

#: Wartość przycisku zapisu w formularzu dodawania.
SAVE_ACTION = "ZAPISZ_NOWY"

ROLE_FIELDS = {"sedzia": "CzySedzia", "delegat": "CzyDelegat", "stolikowy": "CzyStolikowy"}
ROLE_LABELS = {"sedzia": "Sędzia", "delegat": "Delegat", "stolikowy": "Stolikowy"}

#: Statusy duplikatu. Pierwsze dwa blokują zapis (chyba że ktoś świadomie wymusi).
DUP_EXACT = "exact"          # to samo imię, nazwisko i data urodzenia
DUP_PROBABLE = "probable"    # to samo imię i nazwisko, daty nie udało się odczytać
DUP_NAMESAKE = "namesake"    # to samo imię i nazwisko, inna data urodzenia
DUP_SIMILAR = "similar"      # bardzo podobne nazwisko / zamienione imię z nazwiskiem
DUP_NONE = "none"
BLOCKING = frozenset({DUP_EXACT, DUP_PROBABLE})

_PL_FOLD = str.maketrans({"ł": "l", "Ł": "L"})


def s(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value if value is not None else "")).strip()


def fold(value: Any) -> str:
    """Wielkie litery bez ogonków i nadmiarowych spacji - do porównań."""
    text = s(value).translate(_PL_FOLD)
    text = unicodedata.normalize("NFKD", text)
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    return text.upper()


# ---------------------------------------------------------------------------
# Normalizacja osoby
# ---------------------------------------------------------------------------


def _cap_word(word: str) -> str:
    return "-".join(part[:1].upper() + part[1:].lower() for part in word.split("-"))


def cap_name(value: Any) -> str:
    """„anna-maria  KOWAL" -> „Anna-Maria Kowal" (myślnik też dzieli, inaczej niż JS ZPRP)."""
    return " ".join(_cap_word(w) for w in s(value).split(" ") if w)


def upper_name(value: Any) -> str:
    return s(value).upper()


def digits(value: Any) -> str:
    return re.sub(r"\D", "", s(value))


def normalize_phone(value: Any) -> str:
    """ZPRP przyjmuje same cyfry (maks. 12). Polski numer bez prefiksu 48."""
    d = digits(value)
    if d.startswith("0048"):
        d = d[4:]
    elif len(d) == 11 and d.startswith("48"):
        d = d[2:]
    return d[:12]


def normalize_postal(value: Any) -> str:
    d = digits(value)
    if len(d) == 5:
        return f"{d[:2]}-{d[2:]}"
    return s(value)[:6]


def parse_date(value: Any) -> Optional[_dt.date]:
    text = s(value)
    if not text:
        return None
    for fmt in ("%Y-%m-%d", "%d.%m.%Y", "%d-%m-%Y", "%d/%m/%Y", "%Y.%m.%d", "%Y/%m/%d"):
        try:
            return _dt.datetime.strptime(text[:10], fmt).date()
        except ValueError:
            continue
    return None


def normalize_roles(raw: Any) -> List[str]:
    if isinstance(raw, dict):
        raw = [k for k, v in raw.items() if v]
    if isinstance(raw, str):
        raw = [raw]
    out: List[str] = []
    for item in raw or []:
        key = fold(item).lower()
        if key.startswith("sed"):
            key = "sedzia"
        elif key.startswith("del"):
            key = "delegat"
        elif key.startswith("sto"):
            key = "stolikowy"
        if key in ROLE_FIELDS and key not in out:
            out.append(key)
    return out


def normalize_person(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Ujednolicone pola osoby (klucze jak w kreatorze BAZA_web)."""
    gender = fold(raw.get("gender"))[:1]
    birth = parse_date(raw.get("birth_date"))
    return {
        "first_name": cap_name(raw.get("first_name")),
        "middle_name": cap_name(raw.get("middle_name")),
        "last_name": upper_name(raw.get("last_name")),
        "maiden_name": upper_name(raw.get("maiden_name")),
        "gender": gender if gender in ("M", "K") else "",
        "birth_date": birth.isoformat() if birth else "",
        "street": s(raw.get("street")),
        "postal_code": normalize_postal(raw.get("postal_code")),
        "city": cap_name(raw.get("city")),
        "phone": normalize_phone(raw.get("phone")),
        "email": s(raw.get("email")).lower(),
        "roles": normalize_roles(raw.get("roles")) or ["sedzia"],
    }


def validate_person(person: Dict[str, Any], *, today: Optional[_dt.date] = None) -> List[str]:
    """Błędy blokujące zapis - lustro pól wymaganych formularza ZPRP."""
    today = today or _dt.date.today()
    errors: List[str] = []
    if not person.get("first_name"):
        errors.append("Brak imienia.")
    if not person.get("last_name"):
        errors.append("Brak nazwiska.")
    if person.get("gender") not in ("M", "K"):
        errors.append("Brak płci (M/K).")
    birth = parse_date(person.get("birth_date"))
    if not birth:
        errors.append("Brak lub błędna data urodzenia.")
    elif birth >= today or birth.year < 1920:
        errors.append("Data urodzenia spoza zakresu.")
    if not person.get("roles"):
        errors.append("Zaznacz rolę (Sędzia / Delegat / Stolikowy).")
    email = s(person.get("email"))
    if email and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[A-Za-z]{2,}", email):
        errors.append("Błędny adres email.")
    return errors


def build_form(person: Dict[str, Any], woj_code: str) -> Dict[str, str]:
    """Pola POST formularza `?a=sedzia&b=dodaj` (zablokowany select `woj` nie idzie, idzie ukryte pole)."""
    data: Dict[str, str] = {
        "Imie": person.get("first_name", ""),
        "Imie2": person.get("middle_name", ""),
        "Nazwisko": person.get("last_name", ""),
        "NazwiskoRodowe": person.get("maiden_name", ""),
        "Plec": person.get("gender", ""),
        "DataUr": person.get("birth_date", ""),
        "Ulica": person.get("street", ""),
        "KodPocztowy": person.get("postal_code", ""),
        "Miasto": person.get("city", ""),
        "woj": s(woj_code),
        "Telefon": person.get("phone", ""),
        "Email": person.get("email", ""),
    }
    for role in person.get("roles") or []:
        field = ROLE_FIELDS.get(role)
        if field:
            data[field] = "1"
    # Pary nie wskazujemy przy zakładaniu (decyzja właściciela, 09.11.2026).
    data["NrSedzia_para"] = ""
    data["akcja"] = SAVE_ACTION
    return data


def encodable(person: Dict[str, Any], charset: str = "iso-8859-2") -> List[str]:
    """Pola, których nie da się zapisać w kodowaniu ZPRP (np. cyrylica, emoji)."""
    bad = []
    for key, value in person.items():
        if isinstance(value, str):
            try:
                value.encode(charset)
            except UnicodeEncodeError:
                bad.append(key)
    return bad


# ---------------------------------------------------------------------------
# Strony ZPRP
# ---------------------------------------------------------------------------


def _split_option_label(label: str) -> Dict[str, str]:
    """„KOWALCZYK Bartłomiej          L (SZPINDA Michał)" -> nazwisko, imię, partner."""
    text = s(label)
    partner = ""
    m = re.match(r"^(.*?)\s*\((.*)\)\s*$", text)
    if m:
        text, partner = s(m.group(1)), s(m.group(2))
    words = text.split(" ")
    last: List[str] = []
    for word in words:
        letters = re.sub(r"[^A-Za-zÀ-ž]", "", word)
        if letters and letters == letters.upper() and (not last or len(last) < 3):
            last.append(word)
        else:
            break
    if not last or len(last) == len(words):
        # „KONIECZNY SARA" - całe wielkimi literami: pierwsze słowo to nazwisko.
        last = words[:1]
    first = " ".join(words[len(last):])
    return {"last_name": " ".join(last), "first_name": first, "partner": partner}


def parse_add_page(html: str) -> Dict[str, Any]:
    soup = BeautifulSoup(html or "", "html.parser")
    has_form = bool(
        soup.find(["button", "input"], attrs={"name": "akcja", "value": SAVE_ACTION})
    )
    woj_code = ""
    for inp in soup.find_all("input", attrs={"name": "woj"}):
        if (inp.get("type") or "").lower() == "hidden" and s(inp.get("value")):
            woj_code = s(inp.get("value"))
            break
    woj_name = ""
    select = soup.find("select", attrs={"name": "woj"})
    if select:
        for opt in select.find_all("option"):
            if opt.has_attr("selected") or (woj_code and s(opt.get("value")) == woj_code):
                woj_name = s(opt.get_text(" "))
                if opt.has_attr("selected"):
                    break
        if not woj_code:
            chosen = select.find("option", selected=True)
            woj_code = s(chosen.get("value")) if chosen else ""
    options: List[Dict[str, str]] = []
    pair = soup.find("select", attrs={"name": "NrSedzia_para"})
    if pair:
        for opt in pair.find_all("option"):
            nr = s(opt.get("value"))
            label = s(opt.get_text(" "))
            if not nr or not label or label.startswith("---"):
                continue
            options.append({"nr": nr, "label": label, **_split_option_label(label)})
    return {
        "has_form": has_form,
        "woj_code": woj_code,
        "woj_name": woj_name,
        "options": options,
        "values": _form_values(soup),
    }


def _form_values(soup: BeautifulSoup) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for name in ("Imie", "Nazwisko", "DataUr", "NrSedzia"):
        inp = soup.find("input", attrs={"name": name})
        if inp is not None:
            out[name] = s(inp.get("value"))
    return out


def has_new_button(list_html: str) -> bool:
    """Lista „Sędziowie i Delegaci" z przyciskiem NOWY (link `b=dodaj`)."""
    soup = BeautifulSoup(list_html or "", "html.parser")
    for a in soup.find_all("a", href=True):
        href = a["href"]
        if re.search(r"\ba=sedzia\b", href) and re.search(r"\bb=dodaj\b", href):
            return True
    return False


def birth_date_from_edit_page(html: str) -> str:
    soup = BeautifulSoup(html or "", "html.parser")
    inp = soup.find("input", attrs={"name": "DataUr"})
    d = parse_date(inp.get("value")) if inp is not None else None
    return d.isoformat() if d else ""


def page_message(html: str) -> str:
    """Komunikat ZPRP po zapisie: `info_edit`, alert z JS albo czerwony napis."""
    soup = BeautifulSoup(html or "", "html.parser")
    node = soup.find(id="info_edit")
    if node and s(node.get_text(" ")):
        return s(node.get_text(" "))
    for script in soup.find_all("script"):
        m = re.search(r"alert\(\s*['\"](.+?)['\"]\s*\)", script.get_text() or "")
        if m:
            return s(m.group(1))
    for tag in soup.find_all(["font", "span", "div", "b"]):
        style = (tag.get("style") or "").lower().replace(" ", "")
        color = (tag.get("color") or "").lower()
        if ("color:#ff0000" in style or "color:red" in style or color in ("red", "#ff0000")) and tag.get(
            "id"
        ) != "SprawdzSedzia2":
            text = s(tag.get_text(" "))
            if text and "SPRAWDŹ CZY WPIS" not in text:
                return text
    return ""


# ---------------------------------------------------------------------------
# Duplikaty
# ---------------------------------------------------------------------------


def split_full_name(value: Any) -> Dict[str, str]:
    """Nazwa z rejestru BAZA: „KOWALSKI Jan" albo „Jan Kowalski"."""
    words = s(value).split(" ")
    if len(words) < 2:
        return {"first_name": "", "last_name": s(value)}

    def caps(w: str) -> bool:
        letters = re.sub(r"[^A-Za-zÀ-ž]", "", w)
        return len(letters) > 1 and letters == letters.upper()

    if caps(words[0]) and not caps(words[-1]):
        return _split_option_label(" ".join(words))
    if caps(words[-1]) and not caps(words[0]):
        return {"first_name": " ".join(words[:-1]), "last_name": words[-1]}
    return {"first_name": " ".join(words[:-1]), "last_name": words[-1]}


def _first_token(value: Any) -> str:
    return fold(value).split(" ")[0] if fold(value) else ""


def _lev(a: str, b: str, limit: int = 2) -> int:
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def name_relation(person: Dict[str, Any], other: Dict[str, Any]) -> str:
    """'same' | 'similar' | '' dla pary (imię, nazwisko)."""
    pf, pl = _first_token(person.get("first_name")), fold(person.get("last_name"))
    of, ol = _first_token(other.get("first_name")), fold(other.get("last_name"))
    if not pf or not pl or not of or not ol:
        return ""
    if pf == of and pl == ol:
        return "same"
    # Nazwisko dwuczłonowe w jednym miejscu, a w drugim tylko jeden człon.
    if pf == of and (set(pl.replace("-", " ").split()) & set(ol.replace("-", " ").split())) and (
        "-" in pl or "-" in ol or " " in pl or " " in ol
    ):
        return "similar"
    if pf == ol and pl == of:
        return "similar"
    if pf == of and len(pl) >= 4 and _lev(pl, ol, 1) <= 1:
        return "similar"
    if pl == ol and len(pf) >= 4 and _lev(pf, of, 1) <= 1:
        return "similar"
    return ""


def match_candidates(
    person: Dict[str, Any],
    sources: Iterable[Dict[str, Any]],
    *,
    limit: int = 6,
) -> List[Dict[str, Any]]:
    """Osoby z ZPRP podobne do `person`. Każde źródło: nr, first_name, last_name, (label, city, source)."""
    seen: Dict[str, Dict[str, Any]] = {}
    for other in sources:
        nr = s(other.get("nr"))
        rel = name_relation(person, other)
        if not rel or not nr:
            continue
        prev = seen.get(nr)
        if prev and prev["relation"] == "same":
            continue
        seen[nr] = {
            "nr": nr,
            "relation": rel,
            "name": s(other.get("label")) or f"{s(other.get('last_name'))} {s(other.get('first_name'))}",
            "city": s(other.get("city")),
            "source": s(other.get("source")),
            "birth_date": s(other.get("birth_date")),
        }
    items = sorted(seen.values(), key=lambda m: (m["relation"] != "same", m["name"]))
    return items[:limit]


def classify_duplicate(person: Dict[str, Any], matches: List[Dict[str, Any]]) -> str:
    birth = s(person.get("birth_date"))
    status = DUP_NONE
    for m in matches:
        if m["relation"] == "same":
            other_birth = s(m.get("birth_date"))
            if other_birth and birth and other_birth == birth:
                return DUP_EXACT
            if not other_birth:
                status = DUP_PROBABLE
            elif status not in (DUP_PROBABLE,):
                status = DUP_NAMESAKE
        elif status == DUP_NONE:
            status = DUP_SIMILAR
    return status


# ---------------------------------------------------------------------------
# Wynik zapisu
# ---------------------------------------------------------------------------


def detect_result(
    person: Dict[str, Any],
    html_after: str,
    options_before: List[Dict[str, Any]],
    options_after: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Status po POST: created (z numerem), error (formularz wrócił z danymi) albo unconfirmed."""
    soup = BeautifulSoup(html_after or "", "html.parser")
    values = _form_values(soup)
    message = page_message(html_after)
    same_person = fold(values.get("Imie")) == fold(person.get("first_name")) and fold(
        values.get("Nazwisko")
    ) == fold(person.get("last_name"))

    # 1) ZPRP pokazał od razu kartę edycji nowej osoby.
    if values.get("NrSedzia") and same_person:
        return {"status": "created", "nr": values["NrSedzia"], "message": message}

    # 2) Nowa pozycja na liście osób, której wcześniej nie było.
    if options_after is not None:
        before = {s(o.get("nr")) for o in options_before}
        fresh = [
            o
            for o in options_after
            if s(o.get("nr")) not in before and name_relation(person, o) == "same"
        ]
        if fresh:
            nr = max(fresh, key=lambda o: int(digits(o.get("nr")) or 0))["nr"]
            return {"status": "created", "nr": nr, "message": message}

    # 3) Formularz dodawania wrócił z wpisanymi danymi = ZPRP nie przyjął zapisu.
    still_form = bool(soup.find(["button", "input"], attrs={"name": "akcja", "value": SAVE_ACTION}))
    if still_form and same_person:
        return {
            "status": "error",
            "nr": "",
            "message": message or "ZPRP nie przyjął zapisu - formularz wrócił z danymi.",
        }

    # 4) Link do edycji tej osoby na stronie wyniku (np. lista z komunikatem).
    for a in soup.find_all("a", href=True):
        m = re.search(r"b=edycja&(?:amp;)?NrSedzia=(\d+)", a["href"])
        if m and name_relation(person, _split_option_label(s(a.get_text(" ")))) == "same":
            return {"status": "created", "nr": m.group(1), "message": message}

    return {
        "status": "unconfirmed",
        "nr": "",
        "message": message
        or "ZPRP przyjął formularz, ale nie pokazał numeru nowej osoby. Sprawdź listę na baza.zprp.pl.",
    }
