"""
Formularze okręgowe - bloki informacyjne nad i pod formularzem (§17), bez bazy i bez sieci.

Kontrakt: `docs/formularze-okregowe.md` §17. Bloki niosą tylko treść: tekst, ramkę,
licznik do terminu, dane do przelewu, pola do skopiowania, miejsce, kontakty, linki.

  - `clean_info` czyści wejście kreatora: przycina teksty, pomija nieznane typy, sprawdza
    NRB (suma kontrolna IBAN PL), odwołania do kolumn `confirm` i linki (tylko https).
    Błędy zbiera per blok: 400 `bad_info` z `errors: {blockId: zdanie}`,
  - `resolve_info` dokłada do odpowiedzi `resolved_at` (licznik) i `resolved_amount` (przelew),
  - `public_info` przy wyłączonym webie zostawia tylko `countdown` i `text`.
"""

from __future__ import annotations

import copy
import math
import re
from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from app.district_forms_rules import FormError, columns_of, iso, parse_iso

ZONES = ("above", "below")
BLOCK_TYPES = ("text", "callout", "countdown", "payment", "copy", "place", "contact", "links")
CALLOUT_TONES = ("info", "warning", "success", "danger")
COUNTDOWN_TARGETS = ("deadline", "event", "date")
ZONE_MAX = 12
TITLE_MAX = 80
TEXT_MAX = 3000
CALLOUT_MAX = 600
DONE_LABEL_MAX = 60
RECIPIENT_MAX = 70
TRANSFER_TITLE_MAX = 140
ADDRESS_MAX = 140
NOTE_MAX = 300
COPY_ITEMS = (1, 10)
COPY_VALUE_MAX = 300
LABEL_MAX = 60
PLACE_NAME_MAX = 120
PLACE_ADDRESS_MAX = 200
PEOPLE = (1, 6)
PERSON_NAME_MAX = 80
ROLE_MAX = 60
LINKS = (1, 6)
URL_MAX = 500
AMOUNT_MAX = 1_000_000
#: Symbole w tytule przelewu (klient podstawia dane oglądającego).
TRANSFER_SYMBOLS = ("{imie_nazwisko}", "{imie}", "{nazwisko}", "{numer_sedziego}")

BLOCK_ID = re.compile(r"^[A-Za-z0-9_-]{1,24}$")
_EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]{2,}$")
_PHONE = re.compile(r"^\+?[\d\s\-()]{7,20}$")

EMPTY_INFO: Dict[str, List[Any]] = {"above": [], "below": []}


class _Bad(ValueError):
    pass


def _s(value: Any) -> str:
    return str(value if value is not None else "").strip()


def _text(raw: Mapping[str, Any], key: str, limit: int, *, required: bool = False, what: str = "") -> Optional[str]:
    value = raw.get(key)
    text = str(value if value is not None else "").strip()
    if not text:
        if required:
            raise _Bad(f"Uzupełnij pole „{what or key}”.")
        return None
    if len(text) > limit:
        raise _Bad(f"„{what or key}” ma najwyżej {limit} znaków.")
    return text


def _number(value: Any, what: str) -> Optional[float]:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise _Bad(f"{what}: to musi być liczba.")
    try:
        number = float(str(value).replace(",", "."))
    except (TypeError, ValueError) as error:
        raise _Bad(f"{what}: to musi być liczba.") from error
    if not math.isfinite(number):
        raise _Bad(f"{what}: to musi być liczba.")
    return int(number) if int(number) == number else number


# ---------------------------------------------------------------------------
# Konto bankowe
# ---------------------------------------------------------------------------


def normalize_nrb(value: Any) -> str:
    """Cyfry numeru konta bez spacji i bez prefiksu PL."""
    text = re.sub(r"[\s-]", "", _s(value)).upper()
    if text.startswith("PL"):
        text = text[2:]
    return text


def nrb_valid(value: Any) -> bool:
    """NRB: 26 cyfr i suma kontrolna IBAN (PL + przestawienie, mod 97 == 1)."""
    digits = normalize_nrb(value)
    if not re.fullmatch(r"\d{26}", digits):
        return False
    rearranged = digits[2:] + "2521" + digits[:2]  # P=25, L=21
    return int(rearranged) % 97 == 1


def format_nrb(digits: str) -> str:
    """`12 3456 7890 ...` - do eksportu i podglądu."""
    clean = normalize_nrb(digits)
    if len(clean) != 26:
        return clean
    return clean[:2] + " " + " ".join(clean[i : i + 4] for i in range(2, 26, 4))


# ---------------------------------------------------------------------------
# Bloki
# ---------------------------------------------------------------------------


def _confirm_column(columns: Sequence[Mapping[str, Any]], cid: Any, what: str) -> Optional[str]:
    column_id = _s(cid)
    if not column_id:
        return None
    for column in columns:
        if column.get("id") == column_id:
            if column.get("type") != "confirm":
                raise _Bad(f"{what}: wskazana kolumna nie jest kolumną potwierdzenia wpłaty.")
            return column_id
    raise _Bad(f"{what}: takiej kolumny nie ma na liście.")


def _items(raw: Any, limits: Tuple[int, int], what: str) -> List[Mapping[str, Any]]:
    items = [x for x in raw or [] if isinstance(x, Mapping)] if isinstance(raw, list) else []
    low, high = limits
    if not low <= len(items) <= high:
        raise _Bad(f"{what}: od {low} do {high} pozycji.")
    return items


def _item_id(raw: Mapping[str, Any], index: int, prefix: str, seen: set) -> str:
    iid = _s(raw.get("id"))
    if not BLOCK_ID.match(iid) or iid in seen:
        iid = f"{prefix}{index + 1}"
        while iid in seen:
            iid += "x"
    seen.add(iid)
    return iid


def _clean_block(raw: Mapping[str, Any], *, columns: Sequence[Mapping[str, Any]], has_event: bool) -> Dict[str, Any]:
    btype = _s(raw.get("type"))
    out: Dict[str, Any] = {"type": btype}
    title = _text(raw, "title", TITLE_MAX, what="Tytuł")
    if title:
        out["title"] = title
    if btype == "text":
        out["body"] = _text(raw, "body", TEXT_MAX, required=True, what="Treść")
    elif btype == "callout":
        tone = _s(raw.get("tone")) or "info"
        if tone not in CALLOUT_TONES:
            raise _Bad("Nieznany kolor ramki.")
        out["tone"] = tone
        out["body"] = _text(raw, "body", CALLOUT_MAX, required=True, what="Treść")
    elif btype == "countdown":
        target = _s(raw.get("target")) or "deadline"
        if target not in COUNTDOWN_TARGETS:
            raise _Bad("Licznik odlicza do terminu formularza, do wydarzenia albo do wybranej daty.")
        if target == "event" and not has_event:
            raise _Bad("Licznik do wydarzenia wymaga spięcia formularza z wydarzeniem.")
        out["target"] = target
        if target == "date":
            try:
                when = parse_iso(raw.get("date"))
            except FormError as error:
                raise _Bad("Licznik: niepoprawna data.") from error
            if when is None:
                raise _Bad("Licznik: wybierz datę.")
            out["date"] = when.isoformat()
        done = _text(raw, "done_label", DONE_LABEL_MAX, what="Napis po czasie")
        if done:
            out["done_label"] = done
        out["show_date"] = raw.get("show_date") is not False
    elif btype == "payment":
        out["recipient"] = _text(raw, "recipient", RECIPIENT_MAX, required=True, what="Odbiorca")
        if not _s(raw.get("account")):
            raise _Bad("Wpisz numer konta.")
        if not nrb_valid(raw.get("account")):
            raise _Bad("Numer konta jest niepoprawny - sprawdź 26 cyfr.")
        out["account"] = normalize_nrb(raw.get("account"))
        out["transfer_title"] = _text(raw, "transfer_title", TRANSFER_TITLE_MAX, required=True, what="Tytuł przelewu")
        amount = _number(raw.get("amount"), "Kwota")
        if amount is not None and not 0 <= amount <= AMOUNT_MAX:
            raise _Bad(f"Kwota od 0 do {AMOUNT_MAX} zł.")
        out["amount"] = round(amount, 2) if isinstance(amount, float) else amount
        out["amount_column"] = _confirm_column(columns, raw.get("amount_column"), "Kwota z kolumny")
        out["confirm_column"] = _confirm_column(columns, raw.get("confirm_column"), "Stan wpłaty")
        address = _text(raw, "address", ADDRESS_MAX, what="Adres")
        if address:
            out["address"] = address
        out["bank_qr"] = raw.get("bank_qr") is not False
        note = _text(raw, "note", NOTE_MAX, what="Uwaga")
        if note:
            out["note"] = note
    elif btype == "copy":
        seen: set = set()
        items = []
        for index, item in enumerate(_items(raw.get("items"), COPY_ITEMS, "Pola do skopiowania")):
            items.append(
                {
                    "id": _item_id(item, index, "c", seen),
                    "label": _text(item, "label", LABEL_MAX, required=True, what="Etykieta"),
                    "value": _text(item, "value", COPY_VALUE_MAX, required=True, what="Wartość"),
                    "mono": bool(item.get("mono")),
                }
            )
        out["items"] = items
    elif btype == "place":
        out["name"] = _text(raw, "name", PLACE_NAME_MAX, required=True, what="Nazwa miejsca")
        address = _text(raw, "address", PLACE_ADDRESS_MAX, what="Adres")
        if address:
            out["address"] = address
        lat, lon = _number(raw.get("lat"), "Szerokość"), _number(raw.get("lon"), "Długość")
        if (lat is None) != (lon is None):
            raise _Bad("Pinezka miejsca potrzebuje obu współrzędnych.")
        if lat is not None:
            if not (-90 <= lat <= 90 and -180 <= lon <= 180):
                raise _Bad("Pinezka miejsca ma złe współrzędne.")
            out["lat"], out["lon"] = round(float(lat), 6), round(float(lon), 6)
        note = _text(raw, "note", NOTE_MAX, what="Uwaga")
        if note:
            out["note"] = note
    elif btype == "contact":
        seen = set()
        people = []
        for index, person in enumerate(_items(raw.get("people"), PEOPLE, "Kontakty")):
            entry: Dict[str, Any] = {
                "id": _item_id(person, index, "p", seen),
                "name": _text(person, "name", PERSON_NAME_MAX, required=True, what="Imię i nazwisko"),
            }
            role = _text(person, "role", ROLE_MAX, what="Rola")
            if role:
                entry["role"] = role
            phone = _s(person.get("phone"))
            if phone:
                if not _PHONE.match(phone) or len(re.sub(r"\D", "", phone)) < 7:
                    raise _Bad(f"Telefon „{phone}” wygląda na niepoprawny.")
                entry["phone"] = phone
            email = _s(person.get("email"))
            if email:
                if not _EMAIL.match(email) or len(email) > 120:
                    raise _Bad(f"Adres „{email}” nie wygląda na e-mail.")
                entry["email"] = email
            people.append(entry)
        out["people"] = people
    elif btype == "links":
        seen = set()
        links = []
        for index, item in enumerate(_items(raw.get("items"), LINKS, "Linki")):
            url = _s(item.get("url"))
            if not url.lower().startswith("https://") or len(url) > URL_MAX or re.search(r"\s", url) or len(url) <= 8:
                raise _Bad("Link musi zaczynać się od https:// (bez spacji).")
            links.append(
                {
                    "id": _item_id(item, index, "l", seen),
                    "label": _text(item, "label", LABEL_MAX, required=True, what="Nazwa linku"),
                    "url": url,
                }
            )
        out["items"] = links
    return out


def clean_info(raw: Any, schema: Any = None, *, has_event: bool = False) -> Dict[str, List[Dict[str, Any]]]:
    """Bloki z kreatora. Nieznane typy odpadają po cichu, zła treść = 400 `bad_info` (wszystkie błędy naraz)."""
    if raw in (None, "", {}):
        return copy.deepcopy(EMPTY_INFO)
    if not isinstance(raw, Mapping):
        raise FormError("bad_info", "Bloki informacyjne mają zły kształt.", 400, errors={})
    columns = columns_of(schema) if isinstance(schema, Mapping) else []
    out: Dict[str, List[Dict[str, Any]]] = {"above": [], "below": []}
    errors: Dict[str, str] = {}
    seen: set = set()
    counter = 0
    for zone in ZONES:
        blocks = raw.get(zone)
        if blocks is None:
            continue
        if not isinstance(blocks, list):
            raise FormError("bad_info", "Bloki informacyjne mają zły kształt.", 400, errors={})
        known = [b for b in blocks if isinstance(b, Mapping) and _s(b.get("type")) in BLOCK_TYPES]
        if len(known) > ZONE_MAX:
            raise FormError("bad_info", f"W jednej strefie mieści się najwyżej {ZONE_MAX} bloków.", 400, errors={})
        for block in known:
            counter += 1
            bid = _s(block.get("id"))
            if not BLOCK_ID.match(bid) or bid in seen:
                bid = f"b{counter}"
                while bid in seen:
                    bid += "x"
            seen.add(bid)
            try:
                out[zone].append({"id": bid, **_clean_block(block, columns=columns, has_event=has_event)})
            except _Bad as error:
                errors[bid] = str(error)
    if errors:
        first = next(iter(errors.values()))
        raise FormError("bad_info", f"Popraw bloki informacyjne. {first}", 400, errors=errors)
    return out


def stored_info(raw: Any) -> Dict[str, List[Dict[str, Any]]]:
    """Info z bazy (już sprawdzone) w pełnym kształcie - stare wiersze mają NULL."""
    data = raw if isinstance(raw, Mapping) else {}
    return {zone: [dict(b) for b in data.get(zone) or [] if isinstance(b, Mapping)] for zone in ZONES}


# ---------------------------------------------------------------------------
# Odpowiedzi
# ---------------------------------------------------------------------------


def _column_amount(columns: Sequence[Mapping[str, Any]], cid: Any) -> Optional[float]:
    for column in columns:
        if column.get("id") == cid and column.get("type") == "confirm":
            return column.get("amount")
    return None


def resolve_info(
    info: Any,
    *,
    closes_at: Any = None,
    event_start: Any = None,
    schema: Any = None,
) -> Dict[str, List[Dict[str, Any]]]:
    """Kopia bloków z `resolved_at` (licznik) i `resolved_amount` (przelew)."""
    columns = columns_of(schema) if isinstance(schema, Mapping) else []
    out = stored_info(info)
    for zone in ZONES:
        for block in out[zone]:
            if block.get("type") == "countdown":
                target = block.get("target")
                if target == "deadline":
                    block["resolved_at"] = iso(closes_at) if isinstance(closes_at, datetime) else _iso_text(closes_at)
                elif target == "event":
                    block["resolved_at"] = iso(event_start) if isinstance(event_start, datetime) else _iso_text(event_start)
                else:
                    block["resolved_at"] = _iso_text(block.get("date"))
            elif block.get("type") == "payment":
                amount = block.get("amount")
                if amount is None and block.get("amount_column"):
                    amount = _column_amount(columns, block.get("amount_column"))
                block["resolved_amount"] = amount
    return out


def _iso_text(value: Any) -> Optional[str]:
    try:
        moment = parse_iso(value)
    except FormError:
        return None
    return moment.isoformat() if moment else None


def public_info(info: Mapping[str, Any], *, web_enabled: bool) -> Dict[str, List[Dict[str, Any]]]:
    """Strona przy wyłączonym webie (karta „tylko w aplikacji") pokazuje tylko licznik i tekst."""
    data = stored_info(info)
    if web_enabled:
        return data
    return {zone: [b for b in data[zone] if b.get("type") in ("countdown", "text")] for zone in ZONES}


def first_countdown(info: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    data = stored_info(info)
    for zone in ZONES:
        for block in data[zone]:
            if block.get("type") == "countdown":
                return block
    return None


def first_payment(info: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    data = stored_info(info)
    for zone in ZONES:
        for block in data[zone]:
            if block.get("type") == "payment":
                return block
    return None


def info_changed(before: Any, after: Any) -> bool:
    return stored_info(before) != stored_info(after)


def adapt_template_info(info: Any, *, has_event: bool, template_title: str, form_title: str) -> Dict[str, Any]:
    """Bloki szablonu użyte bez kreatora: licznik do wydarzenia bez wydarzenia liczy do terminu,
    tytuł przelewu bierze tytuł formularza, a puste bloki do uzupełnienia (konto, kontakty,
    miejsce) odpadają - inaczej utworzenie formularza z samego szablonu kończyłoby się 400."""
    data = stored_info(info)
    out: Dict[str, List[Dict[str, Any]]] = {"above": [], "below": []}
    for zone in ZONES:
        for block in data[zone]:
            block = dict(block)
            btype = block.get("type")
            if btype == "countdown" and block.get("target") == "event" and not has_event:
                block["target"] = "deadline"
            if btype == "payment":
                title = _s(block.get("transfer_title"))
                if template_title and title.startswith(template_title):
                    block["transfer_title"] = (form_title + title[len(template_title):])[:TRANSFER_TITLE_MAX]
                if not _s(block.get("account")) or not _s(block.get("recipient")):
                    continue
            if btype == "contact" and not block.get("people"):
                continue
            if btype == "place" and not _s(block.get("name")):
                continue
            out[zone].append(block)
    return out


# ---------------------------------------------------------------------------
# Kto ogląda
# ---------------------------------------------------------------------------


def split_full_name(full_name: Any) -> Tuple[str, str]:
    """(imię, nazwisko) z `province_judges.full_name`.

    Zapis ZPRP ma nazwisko WERSALIKAMI („NOWAK Jan", „Jan NOWAK") - wtedy kolejność jest
    pewna. Bez tego znaku kolejność jest niejasna: imię puste, całość jako nazwisko.
    """
    text = re.sub(r"\s+", " ", _s(full_name))
    if not text:
        return "", ""
    parts = text.split(" ")
    upper = [p for p in parts if len(p.strip(".-")) > 1 and p.isupper()]
    rest = [p for p in parts if p not in upper]
    if upper and rest:
        return " ".join(rest), " ".join(upper)
    return "", text


def viewer_info(judge_id: str, full_name: Any) -> Dict[str, str]:
    first, last = split_full_name(full_name)
    name = re.sub(r"\s+", " ", _s(full_name)) or judge_id
    return {"judge_id": judge_id, "name": name, "first_name": first, "last_name": last or name}
