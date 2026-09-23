"""
Odczyt faktury z tekstu PDF - czyste reguły, bez bazy i bez sieci.

Faktury za obsługę sędziowską wystawia okręg (program SaldeoSMART i podobne),
a panel klubów zamienia je na WPŁATY klubów. Najpierw próbujemy regułami, bo
są darmowe, szybkie i przewidywalne; model językowy wchodzi dopiero wtedy, gdy
reguły nie znajdą kwoty albo nabywcy (patrz `invoice_ai`).

Pułapki tekstu z PDF (por. pamięć „Pułapki PDF-ów ZPRP"):
  - kwoty mają separator tysięcy jako spację, twardą spację (U+00A0) albo
    wąską twardą spację (U+202F): „3 000,00",
  - dwie kolumny (Sprzedawca | Nabywca) potrafią się przepleść w jednej
    linii - wtedy NIP-y bierzemy po kolei (lewa kolumna = sprzedawca),
  - SaldeoSMART pisze datę PRZED etykietą („15-06-2026 data wystawienia"),
    inne programy PO niej („Data wystawienia: 2026-06-15").

Wynik `parse_invoice_text` to zwykły słownik, który trafia prosto do JSON-a
pozycji partii - te same klucze zwraca awaryjny odczyt przez AI.
"""

from __future__ import annotations

import re
import unicodedata
from datetime import date
from typing import Any, Optional

#: Pola, bez których faktury nie da się zamienić na wpłatę.
REQUIRED_FIELDS = ("gross", "buyer")

_SPACES = "\u00a0\u202f\u2007\u2009\u200a"

_DATE = r"(\d{4}-\d{2}-\d{2}|\d{1,2}[.\-/]\d{1,2}[.\-/]\d{4})"
#: Kwota z opcjonalnym separatorem tysięcy (spacja albo kropka) i groszami.
_AMOUNT = r"(-?\d{1,3}(?:[ .]\d{3})+(?:,\d{1,2})?|-?\d+(?:[.,]\d{1,2})?)"

#: Etykiety, na których kończy się blok nabywcy.
_BUYER_END = (
    r"Odbiorca|Płatnik|Sposób zapłaty|Forma płatności|Metoda płatności|Termin płatności|"
    r"Lp\.|Nazwa towaru|Numer konta|Nr konta|Bank|Uwagi|Sprzedawca"
)
#: Etykiety, na których kończy się sama NAZWA w bloku strony.
_NAME_END = r"Adres|NIP|ul\.|REGON|KRS|PESEL|Tel\.|tel\.|e-mail|Email|Kod pocztowy"


#: Etykieta kończy się na nie-literze („Adres:", „Lp. ") - „Bank" nie łapie „Bankowy".
_NOT_LETTER = r"(?![A-Za-zĄĆĘŁŃÓŚŹŻąćęłńóśźż])"


def _s(value: Any) -> str:
    return str(value if value is not None else "").strip()


def clean_text(text: Any) -> str:
    """Twarde spacje na zwykłe, a odstępy wewnątrz linii zwinięte do jednego."""
    raw = _s(text)
    for ch in _SPACES:
        raw = raw.replace(ch, " ")
    lines = [" ".join(line.split()) for line in raw.replace("\r", "\n").split("\n")]
    return "\n".join(line for line in lines if line)


def flat(text: Any) -> str:
    """Cały tekst w jednej linii - wygodne dla reguł obejmujących kilka linii."""
    return " ".join(clean_text(text).split())


def parse_amount(raw: Any) -> Optional[float]:
    """„3 000,00", „3.000,00", „3000.00", „3 000" - na liczbę; śmieci na None."""
    text = _s(raw)
    for ch in _SPACES:
        text = text.replace(ch, " ")
    text = text.replace("PLN", "").replace("zł", "").replace("zl", "").strip()
    if not text:
        return None
    negative = text.startswith("-")
    text = text.lstrip("-").strip()
    if "," in text:
        # Polski zapis: przecinek to grosze, kropka i spacja to tysiące.
        whole, _, cents = text.rpartition(",")
        whole = whole.replace(" ", "").replace(".", "")
        text = f"{whole}.{cents}"
    else:
        parts = text.replace(" ", "")
        # „3.000" to trzy tysiące, „30.50" to grosze.
        if re.fullmatch(r"\d{1,3}(?:\.\d{3})+", parts):
            parts = parts.replace(".", "")
        text = parts
    try:
        value = round(float(text), 2)
    except ValueError:
        return None
    return -value if negative else value


def parse_date(raw: Any) -> Optional[date]:
    """„15-06-2026", „15.06.2026", „2026-06-15" - na datę; zła data na None."""
    text = _s(raw)
    match = re.fullmatch(r"(\d{4})-(\d{2})-(\d{2})", text)
    try:
        if match:
            return date(int(match.group(1)), int(match.group(2)), int(match.group(3)))
        match = re.fullmatch(r"(\d{1,2})[.\-/](\d{1,2})[.\-/](\d{4})", text)
        if match:
            return date(int(match.group(3)), int(match.group(2)), int(match.group(1)))
    except ValueError:
        return None
    return None


def normalize_nip(raw: Any) -> str:
    """Same cyfry NIP-u (bez „PL", kresek i spacji); 10 cyfr albo pusto."""
    digits = re.sub(r"\D", "", _s(raw))
    return digits if len(digits) == 10 else ""


def nip_is_valid(nip: Any) -> bool:
    """Suma kontrolna NIP-u - odsiewa numer konta albo telefon wzięty za NIP."""
    digits = normalize_nip(nip)
    if not digits:
        return False
    weights = (6, 5, 7, 2, 3, 4, 5, 6, 7)
    total = sum(int(d) * w for d, w in zip(digits[:9], weights))
    return total % 11 == int(digits[9])


def invoice_key(invoice_no: Any, seller_nip: Any) -> str:
    """Klucz duplikatu: numer faktury (bez spacji, wielkie litery) + NIP sprzedawcy."""
    number = re.sub(r"\s+", "", _s(invoice_no)).upper()
    if not number:
        return ""
    return f"{normalize_nip(seller_nip)}|{number}"


def _first(pattern: str, text: str, flags: int = re.IGNORECASE) -> Optional[re.Match]:
    return re.search(pattern, text, flags)


def _find_date(text: str, label: str) -> Optional[date]:
    """Data przy etykiecie: najpierw „Etykieta: DATA", potem „DATA etykieta", na koniec „Etykieta DATA"."""
    for pattern in (
        rf"{label}\s*:\s*(?:[A-Za-zĄĆĘŁŃÓŚŹŻąćęłńóśźż \-]+,\s*)?{_DATE}",
        rf"{_DATE}\s*{label}",
        rf"{label}\s*{_DATE}",
    ):
        match = _first(pattern, text)
        if match:
            found = parse_date(match.group(1))
            if found:
                return found
    return None


def _find_amount(text: str, labels: tuple[str, ...]) -> Optional[float]:
    for label in labels:
        match = _first(rf"{label}\s*:?\s*{_AMOUNT}\s*(?:PLN|zł|zl)?", text)
        if match:
            value = parse_amount(match.group(1))
            if value is not None:
                return value
    return None


def _party(text: str, label: str, end: str) -> tuple[str, str]:
    """(nazwa, NIP) z bloku strony: od etykiety do następnej etykiety."""
    match = _first(rf"{label}\s*:?\s*(.*?)(?=\s(?:{end}){_NOT_LETTER}|$)", text, re.IGNORECASE | re.DOTALL)
    if not match:
        return "", ""
    block = match.group(1)
    name_match = re.match(rf"\s*(.*?)(?=(?:^|\s)(?:{_NAME_END}){_NOT_LETTER}|$)", block, re.DOTALL)
    name = " ".join((name_match.group(1) if name_match else "").split()).strip(" :,;")
    nip_match = re.search(r"NIP\s*:?\s*(?:PL)?\s*([\d][\d \-]{8,14}\d)", block, re.IGNORECASE)
    nip = normalize_nip(nip_match.group(1)) if nip_match else ""
    return name, nip


def _all_nips(text: str) -> list[str]:
    out: list[str] = []
    for match in re.finditer(r"NIP\s*:?\s*(?:PL)?\s*([\d][\d \-]{8,14}\d)", text, re.IGNORECASE):
        nip = normalize_nip(match.group(1))
        if nip and nip not in out:
            out.append(nip)
    return out


_UNITS = r"szt\.?|usł\.?|usł|kpl\.?|godz\.?|h|m-c|mies\.?|mc|ryczałt|x|op\.?|km|dzień|dni"


def _items(text: str) -> list[dict]:
    """Pozycje faktury: „1 Obsługa sędziowska zawodów 1.0 szt. 3 000,00 ..."."""
    start = _first(r"Lp\.?", text)
    if not start:
        return []
    region = text[start.end():]
    stop = _first(r"\b(?:Razem do zapłaty|Do zapłaty|Razem\s*:|Razem\b|Sposób zapłaty|Uwagi)", region)
    if stop:
        region = region[: stop.start()]
    row = re.compile(
        rf"(?:^|\s)(\d{{1,3}})\s+([^\d\s][^\n]*?)\s+(\d+(?:[.,]\d+)?)\s*({_UNITS})(?=\s)",
        re.IGNORECASE,
    )
    found = list(row.finditer(region))
    items: list[dict] = []
    for index, match in enumerate(found):
        # Nagłówek tabeli („Nazwa towaru/usługi Ilość J.m. ...") to nie pozycja.
        name = " ".join(match.group(2).split())
        if re.search(r"Nazwa towaru|Ilość|J\.m\.", name, re.IGNORECASE):
            continue
        tail_end = found[index + 1].start() if index + 1 < len(found) else len(region)
        tail = region[match.end(): tail_end]
        amounts = [parse_amount(item) for item in re.findall(_AMOUNT, tail)]
        amounts = [value for value in amounts if value is not None]
        items.append({
            "name": name,
            "quantity": parse_amount(match.group(3)),
            "unit": match.group(4),
            # Ostatnia kwota wiersza to wartość brutto (kolejność kolumn polskich faktur).
            "gross": amounts[-1] if amounts else None,
        })
    return items


def parse_invoice_text(text: Any) -> dict:
    """
    Pola faktury z tekstu. Brakujące pole = None albo pusty napis - nic tu nie
    zgadujemy. `missing` mówi, czego zabrakło do utworzenia wpłaty.
    """
    one = flat(text)
    out: dict[str, Any] = {
        "invoice_no": "",
        "issue_date": None,
        "sale_date": None,
        "due_date": None,
        "seller_name": "",
        "seller_nip": "",
        "buyer_name": "",
        "buyer_nip": "",
        "gross": None,
        "paid": None,
        "remaining": None,
        "currency": "PLN",
        "items": [],
    }

    number = _first(
        r"Faktura(?:\s+VAT)?(?:\s+korygująca)?(?:\s+(?:Nr|numer|nr\.?))\s*:?\s*([A-Za-z0-9][A-Za-z0-9/\-_.]*[A-Za-z0-9])",
        one,
    )
    if number:
        out["invoice_no"] = number.group(1)

    issue = _find_date(one, r"data wystawienia")
    sale = _find_date(one, r"data (?:dostawy/wykonania usługi|sprzedaży|dostawy|wykonania usługi)")
    due = _find_date(one, r"termin (?:płatności|zapłaty)")
    out["issue_date"] = issue.isoformat() if issue else None
    out["sale_date"] = sale.isoformat() if sale else None
    out["due_date"] = due.isoformat() if due else None

    seller_name, seller_nip = _party(one, r"Sprzedawca", r"Nabywca|Odbiorca|Sposób zapłaty|Lp\.")
    buyer_name, buyer_nip = _party(one, r"Nabywca", _BUYER_END)
    nips = _all_nips(one)
    # Kolumny przeplecione („Sprzedawca: Nabywca: ..."): nazwy nie ma, a NIP-y
    # idą po kolei - pierwszy jest ze strony sprzedawcy.
    if not seller_nip and nips:
        seller_nip = nips[0]
    if not buyer_nip:
        rest = [nip for nip in nips if nip != seller_nip]
        buyer_nip = rest[0] if rest else ""
    if buyer_nip == seller_nip:
        rest = [nip for nip in nips if nip != seller_nip]
        buyer_nip = rest[0] if rest else ""
    out["seller_name"] = seller_name
    out["seller_nip"] = seller_nip
    out["buyer_name"] = buyer_name
    out["buyer_nip"] = buyer_nip

    out["gross"] = _find_amount(
        one,
        (
            r"Razem do zapłaty",
            r"Kwota do zapłaty",
            r"Do zapłaty",
            r"Razem brutto",
            r"Wartość brutto razem",
            r"Suma brutto",
        ),
    )
    out["paid"] = _find_amount(one, (r"Zapłacono",))
    out["remaining"] = _find_amount(one, (r"Pozostało do zapłaty",))
    currency = _first(r"Razem do zapłaty\s*:?\s*" + _AMOUNT + r"\s*(PLN|EUR|zł)", one)
    if currency:
        out["currency"] = "PLN" if currency.group(2).lower() == "zł" else currency.group(2).upper()

    out["items"] = _items(one)
    # Brak sumy, a jest jedna pozycja z kwotą - to jest suma.
    if out["gross"] is None:
        grosses = [item["gross"] for item in out["items"] if item.get("gross")]
        if grosses:
            out["gross"] = round(sum(grosses), 2)

    out["missing"] = missing_fields(out)
    return out


def missing_fields(parsed: dict) -> list[str]:
    """Czego brakuje do wpłaty: kwoty brutto albo nabywcy (nazwy lub NIP-u)."""
    missing: list[str] = []
    gross = parsed.get("gross")
    if not isinstance(gross, (int, float)) or gross <= 0:
        missing.append("gross")
    if not _s(parsed.get("buyer_name")) and not normalize_nip(parsed.get("buyer_nip")):
        missing.append("buyer")
    return missing


def needs_ai(parsed: dict, *, has_text: bool) -> bool:
    """AI tylko awaryjnie: skan bez tekstu albo reguły nie znalazły kwoty/nabywcy."""
    return (not has_text) or bool(missing_fields(parsed))


def merge_ai(rules: dict, ai: dict) -> dict:
    """Pola z reguł wygrywają; AI dopełnia tylko to, czego reguły nie znalazły."""
    out = dict(rules)
    for key in (
        "invoice_no",
        "issue_date",
        "sale_date",
        "due_date",
        "seller_name",
        "seller_nip",
        "buyer_name",
        "buyer_nip",
        "gross",
        "paid",
        "remaining",
        "currency",
    ):
        if out.get(key) in (None, "") and ai.get(key) not in (None, ""):
            out[key] = ai[key]
    if not out.get("items") and ai.get("items"):
        out["items"] = ai["items"]
    out["missing"] = missing_fields(out)
    return out


def sanitize_ai(raw: Any) -> dict:
    """Odpowiedź modelu do kształtu `parse_invoice_text` - typy pilnowane tutaj."""
    data = raw if isinstance(raw, dict) else {}

    def day(value: Any) -> Optional[str]:
        text = _s(value)
        found = parse_date(text) or parse_date(text[:10])
        return found.isoformat() if found else None

    def money(value: Any) -> Optional[float]:
        if isinstance(value, (int, float)):
            return round(float(value), 2)
        return parse_amount(value)

    items = []
    for item in data.get("items") or []:
        if not isinstance(item, dict):
            continue
        name = " ".join(_s(item.get("name")).split())
        if name:
            items.append({
                "name": name,
                "quantity": money(item.get("quantity")),
                "unit": _s(item.get("unit")),
                "gross": money(item.get("gross")),
            })
    return {
        "invoice_no": _s(data.get("invoice_no")),
        "issue_date": day(data.get("issue_date")),
        "sale_date": day(data.get("sale_date")),
        "due_date": day(data.get("due_date")),
        "seller_name": " ".join(_s(data.get("seller_name")).split()),
        "seller_nip": normalize_nip(data.get("seller_nip")),
        "buyer_name": " ".join(_s(data.get("buyer_name")).split()),
        "buyer_nip": normalize_nip(data.get("buyer_nip")),
        "gross": money(data.get("gross")),
        "paid": money(data.get("paid")),
        "remaining": money(data.get("remaining")),
        "currency": _s(data.get("currency")).upper() or "PLN",
        "items": items,
    }


def short_items(items: list[dict], limit: int = 60) -> str:
    """Pozycje faktury skrócone do jednego napisu: „A, B (+2)"."""
    names = [" ".join(_s(item.get("name")).split()) for item in items or [] if _s(item.get("name"))]
    unique: list[str] = []
    for name in names:
        if name not in unique:
            unique.append(name)
    if not unique:
        return ""
    text = unique[0]
    shown = 1
    for name in unique[1:]:
        if len(text) + 2 + len(name) > limit:
            break
        text = f"{text}, {name}"
        shown += 1
    if len(text) > limit:
        text = text[: limit - 3].rstrip() + "..."
    if shown < len(unique):
        text = f"{text} (+{len(unique) - shown})"
    return text


def describe(parsed: dict) -> str:
    """Opis wpłaty: „Faktura 77/SL/2026 · Obsługa sędziowska zawodów"."""
    number = _s(parsed.get("invoice_no"))
    head = f"Faktura {number}" if number else "Faktura"
    items = short_items(parsed.get("items") or [])
    return f"{head} · {items}" if items else head


def ascii_fold(text: Any) -> str:
    """Bez ogonków i małymi literami - wspólne dla dopasowania nazw."""
    value = _s(text).replace("Ł", "L").replace("ł", "l")
    value = "".join(ch for ch in unicodedata.normalize("NFD", value) if unicodedata.category(ch) != "Mn")
    return value.lower()
