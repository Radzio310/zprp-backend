"""Zdjęcie sędziego należy do JEDNEJ osoby.

Z produkcji (2026-10-15, „Mentorzy i pary"): przy Dawidzie CELOCHU świeciło
się zdjęcie innego sędziego. Telefon, na którym przełączono konto, wysyłał w
`PATCH /login_records/{id}` zdjęcie poprzedniego konta (leżało jeszcze w
`settings.json`), a codzienna pętla kopiowała je do `province_judges`. Ten sam
adres zdjęcia stał wtedy przy dwóch numerach sędziego - a ZPRP daje każdemu
sędziemu własny plik, więc jeden z tych przydziałów jest na pewno fałszywy.

Reguła naprawy: adres przypisany kilku sędziom zostaje tylko przy tym, którego
numer zgadza się z nazwą pliku ZPRP (`foto_sedzia/<numer>.jpg`), a gdy nie
zgadza się dokładnie jeden - znika u wszystkich. Inicjały w kółku są lepsze niż
cudza twarz; właściciel odzyska zdjęcie przy najbliższej synchronizacji ze
swojego telefonu.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, Mapping

_ZPRP_PHOTO_RE = re.compile(r"foto_sedzia/0*(\d+)\.", re.I)


def _s(value: Any) -> str:
    return str(value or "").strip()


def photo_number(url: Any) -> str:
    """Numer z nazwy pliku ZPRP albo pusty napis."""
    found = _ZPRP_PHOTO_RE.search(_s(url))
    return found.group(1) if found else ""


def shared_photo_fixes(rows: Iterable[Mapping[str, Any]]) -> Dict[str, str]:
    """{judge_id: nowy photo_url} dla sędziów, którzy dzielą zdjęcie z innymi.

    `rows` to wiersze z kluczami `judge_id` i `photo_url`. Zwraca wyłącznie
    zmiany: pusty napis znaczy „zdjęcie do zdjęcia".
    """
    holders: Dict[str, list] = {}
    for row in rows:
        judge_id, url = _s(row.get("judge_id")), _s(row.get("photo_url"))
        if judge_id and url:
            holders.setdefault(url, []).append(judge_id)

    fixes: Dict[str, str] = {}
    for url, ids in holders.items():
        ids = sorted(set(ids))
        if len(ids) < 2:
            continue
        number = photo_number(url)
        owners = [jid for jid in ids if number and jid.lstrip("0") == number]
        keep = owners[0] if len(owners) == 1 else ""
        for jid in ids:
            if jid != keep:
                fixes[jid] = ""
    return fixes
