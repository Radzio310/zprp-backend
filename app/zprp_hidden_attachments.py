# app/zprp_hidden_attachments.py
#
# Ukrywanie załączników meczu na rozgrywki.zprp.pl - reguły i księga.
#
# PO CO. Sędzia potrafi wgrać do meczu nie ten plik (zdjęcie z prywatnej
# galerii, protokół innego meczu). ZPRP (`hide_attachment.php`, API p8) umie
# taki plik schować ze strony WWW, zostawiając go na dysku dla administratorów.
# Ukryty plik znika jednak z publicznego API meczu, więc lista „do
# przywrócenia" musi żyć u nas - stąd księga `zprp_hidden_attachments`.
#
# Moduł-liść: czyste funkcje na odpowiedzi publicznego API plus zapis księgi.
# Importy bazy WYŁĄCZNIE wewnątrz funkcji - `app/db.py` łączy się przy
# imporcie, a reguły mają dać się testować bez Postgresa.

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

ZPRP_FILES_ROOT = "https://baza.zprp.pl/"

#: Identyfikator załącznika w ZPRP to liczba (`protokol_id`). Wszystko inne
#: odrzucamy, zanim cokolwiek pójdzie do związku.
ATTACHMENT_ID_RE = re.compile(r"^[0-9]{1,12}$")

#: Ile znaków opisu pliku trzymamy w księdze - to podpis, nie dokument.
_TEXT_MAX = 300


def _clean(value: Any) -> str:
    return str(value if value is not None else "").strip()


def normalize_attachment_id(value: Any) -> Optional[str]:
    """`"0086914"` i `86914` to ten sam załącznik - porównujemy bez zer wiodących."""
    text = _clean(value)
    if not ATTACHMENT_ID_RE.match(text):
        return None
    return str(int(text))


def normalize_match_id(value: Any) -> Optional[int]:
    try:
        number = int(_clean(value))
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


def match_from_details(payload: Any) -> Optional[Dict[str, Any]]:
    """Rekord meczu z odpowiedzi `pokaz_mecze_szczegoly.php`.

    Produkcja zwraca `[[{...}]]`, starsze odpowiedzi `{"0": [{...}]}` - ta sama
    tolerancja co `_match_from_details_payload` w `app/official_role.py`
    (tamten moduł ciągnie za sobą konfigurację, więc nie importujemy go tutaj).
    """
    current = payload
    for _ in range(4):
        if isinstance(current, dict):
            if "Id" in current or "NrSedzia_pierwszy" in current or "Zalczniki" in current:
                return current
            for key in ("0", "value", "data", "matches"):
                if key in current:
                    current = current[key]
                    break
            else:
                return None
            continue
        if isinstance(current, list) and current:
            current = current[0]
            continue
        return None
    return current if isinstance(current, dict) else None


def is_approved(match: Dict[str, Any]) -> bool:
    """Protokół zatwierdzony w ZPRP (`protokol_zatwierdz == "1"`)."""
    return _clean(match.get("protokol_zatwierdz")) == "1"


def _file_url(path: str) -> str:
    if re.match(r"^https?://", path, re.I):
        return path
    return ZPRP_FILES_ROOT + re.sub(r"^\.?/", "", path)


def visible_attachments(match: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Widoczne załączniki meczu: `protokol_id` -> opis pliku.

    Klucz słownika `Zalczniki` NIE jest identyfikatorem (205603: klucz "1",
    `protokol_id` 86914) - identyfikatorem jest wyłącznie `protokol_id`.
    """
    out: Dict[str, Dict[str, Any]] = {}
    raw = match.get("Zalczniki")
    items: List[Any] = []
    if isinstance(raw, dict):
        items = list(raw.values())
    elif isinstance(raw, list):
        items = list(raw)
    # Pola na samym meczu to OSTATNI załącznik (z tym samym `protokol_id`) -
    # przy słowniku duplikat, bez słownika jedyne źródło.
    items.append(match)
    for item in items:
        if not isinstance(item, dict):
            continue
        attachment_id = normalize_attachment_id(item.get("protokol_id"))
        path = _clean(item.get("protokol_zalcznik_plik"))
        if not attachment_id or not path or attachment_id in out:
            continue
        filename = path.split("/")[-1]
        kind = _clean(item.get("protokol_zalcznik_plik_typ")).lower()
        out[attachment_id] = {
            "filename": filename,
            "label": _clean(item.get("protokol_zalcznik_nazwa")) or filename,
            "file_url": _file_url(path),
            "is_pdf": kind == "pdf" or filename.lower().endswith(".pdf"),
        }
    return out


def is_already_current(message: Any) -> bool:
    """200 „Status zalacznika jest juz aktualny" = nic się nie zmieniło."""
    return "aktualny" in _clean(message).lower()


def ledger_values(
    *,
    client: Dict[str, Any],
    upstream: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Opis pliku do księgi: najpierw to, co podało publiczne API, potem telefon.

    API jest źródłem sprawdzonym po naszej stronie; telefon tylko uzupełnia
    braki (np. starszy kształt odpowiedzi bez nazwy).
    """
    up = upstream or {}

    def pick(key: str) -> str:
        return (_clean(up.get(key)) or _clean(client.get(key)))[:_TEXT_MAX]

    is_pdf = up.get("is_pdf")
    if is_pdf is None:
        is_pdf = bool(client.get("is_pdf"))
    return {
        "filename": pick("filename"),
        "label": pick("label"),
        "file_url": pick("file_url")[:1000],
        "is_pdf": bool(is_pdf),
    }


def row_to_item(row: Dict[str, Any]) -> Dict[str, Any]:
    """Wiersz księgi -> pozycja odpowiedzi `GET /proel/zprp/attachments/hidden`."""
    hidden_at = row.get("hidden_at")
    return {
        "attachment_id": _clean(row.get("attachment_id")),
        "filename": _clean(row.get("filename")),
        "label": _clean(row.get("label")) or _clean(row.get("filename")),
        "file_url": _clean(row.get("file_url")),
        "is_pdf": bool(row.get("is_pdf")),
        "hidden_at": hidden_at.isoformat() if hasattr(hidden_at, "isoformat") else (hidden_at or None),
        "hidden_by_name": _clean(row.get("hidden_by_name")) or None,
    }


# ─────────────────────────── księga ───────────────────────────


async def ledger_open_entry(zprp_match_id: int, attachment_id: str) -> Optional[Dict[str, Any]]:
    """Wpis „nadal ukryty" (bez `restored_at`) albo `None`."""
    from sqlalchemy import select

    from app.db import database, zprp_hidden_attachments as t

    row = await database.fetch_one(
        select(t).where(
            t.c.zprp_match_id == str(zprp_match_id),
            t.c.attachment_id == attachment_id,
            t.c.restored_at.is_(None),
        )
    )
    return dict(row._mapping) if row is not None else None


async def ledger_mark_hidden(
    zprp_match_id: int,
    attachment_id: str,
    *,
    values: Dict[str, Any],
    by_name: Optional[str],
    by_judge_id: Optional[str],
) -> None:
    """Ukrycie: nowy wiersz albo odświeżenie po wcześniejszym przywróceniu."""
    from datetime import datetime, timezone

    from sqlalchemy.dialects.postgresql import insert as pg_insert

    from app.db import database, zprp_hidden_attachments as t

    now = datetime.now(timezone.utc)
    row = {
        **values,
        "hidden_at": now,
        "hidden_by_name": (by_name or None),
        "hidden_by_judge_id": (by_judge_id or None),
        "restored_at": None,
        "restored_by_name": None,
    }
    statement = pg_insert(t).values(
        zprp_match_id=str(zprp_match_id), attachment_id=attachment_id, **row
    )
    # Wpis już otwarty (ukrycie powtórzone) zostaje z PIERWSZYM ukryciem -
    # „kto i kiedy" ma mówić o tym, kto naprawdę schował plik.
    await database.execute(
        statement.on_conflict_do_update(
            index_elements=[t.c.zprp_match_id, t.c.attachment_id],
            set_=row,
            where=t.c.restored_at.is_not(None),
        )
    )


async def ledger_mark_restored(
    zprp_match_id: int, attachment_id: str, *, by_name: Optional[str]
) -> None:
    from datetime import datetime, timezone

    from sqlalchemy import update

    from app.db import database, zprp_hidden_attachments as t

    await database.execute(
        update(t)
        .where(
            t.c.zprp_match_id == str(zprp_match_id),
            t.c.attachment_id == attachment_id,
            t.c.restored_at.is_(None),
        )
        .values(restored_at=datetime.now(timezone.utc), restored_by_name=(by_name or None))
    )


async def ledger_hidden_for_match(zprp_match_id: int) -> List[Dict[str, Any]]:
    """Załączniki nadal ukryte, najnowsze pierwsze."""
    from sqlalchemy import select

    from app.db import database, zprp_hidden_attachments as t

    rows = await database.fetch_all(
        select(t)
        .where(t.c.zprp_match_id == str(zprp_match_id), t.c.restored_at.is_(None))
        .order_by(t.c.hidden_at.desc())
    )
    return [row_to_item(dict(r._mapping)) for r in rows]
