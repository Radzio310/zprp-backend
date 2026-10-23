"""Autor wpisu sędziego stolikowego dopisanego z aplikacji (16.10.2026).

Kto dopisał stolikowego przez picker BAZY, ten może go z ZPRP usunąć. Inni
widzą, kto go dopisał, i dostają wyjaśnienie zamiast przycisku. ZPRP nie
pamięta autora gniazda, więc pamiętamy go tutaj: jeden wiersz na mecz i rolę,
nadpisywany kolejnym zapisem, kasowany po usunięciu.

Wpis obowiązuje tylko, dopóki w gnieździe stoi TA SAMA osoba. Gdy obsadowy
zmieni stolikowego w bazie związku, stary wpis po cichu przestaje pasować
(porównanie nazwisk), więc nikt nie usunie z aplikacji cudzego wyboru.

Moduł: definicja tabeli, czyste reguły (testowane bez bazy) i trzy krótkie
operacje na bazie - importy `app.db` w funkcjach (db łączy się przy imporcie).
"""

from __future__ import annotations

import logging
import re
import unicodedata
from datetime import datetime, timezone
from typing import Any, Dict, Mapping, Optional

from sqlalchemy import Column, DateTime, MetaData, String, Table

from app.zprp_public.referee_placeholder import is_blank_name

logger = logging.getLogger(__name__)

ROLES = ("secretary", "timekeeper")

#: Imię i nazwisko zalogowanego - z publicznej obsady meczu, po numerze.
_ROLE_NAME_KEYS = (
    ("NrSedzia_pierwszy", "NrSedzia_pierwszy_nazwisko"),
    ("NrSedzia_drugi", "NrSedzia_drugi_nazwisko"),
    ("NrSedzia_delegat", "NrSedzia_delegat_nazwisko"),
    ("NrSedzia_delegat2", "NrSedzia_delegat2_nazwisko"),
)


def define_tables(metadata: MetaData) -> Table:
    return Table(
        "zprp_table_official_authors",
        metadata,
        Column("match_id", String, primary_key=True),
        Column("role", String, primary_key=True),
        Column("official_name", String, nullable=False),
        Column("name_key", String, nullable=False),
        Column("author_judge_id", String, nullable=False),
        Column("author_name", String, nullable=False, server_default=""),
        Column("created_at", DateTime(timezone=True), nullable=False),
    )


# ---------------------------------------------------------------- reguły


def name_key(name: Any) -> str:
    """Zbiór członów bez ogonków: „WITKOWICZ Krzysztof" == „Krzysztof Witkowicz"."""
    txt = unicodedata.normalize("NFKD", str(name or ""))
    txt = "".join(ch for ch in txt if not unicodedata.combining(ch)).lower()
    txt = txt.replace("ł", "l")
    parts = [p for p in re.split(r"[^a-z0-9]+", txt) if p]
    return " ".join(sorted(parts))


def _same_number(a: Any, b: Any) -> bool:
    from app.proel_fields import same_judge_number

    return same_judge_number(a, b)


def author_name_from_match(match: Optional[Mapping[str, Any]], judge_id: str) -> str:
    """Nazwisko zalogowanego z obsady meczu (pokazujemy je innym)."""
    if not match:
        return ""
    for id_key, name_key_ in _ROLE_NAME_KEYS:
        if _same_number(match.get(id_key), judge_id):
            name = str(match.get(name_key_) or "").strip()
            if not is_blank_name(name):  # „--- ---" to puste pole, nie nazwisko
                return name
    return ""


def author_view(
    row: Optional[Mapping[str, Any]], selected_name: str, judge_id: str
) -> Optional[Dict[str, Any]]:
    """Autor dla klienta - tylko gdy wpis dotyczy osoby, która TERAZ stoi w gnieździe."""
    if not row or not str(selected_name or "").strip():
        return None
    if row.get("name_key") != name_key(selected_name):
        return None
    created = row.get("created_at")
    return {
        "name": str(row.get("author_name") or ""),
        "is_me": _same_number(row.get("author_judge_id"), judge_id),
        "at": created.isoformat() if isinstance(created, datetime) else str(created or ""),
    }


def removal_refusal(
    row: Optional[Mapping[str, Any]], expected_name: str, judge_id: str
) -> Optional[str]:
    """None = wolno usunąć; inaczej zdanie dla sędziego, czemu nie."""
    if not str(expected_name or "").strip():
        return "To miejsce jest już puste."
    if not row or row.get("name_key") != name_key(expected_name):
        return (
            "Tej osoby nie dopisano z aplikacji BAZA - usunąć ją może obsadowy "
            "w bazie związku."
        )
    if not _same_number(row.get("author_judge_id"), judge_id):
        who = str(row.get("author_name") or "").strip() or "inny sędzia tego meczu"
        return f"Tę osobę dopisał {who} - tylko on może ją usunąć z aplikacji."
    return None


# ---------------------------------------------------------------- baza


async def load_authors(match_id: str) -> Dict[str, Dict[str, Any]]:
    from sqlalchemy import select

    from app.db import database, zprp_table_official_authors as T

    rows = await database.fetch_all(select(T).where(T.c.match_id == str(match_id).strip()))
    return {str(r["role"]): dict(r._mapping) if hasattr(r, "_mapping") else dict(r) for r in rows}


async def remember_author(
    match_id: str, role: str, official_name: str, judge_id: str, author_name: str
) -> None:
    from sqlalchemy.dialects.postgresql import insert

    from app.db import database, zprp_table_official_authors as T

    values = {
        "match_id": str(match_id).strip(),
        "role": role,
        "official_name": str(official_name or "").strip(),
        "name_key": name_key(official_name),
        "author_judge_id": str(judge_id or "").strip(),
        "author_name": str(author_name or "").strip(),
        "created_at": datetime.now(timezone.utc),
    }
    stmt = insert(T).values(**values)
    stmt = stmt.on_conflict_do_update(
        index_elements=[T.c.match_id, T.c.role],
        set_={k: stmt.excluded[k] for k in values if k not in ("match_id", "role")},
    )
    await database.execute(stmt)


async def forget_author(match_id: str, role: str) -> None:
    from sqlalchemy import and_, delete

    from app.db import database, zprp_table_official_authors as T

    await database.execute(
        delete(T).where(and_(T.c.match_id == str(match_id).strip(), T.c.role == role))
    )
