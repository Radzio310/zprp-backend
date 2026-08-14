"""Tożsamość aktora i role w meczu dla endpointów ProEl.

BAZA nie ma tokenów sesyjnych nadających się do użycia w hali: JWT z
`/auth/login` żyje 15 minut, a jego odświeżenie wymaga zalogowania się przez
scraping baza.zprp.pl. Sędzia potwierdzający badania przy słabym zasięgu nie
może być od tego zależny.

Dlatego aktor przedstawia się parą `judge_id` + `installation_id`, którą
weryfikujemy o tabelę `push_tokens` (PK = `installation_id`, indeks na
`judge_id`) — czyli o rejestr urządzeń, który aplikacja i tak utrzymuje.

To NIE jest twarda granica bezpieczeństwa i nie udajemy, że jest; to jest
o dwie klasy więcej niż dzisiejsze zero na `/proel/*` i wystarcza do
atrybucji („kto potwierdził badania"). Stare endpointy zostają bez auth,
bo inaczej złamalibyśmy aplikacje w terenie.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Set

from fastapi import Header, HTTPException
from sqlalchemy import select

from app.proel_fields import ALL_ROLES, normalize_name

# UWAGA: `app.db` importujemy LENIWIE, wewnątrz funkcji, które naprawdę sięgają
# do bazy. Import modułu bazy wykonuje `metadata.create_all(engine)`, czyli
# wymaga żywego Postgresa — a czysta logika ról (`names_match`, `roles_for`)
# decyduje teraz o prawie do zapisu i musi dać się testować bez bazy.

logger = logging.getLogger(__name__)


@dataclass
class Actor:
    judge_id: str
    installation_id: str
    name: str = ""
    #: True gdy para (installation_id, judge_id) zgadza się z `push_tokens`.
    #: False oznacza „nie potrafimy potwierdzić", nie „na pewno oszust".
    verified: bool = False
    roles: Set[str] = field(default_factory=set)

    def as_by(self) -> Dict[str, Any]:
        """Kształt zapisywany w overlayu i audycie."""
        return {
            "judge_id": self.judge_id,
            "name": self.name,
            "install": self.installation_id,
            "verified": self.verified,
        }


def _clean(v: Any) -> str:
    return str(v or "").strip()


async def proel_actor(
    x_judge_id: Optional[str] = Header(None, alias="X-Judge-Id"),
    x_installation_id: Optional[str] = Header(None, alias="X-Installation-Id"),
    x_actor_name: Optional[str] = Header(None, alias="X-Actor-Name"),
) -> Actor:
    """Zależność FastAPI: kto wykonuje zapis.

    Reguła weryfikacji jest celowo asymetryczna:
      • jest wiersz dla tego `installation_id` i zgadza się `judge_id` → verified,
      • jest wiersz, ale z INNYM `judge_id` → 401 (to realny sygnał, nie szum),
      • nie ma wiersza → przepuszczamy jako niezweryfikowanego.

    Ten ostatni przypadek jest konieczny: użytkownik, który odmówił zgody na
    powiadomienia, nigdy nie trafia do `push_tokens`. Odrzucanie go oznaczałoby,
    że sędzia bez powiadomień nie może potwierdzić badań.
    """
    judge_id = _clean(x_judge_id)
    installation_id = _clean(x_installation_id)

    if not judge_id or not installation_id:
        raise HTTPException(
            401,
            detail={
                "code": "ACTOR_REQUIRED",
                "message": "Brak tożsamości urządzenia. Zaloguj się ponownie.",
            },
        )

    from app.db import database, push_tokens  # lazy — patrz nota przy imporcie

    verified = False
    try:
        row = await database.fetch_one(
            select(push_tokens.c.judge_id).where(
                push_tokens.c.installation_id == installation_id
            )
        )
        if row is not None:
            known = _clean(row["judge_id"])
            if known and known != judge_id:
                raise HTTPException(
                    401,
                    detail={
                        "code": "ACTOR_MISMATCH",
                        "message": "To urządzenie jest przypisane do innego sędziego.",
                    },
                )
            verified = bool(known)
    except HTTPException:
        raise
    except Exception:  # noqa: BLE001 — awaria odczytu nie może blokować meczu
        logger.warning("proel_actor: nie udało się zweryfikować urządzenia", exc_info=True)

    return Actor(
        judge_id=judge_id,
        installation_id=installation_id,
        name=_clean(x_actor_name),
        verified=verified,
    )


async def is_admin(judge_id: str) -> bool:
    """Admin = numer sędziego na liście `admin_settings.allowed_admins`.

    Ta sama lista, z której korzysta aplikacja (`GET /admin/admins`), więc
    uprawnienie widoczne w UI i egzekwowane na serwerze są tym samym.
    """
    from app.db import admin_settings, database  # lazy — patrz nota przy imporcie

    jid = _clean(judge_id)
    if not jid:
        return False
    try:
        row = await database.fetch_one(select(admin_settings).limit(1))
        if not row:
            return False
        allowed = row["allowed_admins"] or []
        return jid in {str(a).strip() for a in allowed}
    except Exception:  # noqa: BLE001
        logger.warning("is_admin: odczyt listy adminów nieudany", exc_info=True)
        return False


# ─────────────────────────── role w meczu ───────────────────────────

_ROLE_KEYS = ("referee1", "referee2", "secretary", "timekeeper", "delegate")


def _tokens(s: Any) -> Set[str]:
    return {t for t in normalize_name(s).split(" ") if t}


def names_match(a: Any, b: Any) -> bool:
    """Port `namesMatch` z BAZA/utils/matchRole.ts, symetryczny.

    Oryginał wymaga, żeby WSZYSTKIE tokeny `a` były w `b`. Przy dwuczłonowym
    nazwisku po jednej stronie i jednoczłonowym po drugiej rola przepadała.
    Skoro rola daje teraz prawo zapisu, sprawdzamy obie strony.
    """
    ta, tb = _tokens(a), _tokens(b)
    if not ta or not tb:
        return False
    return ta.issubset(tb) or tb.issubset(ta)


def _crew_is_known(officials: Optional[Dict[str, Any]]) -> bool:
    """Czy o obsadzie tego meczu wiemy cokolwiek."""
    if not isinstance(officials, dict):
        return False
    for key in _ROLE_KEYS:
        raw = officials.get(key)
        if isinstance(raw, dict):
            if _clean(raw.get("judgeId") or raw.get("judge_id")) or _clean(
                raw.get("name") or raw.get("fullName")
            ):
                return True
        elif _clean(raw):
            return True
    return False


def roles_for(actor: Actor, officials: Optional[Dict[str, Any]]) -> Set[str]:
    """Zbiór ról aktora w tym meczu.

    NUMER SĘDZIEGO PRZED NAZWISKIEM: gdy znamy `judgeId` obsady, porównujemy
    numery i nie zgadujemy po nazwisku. Dopasowanie po nazwisku zostaje jako
    zapasowe, bo starsze wpisy w bazie nie mają numerów.

    `officials` ma kształt {"referee1": {"name": ..., "judgeId": ...}, ...}
    albo (starsze seedy) {"referee1": "NAZWISKO Imię", ...}.

    OBSADA NIEZNANA = WSZYSTKIE ROLE. Mecz stolikowy założony ręcznie nie ma
    obsady z ZPRP i nigdy jej mieć nie będzie. Gdybyśmy przy pustej liście
    odmawiali wszystkim, jedyny człowiek prowadzący taki mecz nie mógłby zapisać
    ani badań, ani danych pomeczowych — dostawałby „Nie masz roli uprawniającej
    do tej zmiany" przy każdym dotknięciu. Brak wiedzy o obsadzie to nie to samo
    co wiedza, że ktoś do niej nie należy: pierwsze przepuszczamy, drugie nie.
    """
    out: Set[str] = set()
    if not isinstance(officials, dict):
        return out
    if not _crew_is_known(officials):
        return set(ALL_ROLES)

    for key in _ROLE_KEYS:
        raw = officials.get(key)
        if raw is None:
            continue
        if isinstance(raw, dict):
            oid = _clean(raw.get("judgeId") or raw.get("judge_id"))
            oname = raw.get("name") or raw.get("fullName")
        else:
            oid = ""
            oname = raw

        if oid:
            if oid == actor.judge_id:
                out.add(key)
            # Numer jest rozstrzygający: gdy jest i się nie zgadza, nie
            # ratujemy roli zbieżnością nazwisk (dwóch Kowalskich na mecz).
            continue

        if actor.name and names_match(actor.name, oname):
            out.add(key)

    return out & ALL_ROLES


def _merge_official(existing: Any, incoming: Any) -> Any:
    """Scala jeden wpis obsady, nigdy nie tracąc numeru sędziego."""
    def as_dict(v: Any) -> Dict[str, Any]:
        if isinstance(v, dict):
            return dict(v)
        return {"name": _clean(v)} if _clean(v) else {}

    prev, nxt = as_dict(existing), as_dict(incoming)
    if not nxt:
        return existing
    out = dict(prev)
    for key, value in nxt.items():
        # Pusta wartość nie kasuje wypełnionej — ekran, który nie zna numerów,
        # nie może wymazać tych, które ktoś już przysłał.
        if _clean(value) or not _clean(out.get(key)):
            out[key] = value
    # Numer jest rozstrzygający dla roli i nigdy nie znika przez ekran, który
    # zna tylko nazwiska.
    for id_key in ("judgeId", "judge_id"):
        if _clean(prev.get(id_key)) and not _clean(out.get(id_key)):
            out[id_key] = prev[id_key]
    return out


def merge_guard(
    existing: Optional[Dict[str, Any]], incoming: Optional[Dict[str, Any]]
) -> Dict[str, Any]:
    """Scala `guard_json` przy `/ensure`.

    Płytkie `dict.update` gubiłoby tu numery sędziów: ekran finalizacji zna
    obsadę wyłącznie z nazwisk, więc jego `officials` zastąpiłby w całości
    wpisy z numerami, które przysłał wcześniej ekran meczu. A numer jest
    rozstrzygający przy rozpoznawaniu roli.
    """
    out: Dict[str, Any] = dict(existing or {})
    for key, value in (incoming or {}).items():
        if key != "officials":
            out[key] = value
            continue
        prev_off = out.get("officials")
        prev_off = dict(prev_off) if isinstance(prev_off, dict) else {}
        for role in _ROLE_KEYS:
            if not isinstance(value, dict) or role not in value:
                continue
            merged = _merge_official(prev_off.get(role), value.get(role))
            if merged:
                prev_off[role] = merged
        out["officials"] = prev_off
    return out


def can_confirm_exams(roles: Set[str]) -> bool:
    """Kto WIDZI przycisk „Sprawdź badania" — sędziowie główni i delegat.

    Serwer przyjmuje zapis `exam.*` od wszystkich pięciu ról (patrz rejestr):
    stolikowy robi to dzisiaj w ekranie konfiguracji i odebranie mu tego byłoby
    regresją. Asymetria UI ↔ serwer jest świadoma.
    """
    return bool(roles & {"referee1", "referee2", "delegate"})
