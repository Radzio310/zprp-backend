"""Centralny model uprawnień (capabilities) dla aplikacji BEACH.

Uprawnienia to płaska lista identyfikatorów (string), nadawanych użytkownikom
przez badge'y. Każdy badge w tabeli ``beach_badges`` przechowuje w polu
``config_json`` listę ``capabilities`` (lista identyfikatorów). Efektywne
uprawnienia użytkownika to suma uprawnień ze wszystkich jego badge'y.

Zasady:
- Backend NIE przechowuje katalogu etykiet/opisów uprawnień — etykiety żyją
  wyłącznie we frontendzie (``BAZA_Beach/utils/permissions.ts``).
- Backend rozwiązuje uprawnienia GENERYCZNIE: czyta zapisane identyfikatory z
  ``config_json.capabilities`` i zwraca ich sumę.
- ``LEGACY_BADGE_CAPS`` to mapa fallback dla badge'y, które nie mają jeszcze
  ustawionego pola ``capabilities`` (np. przed migracją). Służy też jako źródło
  danych dla skryptu migracyjnego ``migrate_badge_capabilities.py``.
- Administrator ma WSZYSTKIE uprawnienia — sprawdzane jest to flagą ``is_admin``
  zarówno po stronie backendu (``user_has_capability``) jak i frontendu.

Aby dodać nowe uprawnienie: dopisz jego identyfikator w rejestrze frontendu
oraz (jeśli ma być domyślnie nadawane istniejącym badge'om) w
``LEGACY_BADGE_CAPS`` poniżej. Szczegóły w ``BAZA_Beach/PERMISSIONS.md``.
"""

from __future__ import annotations

from typing import Any, Iterable, List, Set

from sqlalchemy import select

from app.db import database, beach_badges, beach_users


# ---------------------------------------------------------------------------
# Identyfikatory uprawnień (źródło prawdy dla seedów / migracji).
# Pełny katalog z etykietami znajduje się we froncie: utils/permissions.ts
# ---------------------------------------------------------------------------

# Uprawnienia w obrębie obszaru "Turnieje".
TOURNAMENT_CAPS: List[str] = [
    "tournament.create",
    "tournament.editBasics",
    "tournament.delete",
    "tournament.actAsHostEverywhere",
    "tournament.announcements.edit",
    "tournament.judges.manageHead",
    "tournament.judges.addField",
    "tournament.judges.addTable",
    "tournament.judges.assignField",
    "tournament.judges.assignTable",
    "tournament.schedule.edit",
    "tournament.schedule.score",
    "tournament.teams.manageSquads",
    "tournament.results.enterScores",
    "tournament.results.grantPoints",
    "tournament.settlements.use",
    "tournament.docs.use",
    "tournament.docs.headJudgeActions",
    "tournament.disqualifications.manage",
    "tournament.match.score",
    "tournament.tab.myTeam.always",
]

RULES_CAPS: List[str] = [
    "rules.edit",
]

# Wszystkie znane backendowi identyfikatory (informacyjnie / dla migracji).
CAPABILITY_IDS: List[str] = [*TOURNAMENT_CAPS, *RULES_CAPS]


# ---------------------------------------------------------------------------
# Mapa legacy: badge -> domyślne uprawnienia (fallback i seed migracji).
# ---------------------------------------------------------------------------

LEGACY_BADGE_CAPS: dict[str, List[str]] = {
    "Gospodarz zawodów": [
        "tournament.create",
        "tournament.editBasics",
        "tournament.announcements.edit",
        "tournament.schedule.edit",
        "tournament.schedule.score",
        "tournament.teams.manageSquads",
        "tournament.settlements.use",
        "tournament.docs.use",
        "tournament.results.enterScores",
    ],
    # Obsadowy = gospodarz każdego turnieju + zarządzanie sędzią głównym +
    # zakładka "Moja drużyna" zawsze widoczna.
    "Obsadowy": [
        *[c for c in TOURNAMENT_CAPS if c != "tournament.delete"],
    ],
    "Sędzia": [
        "tournament.match.score",
    ],
    "Rulemaker": [
        "rules.edit",
    ],
    "Beach Handball Lover": [],
}


def _normalize_badge_names(badges_raw: Any) -> List[str]:
    """Zwraca listę nazw badge'y z reprezentacji dict {nazwa: true} lub listy."""
    if badges_raw is None:
        return []
    if isinstance(badges_raw, dict):
        return [str(k) for k, v in badges_raw.items() if v]
    if isinstance(badges_raw, list):
        return [str(x) for x in badges_raw if x is not None]
    return []


def _caps_from_config(config_json: Any) -> List[str] | None:
    """Wyciąga listę capabilities z config_json badge'a.

    Zwraca ``None``, jeśli pole nie jest ustawione (badge niezmigrowany) —
    wtedy stosujemy fallback z ``LEGACY_BADGE_CAPS``.
    """
    if not isinstance(config_json, dict):
        return None
    if "capabilities" not in config_json:
        return None
    raw = config_json.get("capabilities")
    if isinstance(raw, list):
        return [str(x) for x in raw if x]
    return []


async def resolve_capabilities_for_badges(badge_names: Iterable[str]) -> Set[str]:
    """Suma uprawnień dla podanego zbioru nazw badge'y.

    Dla każdego badge'a czyta ``config_json.capabilities``; jeśli pole nie jest
    ustawione, używa fallbacku z ``LEGACY_BADGE_CAPS``.
    """
    names = [n for n in {str(b) for b in badge_names} if n]
    if not names:
        return set()

    rows = await database.fetch_all(
        select(beach_badges.c.name, beach_badges.c.config_json).where(
            beach_badges.c.name.in_(names)
        )
    )
    defined: dict[str, List[str] | None] = {}
    for r in rows:
        rd = dict(r)
        defined[str(rd["name"])] = _caps_from_config(rd.get("config_json"))

    result: Set[str] = set()
    for name in names:
        caps = defined.get(name)
        if caps is None:
            caps = LEGACY_BADGE_CAPS.get(name, [])
        result.update(caps)
    return result


async def resolve_user_capabilities(badges_raw: Any) -> Set[str]:
    """Efektywne uprawnienia użytkownika na podstawie jego badge'y."""
    return await resolve_capabilities_for_badges(_normalize_badge_names(badges_raw))


async def user_has_capability(user_id: int, capability: str, is_admin: bool = False) -> bool:
    """Czy użytkownik ma dane uprawnienie (admin ma wszystkie)."""
    if is_admin:
        return True
    row = await database.fetch_one(
        select(beach_users.c.badges).where(beach_users.c.id == user_id)
    )
    if not row:
        return False
    caps = await resolve_user_capabilities(dict(row).get("badges"))
    return capability in caps
