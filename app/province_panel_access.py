"""
Kto może PISAĆ w panelach okręgu z BAZA_web: panel klubów i Obsada.

Te panele nie należą do Masterów. Otwiera je w BAZA_web wyłącznie konto VIP
okręgu z uprawnieniem nadanym w panelu admina:

  - panel klubów (Rozliczenia) - `settlements`,
  - Obsada - `assignments`,

(`BAZA_web/app/(tabs)/explore.tsx` i `assignments.tsx`). Konto sędziego ma przy
logowaniu do BAZA_web kasowany rekord VIP, więc na tych ekranach w ogóle nie
staje - a aplikacja mobilna do tych tras nie pisze. Dlatego zwykła bramka
okręgowa (`province_guard.ensure_province_write`) tu nie pasuje: pyta o listę
Masterów i konta organizacji odrzuca z zasady, czyli odcięłaby dokładnie tych,
dla których te panele są.

Reguła, lustro ekranu:
  - konto VIP: własne województwo (albo okręg z listy `provinces` w
    uprawnieniach) ORAZ uprawnienie panelu albo `admin`. Samo województwo nie
    wystarcza - ta sama decyzja co przy ocenach delegatów z 16.09.2026,
  - sędzia: tylko administrator aplikacji (lista z panelu admina). Tędy piszą
    skrypty z `scripts/`, logujące się kontem sędziego.

Każda odmowa mówi, czego brakuje i do kogo z tym iść.

MODUŁ-LIŚĆ: bez bazy i sieci, żeby reguła chodziła w teście.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, Optional

from app.province_access import normalize_province

PANEL_SETTLEMENTS = "settlements"
PANEL_ASSIGNMENTS = "assignments"

#: Nazwa uprawnienia tak, jak widzi ją administrator w panelu kont VIP.
PANEL_LABELS = {
    PANEL_SETTLEMENTS: "Rozliczenia",
    PANEL_ASSIGNMENTS: "Obsada",
}

NO_PROVINCE = "Żądanie nie wskazuje okręgu, więc nie da się sprawdzić uprawnień."
NO_ACCOUNT = "Tego konta nie da się rozpoznać. Zaloguj się ponownie."


@dataclass(frozen=True)
class VipRecord:
    """Rekord z `baza_vips` - tylko to, co potrzebne do decyzji."""

    username: str
    province: str
    permissions: Dict[str, Any]


def vip_permissions(raw: Any) -> Dict[str, Any]:
    """`permissions_json` jako słownik - kolumna JSONB potrafi wrócić napisem."""
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            return {}
    return dict(raw) if isinstance(raw, dict) else {}


def vip_has_panel(permissions: Any, panel: str) -> bool:
    """`admin` daje każdy panel, poza tym tylko osobna flaga danego panelu."""
    perms = vip_permissions(permissions)
    return bool(perms.get("admin") or perms.get(panel))


def vip_covers_province(vip_province: Any, permissions: Any, province: Any) -> bool:
    """
    Czy konto VIP pisze w tym okręgu.

    Województwo porównujemy bez ogonków: jedna strona zapisuje „ŚLĄSKIE",
    druga „SLASKIE", a to ten sam okręg.
    """
    wanted = normalize_province(province)
    if not wanted:
        return False
    if normalize_province(vip_province) == wanted:
        return True
    extra = vip_permissions(permissions).get("provinces")
    if isinstance(extra, (list, tuple)):
        return any(normalize_province(item) == wanted for item in extra)
    return False


def panel_write_refusal(
    *,
    panel: str,
    province: Any,
    account_type: str,
    judge_id: str,
    login: str,
    is_admin: bool,
    vip: Optional[VipRecord],
) -> str:
    """
    Powód odmowy albo pusty napis, gdy wolno pisać.

    `account_type`, `judge_id` i `login` pochodzą WYŁĄCZNIE z tokenu - numer czy
    login przysłany w treści żądania nie ma tu nic do powiedzenia.
    """
    label = PANEL_LABELS.get(panel, panel)
    if not normalize_province(province):
        return NO_PROVINCE

    if judge_id:
        if is_admin:
            return ""
        return (
            f"W panelu „{label}” piszą konta VIP okręgu z tym uprawnieniem "
            "albo administrator aplikacji. Konto sędziego go nie ma."
        )

    if str(account_type or "").strip().lower() != "org" or not login:
        return NO_ACCOUNT
    if vip is None:
        return (
            f"Konto {login} nie ma rekordu VIP. Administrator aplikacji musi je "
            f"dodać i nadać uprawnienie „{label}”."
        )
    if not vip_covers_province(vip.province, vip.permissions, province):
        mine = normalize_province(vip.province) or "brak"
        return (
            f"Konto VIP ma ustawione inne województwo ({mine}) niż ten okręg "
            f"({normalize_province(province)}). Zmienia je administrator aplikacji."
        )
    if not vip_has_panel(vip.permissions, panel):
        return (
            f"Konto VIP nie ma uprawnienia „{label}”. Nadaje je administrator "
            "aplikacji w panelu kont VIP."
        )
    return ""
