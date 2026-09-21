# app/match_market_access.py
#
# Kto może zatwierdzić wymianę meczu.
#
# Liść bez bazy - wołający podaje to, co odczytał, a tu zapada sama decyzja.
# Dzięki temu regułę da się sprawdzić testem bez Postgresa, a przy okazji widać
# ją w całości w jednym miejscu zamiast rozsypanej po endpointach.
#
# Kształt wzorowany na `_check_board_write_access` (`app/board.py`), z jedną
# świadomą różnicą: tam konto organizacji przechodzi zawsze, tutaj nie.
# Na tablicy ogłoszeń stawką jest wpis, który da się skasować. Tutaj stawką
# jest obsada meczu, który się odbędzie - i zmiana w bazie związku, do której
# nie ma przycisku „cofnij". Prawo do niej ma człowiek z odznaką obsadowego w
# TYM okręgu albo administrator aplikacji, i nikt poza nimi.

from __future__ import annotations

import json
from typing import Any, Iterable, List, Optional

from app.settlement_province import canonical

#: Odznaka dająca prawo zatwierdzania. Ta sama nazwa co w module Beacha, gdzie
#: „Obsadowy" jest odznaką od początku - jeden słownik pojęć na całą aplikację.
APPROVER_BADGE = "Obsadowy"


def normalize_province(value: Any) -> str:
    """Jeden klucz dla `ŚLĄSKIE` z katalogu i `SLASKIE` z giełdy."""
    return canonical(value)


def badge_names(badges_raw: Any) -> List[str]:
    """Nazwy odznak z każdego kształtu, w jakim leżą w bazie.

    Starsze wiersze mają listę, nowsze słownik `{nazwa: true}` z wyłączonymi
    odznakami zapisanymi jako `false` - i te ostatnie muszą wypaść, bo wyłączona
    odznaka nie jest odznaką. Kolumna JSON potrafi do tego wrócić z bazy jako
    SUROWY NAPIS (asyncpg pod `databases` bez kodeka jsonb nie dekoduje
    niczego) - obsadowy z odznaką w napisie wychodził wtedy bez uprawnień,
    czego nie widać było na kontach administratorów, bo te przechodzą inną
    bramką.
    """
    if isinstance(badges_raw, str) and badges_raw.strip():
        try:
            badges_raw = json.loads(badges_raw)
        except ValueError:
            return []
    if isinstance(badges_raw, dict):
        return [str(k) for k, v in badges_raw.items() if v]
    if isinstance(badges_raw, (list, tuple, set)):
        return [str(x) for x in badges_raw if x]
    return []


def normalize_approver_badges(value: Any) -> List[str]:
    """Lista odznak uprawnionych do rozstrzygania wymian - z każdego kształtu.

    Okręg wybiera odznaki sam (kolumna `approver_badges` w konfiguracji), a ta
    funkcja sprowadza wybór do porządku: kolumna JSON bywa napisem (asyncpg bez
    kodeka), stare wpisy bywają słownikiem `{nazwa: true}`, a duplikaty i puste
    wpisy wypadają. PUSTKA znaczy DOMYŚLNIE odznaka obsadowego - brak zaznaczeń
    nie może zostawić okręgu z giełdą, której nikt nie rozstrzyga.
    """
    raw = value
    if isinstance(raw, (bytes, bytearray)):
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError:
            raw = ""
    if isinstance(raw, str) and raw.strip():
        try:
            raw = json.loads(raw)
        except ValueError:
            raw = []
    if isinstance(raw, dict):
        raw = [k for k, v in raw.items() if v]
    out: List[str] = []
    for item in raw if isinstance(raw, (list, tuple, set)) else []:
        name = str(item or "").strip()
        if name and name not in out:
            out.append(name)
    return out or [APPROVER_BADGE]


def has_approver_badge(
    badges_raw: Any, allowed_badges: Optional[Iterable[str]] = None
) -> bool:
    """Czy wśród odznak jest któraś z uprawnionych (domyślnie: obsadowego)."""
    wanted = {
        str(b or "").strip()
        for b in (allowed_badges or (APPROVER_BADGE,))
        if str(b or "").strip()
    }
    return any(name in wanted for name in badge_names(badges_raw))


def may_approve(
    *,
    is_admin: bool,
    province: Any,
    judge_province: Any,
    badges_raw: Any,
    allowed_badges: Optional[Iterable[str]] = None,
) -> bool:
    """Czy ten człowiek może rozstrzygać wymiany w tym województwie.

    `judge_province` to województwo z `province_judges` - a nie to, które
    przyszło z telefonu. Województwo w tokenie ustawia sobie sam użytkownik w
    ustawieniach aplikacji i nie może być podstawą do decyzji o cudzej obsadzie.

    `allowed_badges` to wybór okręgu (`normalize_approver_badges`); bez niego
    obowiązuje domyślna odznaka obsadowego. Administrator przechodzi zawsze.
    """
    if is_admin:
        return True
    prov = normalize_province(province)
    if not prov or normalize_province(judge_province) != prov:
        return False
    return has_approver_badge(badges_raw, allowed_badges)


def may_manage_config(*, is_admin: bool) -> bool:
    """Włączanie modułu i próg czasowy okręgu - wyłącznie administrator.

    Obsadowy rozstrzyga pojedyncze wymiany, ale nie zmienia zasad, na których
    działa jego okręg. To jest ta sama granica, co między prowadzeniem meczu a
    ustawieniami aplikacji.
    """
    return bool(is_admin)


def approver_judge_ids(
    rows: Iterable[Any],
    province: Any,
    *,
    admin_ids: Optional[Iterable[Any]] = None,
    allowed_badges: Optional[Iterable[str]] = None,
) -> List[str]:
    """Numery ludzi, do których ma pójść powiadomienie o nowym zgłoszeniu.

    `rows` to wiersze `province_judges` (dowolny kształt z `judge_id`,
    `province` i `badges`). Administratorzy dochodzą osobno, bo nie muszą mieć
    ani odznaki, ani wpisu w okręgu.
    """
    prov = normalize_province(province)
    if not prov:
        return []
    out: List[str] = []

    for row in rows or []:
        data = dict(row._mapping) if hasattr(row, "_mapping") else dict(row or {})
        if normalize_province(data.get("province")) != prov:
            continue
        if not has_approver_badge(data.get("badges"), allowed_badges):
            continue
        judge_id = str(data.get("judge_id") or "").strip()
        if judge_id:
            out.append(judge_id)

    for admin_id in admin_ids or []:
        value = str(admin_id or "").strip()
        if value:
            out.append(value)

    return sorted(set(out))


def notification_manager_ids(
    rows: Iterable[Any],
    province: Any,
    *,
    admin_ids: Iterable[Any],
    notify_admins: bool,
    allowed_badges: Optional[Iterable[str]] = None,
) -> List[str]:
    """Powiadomienia roli z per-okręgowym wyłącznikiem administratorów.

    Admin z lokalną odznaką również pozostaje wyciszony, gdy przełącznik jest
    wyłączony. Osobiste powiadomienia o jego własnym meczu idą inną drogą.
    """
    admins = {str(value or "").strip() for value in admin_ids if str(value or "").strip()}
    known_rows = [dict(row._mapping) if hasattr(row, "_mapping") else dict(row or {}) for row in rows or []]
    eligible = known_rows if notify_admins else [
        row for row in known_rows if str(row.get("judge_id") or "").strip() not in admins
    ]
    return approver_judge_ids(
        eligible, province,
        admin_ids=admins if notify_admins else (),
        allowed_badges=allowed_badges,
    )


def offer_notification_groups(
    public_ids: Iterable[Any],
    manager_ids: Iterable[Any],
    admin_ids: Iterable[Any],
    exclude: Any,
) -> tuple[List[str], List[str]]:
    """Admin wyłącznie przez rolę, pozostali bez podwójnych powiadomień."""
    clean = lambda values: {str(value or "").strip() for value in values if str(value or "").strip()}
    managers = clean(manager_ids) - {str(exclude or "").strip()}
    public = clean(public_ids) - clean(admin_ids) - managers - {str(exclude or "").strip()}
    return sorted(public), sorted(managers)


def claim_notification_groups(
    manager_ids: Iterable[Any], giver_id: Any, claimer_id: Any,
) -> tuple[List[str], List[str], List[str]]:
    """To samo rozdzielenie treści dla oddającego i zarządzających w teście i akcji."""
    claimer = str(claimer_id or "").strip()
    giver = str(giver_id or "").strip()
    managers = {str(value or "").strip() for value in manager_ids if str(value or "").strip()} - {claimer}
    giver_targets = [giver] if giver and giver not in managers and giver != claimer else []
    return sorted(managers), giver_targets, [claimer] if claimer else []


def rejected_notification_targets(
    manager_ids: Iterable[Any], giver_id: Any, interested_ids: Iterable[Any], actor_id: Any,
) -> List[str]:
    ids = {str(value or "").strip() for value in (*manager_ids, giver_id, *interested_ids)
           if str(value or "").strip()}
    return sorted(ids - {str(actor_id or "").strip()})


def approved_notification_groups(
    manager_ids: Iterable[Any], giver_id: Any, taker_id: Any,
    other_ids: Iterable[Any], crew_ids: Iterable[Any], actor_id: Any,
) -> dict[str, List[str]]:
    """Adresaci udanej wymiany, rozdzieleni według osobistej treści push-a."""
    clean = lambda values: sorted({str(value or "").strip() for value in values if str(value or "").strip()})
    giver = str(giver_id or "").strip()
    taker = str(taker_id or "").strip()
    others = clean(other_ids)
    crew = clean(crew_ids)
    informed = {giver, taker, str(actor_id or "").strip(), *others, *crew}
    return {
        "taker": [taker] if taker else [],
        "giver": [giver] if giver else [],
        "others": others,
        "crew": crew,
        "managers": sorted(set(clean(manager_ids)) - informed),
    }
