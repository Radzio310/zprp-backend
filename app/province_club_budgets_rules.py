"""
Wspólny budżet klubów - reguła scalania (moduł-liść, bez bazy i HTTP).

ZPRP prowadzi niektóre kluby pod kilkoma numerami (np. stowarzyszenie i spółka
tego samego klubu), a okręg rozlicza je jako JEDEN budżet: jedna wpłata
pokrywa mecze wszystkich numerów, a saldo jest jedno. Decyzja użytkownika
z 23.09.2026: w panelu klubów taki klub to jeden wiersz, a pod spodem lista
numerów ZPRP.

Zasady:
  - klub należy najwyżej do jednego budżetu,
  - budżet ma klub GŁÓWNY: jego numer jest kluczem wiersza (lista, szczegóły,
    szablon Excela), na niego idą nowe wpisy i z niego czytamy ustawienia
    „Rozlicza się przez okręg" i „4. sędzia przez okręg",
  - pieniądze się sumują: wpłaty, wypłaty, rozliczenia poza systemem,
    obciążenia i mecze; saldo liczymy OD NOWA z sum (`club_charges.balance`
    zaokrągla do złotych, więc suma zaokrąglonych sald potrafi się rozjechać
    o złotówkę),
  - gdy członkowie mają różne ustawienia, budżet dostaje flagę
    `mixed_settings` - panel mówi o tym wprost, zamiast po cichu wybrać,
  - klub spoza budżetów to budżet jednoosobowy: kształt jak dotąd, plus
    `member_ids=[club_id]`.

Nazwa budżetu: zapisana ręcznie albo (pusta) nazwa klubu głównego z panelu.
"""

from __future__ import annotations

import json
from typing import Any, Iterable, Mapping, Optional

from app import club_charges as C
from app.settlement_money import money_sum

#: Ile numerów ZPRP przyjmuje jeden budżet - więcej to pomyłka w zaznaczeniu.
MAX_MEMBERS = 12

#: Budżety zakładane przy starcie (decyzja użytkownika z 23.09.2026). Główny
#: numer pierwszy; nazwa pusta = nazwa klubu głównego z panelu.
DEFAULT_BUDGETS: dict[str, list[dict[str, Any]]] = {
    "SLASKIE": [
        # KS Bystra + Beskidzki Handball
        {"primary": "3608", "members": ["3608", "4986"]},
        # MKS Olimpia Piekary Śląskie + MKS Olimpia Piekary Śląskie Sp. z o.o.
        {"primary": "41", "members": ["41", "4927"]},
        # UKS Kuźnia Raciborska + UKS Start Pietrowice Wielkie
        {"primary": "2049", "members": ["2049", "4997"]},
        # Handballmania MTS Żory - jeden klub pod dwoma numerami
        {"primary": "27", "members": ["27", "5011"]},
    ],
}


def _s(value: Any) -> str:
    return str(value or "").strip()


def parse_members(raw: Any) -> list[str]:
    """Lista numerów z kolumny tekstowej (JSON jako napis) - odporna na śmieci."""
    if isinstance(raw, (list, tuple)):
        items = raw
    elif isinstance(raw, str) and raw.strip():
        try:
            items = json.loads(raw)
        except Exception:
            items = [part for part in raw.split(",")]
        if not isinstance(items, list):
            items = []
    else:
        items = []
    out: list[str] = []
    for item in items:
        club_id = _s(item)
        if club_id and club_id not in out:
            out.append(club_id)
    return out


def dump_members(members: Iterable[str]) -> str:
    return json.dumps(list(members), ensure_ascii=False)


def clean_members(primary: Any, members: Optional[Iterable[Any]]) -> list[str]:
    """
    Członkowie budżetu: główny pierwszy, bez pustych i powtórzeń.

    ValueError z komunikatem dla człowieka - warstwa HTTP zamienia go na 400.
    """
    primary_id = _s(primary)
    out: list[str] = [primary_id] if primary_id else []
    for value in members or []:
        club_id = _s(value)
        if club_id and club_id not in out:
            out.append(club_id)
    if not primary_id:
        raise ValueError("Wskaż klub główny budżetu")
    if len(out) < 2:
        raise ValueError("Wspólny budżet potrzebuje co najmniej dwóch numerów klubów")
    if len(out) > MAX_MEMBERS:
        raise ValueError(f"Za dużo numerów w jednym budżecie - limit to {MAX_MEMBERS}")
    return out


def conflicts(
    members: Iterable[str],
    budgets: Iterable[Mapping[str, Any]],
    *,
    budget_id: Any = None,
) -> dict[str, Mapping[str, Any]]:
    """Który z podanych klubów siedzi już w INNYM budżecie: {club_id: budżet}."""
    wanted = set(members)
    out: dict[str, Mapping[str, Any]] = {}
    for budget in budgets:
        if budget_id is not None and str(budget.get("budget_id")) == str(budget_id):
            continue
        for club_id in budget.get("member_ids") or []:
            if club_id in wanted:
                out[club_id] = budget
    return out


def member_map(budgets: Iterable[Mapping[str, Any]]) -> dict[str, str]:
    """Numer członka -> numer klubu głównego jego budżetu."""
    out: dict[str, str] = {}
    for budget in budgets:
        primary = _s(budget.get("primary_club_id"))
        for club_id in budget.get("member_ids") or []:
            out.setdefault(club_id, primary)
    return out


def group_of(club_id: str, budgets: Iterable[Mapping[str, Any]]) -> Optional[Mapping[str, Any]]:
    """Budżet, do którego należy klub - albo None."""
    for budget in budgets:
        if club_id in (budget.get("member_ids") or []):
            return budget
    return None


def seed_plan(
    existing: Iterable[Mapping[str, Any]],
    defaults: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """
    Które domyślne budżety założyć.

    Grupa, której którykolwiek numer jest już w jakimś budżecie, zostaje
    pominięta - seed nigdy nie przepina klubu ani nie dubluje budżetu, więc
    drugie uruchomienie niczego nie zmienia.
    """
    taken = set(member_map(existing))
    plan: list[dict[str, Any]] = []
    for group in defaults:
        members = clean_members(group.get("primary"), group.get("members"))
        if taken & set(members):
            continue
        taken.update(members)
        plan.append({"primary_club_id": members[0], "member_ids": members, "name": group.get("name")})
    return plan


#: Klub zastępczy z synchronizacji - drużyna, przy której ZPRP nie podał numeru
#: klubu (`province_clubs_scrape.eligible_fallback_club_id`).
FALLBACK_PREFIX = "eligible-team:"

#: Człony nazwy, które odróżniają DRUŻYNY jednego klubu, a nie kluby:
#: liczebniki rzymskie i krótkie numery („OSP Świętochłowice 1").
_TEAM_MARKS = frozenset({"i", "ii", "iii", "iv", "v", "vi", "vii", "viii", "ix", "x"})


def club_base_key(name_key: Any) -> str:
    """
    Nazwa klubu bez znacznika drużyny: „spr pogon 1945 ii zabrze" -> „spr pogon 1945 zabrze".

    Dostaje KLUCZ nazwy (`province_clubs_scrape.team_key`). Rok w nazwie
    („1945") zostaje - to część nazwy klubu, nie numer drużyny.
    """
    words = [
        word
        for word in _s(name_key).split()
        if word not in _TEAM_MARKS and not (word.isdigit() and len(word) <= 2)
    ]
    return " ".join(words)


def auto_merge_plan(
    teams: Iterable[tuple[Any, Any]],
    *,
    key_of: Any,
    taken: Iterable[str] = (),
    rejected: Iterable[str] = (),
    owner: Optional[Mapping[str, str]] = None,
) -> dict[str, str]:
    """
    Automatyczne scalenie: klub zastępczy -> klub z numerem ZPRP (decyzja z 06.10.2026).

    Zgłoszenie: „pogonie się porozbijały" - drużyny „SPR Pogoń 1945 II Zabrze",
    „... III Zabrze", „... Zabrze III" bez numeru klubu w ZPRP dostały po
    klubie zastępczym i panel pokazywał pięć Pogoni. Klub zastępczy dołącza
    do klubu z PRAWDZIWYM numerem, którego drużyna ma tę samą nazwę bez
    znacznika drużyny (`club_base_key`) - tylko gdy kandydat jest JEDEN.

    Nigdy nie łączymy dwóch prawdziwych numerów ZPRP (to robi człowiek
    wspólnym budżetem). Pomijamy kluby już w ręcznym budżecie (`taken`)
    i scalenia rozdzielone w panelu (`rejected`).

    `owner` - numer klubu -> klub GŁÓWNY jego budżetu (`member_map`).
    Zgłoszenie z 07.10.2026: drużyna Junior mł. bez numeru klubu została
    obok „MKS Olimpia Piekary Śląskie", bo pasowały do niej dwa numery
    (41 i 4927 - „Sp. z o.o."), choć oba są JEDNYM budżetem. Numery jednego
    budżetu liczą się teraz jako jeden kandydat - jego klub główny.
    """
    owner = owner or {}
    taken_set = {_s(club_id) for club_id in taken}
    rejected_set = {_s(club_id) for club_id in rejected}
    real: dict[str, set[str]] = {}
    fallback: dict[str, set[str]] = {}
    for club_id, name in teams:
        club = _s(club_id)
        base = club_base_key(key_of(name))
        if not club or not base:
            continue
        if club.startswith(FALLBACK_PREFIX):
            fallback.setdefault(club, set()).add(base)
        elif club != "OKREG":
            real.setdefault(base, set()).add(_s(owner.get(club)) or club)
    plan: dict[str, str] = {}
    for club, bases in fallback.items():
        if club in taken_set or club in rejected_set:
            continue
        targets: set[str] = set()
        for base in bases:
            targets |= real.get(base, set())
        if len(targets) == 1:
            plan[club] = next(iter(targets))
    return plan


def with_auto_groups(
    groups: list[dict[str, Any]], plan: Mapping[str, str]
) -> list[dict[str, Any]]:
    """
    Budżety ręczne + scalenia automatyczne, jedna lista dla wszystkich odbiorców.

    Klub docelowy w ręcznym budżecie - klub zastępczy dochodzi do TEGO budżetu.
    Inaczej powstaje grupa automatyczna (`budget_id` None, `auto` True) z klubem
    docelowym jako głównym. `auto_member_ids` mówi panelowi, które numery da się
    rozdzielić jednym kliknięciem.
    """
    out = [dict(group, member_ids=list(group.get("member_ids") or [])) for group in groups]
    owner = member_map(out)
    autos: dict[str, dict[str, Any]] = {}
    for fallback, target in sorted(plan.items()):
        primary = owner.get(target)
        if primary is not None:
            group = next(g for g in out if _s(g.get("primary_club_id")) == primary)
            if fallback not in group["member_ids"]:
                group["member_ids"].append(fallback)
                group.setdefault("auto_member_ids", []).append(fallback)
            continue
        group = autos.get(target)
        if group is None:
            group = {
                "budget_id": None,
                "name": None,
                "primary_club_id": target,
                "member_ids": [target],
                "auto": True,
                "auto_member_ids": [],
            }
            autos[target] = group
        group["member_ids"].append(fallback)
        group["auto_member_ids"].append(fallback)
    return out + list(autos.values())


def _money(value: Any) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def _solo(club: Mapping[str, Any]) -> dict[str, Any]:
    club_id = _s(club.get("club_id"))
    return {
        **club,
        "budget_id": None,
        "member_ids": [club_id],
        "members": [{"club_id": club_id, "name": club.get("name") or club_id, "present": True}],
        "mixed_settings": False,
        "auto_merged": False,
        "auto_member_ids": [],
    }


def merge_budgets(
    clubs: Mapping[str, Mapping[str, Any]],
    budgets: Iterable[Mapping[str, Any]],
    *,
    names: Optional[Mapping[str, str]] = None,
) -> dict[str, dict[str, Any]]:
    """
    Kluby sezonu (kształt z `province_clubs._season_clubs`) -> budżety.

    Klucz wyniku = numer klubu głównego. Członek bez meczu i wpisu w sezonie
    (brak w `clubs`) nie wnosi pieniędzy, ale zostaje na liście numerów -
    przełączniki budżetu mają zmieniać WSZYSTKICH członków.
    Budżet, którego żaden członek nie gra w sezonie, nie pojawia się wcale.
    """
    names = names or {}
    out: dict[str, dict[str, Any]] = {}
    grouped: set[str] = set()

    for budget in budgets:
        member_ids = [club_id for club_id in (budget.get("member_ids") or []) if club_id not in grouped]
        primary = _s(budget.get("primary_club_id"))
        if primary and primary not in member_ids and primary not in grouped:
            member_ids.insert(0, primary)
        if not member_ids:
            continue
        grouped.update(member_ids)
        present = [clubs[club_id] for club_id in member_ids if club_id in clubs]
        if not present:
            continue
        # Ustawienia z klubu głównego; gdy głównego nie ma w sezonie - z pierwszego obecnego.
        anchor = clubs.get(primary) or present[0]

        paid_in = money_sum(item.get("paid_in") for item in present)
        paid_out = money_sum(item.get("paid_out") for item in present)
        settled = money_sum(item.get("settled") for item in present)
        charged = money_sum(item.get("charged") for item in present)
        teams = sorted(
            (team for item in present for team in (item.get("teams") or [])),
            key=lambda team: _s(team.get("name")),
        )
        settles_set = {bool(item.get("settles_via_district", True)) for item in present}
        table_set = {int(item.get("table_by_club") or 0) for item in present}

        members = []
        for club_id in member_ids:
            club = clubs.get(club_id)
            members.append(
                {
                    "club_id": club_id,
                    "name": (club or {}).get("name") or names.get(club_id) or club_id,
                    "present": club is not None,
                    **(
                        {
                            "settles_via_district": bool(club.get("settles_via_district", True)),
                            "table_by_club": int(club.get("table_by_club") or 0),
                            "paid_in": club.get("paid_in", 0),
                            "paid_out": club.get("paid_out", 0),
                            "settled": club.get("settled", 0),
                            "charged": club.get("charged", 0),
                            "matches": club.get("matches", 0),
                            "balance": club.get("balance", 0),
                        }
                        if club is not None
                        else {}
                    ),
                }
            )

        key = primary or member_ids[0]
        name = _s(budget.get("name")) or _s((clubs.get(primary) or {}).get("name")) or names.get(primary) or _s(anchor.get("name")) or key
        out[key] = {
            **anchor,
            "club_id": key,
            "name": name,
            "teams": teams,
            "paid_in": paid_in,
            "paid_out": paid_out,
            "settled": settled,
            "charged": charged,
            "matches": sum(int(item.get("matches") or 0) for item in present),
            "balance": C.balance(paid_in=paid_in + settled, paid_out=paid_out, charged=charged),
            "budget_id": budget.get("budget_id"),
            "member_ids": member_ids,
            "members": members,
            "mixed_settings": len(settles_set) > 1 or len(table_set) > 1,
            # Scalenie automatyczne (06.10.2026): cała grupa albo dołączone numery.
            "auto_merged": bool(budget.get("auto")),
            "auto_member_ids": [
                club_id for club_id in (budget.get("auto_member_ids") or []) if club_id in member_ids
            ],
        }

    for club_id, club in clubs.items():
        if club_id in grouped:
            continue
        out[club_id] = _solo(club)
    return out
