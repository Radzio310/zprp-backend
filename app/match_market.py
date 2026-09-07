# app/match_market.py
#
# Giełda meczów - wymiana obsady między sędziami.
#
# Sędzia wystawia mecz albo zgłasza się na cudzy. Obsadowy widzi komplet
# chętnych i wybiera jednego. Dopiero jego decyzja rusza zapis w bazie związku -
# wykonany kontem okręgu, tym samym mechanizmem, którym posługuje się moduł
# obsadowego (`app/zprp/assignments.apply_referee_assignment`).
#
# Trzy zasady, na których to stoi:
#
#   1. NIC nie jedzie do ZPRP bez decyzji człowieka z uprawnieniem. Sędziowie
#      umawiają się między sobą, ale obsadę zmienia obsadowy.
#   2. Stan `applying` blokuje ofertę na czas zapisu. Zapis trwa kilka sekund na
#      cudzym serwerze i drugi obsadowy nie może w tym czasie wejść na to samo.
#   3. Zapis, który się nie potwierdził, jest porażką - a oferta wraca na
#      giełdę zamiast zniknąć z notatką „gotowe".
#
# Kolizje: liczymy tu WYŁĄCZNIE podwójny termin, czyli inny mecz tego samego
# sędziego tego samego dnia. Ta wiedza jest nasza i pewna. Niedyspozycje leżą w
# `silesia_offtimes.data_json` w kształcie, który definiuje aplikacja, a serwer
# trzyma jako nieprzejrzysty blob - zgadywanie go tutaj dałoby ostrzeżenia, za
# którymi nikt nie stoi. Ostrzeżenie o kalendarzu dokłada ekran, który ten
# format rozumie.

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from fastapi import APIRouter, Depends, HTTPException, Query
from httpx import AsyncClient
from pydantic import BaseModel
from sqlalchemy import and_, func, insert, or_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.db import (
    match_market_events,
    database,
    match_market_claims,
    match_market_offers,
    province_judges,
    push_tokens,
    province_match_assignability,
    province_matches,
    province_module_config,
)
from app.deps import Settings, get_jwt_payload, get_settings
from app.match_market_journal import (
    config_diff_message,
    kinds_in_group,
)
from app.match_market_notify import (
    apply_failed as text_apply_failed,
    conflict_sentence,
    claim_created as text_claim_created,
    claim_impossible as text_claim_impossible,
    claim_lost as text_claim_lost,
    crew_changed as text_crew_changed,
    giver_released as text_giver_released,
    offer_created as text_offer_created,
    offer_rejected as text_offer_rejected,
    offer_withdrawn as text_offer_withdrawn,
    taker_won as text_taker_won,
)
from app.match_market_access import (
    APPROVER_BADGE,
    approver_judge_ids,
    badge_names,
    may_approve,
    may_manage_config,
    normalize_approver_badges,
)
from app.match_market_rules import (
    ASSIGNABILITY_TTL_HOURS,
    apply_known_swaps,
    DEFAULT_DEADLINE_HOURS,
    FIELD_SLOTS,
    LIVE_CREW_BUDGET_SECONDS,
    LIVE_CREW_LIMIT,
    LIVE_CREW_NOTE,
    LIVE_CREW_REQUEST_SECONDS,
    PROBE_BATCH_LIMIT,
    SLOT_STATE_FIELDS,
    assignability_is_fresh,
    assignability_message,
    can_offer,
    clean_match_ids,
    crew_is_fresh,
    crew_judge_ids,
    crew_label,
    deadline_for,
    is_managed_by_province,
    league_level,
    live_check_order,
    managed_prefixes_for,
    market_pushes_allowed,
    may_claim,
    names_match,
    next_claim_status,
    next_offer_status,
    normalize_deadline_hours,
    normalize_prefixes,
    offerable_slots,
    past_season,
    roles_held_by,
    season_label,
    season_start_year,
    slot_holder_name,
    slot_is_tradeable,
    slot_label,
    slot_select_name,
    slots_held_by,
    state_dict,
    with_slot_holder,
)
from app.proel_auth import is_admin
from app.push.push import send_push_to_judges
from app.zprp.assignments import (
    SELECT_TO_SLOT,
    _login_zprp,
    apply_referee_assignment,
    probe_assignment_rights,
    walk_judge_route,
    zprp_season_label,
)
from app.zprp_accounts import account_status, assign_credentials, normalize_province

logger = logging.getLogger("app.match_market")

router = APIRouter(prefix="/match-market", tags=["Giełda meczów"])


# ─────────────────────────── pomocnicze ───────────────────────────


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _s(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _row(row: Any) -> Dict[str, Any]:
    return dict(row._mapping) if hasattr(row, "_mapping") else dict(row or {})


def _iso(value: Any) -> Optional[str]:
    return value.isoformat() if isinstance(value, datetime) else None


class Actor:
    """Kto pyta - złożony z podpisanego tokenu i z listy sędziów okręgu.

    Województwo bierzemy z `province_judges`, a NIE z tokenu. To pierwsze
    ustawia administrator okręgu, to drugie użytkownik sam sobie w ustawieniach
    aplikacji - a od województwa zależy tutaj i widok giełdy, i prawo do
    zatwierdzania cudzej obsady.
    """

    def __init__(self, payload: Dict[str, Any], row: Optional[Dict[str, Any]], admin: bool):
        self.judge_id = _s(payload.get("judge_id"))
        self.account_type = _s(payload.get("account_type"))
        self.is_admin = bool(admin)
        self.province = normalize_province((row or {}).get("province"))
        self.full_name = _s((row or {}).get("full_name"))
        self.photo_url = _s((row or {}).get("photo_url"))
        self.badges = (row or {}).get("badges")
        self.known = row is not None

async def market_actor(payload: Dict[str, Any] = Depends(get_jwt_payload)) -> Actor:
    judge_id = _s(payload.get("judge_id"))
    if not judge_id:
        raise HTTPException(403, "Ten token nie niesie numeru sędziego.")
    row = await database.fetch_one(
        select(
            province_judges.c.judge_id,
            province_judges.c.full_name,
            province_judges.c.province,
            province_judges.c.photo_url,
            province_judges.c.badges,
        ).where(province_judges.c.judge_id == judge_id)
    )
    return Actor(payload, _row(row) if row else None, await is_admin(judge_id))


def _require_province(actor: Actor) -> str:
    if not actor.province:
        raise HTTPException(
            403,
            "Nie ma Cię na liście sędziów okręgu, więc giełda nie wie, do którego "
            "województwa Cię przypisać. Zgłoś to administratorowi okręgu.",
        )
    return actor.province


async def _config(province: str) -> Dict[str, Any]:
    """Ustawienia okręgu; brak wiersza znaczy moduł WYŁĄCZONY."""
    row = await database.fetch_one(
        select(province_module_config).where(province_module_config.c.province == province)
    )
    data = _row(row) if row else {}
    return {
        "province": province,
        "market_enabled": bool(data.get("market_enabled", False)),
        "offer_deadline_hours": normalize_deadline_hours(
            data.get("offer_deadline_hours", DEFAULT_DEADLINE_HOURS)
        ),
        "assign_account_mode": _s(data.get("assign_account_mode")) or "own",
        "approver_badges": normalize_approver_badges(data.get("approver_badges")),
        # Mecze spoza obsady okręgu - patrz sekcja „Poziom rozgrywek" w liściu
        # reguł. Wymiana domyślnie WYŁĄCZONA; lista lig powierzonych z panelu
        # albo z katalogu domyślnego (`managed_prefixes_custom` mówi, która).
        "foreign_matches_enabled": bool(data.get("foreign_matches_enabled", False)),
        "managed_prefixes": managed_prefixes_for(province, data.get("managed_prefixes")),
        "managed_prefixes_custom": normalize_prefixes(data.get("managed_prefixes")) is not None,
    }


async def _require_enabled(province: str) -> Dict[str, Any]:
    cfg = await _config(province)
    if not cfg["market_enabled"]:
        raise HTTPException(
            403,
            "Giełda meczów nie jest jeszcze włączona w Twoim okręgu.",
        )
    return cfg


async def _judges_by_id(judge_ids: List[str]) -> Dict[str, Dict[str, Any]]:
    """Wizytówki sędziów - nazwisko i zdjęcie do kafla."""
    ids = sorted({_s(j) for j in judge_ids if _s(j)})
    if not ids:
        return {}
    rows = await database.fetch_all(
        select(
            province_judges.c.judge_id,
            province_judges.c.full_name,
            province_judges.c.province,
            province_judges.c.photo_url,
            province_judges.c.badges,
        ).where(province_judges.c.judge_id.in_(ids))
    )
    return {_s(_row(r)["judge_id"]): _row(r) for r in rows}


def _person(judge_id: str, card: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    data = card or {}
    return {
        "judgeId": _s(judge_id),
        "fullName": _s(data.get("full_name")),
        "photoUrl": _s(data.get("photo_url")),
    }


def _match_view(state: Dict[str, Any], match_at: Any) -> Dict[str, Any]:
    """Mecz sprowadzony do tego, co widać na kaflu."""
    state = state_dict(state)
    hall = " ".join(
        p for p in (_s(state.get("Hala_nazwa")), _s(state.get("Hala_miasto"))) if p
    )
    return {
        "matchCode": _s(state.get("RozgrywkiCode")),
        "hostTeam": _s(state.get("ID_zespoly_gosp_ZespolNazwa")),
        "guestTeam": _s(state.get("ID_zespoly_gosc_ZespolNazwa")),
        "matchAt": _iso(match_at),
        "hall": hall,
        "season": _s(state.get("season")),
        "crew": {
            key: _s(state.get(field))
            for key, field in (
                ("sedzia1", "NrSedzia_pierwszy_nazwisko"),
                ("sedzia2", "NrSedzia_drugi_nazwisko"),
                ("sekretarz", "NrSedzia_sekretarz_nazwisko"),
                ("czas", "NrSedzia_czas_nazwisko"),
                ("delegat", "NrSedzia_delegat_nazwisko"),
            )
        },
    }


def _holds_any_role(state: Dict[str, Any], judge_id: str, full_name: str) -> bool:
    """Czy ten sedzia jest przy tym meczu w JAKIEJKOLWIEK roli.

    Katalog rol (gniazda gieldy PLUS delegaci) i porzadek "numer przed
    nazwiskiem" mieszkaja w lisciu: `roles_held_by`. Dwa katalogi rol w jednym
    module rozjechalyby sie przy pierwszej poprawce - a stad bierze sie i
    kolizja terminarza, i rygiel zgloszenia na wlasny mecz.
    """
    return bool(roles_held_by(state, judge_id, full_name))


async def _roles_of(
    province: str,
    match_ids: List[str],
    judge_id: str,
    full_name: str,
) -> Dict[str, str]:
    """Rola TEGO sędziego w tych meczach - podpis roli albo pusto.

    Giełda nie ma prawa proponować „Biorę" na mecz, który sędzia już prowadzi:
    partner wystawia DRUGIE gniazdo tego samego spotkania, a jeden człowiek nie
    stanie w dwóch. Kafel ma to powiedzieć od razu, zamiast odmowy po
    dotknięciu - a serwer i tak odmawia, bo o tym decyduje `create_claim`.

    Czytamy migawkę terminarza z pamięcią własnych wymian giełdy, tą samą
    drogą, co lista „moich meczów" i kolizje - jedno pojęcie „mam ten mecz".
    """
    wanted = [_s(m) for m in match_ids if _s(m)]
    if not wanted:
        return {}
    rows = await database.fetch_all(
        select(province_matches.c.match_id, province_matches.c.state_json)
        .where(province_matches.c.province == province)
        .where(province_matches.c.match_id.in_(wanted))
    )
    states = {_s(_row(r)["match_id"]): state_dict(_row(r).get("state_json")) for r in rows}
    swaps = await _applied_swaps(province, list(states))
    out: Dict[str, str] = {}
    for match_id, state in states.items():
        roles = roles_held_by(
            apply_known_swaps(state, swaps.get(match_id, ())),
            judge_id,
            full_name,
        )
        if roles:
            out[match_id] = crew_label(roles[0])
    return out


async def _viewer_roles(
    province: str,
    match_ids: List[str],
    actor: Actor,
) -> Dict[str, str]:
    """Rola PYTAJĄCEGO w tych meczach - `_roles_of` dla człowieka z tokenu."""
    return await _roles_of(province, match_ids, actor.judge_id, actor.full_name)


async def _same_day_matches(
    province: str,
    judges: Dict[str, str],
    match_at: Optional[datetime],
    skip_match_id: str,
) -> Dict[str, List[Dict[str, str]]]:
    """Inne mecze tych sędziów w TYM dniu - jedyna kolizja, której jesteśmy pewni.

    Czytamy TERMINARZ okręgu, a nie `province_match_judges`. Tamta tabela
    powstaje wyłącznie dla sędziów z zarejestrowanym tokenem push (monitor
    pobiera listy meczów tylko im), więc sędzia, który odmówił powiadomień,
    ZAWSZE wychodził „bez kolizji" - a obsadowy czytał to jako zgodę i wsadzał
    go na drugi mecz tego dnia. Terminarz jest niezależny od tego, kto ma
    aplikację; o obecności rozstrzyga stan meczu, tak samo jak przy „moich
    meczach" (patrz nota w `my_matches`).

    Dzień liczymy w dobie kalendarzowej UTC. Mecze okręgowe grają się po
    południu, więc przesunięcie strefy nie ma jak przenieść meczu na sąsiedni
    dzień - a doba to i tak przybliżenie: dwa mecze o 10:00 i o 20:00 w różnych
    halach są kolizją dla człowieka, choć zegar ich nie wyklucza.
    """
    wanted = {_s(j): _s(n) for j, n in (judges or {}).items() if _s(j)}
    if not wanted or match_at is None:
        return {}
    day_start = match_at.replace(hour=0, minute=0, second=0, microsecond=0)
    rows = await database.fetch_all(
        select(
            province_matches.c.match_id,
            province_matches.c.match_code,
            province_matches.c.match_at,
            province_matches.c.state_json,
        )
        .where(province_matches.c.province == province)
        .where(province_matches.c.active.is_(True))
        .where(province_matches.c.match_id != _s(skip_match_id))
        .where(province_matches.c.match_at >= day_start)
        .where(province_matches.c.match_at < day_start + timedelta(days=1))
    )
    # Wymiany zapisane przez giełdę nakładamy tak samo, jak na liście „moich
    # meczów". Właśnie tu jest to najważniejsze: sędzia bierze mecz przez
    # giełdę, a chwilę później zgłasza się na drugi tego samego dnia - i to
    # pierwszy mecz miałby ostrzec obsadowego, gdyby migawka o nim wiedziała.
    swaps = await _applied_swaps(province, [_s(_row(r)["match_id"]) for r in rows])
    out: Dict[str, List[Dict[str, str]]] = {}
    for raw in rows:
        data = _row(raw)
        state = apply_known_swaps(
            state_dict(data.get("state_json")),
            swaps.get(_s(data["match_id"]), ()),
        )
        card = {
            "matchId": _s(data["match_id"]),
            "matchCode": _s(data.get("match_code")),
            "matchAt": _iso(data.get("match_at")),
            "hall": _s(state.get("Hala_miasto")),
        }
        for judge_id, full_name in wanted.items():
            if _holds_any_role(state, judge_id, full_name):
                out.setdefault(judge_id, []).append(card)
    return out


# ───────────────────────── uprawnienia okregu ────────────────────────
#
# Sedzia widzi w aplikacji wszystkie swoje mecze, ale okreg obsadza tylko czesc
# z nich. Superlige, ligi centralne i turnieje mlodziezowe obsadza zwiazek i
# konto wojewodzkie nie ma tam czego kliknac. Taki mecz nie ma prawa trafic na
# gielde: umowa dwoch sedziow rozbilaby sie dopiero o zapis, juz PO decyzji
# obsadowego i po tym, jak oddajacy przestal szukac zastepstwa gdzie indziej.
#
# Pytanie zadajemy wprost bazie zwiazku, tym samym formularzem, ktorym potem
# zapisujemy - a odpowiedz trzymamy w `province_match_assignability`, bo kazde
# sprawdzenie to osobne wejscie na ich serwer.


#: Ile sond chodzi naraz w jednej sesji.
#:
#: Trojka, nie dziesiatka: po drugiej stronie stoi wysluzony serwis PHP, ktory
#: obsluguje caly polski zwiazek, a my jestesmy tam gosciem. Przy limicie 12
#: meczow daje to cztery rundy - wolniej niz musi, ale bez ryzyka, ze nasza
#: aplikacja pojawi sie w ich logach jako zrodlo klopotow.
_PROBE_CONCURRENCY = 3

#: Jak daleko w przod siega lista „moich meczow".
#:
#: Cztery miesiace to caly rundowy horyzont okregu. Dalej i tak nie ma czego
#: oddawac, a kazdy dodatkowy tydzien to wiecej stanow meczow do przejrzenia.
MY_MATCHES_HORIZON_DAYS = 120

#: Ile wierszy BEZ numerow sedziow przegladamy, szukajac swoich po nazwisku.
#:
#: Wiersze z numerami znajduje samo zapytanie (`->>` po gniazdach), bez limitu.
#: Ten bezpiecznik dotyczy tylko resztki z lekkiego przebiegu monitora, ktorej
#: glebokie sprawdzenie jeszcze nie doszlo - garstki, nie terminarza. Zapytania
#: pod nim maja stala kolejnosc: limit bez `ORDER BY` oddawal ROZNE wiersze przy
#: kolejnych wolaniach i ten sam mecz raz byl na liscie, raz nie.
MY_MATCHES_SCAN_LIMIT = 600

#: Co mówimy o meczu, za który ręczy telefon, a którego związek nie potwierdził.
#:
#: Nie „nie masz tego meczu" - tego nie wiemy. Wiemy tylko, że publiczne API nie
#: odpowiedziało w wyznaczonym czasie, a to jest wiadomość o AWARII PO DRUGIEJ
#: STRONIE, nie o obsadzie.
UNCONFIRMED_NOTE = (
    "Nie potwierdziliśmy w bazie związku, czy ten mecz jest Twój - "
    "związek nie odpowiedział na czas. Sprawdź go jeszcze raz."
)

#: Ile czekamy na obsadę JEDNEGO meczu przy ponownym sprawdzeniu.
#:
#: Wspólny budżet listy dzieli się na kilkadziesiąt meczów, więc ten, który
#: sędzia właśnie chce oddać, przegrywał wyścig z resztą terminarza. Tu pytanie
#: jest jedno i ma prawo potrwać.
RECHECK_BUDGET_SECONDS = 25.0


def _verdict_view(row: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Werdykt sondy w postaci, ktora rozumie ekran."""
    if not row:
        return {"assignable": None, "reason": "UNCHECKED", "message": "", "checkedAt": None}
    reason = _s(row.get("reason")) or ("OK" if row.get("assignable") else "NO_FORM")
    return {
        "assignable": bool(row.get("assignable")),
        "reason": reason,
        "message": "" if row.get("assignable") else assignability_message(reason),
        "checkedAt": _iso(row.get("checked_at")),
    }


def _probe_view(verdict: Dict[str, Any]) -> Dict[str, Any]:
    """Swieza odpowiedz sondy w tym samym ksztalcie, co werdykt z pamieci.

    NIEUDANA sonda to NIE odmowa. `_store_verdict` z tego samego powodu nie
    zapisuje PROBE_FAILED do pamieci - zerwana odpowiedz zablokowalaby mecz na
    cala dobe. Tu jest to samo w skali jednej odpowiedzi: mecz zostaje
    NIEROZSTRZYGNIETY (`assignable: None`), a nie "poza gielda". Inaczej jedno
    potkniecie serwera zwiazku kasowalo cala liste meczow do oddania, choc
    nikt nie stwierdzil, ze okreg ich nie obsadza. O wystawieniu decyduje i tak
    twarda bramka `_require_assignable` przy `POST /offers`, ktora sonduje ten
    JEDEN mecz od nowa i odmawia po ludzku.
    """
    reason = _s(verdict.get("reason")) or (
        "OK" if verdict.get("assignable") else "NO_FORM"
    )
    if reason == "PROBE_FAILED":
        return {
            "assignable": None,
            "reason": reason,
            "message": _s(verdict.get("message")) or assignability_message(reason),
            "checkedAt": None,
        }
    ok = bool(verdict.get("assignable"))
    return {
        "assignable": ok,
        "reason": reason,
        "message": "" if ok else (_s(verdict.get("message")) or assignability_message(reason)),
        "checkedAt": _s(verdict.get("fetched_at")) or None,
    }


async def _cached_verdicts(
    province: str, match_ids: List[str], mode: str, now: datetime
) -> Dict[str, Dict[str, Any]]:
    """Swieze werdykty z pamieci podrecznej, po jednym na mecz.

    Werdykt wydany INNYM trybem konta pomijamy: przelaczenie okregu z konta
    obsadowego na monitorowe zmienia zakres uprawnien, wiec stara odpowiedz
    przestaje dotyczyc tego, o co pytamy.
    """
    ids = sorted({_s(m) for m in match_ids if _s(m)})
    if not ids:
        return {}
    rows = await database.fetch_all(
        select(province_match_assignability)
        .where(province_match_assignability.c.province == province)
        .where(province_match_assignability.c.match_id.in_(ids))
    )
    out: Dict[str, Dict[str, Any]] = {}
    for raw in rows:
        data = _row(raw)
        if _s(data.get("account_mode")) != _s(mode):
            continue
        if not assignability_is_fresh(data.get("checked_at"), now, ASSIGNABILITY_TTL_HOURS):
            continue
        out[_s(data["match_id"])] = data
    return out


async def _store_verdict(
    province: str, match_id: str, mode: str, verdict: Dict[str, Any]
) -> None:
    """Zapisuje odpowiedz sondy. Awarii sieci NIE zapisujemy.

    Werdykt "nie udalo sie sprawdzic" wygladalby w pamieci tak samo jak "okreg
    tego nie obsadza" i blokowalby mecz na cala dobe z powodu jednej zerwanej
    odpowiedzi.
    """
    if _s(verdict.get("reason")) in ("PROBE_FAILED", "NOT_ON_LIST"):
        # NOT_ON_LIST mówi o LIŚCIE SĘDZIEGO z chwili pytania - obsada może
        # wejść do bazy związku za godzinę. Zapamiętana odmowa blokowałaby
        # mecz na dobę bez pytania; niech sonda spyta jeszcze raz.
        return
    values = {
        "assignable": bool(verdict.get("assignable")),
        "reason": _s(verdict.get("reason")) or "OK",
        "holder": _s(verdict.get("holder")) or None,
        "account_mode": _s(mode),
        "checked_at": _now(),
    }
    # Upsert jedna instrukcja, jak w monitorze meczow i w `admin.py`. Dwie sondy
    # potrafia trafic na ten sam mecz w tej samej sekundzie - przy zapisie w
    # dwoch krokach jedna z nich przewrocilaby sie o unikat klucza glownego.
    await database.execute(
        pg_insert(province_match_assignability)
        .values(province=province, match_id=_s(match_id), **values)
        .on_conflict_do_update(
            index_elements=[
                province_match_assignability.c.province,
                province_match_assignability.c.match_id,
            ],
            set_=values,
        )
    )


async def _probe(
    province: str,
    mode: str,
    creds: Dict[str, Any],
    match_ids: List[str],
    settings: Settings,
    *,
    slot: str = "",
    store: bool = True,
    walk_ids: Optional[Set[str]] = None,
    giver_id: str = "",
) -> Dict[str, Dict[str, Any]]:
    """Pyta baze zwiazku o wskazane mecze - jedno logowanie na cala paczke.

    Mecze z `walk_ids` (spoza obsady okregu) ida TRASA SEDZIEGO: lista meczow
    oddajacego (`giver_id`) -> strona meczu -> formularz - ta sama droga, ktora
    pojdzie zapis. Odmowa na trasie ma wlasny kod (NOT_ON_LIST / NO_FORM).

    `slot` zawezza pytanie do JEDNEGO gniazda. Bez niego sonda uznaje mecz za
    obsadzalny, gdy okreg ma liste sedziow przy DOWOLNYM gniazdzie - a wymienia
    sie konkretne, wiec pusta lista przy "czasie" wychodzila dopiero przy
    zapisie, po umowie dwoch osob. Odpowiedzi na pytanie o gniazdo NIE
    zapisujemy (`store=False`): pamiec jest kluczowana meczem, a "nie ma listy
    przy czasie" nie znaczy "okreg nie obsadza tego meczu".
    """
    targets = [_s(m) for m in match_ids if _s(m)]
    if not targets:
        return {}
    out: Dict[str, Dict[str, Any]] = {}
    gate = asyncio.Semaphore(_PROBE_CONCURRENCY)
    walking = {_s(m) for m in (walk_ids or ()) if _s(m)}
    # Lista meczow sedziego jest jedna na sedziego - trasa dzieli ja miedzy
    # jego mecze zamiast pobierac przy kazdym od nowa.
    pages: Dict[str, Any] = {}
    season = zprp_season_label(_now())

    try:
        async with AsyncClient(
            base_url=settings.ZPRP_BASE_URL, follow_redirects=True, timeout=45.0
        ) as client:
            cookies = await _login_zprp(client, creds["username"], creds["password"])

            async def ask(match_id: str) -> Dict[str, Any]:
                """Sonda jednego meczu: prosto do formularza albo trasa sedziego."""
                user = ""
                referer = ""
                if match_id in walking:
                    route = await walk_judge_route(
                        client,
                        cookies,
                        judge_id=giver_id,
                        id_zawody=match_id,
                        season_label=season,
                        page_cache=pages,
                        log_prefix=f"gielda/trasa/{province}",
                    )
                    if not route["ok"]:
                        return {
                            "assignable": False,
                            "reason": _s(route.get("reason")) or "NO_FORM",
                            "message": _s(route.get("message")),
                            "holder": "",
                        }
                    user = _s(route.get("user"))
                    referer = _s(route.get("detail_path"))
                return await probe_assignment_rights(
                    client,
                    cookies,
                    match_id,
                    slot=slot,
                    user=user,
                    referer=referer,
                    log_prefix=f"gielda/sonda/{province}",
                )

            async def one(match_id: str) -> None:
                async with gate:
                    try:
                        verdict = await ask(match_id)
                    except Exception as exc:  # noqa: BLE001
                        logger.warning("gielda: sonda %s nieudana: %s", match_id, exc)
                        verdict = {
                            "assignable": False,
                            "reason": "PROBE_FAILED",
                            "message": assignability_message("PROBE_FAILED"),
                            "holder": "",
                        }
                    out[match_id] = verdict
                    if store:
                        await _store_verdict(province, match_id, mode, verdict)

            # Mecze idace trasa sedziego po kolei: pierwszy pobiera liste
            # sedziego, nastepne biora ja z `pages`. Reszta rownolegle.
            async def walk_all() -> None:
                for match_id in targets:
                    if match_id in walking:
                        await one(match_id)

            await asyncio.gather(
                walk_all(), *(one(m) for m in targets if m not in walking)
            )
    except Exception as exc:  # noqa: BLE001
        # Nie udalo sie nawet zalogowac - zaden mecz nie zostaje rozstrzygniety.
        logger.warning("gielda: logowanie konta obsadowego %s nieudane: %s", province, exc)
        failed = {
            "assignable": False,
            "reason": "PROBE_FAILED",
            "message": assignability_message("PROBE_FAILED"),
            "holder": "",
        }
        return {m: dict(failed) for m in targets}
    return out


async def _require_assignable(
    province: str,
    cfg: Dict[str, Any],
    match_id: str,
    settings: Settings,
    *,
    slot: str = "",
    walk: bool = False,
    giver_id: str = "",
) -> None:
    """Twarda bramka przed wystawieniem meczu. Odmowa mowi, dlaczego.

    `walk` = mecz spoza obsady okregu: sonda idzie trasa sedziego (`giver_id`),
    ta sama, ktora pojdzie zapis przy zatwierdzeniu.

    Zapamietane NIE dotyczy calego meczu i wystarcza, zeby odmowic bez pytania.
    Zapamietane TAK mowi jednak o MECZU, a wymieniamy GNIAZDO - dlatego przy
    wystawianiu pytamy jeszcze raz, wprost o to gniazdo. To jedno wejscie na
    strone zwiazku przy czynnosci, ktora sedzia wykonuje kilka razy w sezonie, i
    tanszy blad niz "zapisu nie ma jak wykonac" odkryty po umowie dwoch osob.
    """
    creds = assign_credentials(province, cfg["assign_account_mode"])
    if not creds["configured"]:
        raise HTTPException(409, assignability_message("NO_ACCOUNT"))

    mode = _s(creds["mode"])
    cached = await _cached_verdicts(province, [match_id], mode, _now())
    verdict = cached.get(_s(match_id))
    if verdict is not None and not verdict.get("assignable"):
        raise HTTPException(409, assignability_message(verdict.get("reason")))

    fresh = await _probe(
        province,
        mode,
        creds,
        [_s(match_id)],
        settings,
        slot=_s(slot),
        store=not _s(slot),
        walk_ids={_s(match_id)} if walk else None,
        giver_id=giver_id,
    )
    answer = fresh.get(_s(match_id)) or {}
    if answer.get("assignable"):
        return
    raise HTTPException(
        409, _s(answer.get("message")) or assignability_message(answer.get("reason"))
    )


# ─────────────────────────── migawka terminarza ───────────────────────────


async def _applied_swaps(province: str, match_ids: List[str]) -> Dict[str, List[Dict[str, Any]]]:
    """Wymiany zapisane w bazie związku, po meczach - od najstarszej.

    Własna pamięć giełdy o tym, kto komu oddał gniazdo. Migawka terminarza
    dowiaduje się o tym od monitora, więc bywa o kilkanaście minut z tyłu; ta
    tabela wie od razu, bo to ona zamawiała zapis. Bierzemy tylko wymiany
    POTWIERDZONE w ZPRP (`status="done"`, `applied_at`) - zamówienie, które nie
    przeszło, nic o obsadzie nie mówi.
    """
    if not match_ids:
        return {}
    rows = await database.fetch_all(
        select(
            match_market_offers.c.match_id,
            match_market_offers.c.slot,
            match_market_offers.c.from_judge_id,
            match_market_claims.c.judge_id.label("to_judge_id"),
        )
        .select_from(
            match_market_offers.join(
                match_market_claims,
                and_(
                    match_market_claims.c.offer_id == match_market_offers.c.id,
                    match_market_claims.c.status == "chosen",
                ),
            )
        )
        .where(match_market_offers.c.province == province)
        .where(match_market_offers.c.status == "done")
        .where(match_market_offers.c.applied_at.isnot(None))
        .where(match_market_offers.c.match_id.in_(match_ids))
        .order_by(match_market_offers.c.applied_at.asc())
    )
    if not rows:
        return {}
    # Nazwiska, bo migawka z lekkiego przebiegu monitora nie ma numerów i
    # rygiel „w gnieździe stoi oddający" ma wtedy tylko nazwisko do porównania.
    cards = await _judges_by_id(
        [_s(_row(r)["from_judge_id"]) for r in rows]
        + [_s(_row(r)["to_judge_id"]) for r in rows]
    )
    out: Dict[str, List[Dict[str, Any]]] = {}
    for raw in rows:
        row = _row(raw)
        match_id = _s(row["match_id"])
        giver = _s(row["from_judge_id"])
        taker = _s(row["to_judge_id"])
        out.setdefault(match_id, []).append(
            {
                "slot": _s(row["slot"]),
                "from_judge_id": giver,
                "from_name": _s((cards.get(giver) or {}).get("full_name")),
                "to_judge_id": taker,
                "to_name": _s((cards.get(taker) or {}).get("full_name")),
            }
        )
    return out


async def _sync_slot_holder(
    province: str,
    match_id: str,
    slot: str,
    judge_id: str,
    full_name: str,
) -> Dict[str, Any]:
    """Wpisuje nowego gospodarza gniazda do migawki terminarza okręgu.

    Zapis w bazie związku właśnie przeszedł, ale `province_matches.state_json`
    wypełnia monitor przy własnym przebiegu - i do tej chwili giełda pokazywała
    STARY stan gniazda. Sędzia, który mecz odzyskał wymianą w drugą stronę, nie
    widział go na liście „Oddaj mecz", bo `slots_held_by` czytało tam
    poprzednika, a lista nie miała nawet czego wygasić: wiersz po prostu nie
    powstawał. Migawkę poprawia więc ta czynność, która ją unieważniła.

    Oddaje poprawiony stan meczu - albo pusty słownik, gdy nie było czego
    poprawić. Całość jest osłonięta, bo obsada w ZPRP jest już zmieniona:
    nieudane odświeżenie WŁASNEJ kopii nie ma prawa zamienić udanej wymiany w
    błąd. Monitor doczyta prawdę przy najbliższym przebiegu.

    Odcisk stanu liczymy od nowa świadomie. Monitor po nim poznaje, czy jest o
    czym powiadamiać obsadę - a o TEJ zmianie giełda mówi sama, w chwili, w
    której się dzieje. Zostawiony stary odcisk kazałby ogłosić ją drugi raz.
    """
    try:
        row = await database.fetch_one(
            select(province_matches.c.state_json).where(
                and_(
                    province_matches.c.province == province,
                    province_matches.c.match_id == match_id,
                )
            )
        )
        state = state_dict(_row(row).get("state_json")) if row else {}
        if not state:
            return {}
        patched = with_slot_holder(state, slot, judge_id, full_name)
        # Import lokalny: monitor ciągnie za sobą scraper z bs4 i httpx, a
        # router giełdy nie ma powodu budzić go przy starcie aplikacji.
        from app.province_match_monitor import fingerprint

        await database.execute(
            update(province_matches)
            .where(
                and_(
                    province_matches.c.province == province,
                    province_matches.c.match_id == match_id,
                )
            )
            .values(
                state_json=patched,
                fingerprint=fingerprint(patched),
                updated_at=func.now(),
            )
        )
        return patched
    except Exception:
        logger.exception("giełda: nie udało się odświeżyć migawki meczu %s", match_id)
        return {}


#: Ile pytań do publicznego API idzie naraz przy sprawdzaniu obsady na żywo.
#:
#: Szóstka jak w monitorze - ta sama grzeczność wobec tego samego serwera
#: związku. Przy sześćdziesięciu meczach to dziesięć rund, a odpowiedzi
#: przychodzą w ułamkach sekundy.
_LIVE_CONCURRENCY = 6


def _row_from_state(state: Dict[str, Any]) -> Dict[str, Any]:
    """Kolumny wiersza terminarza wyliczone z żywego stanu meczu.

    Te same reguły, którymi monitor wypełnia wiersz przy zapisie - inaczej
    lista liczyłaby próg czasowy od innej daty niż ta, którą właśnie dostała.
    """
    # Import lokalny - ten sam powód, co w `_sync_slot_holder`.
    from app.province_match_monitor import parse_match_at

    return {
        "match_code": _s(state.get("RozgrywkiCode")) or None,
        "match_at": parse_match_at(state.get("data_fakt") or state.get("data_prop")),
        "approved": _s(state.get("protocol_status")) == "approved",
        "state_json": state,
    }


async def _live_crews(
    province: str,
    actor: Actor,
    bases: Dict[str, Dict[str, Any]],
    known: Set[str],
    vouched: Set[str],
    budget: float = LIVE_CREW_BUDGET_SECONDS,
) -> Tuple[Dict[str, Dict[str, Any]], List[str]]:
    """Obsada TYCH meczów z bazy związku w tej chwili - i jej ślad w migawce.

    `bases` to migawki, na które nakłada się odpowiedź publicznego API tą samą
    regułą, co w monitorze (`_api_to_state`: puste pole nie kasuje, numer „0"
    kasuje całą parę). Zwraca żywe stany i numery meczów bez odpowiedzi. Czas
    jest ograniczony budżetem: co doszło - jest żywe, reszta wraca do migawki
    i zostaje PODPISANA jako ostatni znany stan. Pytanie o cudzą obsadę przy
    otwartym ekranie nie ma prawa trwać pół minuty.

    Utrwalenie idzie tą samą funkcją, którą pisze monitor, więc migawka okręgu
    zdrowieje przy okazji, a obsada dostaje te same powiadomienia, które
    dostałaby z jego przebiegu - tylko wcześniej. Nowy wiersz powstaje wyłącznie
    dla meczu, za którym ręczy telefon (`vouched`) I w którym sędzia naprawdę
    stoi w gnieździe: numer przysłany z aplikacji to nie dowód, obsada z bazy
    związku - tak. Zapis jest osłonięty: odpowiedź dla sędziego nie zależy od
    tego, czy kopia się udała.
    """
    if not bases:
        return {}, []
    # Import lokalny - ten sam powód, co w `_sync_slot_holder`.
    from app.province_match_monitor import _api_to_state, _fetch_public_details, _upsert_match

    fresh: Dict[str, Dict[str, Any]] = {}
    semaphore = asyncio.Semaphore(_LIVE_CONCURRENCY)

    async def one(client: AsyncClient, match_id: str, base: Dict[str, Any]) -> None:
        async with semaphore:
            payload = await _fetch_public_details(
                client, match_id, timeout=LIVE_CREW_REQUEST_SECONDS, retries=1
            )
        state = _api_to_state(payload or {}, base)
        if state:
            fresh[match_id] = state

    async with AsyncClient(follow_redirects=True) as client:
        tasks = [
            asyncio.ensure_future(one(client, match_id, base))
            for match_id, base in bases.items()
        ]
        _done, pending = await asyncio.wait(tasks, timeout=budget)
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
    failed = [match_id for match_id in bases if match_id not in fresh]

    for match_id, state in fresh.items():
        holds = bool(slots_held_by(state, actor.judge_id, actor.full_name))
        if match_id not in known and not (match_id in vouched and holds):
            continue
        try:
            await _upsert_match(
                province,
                match_id,
                state,
                True,
                # Lista z telefonu to ta sama prywatna lista sędziego, z której
                # czyta lekki przebieg - i tak samo jak on ręczy, że mecz żyje.
                # Sama odpowiedź API takim dowodem nie jest (patrz `_upsert_match`).
                seen_in_schedule=match_id in vouched and holds,
            )
        except Exception:  # noqa: BLE001
            logger.exception("giełda: nie udało się utrwalić żywej obsady meczu %s", match_id)
    return fresh, failed


# ─────────────────────────── powiadomienia ───────────────────────────


async def _log(
    kind: str,
    *,
    province: str,
    actor: Optional[Actor] = None,
    offer: Optional[Dict[str, Any]] = None,
    subject_id: str = "",
    subject_name: str = "",
    ok: Optional[bool] = None,
    message: str = "",
    payload: Optional[Dict[str, Any]] = None,
) -> None:
    """Dopisuje wiersz do dziennika giełdy.

    NIGDY nie przewraca czynności, którą opisuje. Dziennik jest świadkiem, nie
    stroną: gdyby zapis wpisu potrafił wywrócić zatwierdzenie wymiany, obsada w
    bazie związku byłaby już zmieniona, a telefon dostałby błąd i kazał
    próbować drugi raz. Potknięcie dziennika idzie więc do logu serwera.
    """
    try:
        await database.execute(
            insert(match_market_events).values(
                province=province,
                offer_id=int(offer["id"]) if offer and offer.get("id") is not None else None,
                match_id=_s((offer or {}).get("match_id")) or None,
                match_code=_s((offer or {}).get("match_code")) or None,
                slot=_s((offer or {}).get("slot")) or None,
                kind=kind,
                actor_judge_id=(actor.judge_id if actor else None),
                actor_name=(actor.full_name if actor else None),
                subject_judge_id=_s(subject_id) or None,
                subject_name=_s(subject_name) or None,
                ok=ok,
                message=_s(message) or None,
                payload=payload or {},
            )
        )
    except Exception:  # noqa: BLE001
        logger.exception("giełda: nie udało się dopisać do dziennika (%s)", kind)


def _offer_data(offer: Dict[str, Any]) -> Dict[str, str]:
    """Ładunek push-a - stąd dispatcher deep-linków wie, co otworzyć."""
    return {
        "kind": "match_market",
        "offerId": str(offer.get("id")),
        "province": _s(offer.get("province")),
        "matchId": _s(offer.get("match_id")),
        "matchNumber": _s(offer.get("match_code")),
    }


async def _notify(
    judge_ids: List[str],
    text: Tuple[str, str],
    offer: Dict[str, Any],
) -> None:
    """Wysyłka, która nigdy nie wywraca operacji, przy której powstała.

    Treść przychodzi GOTOWA z `app.match_market_notify` - para (tytuł, treść).
    Zdania nie składają się tutaj po to, żeby dały się sprawdzić testem, a nie
    przeczytać pierwszy raz na czyimś telefonie.
    """
    title, body = text
    targets = sorted({_s(j) for j in judge_ids if _s(j)})
    if not targets:
        return
    try:
        await send_push_to_judges(targets, title, body, _offer_data(offer))
    except Exception:  # noqa: BLE001
        logger.warning("giełda: powiadomienie nieudane", exc_info=True)


async def _broadcast_targets(province: str, exclude: str) -> List[str]:
    """Sedziowie okregu, ktorzy CHCA wiedziec o nowej ofercie.

    To jedyne powiadomienie gieldy wysylane do wszystkich naraz, wiec jedyne,
    ktore ma wlasny wylacznik. Reszta - „ktos zglosil sie na TWOJ mecz",
    „wymiane zatwierdzono", „zapis nie przeszedl" - to nastepstwa wlasnych
    czynnosci adresata i nie chowaja sie za przelacznikiem od listy ofert.

    Preferencje siedza per instalacja, bo ten sam sedzia miewa dwa telefony.
    Wystarczy, ze JEDNO urzadzenie chce - powiadomienie i tak rozejdzie sie
    na wszystkie jego urzadzenia, a cisza na wszystkich naraz jest tym, o co
    prosi ten, kto przelaczyl wylacznik wszedzie.
    """
    rows = await database.fetch_all(
        select(
            push_tokens.c.judge_id,
            push_tokens.c.notification_prefs,
        )
        .where(push_tokens.c.app_variant == "baza")
        .where(push_tokens.c.judge_id.is_not(None))
    )
    known = await database.fetch_all(
        select(province_judges.c.judge_id).where(province_judges.c.province == province)
    )
    in_province = {_s(_row(r)["judge_id"]) for r in known}

    wanted: Dict[str, bool] = {}
    for raw in rows:
        data = _row(raw)
        judge_id = _s(data.get("judge_id"))
        if not judge_id or judge_id == _s(exclude) or judge_id not in in_province:
            continue
        wanted[judge_id] = wanted.get(judge_id, False) or market_pushes_allowed(
            data.get("notification_prefs")
        )
    return sorted(j for j, ok in wanted.items() if ok)


async def _approvers_of(province: str) -> List[str]:
    cfg = await _config(province)
    rows = await database.fetch_all(
        select(
            province_judges.c.judge_id,
            province_judges.c.province,
            province_judges.c.badges,
        ).where(province_judges.c.province == province)
    )
    return approver_judge_ids(
        [_row(r) for r in rows], province, allowed_badges=cfg["approver_badges"]
    )


# ─────────────────────────── modele ───────────────────────────


class CreateOfferRequest(BaseModel):
    match_id: str
    slot: str
    reason: Optional[str] = None


class ClaimRequest(BaseModel):
    note: Optional[str] = None


class ApproveRequest(BaseModel):
    claim_id: int
    #: Świadome przejście nad kolizją terminarza - patrz bramka w `approve_offer`.
    #: Domyślnie `False`, więc starsza aplikacja nigdy nie wymusi zapisu przez
    #: przypadek.
    force: bool = False


class RejectRequest(BaseModel):
    reason: Optional[str] = None


class ProvinceConfigRequest(BaseModel):
    market_enabled: Optional[bool] = None
    offer_deadline_hours: Optional[int] = None
    assign_account_mode: Optional[str] = None
    approver_badges: Optional[List[str]] = None
    #: Wymiana meczów spoza obsady okręgu (boiskowe gniazda I ligi i wyżej
    #: oraz obcych II lig). Domyślnie wyłączona - patrz liść reguł.
    foreign_matches_enabled: Optional[bool] = None
    #: II ligi powierzone okręgowi; pusta lista = żadna. Powrót do katalogu
    #: domyślnego idzie osobnym polem, bo `None` znaczy tu „nie ruszaj".
    managed_prefixes: Optional[List[str]] = None
    reset_managed_prefixes: Optional[bool] = None


class RouteCheckRequest(BaseModel):
    """Sprawdzenie trasy sędziego dla jednego meczu - bez zapisu."""

    match_code: str
    judge_id: Optional[str] = None


# ─────────────────────────── kontekst ekranu ───────────────────────────


@router.get("/context", summary="Co ekran giełdy ma pokazać temu użytkownikowi")
async def get_context(actor: Actor = Depends(market_actor)) -> Dict[str, Any]:
    """Jedno wywołanie zamiast trzech przy otwarciu ekranu.

    Odpowiada też wtedy, gdy moduł jest wyłączony albo sędziego nie ma na liście
    okręgu - ekran ma wtedy co napisać zamiast pustej listy bez wyjaśnienia.
    """
    cfg = await _config(actor.province) if actor.province else None
    # Czy zatwierdzona wymiana ma dzis czym pojechac do bazy zwiazku. Ekran
    # pyta o to raz, przy wejsciu - wczesniej kosztowalo to osobne wywolanie
    # `/my-matches` przy kazdym odswiezeniu listy.
    account_ready = (
        bool(assign_credentials(actor.province, cfg["assign_account_mode"])["configured"])
        if cfg
        else False
    )
    allowed = cfg["approver_badges"] if cfg else [APPROVER_BADGE]
    return {
        "judgeId": actor.judge_id,
        "province": actor.province,
        "fullName": actor.full_name,
        "photoUrl": actor.photo_url,
        "knownInProvince": actor.known and bool(actor.province),
        "isApprover": may_approve(
            is_admin=actor.is_admin,
            province=actor.province,
            judge_province=actor.province,
            badges_raw=actor.badges,
            allowed_badges=allowed,
        ),
        "isAdmin": actor.is_admin,
        "enabled": bool(cfg and cfg["market_enabled"]),
        "deadlineHours": cfg["offer_deadline_hours"] if cfg else DEFAULT_DEADLINE_HOURS,
        # Plakietka przy nazwisku: odznaka, która NAPRAWDĘ daje to prawo w tym
        # okręgu - odkąd okręg sam wybiera odznaki, nie zawsze jest to
        # "Obsadowy". Dla administratora bez odznaki zostaje pierwsza z listy;
        # aplikacja i tak podpisuje go wtedy "Admin".
        "approverBadge": next(
            (n for n in badge_names(actor.badges) if n in set(allowed)),
            allowed[0] if allowed else APPROVER_BADGE,
        ),
        "accountReady": account_ready,
        # Mecze spoza obsady okręgu - czy okręg włączył ich wymianę i które
        # II ligi prowadzi. Ekran nie odsiewa nimi niczego (lista przychodzi z
        # serwera już odsiana); to wiedza do podpisów i na przyszłość.
        "foreignMatchesEnabled": bool(cfg and cfg["foreign_matches_enabled"]),
        "managedPrefixes": (
            cfg["managed_prefixes"] if cfg else managed_prefixes_for(actor.province)
        ),
    }


# ─────────────────────────── moje mecze ───────────────────────────


@router.get("/my-matches", summary="Moje najbliższe mecze - co da się oddać")
async def get_my_matches(
    verify: int = Query(
        0,
        ge=0,
        le=1,
        description=(
            "1 = dopytaj bazę związku o mecze bez świeżego werdyktu. "
            "Ekran maluje się najpierw bez tego, a arkusz „Oddaj mecz” dopytuje."
        ),
    ),
    actor: Actor = Depends(market_actor),
    settings: Settings = Depends(get_settings),
) -> Dict[str, Any]:
    """Droga starszej aplikacji - bez listy z telefonu.

    Odpowiedź jest ta sama i tak samo żywa; różnica jest jedna: kandydatów do
    sprawdzenia wskazuje wyłącznie migawka okręgu, więc mecz, o którym okręg
    jeszcze nie wie, tu nie wejdzie. Nowsza aplikacja domyka to trasą POST.
    """
    return await my_matches(actor, settings, bool(verify), [])


class MyMatchesRequest(BaseModel):
    """Lista meczów z telefonu - te, które sędzia widzi w zakładce „Mecze"."""

    match_ids: List[str] = []
    verify: bool = False


class RecheckRequest(BaseModel):
    """Jeden mecz do ponownego sprawdzenia w bazie związku."""

    match_id: str


@router.post("/my-matches/recheck", summary="Sprawdź obsadę jednego meczu jeszcze raz")
async def post_my_match_recheck(
    req: RecheckRequest,
    actor: Actor = Depends(market_actor),
    settings: Settings = Depends(get_settings),
) -> Dict[str, Any]:
    """Ten jeden mecz, pytany bez pośpiechu.

    Odpowiedź ma KSZTAŁT LISTY „moich meczów" z jednym wierszem - żeby ekran
    wstawił go na miejsce niepotwierdzonego, nie ucząc się drugiego kształtu.
    Trasa istnieje, bo mecz bez daty nie łapie się na szybkie przebiegi
    monitora, a wspólny budżet listy dzieli się na kilkadziesiąt numerów.
    """
    match_id = _s(req.match_id)
    if not match_id:
        raise HTTPException(400, "Brak numeru meczu.")
    data = await my_matches(
        actor, settings, verify=True, app_ids=[match_id], budget=RECHECK_BUDGET_SECONDS
    )
    # Tylko ten jeden wiersz. Lista i tak przegląda terminarz, ale ekran pytał o
    # KONKRETNY mecz i musi wiedzieć, czy właśnie ten wrócił - pusta odpowiedź
    # znaczy „nie ma go już na Twojej liście do oddania", a nie „nie wiem".
    data["matches"] = [
        row for row in data["matches"] if _s(row.get("matchId")) == match_id
    ]
    return data


@router.post("/my-matches", summary="Moje mecze - razem z listą z telefonu")
async def post_my_matches(
    req: MyMatchesRequest,
    actor: Actor = Depends(market_actor),
    settings: Settings = Depends(get_settings),
) -> Dict[str, Any]:
    return await my_matches(actor, settings, req.verify, clean_match_ids(req.match_ids))


async def my_matches(
    actor: Actor,
    settings: Settings,
    verify: bool,
    app_ids: List[str],
    budget: float = LIVE_CREW_BUDGET_SECONDS,
) -> Dict[str, Any]:
    """Moje mecze do oddania - obsada sprawdzona w bazie związku W TEJ CHWILI.

    Migawka terminarza to pamięć, nie prawda: wypełnia ją monitor w swoim
    rytmie, a mecz bez daty nie łapie się na żaden z jego szybkich przebiegów.
    Sędzia widział przez to na liście spotkanie, z którego okręg zdążył go już
    zdjąć, a nie widział tego, które właśnie dostał - i za każdym razem „wczoraj
    działało". Dlatego migawka służy tu tylko do WSKAZANIA kandydatów, a o tym,
    czy mecz jest mój, rozstrzyga publiczne API po numerze meczu. Gdy związek
    nie odpowie, wraca ostatni znany stan i jest tak PODPISANY.

    Kandydaci, w tej kolejności:

    * lista z telefonu (`app_ids`) - to, co sędzia widzi i o co pyta;
    * terminarz okręgu: wiersze z NUMEREM sędziego w którymś z gniazd giełdy
      (dokładne, bez limitu - sędzia ma kilkadziesiąt meczów, nie tysiące);
    * wiersze BEZ numerów, czyli z lekkiego przebiegu monitora, gdzie zostaje
      nazwisko - tych jest garstka, ale sito jest ograniczone bezpiecznikiem.

    Czytamy TERMINARZ okręgu, a nie `province_match_judges`: tamta tabela
    powstaje z list meczów sędziów z tokenem push, a sędzia, który odmówił
    powiadomień, nie ma tam ani wiersza. Terminarz województwa jest niezależny
    od tego, kto ma aplikację.
    """
    province = _require_province(actor)
    cfg = await _require_enabled(province)
    now = _now()
    horizon = now + timedelta(days=MY_MATCHES_HORIZON_DAYS)

    columns = (
        province_matches.c.match_id,
        province_matches.c.match_code,
        province_matches.c.match_at,
        province_matches.c.state_json,
        province_matches.c.approved,
        province_matches.c.last_deep_checked_at,
        # Sezon i pierwsze zobaczenie - po nich poznajemy mecz BEZ DATY z
        # minionego sezonu. Taki nie ma terminu, który mógłby minąć, więc bez
        # tego wisiał na liście „Oddaj mecz" bez końca.
        province_matches.c.season,
        province_matches.c.first_seen_at,
    )
    base_query = (
        select(*columns)
        .where(province_matches.c.province == province)
        .where(province_matches.c.active.is_(True))
    )
    in_window = and_(
        province_matches.c.match_at >= now,
        province_matches.c.match_at <= horizon,
    )
    # `->>` na kolumnie JSONB: numer w gnieździe porównujemy w bazie, nie w
    # Pythonie po przewinięciu całego terminarza. Wcześniej lista brała
    # pierwsze sześćset meczów bez daty W DOWOLNEJ KOLEJNOŚCI (bez `ORDER BY`)
    # i na początku sezonu, gdy dat nie ma prawie nikt, ten sam mecz raz się
    # łapał, a raz nie - stąd „wczoraj mogłem, dziś nie mogę".
    slot_numbers = [
        province_matches.c.state_json[id_field].as_string()
        for id_field, _name_field in SLOT_STATE_FIELDS.values()
    ]
    by_number = or_(*[column == actor.judge_id for column in slot_numbers])
    numbered_rows = await database.fetch_all(
        base_query.where(or_(province_matches.c.match_at.is_(None), in_window))
        .where(by_number)
        .order_by(province_matches.c.match_at.asc(), province_matches.c.match_id.asc())
    )
    # Wiersze bez żadnego numeru - lekki przebieg monitora zna same nazwiska,
    # a głębokie sprawdzenie jeszcze nie doszło. Nazwisko rozstrzyga niżej,
    # w `slots_held_by`. Mecze BEZ daty osobnym zapytaniem: w jednym sortowały
    # się na koniec, więc bezpiecznik LIMIT ucinał właśnie je - a „termin do
    # ustalenia" to często dokładnie ten mecz, który sędzia chce oddać.
    without_numbers = and_(*[func.coalesce(column, "") == "" for column in slot_numbers])
    dated_rows = await database.fetch_all(
        base_query.where(without_numbers)
        .where(in_window)
        .order_by(province_matches.c.match_at.asc(), province_matches.c.match_id.asc())
        .limit(MY_MATCHES_SCAN_LIMIT)
    )
    undated_rows = await database.fetch_all(
        base_query.where(without_numbers)
        .where(province_matches.c.match_at.is_(None))
        .order_by(province_matches.c.match_code.asc(), province_matches.c.match_id.asc())
        .limit(MY_MATCHES_SCAN_LIMIT)
    )
    rows: Dict[str, Dict[str, Any]] = {}
    for raw in list(numbered_rows) + list(dated_rows) + list(undated_rows):
        data = _row(raw)
        rows.setdefault(_s(data["match_id"]), data)
    # Mecze z telefonu, których terminarz wyżej nie wskazał - także wygaszone:
    # o tym, czy żyją, powie za chwilę baza związku, nie nasz znacznik.
    phoned = [mid for mid in app_ids if mid not in rows]
    if phoned:
        for raw in await database.fetch_all(
            select(*columns)
            .where(province_matches.c.province == province)
            .where(province_matches.c.match_id.in_(phoned))
        ):
            data = _row(raw)
            rows.setdefault(_s(data["match_id"]), data)

    # Migawka mówi, co monitor zdążył zobaczyć; ta tabela - co giełda sama
    # zapisała. Bez tego sędzia, który mecz właśnie przejął, nie widział go na
    # liście „Oddaj mecz" do najbliższego przebiegu monitora.
    swaps = await _applied_swaps(province, list(rows))

    def remembered(match_id: str) -> Dict[str, Any]:
        # `state_dict`, nie gołe `.get`: kolumna JSON bywa napisem i to o nią,
        # a nie o dane, kładła się cała lista (patrz nota przy `state_dict`).
        data = rows.get(match_id) or {}
        return apply_known_swaps(state_dict(data.get("state_json")), swaps.get(match_id, ()))

    held_ids = [
        match_id
        for match_id in rows
        if slots_held_by(remembered(match_id), actor.judge_id, actor.full_name)
    ]

    # Sprawdzenie na żywo. Świeżo sprawdzone głęboko (przed chwilą pytał o nie
    # monitor albo poprzednie wołanie tego arkusza) uchodzą za żywe bez
    # kolejnego pytania - arkusz woła serwer dwa razy pod rząd.
    vouched = {_s(m) for m in app_ids if _s(m)}
    order = live_check_order(app_ids, held_ids, LIVE_CREW_LIMIT)
    bases: Dict[str, Dict[str, Any]] = {}
    trusted: Set[str] = set()
    for match_id in order:
        data = rows.get(match_id)
        if data and crew_is_fresh(data.get("last_deep_checked_at"), now):
            trusted.add(match_id)
            continue
        bases[match_id] = state_dict(data.get("state_json")) if data else {}
    fresh, _failed = await _live_crews(
        province, actor, bases, known=set(rows), vouched=vouched, budget=budget
    )
    live_ids = set(fresh) | trusted

    # Kandydaci ponad limit sprawdzeń zostają z migawki - i są PODPISANI.
    ordered = set(order)
    candidates = order + [match_id for match_id in held_ids if match_id not in ordered]
    mine: List[Tuple[str, Dict[str, Any], Dict[str, Any], List[str], bool]] = []
    # Mecze, za które ręczy telefon, a o których związek nie zdążył odpowiedzieć.
    # MILCZENIE NIE JEST ODPOWIEDZIĄ „to nie Twój mecz": dotąd taki wiersz był
    # po cichu pomijany i sędzia widział listę bez meczu, który ma - bez jednego
    # słowa dlaczego (patrz zasada „zero cichych blokad").
    unconfirmed: List[str] = []
    # Mecze spoza obsady okręgu, w których sędzia stoi TYLKO boiskowo, a okręg
    # nie włączył wymiany takich meczów. Schodzą z listy (decyzja: nie
    # proponować), a liczba wychodzi w odpowiedzi.
    foreign_hidden = 0
    for match_id in candidates:
        data = dict(rows.get(match_id) or {})
        if match_id in fresh:
            state = fresh[match_id]
            # Data i status protokołu też z żywego stanu - termin mógł się
            # zmienić, a wiersz mógł dopiero co powstać.
            data.update(_row_from_state(state))
        else:
            state = remembered(match_id)
        held = slots_held_by(state, actor.judge_id, actor.full_name)
        if not held:
            # Sędziego nie ma w żadnym gnieździe giełdowym tego meczu - w bazie
            # związku, a gdy ta milczy: ani w migawce, ani w pamięci wymian.
            # Delegat albo obsada zmieniona - to nie jest jego mecz do oddania.
            if match_id not in live_ids and match_id in vouched:
                unconfirmed.append(match_id)
            continue
        # Gniazda, które w TYM meczu wolno oddać. Mecz obsadzany przez okręg
        # oddaje wszystkie; w meczu spoza okręgu (I liga i wyżej, obca II liga)
        # stolik zawsze, boisko dopiero po włączeniu wymiany w panelu.
        held, _kept = offerable_slots(
            held,
            _s(data.get("match_code")) or _s(state.get("RozgrywkiCode")),
            cfg["managed_prefixes"],
            cfg["foreign_matches_enabled"],
        )
        if not held:
            foreign_hidden += 1
            continue
        match_at = data.get("match_at")
        if match_at is not None and (match_at < now or match_at > horizon):
            continue
        if match_at is None and past_season(
            data.get("season"), data.get("first_seen_at"), now
        ):
            # Mecz bez terminu z zamkniętego sezonu. Nie ma czego oddawać:
            # obsady tamtych spotkań nikt już nie zmienia, a wiersz nie znika
            # sam, bo nie ma daty, która by minęła.
            continue
        mine.append((match_id, data, state, held, match_id in live_ids))
    # Najbliższe najpierw, mecze bez terminu na końcu - w stałej kolejności,
    # żeby lista nie tasowała się między otwarciami.
    mine.sort(
        key=lambda item: (
            item[1].get("match_at") is None,
            item[1].get("match_at") or now,
            _s(item[1].get("match_code")),
            item[0],
        )
    )

    match_ids = [item[0] for item in mine]
    live = await database.fetch_all(
        select(
            match_market_offers.c.id,
            match_market_offers.c.match_id,
            match_market_offers.c.slot,
            match_market_offers.c.status,
        )
        .where(match_market_offers.c.province == province)
        .where(match_market_offers.c.status.in_(("open", "applying")))
        .where(match_market_offers.c.match_id.in_(match_ids or ["__none__"]))
    )
    taken = {(_s(_row(o)["match_id"]), _s(_row(o)["slot"])): _row(o) for o in live}

    # Uprawnienia okręgu. Werdykty z pamięci są darmowe; `verify=1` dopytuje
    # bazę związku o te mecze, których jeszcze nie znamy - najbliższe najpierw,
    # bo `mine` jest już posortowane po dacie.
    creds = assign_credentials(province, cfg["assign_account_mode"])
    account_ready = bool(creds["configured"])
    mode = _s(creds["mode"])
    cached = await _cached_verdicts(province, match_ids, mode, now) if account_ready else {}
    missing = [m for m in match_ids if m not in cached]
    probed: Dict[str, Dict[str, Any]] = {}
    if verify and account_ready and missing:
        # Mecze spoza obsady okręgu sonda sprawdza TRASĄ SĘDZIEGO - tą samą,
        # którą pójdzie zapis - a nie prostym wejściem w formularz.
        codes = {item[0]: _s(item[1].get("match_code")) for item in mine}
        batch = missing[:PROBE_BATCH_LIMIT]
        probed = await _probe(
            province,
            mode,
            creds,
            batch,
            settings,
            walk_ids={
                m
                for m in batch
                if not is_managed_by_province(codes.get(m), cfg["managed_prefixes"])
            },
            giver_id=actor.judge_id,
        )

    def verdict_for(match_id: str) -> Dict[str, Any]:
        if not account_ready:
            return {
                "assignable": False,
                "reason": "NO_ACCOUNT",
                "message": assignability_message("NO_ACCOUNT"),
                "checkedAt": None,
            }
        if match_id in probed:
            return _probe_view(probed[match_id])
        if match_id in cached:
            return _verdict_view(cached[match_id])
        return _verdict_view(None)

    out: List[Dict[str, Any]] = []
    unchecked = 0
    probe_failed = 0
    live_failed = 0
    for match_id, data, state, held, checked in mine:
        verdict = verdict_for(match_id)
        if verdict["assignable"] is None:
            unchecked += 1
            # "Pytalismy i nie doszlo" to inna wiadomosc niz "jeszcze nie
            # pytalismy" - pierwsza mowi o awarii po drugiej stronie.
            if verdict["reason"] == "PROBE_FAILED":
                probe_failed += 1
        if not checked:
            live_failed += 1
        offerable = can_offer(data.get("match_at"), now, cfg["offer_deadline_hours"])
        approved = bool(data.get("approved"))
        # Gniazda, które NIE wiszą już na giełdzie - tylko one dają się oddać.
        free_slots = [s for s in held if (match_id, s) not in taken]
        blocked = None
        if verdict["assignable"] is False:
            blocked = verdict["message"]
        elif approved:
            blocked = "Protokół jest już zatwierdzony."
        elif not offerable:
            blocked = (
                f"Za późno - mecz można oddać najpóźniej "
                f"{cfg['offer_deadline_hours']} h przed pierwszym gwizdkiem."
            )
        elif not free_slots:
            # Bez tego wiersz stał na liście „do oddania", a w środku czekał
            # trwale wygaszony przycisk bez słowa wyjaśnienia - sędzia nie
            # wiedział, że sam to gniazdo już wystawił.
            blocked = (
                "Twoje gniazdo w tym meczu już wisi na giełdzie."
                if len(held) == 1
                else "Wszystkie Twoje gniazda w tym meczu już wiszą na giełdzie."
            )
        out.append(
            {
                "matchId": match_id,
                "match": _match_view(state, data.get("match_at")),
                "slots": [
                    {
                        "slot": slot,
                        "label": slot_label(slot),
                        "offerId": taken.get((match_id, slot), {}).get("id"),
                        "offerStatus": taken.get((match_id, slot), {}).get("status"),
                    }
                    for slot in held
                ],
                "canOffer": (
                    bool(offerable)
                    and not approved
                    and bool(free_slots)
                    and verdict["assignable"] is not False
                ),
                "blockedReason": blocked,
                "assignable": verdict["assignable"],
                "assignableReason": verdict["reason"],
                "checkedAt": verdict["checkedAt"],
                # Czy obsada tego wiersza pochodzi z bazy związku sprzed chwili.
                # Gdy nie - kafel mówi, że to ostatni znany stan.
                "liveChecked": checked,
                "liveNote": "" if checked else LIVE_CREW_NOTE,
            }
        )
    # Niepotwierdzone na KOŃCU listy i z otwartą przyłbicą: kafel mówi, że
    # obsady nie potwierdziliśmy, i daje sprawdzić ten jeden mecz jeszcze raz
    # (`POST /my-matches/recheck` - bez wspólnego budżetu, więc bez wyścigu z
    # resztą terminarza). Wystawienie i tak przechodzi przez twardą bramkę
    # `create_offer`, więc nic nie wyjdzie na giełdę bez potwierdzenia.
    for match_id in unconfirmed:
        data = dict(rows.get(match_id) or {})
        state = state_dict(data.get("state_json"))
        out.append(
            {
                "matchId": match_id,
                "match": _match_view(state, data.get("match_at")),
                "slots": [],
                "canOffer": False,
                "blockedReason": UNCONFIRMED_NOTE,
                "assignable": None,
                "assignableReason": "UNCHECKED",
                "checkedAt": None,
                "liveChecked": False,
                "liveNote": LIVE_CREW_NOTE,
                # Osobne pole, nie samo `liveChecked`: tam chodzi o świeżość
                # obsady, tu o to, że nie wiemy nawet, czy mecz jest jego.
                "unconfirmed": True,
            }
        )
        live_failed += 1

    return {
        "province": province,
        "deadlineHours": cfg["offer_deadline_hours"],
        "matches": out,
        "accountReady": account_ready,
        # Ile meczów czeka jeszcze na sprawdzenie uprawnień. Liczba, której się
        # nie pokazuje, wygląda jak komplet - a to nie jest komplet.
        "unchecked": unchecked,
        # Ile z nich to POTKNIĘCIE bazy związku, a nie kolejka do sprawdzenia.
        # Ekran pisze wtedy o awarii i zostawia mecze do wystawienia zamiast
        # gasić całą listę.
        "probeFailed": probe_failed,
        "probeLimit": PROBE_BATCH_LIMIT,
        # Ile wierszy na liście pokazuje ostatni znany stan zamiast obsady z
        # bazy związku - ta sama zasada: liczba wychodzi na zewnątrz.
        "liveFailed": live_failed,
        # Ile meczów spoza obsady okręgu zeszło z listy, bo sędzia stoi w nich
        # tylko boiskowo, a okręg nie włączył wymiany takich meczów.
        "foreignHidden": foreign_hidden,
        "foreignEnabled": cfg["foreign_matches_enabled"],
    }


# ─────────────────────────── oferty ───────────────────────────


async def _offer_payload(
    offer: Dict[str, Any],
    cards: Dict[str, Dict[str, Any]],
    claims: List[Dict[str, Any]],
    *,
    viewer_id: str,
    my_crew_label: str = "",
) -> Dict[str, Any]:
    return {
        "id": offer["id"],
        "province": _s(offer.get("province")),
        "matchId": _s(offer.get("match_id")),
        "slot": _s(offer.get("slot")),
        "slotLabel": slot_label(offer.get("slot")),
        "status": _s(offer.get("status")),
        "reason": _s(offer.get("reason")) or None,
        "deadlineAt": _iso(offer.get("deadline_at")),
        "createdAt": _iso(offer.get("created_at")),
        "decidedAt": _iso(offer.get("decided_at")),
        "appliedAt": _iso(offer.get("applied_at")),
        "error": _s(offer.get("error")) or None,
        "match": _match_view(state_dict(offer.get("match_snapshot")), offer.get("match_at")),
        "from": _person(_s(offer.get("from_judge_id")), cards.get(_s(offer.get("from_judge_id")))),
        "isMine": _s(offer.get("from_judge_id")) == _s(viewer_id),
        # Rola pytającego w TYM meczu - pusto, gdy nie ma go w obsadzie. Kafel
        # pisze wtedy „Masz już ten mecz" zamiast przycisku „Biorę"; zgłoszenia
        # i tak nie przyjmie serwer (`create_claim`).
        "myCrewLabel": _s(my_crew_label),
        "claimCount": len([c for c in claims if _s(c.get("status")) == "pending"]),
        # Kto przejal mecz - historia ma powiedziec „oddany KOWALSKIEMU", a nie
        # samo „przekazany". Nazwisko wybranego jest juz jawne dla obu stron
        # wymiany, wiec nie odslania niczego nowego.
        "takerName": next(
            (
                _s((cards.get(_s(c.get("judge_id"))) or {}).get("full_name"))
                for c in claims
                if _s(c.get("status")) == "chosen"
            ),
            "",
        )
        or None,
        "myClaim": next(
            (
                {"id": c["id"], "status": _s(c.get("status")), "note": _s(c.get("note")) or None}
                for c in claims
                if _s(c.get("judge_id")) == _s(viewer_id)
            ),
            None,
        ),
        # Chetni PRZY LIScIE i tylko dla oddajacego: zakladka "Moje" obiecuje
        # portrety tych, ktorzy sie zglosili, a brala je z pola, ktorego ta
        # odpowiedz nie miala - wiec zawsze pokazywala zapasowy licznik.
        # Notatki i cudze kolizje zostaja w widoku decyzji (`GET /offers/{id}`):
        # lista potrzebuje twarzy, nie rozpisek.
        "claims": (
            [
                {
                    "id": c["id"],
                    "status": _s(c.get("status")),
                    "note": None,
                    "createdAt": _iso(c.get("created_at")),
                    "person": _person(
                        _s(c.get("judge_id")), cards.get(_s(c.get("judge_id")))
                    ),
                    "conflicts": [],
                }
                for c in claims
                if _s(c.get("status")) in ("pending", "chosen")
            ]
            if _s(offer.get("from_judge_id")) == _s(viewer_id)
            else []
        ),
    }


async def _claims_for(offer_ids: List[int]) -> Dict[int, List[Dict[str, Any]]]:
    if not offer_ids:
        return {}
    rows = await database.fetch_all(
        select(match_market_claims).where(match_market_claims.c.offer_id.in_(offer_ids))
    )
    out: Dict[int, List[Dict[str, Any]]] = {}
    for raw in rows:
        data = _row(raw)
        out.setdefault(int(data["offer_id"]), []).append(data)
    return out


@router.get("/offers", summary="Giełda albo moje oferty")
async def list_offers(
    scope: str = Query("market", pattern="^(market|mine|history)$"),
    actor: Actor = Depends(market_actor),
) -> Dict[str, Any]:
    province = _require_province(actor)
    await _require_enabled(province)

    query = select(match_market_offers).where(match_market_offers.c.province == province)
    if scope == "market":
        # Cudze mecze, które wciąż zbierają zgłoszenia.
        #
        # Po terminie oferta ZNIKA z giełdy, choć w bazie zostaje otwarta (stan
        # `expired` nie ma dziś kto ustawić). Wcześniej wisiała z podpisem
        # „Czeka na chętnych" i bez przycisku - `canClaim` po stronie aplikacji
        # odcinał zgłoszenie po terminie, więc kafel był ślepy. Właściciel widzi
        # ją dalej w „Moich", z podpisem o terminie.
        query = (
            query.where(match_market_offers.c.status == "open")
            .where(match_market_offers.c.from_judge_id != actor.judge_id)
            .where(
                or_(
                    match_market_offers.c.deadline_at.is_(None),
                    match_market_offers.c.deadline_at > _now(),
                )
            )
        )
        query = query.order_by(match_market_offers.c.match_at.asc().nulls_last())
    elif scope == "mine":
        # „Moje" to moje SPRAWY, nie tylko moje oferty: zgłoszenie na cudzy mecz
        # też tu należy. Wcześniej trzeba go było szukać w giełdzie po plakietce,
        # a po terminie albo po wycofaniu oferty ślad znikał bez wyjaśnienia.
        claimed = await database.fetch_all(
            select(match_market_claims.c.offer_id)
            .where(match_market_claims.c.judge_id == actor.judge_id)
            .where(match_market_claims.c.status == "pending")
        )
        claimed_ids = [int(_row(r)["offer_id"]) for r in claimed]
        query = query.where(
            or_(
                match_market_offers.c.from_judge_id == actor.judge_id,
                match_market_offers.c.id.in_(claimed_ids or [-1]),
            )
        ).where(match_market_offers.c.status.in_(("open", "applying")))
        query = query.order_by(match_market_offers.c.created_at.desc())
    else:
        # Historia: moje rozstrzygnięte oferty ORAZ te, o które się starałem.
        mine = await database.fetch_all(
            select(match_market_claims.c.offer_id).where(
                match_market_claims.c.judge_id == actor.judge_id
            )
        )
        claimed_ids = [int(_row(r)["offer_id"]) for r in mine]
        query = query.where(
            or_(
                match_market_offers.c.from_judge_id == actor.judge_id,
                match_market_offers.c.id.in_(claimed_ids or [-1]),
            )
        ).where(match_market_offers.c.status.notin_(("open", "applying")))
        query = query.order_by(match_market_offers.c.updated_at.desc())

    rows = [_row(r) for r in await database.fetch_all(query.limit(200))]
    claims = await _claims_for([int(r["id"]) for r in rows])
    # Wizytowki obejmuja oddajacych, tych, ktorzy mecz przejeli (inaczej historia
    # nie ma czym podpisac wpisu), ORAZ chetnych - z nich powstaja portrety w
    # zakladce "Moje".
    cards = await _judges_by_id(
        [_s(r["from_judge_id"]) for r in rows]
        + [
            _s(c.get("judge_id"))
            for group in claims.values()
            for c in group
            if _s(c.get("status")) in ("pending", "chosen")
        ]
    )

    # Które z tych meczów pytający już prowadzi - jedno zapytanie na całą listę.
    my_roles = await _viewer_roles(province, [_s(r["match_id"]) for r in rows], actor)

    return {
        "scope": scope,
        "offers": [
            await _offer_payload(
                r,
                cards,
                claims.get(int(r["id"]), []),
                viewer_id=actor.judge_id,
                my_crew_label=my_roles.get(_s(r["match_id"]), ""),
            )
            for r in rows
        ],
    }


@router.post("/offers", status_code=201, summary="Wystaw mecz na giełdę")
async def create_offer(
    req: CreateOfferRequest,
    actor: Actor = Depends(market_actor),
    settings: Settings = Depends(get_settings),
) -> Dict[str, Any]:
    province = _require_province(actor)
    cfg = await _require_enabled(province)
    now = _now()

    slot = _s(req.slot)
    if not slot_is_tradeable(slot):
        raise HTTPException(400, "Tym gniazdem nie wolno się wymieniać przez giełdę.")

    match_id = _s(req.match_id)
    match = await database.fetch_one(
        select(province_matches).where(
            and_(
                province_matches.c.province == province,
                province_matches.c.match_id == match_id,
            )
        )
    )
    data = _row(match) if match else {}
    # Obsada z bazy związku W TEJ CHWILI - ta sama droga, co na liście „Oddaj
    # mecz", żeby lista i bramka odpowiadały na to samo pytanie tak samo. Sędzia
    # wybrał ten mecz z listy, więc telefon za niego ręczy (`vouched`): mecz,
    # o którym okręg jeszcze nie wiedział, dostaje tu swój wiersz - o ile w
    # bazie związku naprawdę stoi w nim ten sędzia.
    fresh, _failed = await _live_crews(
        province,
        actor,
        {match_id: state_dict(data.get("state_json"))},
        known={match_id} if match else set(),
        vouched={match_id},
    )
    if match_id in fresh:
        state = fresh[match_id]
        data.update(_row_from_state(state))
    elif not match:
        raise HTTPException(
            404,
            "Nie znam tego meczu w Twoim okręgu, a baza związku nie odpowiada. "
            "Spróbuj za chwilę.",
        )
    else:
        # Związek milczy - zostaje migawka z pamięcią własnych wymian giełdy.
        # Poprawiona migawka idzie też do `match_snapshot`, bo z niej powstaje
        # strażnik `expect` przy zapisie do ZPRP.
        state = apply_known_swaps(
            state_dict(data.get("state_json")),
            (await _applied_swaps(province, [match_id])).get(match_id, ()),
        )

    if slot not in slots_held_by(state, actor.judge_id, actor.full_name):
        raise HTTPException(403, "To nie jest Twoje gniazdo w tym meczu.")
    # Mecz spoza obsady okręgu: boiskowe gniazdo wolno wystawić dopiero, gdy
    # okręg włączył wymianę takich meczów; stolik zawsze. Lista już to
    # odsiała, ale bramka stoi osobno - starsza aplikacja pyta o to, co ma.
    match_code = _s(data.get("match_code")) or _s(state.get("RozgrywkiCode"))
    managed = is_managed_by_province(match_code, cfg["managed_prefixes"])
    if not managed and slot in FIELD_SLOTS and not cfg["foreign_matches_enabled"]:
        raise HTTPException(
            409,
            detail={"code": "FOREIGN_OFF", "message": assignability_message("FOREIGN_OFF")},
        )
    if data.get("approved"):
        raise HTTPException(409, "Protokół tego meczu jest już zatwierdzony.")
    if data.get("match_at") is None and past_season(
        data.get("season"), data.get("first_seen_at"), now
    ):
        # Mecz bez terminu z zamkniętego sezonu. Lista go nie pokazuje, ale
        # bramka musi stać osobno: starsza aplikacja pyta o wystawienie tego,
        # co ma u siebie, i odmowa jest tu jedyną odpowiedzią.
        raise HTTPException(
            409,
            "Ten mecz jest z minionego sezonu - giełda wymienia obsadę tylko w "
            f"sezonie {season_label(season_start_year(now))}.",
        )
    if not can_offer(data.get("match_at"), now, cfg["offer_deadline_hours"]):
        raise HTTPException(
            409,
            f"Za późno - mecz można oddać najpóźniej {cfg['offer_deadline_hours']} h "
            "przed pierwszym gwizdkiem.",
        )

    existing = await database.fetch_one(
        select(match_market_offers.c.id).where(
            and_(
                match_market_offers.c.province == province,
                match_market_offers.c.match_id == _s(req.match_id),
                match_market_offers.c.slot == slot,
                match_market_offers.c.status.in_(("open", "applying")),
            )
        )
    )
    if existing:
        raise HTTPException(409, "To gniazdo już wisi na giełdzie.")

    # Ostatnie i najdroższe sprawdzenie, dlatego stoi na końcu: czy okręg w ogóle
    # obsadza ten mecz. Bez tego można by wystawić spotkanie ligi centralnej,
    # którego konto wojewódzkie nie ma prawa tknąć - i dowiedzieć się o tym
    # dopiero przy zatwierdzaniu, gdy oddający dawno przestał szukać zastępstwa.
    await _require_assignable(
        province,
        cfg,
        _s(req.match_id),
        settings,
        slot=slot,
        # Mecz spoza terminarza okręgu sondujemy trasą sędziego - tą samą,
        # którą pójdzie zapis przy zatwierdzeniu.
        walk=not managed,
        giver_id=actor.judge_id,
    )

    insertion = (
        insert(match_market_offers)
        .values(
            province=province,
            match_id=_s(req.match_id),
            match_code=_s(data.get("match_code")),
            slot=slot,
            from_judge_id=actor.judge_id,
            reason=_s(req.reason) or None,
            status="open",
            deadline_at=deadline_for(data.get("match_at"), cfg["offer_deadline_hours"]),
            match_at=data.get("match_at"),
            match_snapshot=state,
        )
        .returning(match_market_offers.c.id)
    )
    try:
        offer_id = await database.fetch_val(insertion)
    except Exception:  # noqa: BLE001
        # Sonda uprawnien wyzej to kilka sekund na cudzym serwerze i ktos mogl w
        # tym czasie wystawic to samo gniazdo. Unikat `uq_match_market_live_slot`
        # konczyl to piecsetka - a to zwykla, wytlumaczalna odmowa. Sprawdzamy
        # przez PONOWNY odczyt, bo klasa wyjatku zalezy od sterownika bazy.
        again = await database.fetch_one(
            select(match_market_offers.c.id).where(
                and_(
                    match_market_offers.c.province == province,
                    match_market_offers.c.match_id == _s(req.match_id),
                    match_market_offers.c.slot == slot,
                    match_market_offers.c.status.in_(("open", "applying")),
                )
            )
        )
        if again:
            raise HTTPException(409, "To gniazdo już wisi na giełdzie.")
        raise

    offer = {
        "id": offer_id,
        "province": province,
        "match_id": _s(req.match_id),
        "match_code": _s(data.get("match_code")),
        "slot": slot,
    }
    await _log(
        "offer_created",
        province=province,
        actor=actor,
        offer=offer,
        message=_s(req.reason),
        payload={"slotLabel": slot_label(slot), "deadlineHours": cfg["offer_deadline_hours"]},
    )
    # Zainteresowani to sędziowie okręgu, którzy mają aplikację i nie wyłączyli
    # powiadomień giełdy - reszta i tak zobaczy ofertę przy najbliższym wejściu
    # na ekran.
    await _notify(
        await _broadcast_targets(province, actor.judge_id),
        # Migawka i termin są w wierszu meczu, nie w skróconym opisie oferty -
        # a to one mówią sędziemu „czy mam wtedy czas".
        text_offer_created(
            {**offer, "match_at": data.get("match_at"), "match_snapshot": state},
            actor.full_name,
        ),
        offer,
    )
    return {"id": offer_id, "status": "open"}


@router.delete("/offers/{offer_id}", summary="Wycofaj swoją ofertę")
async def withdraw_offer(offer_id: int, actor: Actor = Depends(market_actor)) -> Dict[str, Any]:
    province = _require_province(actor)
    async with database.transaction():
        # RYGIEL na wierszu, jak przy zatwierdzaniu i odrzucaniu. Bez niego
        # wycofanie potrafilo wejsc w SRODEK zapisu do ZPRP: odczytywalo `open`,
        # nadpisywalo `applying` stanem `cancelled`, a zatwierdzanie po powrocie
        # z bazy zwiazku i tak stawialo `done`. Obsada zmieniona, a oddajacy
        # przekonany, ze mecz wrocil do niego.
        row = await database.fetch_one(
            select(match_market_offers)
            .where(match_market_offers.c.id == offer_id)
            .with_for_update()
        )
        if not row:
            raise HTTPException(404, "Nie ma takiej oferty.")
        offer = _row(row)
        if _s(offer["province"]) != province or _s(offer["from_judge_id"]) != actor.judge_id:
            raise HTTPException(403, "To nie jest Twoja oferta.")
        target = next_offer_status(offer["status"], "withdraw")
        if not target:
            raise HTTPException(409, "Tej oferty nie da się już wycofać.")
        # Kogo to obchodzi: ci, ktorych zgloszenie WLASNIE gasimy. Wczesniej
        # powiadomienie szlo do wszystkich wierszy, wiec ktos, kto wycofal sie
        # tydzien temu, dostawal "mecz wrocil do wlasciciela".
        interested = [
            _s(_row(r)["judge_id"])
            for r in await database.fetch_all(
                select(match_market_claims.c.judge_id)
                .where(match_market_claims.c.offer_id == offer_id)
                .where(match_market_claims.c.status.in_(("pending", "chosen")))
            )
        ]
        changed = await database.fetch_val(
            update(match_market_offers)
            .where(match_market_offers.c.id == offer_id)
            .where(match_market_offers.c.status == _s(offer["status"]))
            .values(status=target, updated_at=func.now())
            .returning(match_market_offers.c.id)
        )
        if not changed:
            raise HTTPException(
                409,
                "Ta oferta zmieniła w tej chwili stan - odśwież ekran i sprawdź, "
                "co się z nią stało.",
            )
        await database.execute(
            update(match_market_claims)
            .where(match_market_claims.c.offer_id == offer_id)
            .where(match_market_claims.c.status == "pending")
            .values(status="declined", updated_at=func.now())
        )

    await _log(
        "offer_withdrawn",
        province=province,
        actor=actor,
        offer=offer,
        payload={"claimsDropped": len(interested)},
    )
    await _notify(
        interested,
        text_offer_withdrawn(offer, actor.full_name),
        offer,
    )
    return {"id": offer_id, "status": target}


# ─────────────────────────── zgłoszenia ───────────────────────────


@router.post("/offers/{offer_id}/claims", status_code=201, summary="Zgłoś się na mecz")
async def create_claim(
    offer_id: int, req: ClaimRequest, actor: Actor = Depends(market_actor)
) -> Dict[str, Any]:
    province = _require_province(actor)
    await _require_enabled(province)

    row = await database.fetch_one(
        select(match_market_offers).where(match_market_offers.c.id == offer_id)
    )
    if not row or _s(_row(row)["province"]) != province:
        raise HTTPException(404, "Nie ma takiej oferty.")
    offer = _row(row)

    refusal = may_claim(
        offer["status"], offer["from_judge_id"], actor.judge_id, offer.get("deadline_at"), _now()
    )
    if refusal:
        raise HTTPException(409, refusal)

    # Nie wolno wziąć meczu, który już prowadzisz. Partner wystawia DRUGIE
    # gniazdo tego samego spotkania, a jeden człowiek nie stanie w dwóch - to
    # nie kolizja terminarza (ta jest ostrzeżeniem dla obsadowego), tylko rzecz
    # niemożliwa. Pytamy migawkę z pamięcią wymian giełdy, tą samą drogą, co
    # lista „moich meczów": bez sieci, bo zgłoszenie to jedno dotknięcie.
    my_role = (await _viewer_roles(province, [_s(offer["match_id"])], actor)).get(
        _s(offer["match_id"]), ""
    )
    if not my_role:
        # Migawki mogło nie być (mecz spoza terminarza okręgu) - zostaje
        # migawka z chwili wystawienia oferty, czyli to, co widział oddający.
        roles = roles_held_by(
            state_dict(offer.get("match_snapshot")), actor.judge_id, actor.full_name
        )
        my_role = crew_label(roles[0]) if roles else ""
    if my_role:
        raise HTTPException(
            409,
            detail={
                "code": "ALREADY_IN_CREW",
                "message": f"Masz już ten mecz - stoisz w nim jako {my_role}.",
            },
        )

    conflicts = (
        await _same_day_matches(
            province,
            {actor.judge_id: actor.full_name},
            offer.get("match_at"),
            _s(offer["match_id"]),
        )
    ).get(actor.judge_id, [])

    existing = await database.fetch_one(
        select(match_market_claims).where(
            and_(
                match_market_claims.c.offer_id == offer_id,
                match_market_claims.c.judge_id == actor.judge_id,
            )
        )
    )
    if existing and _s(_row(existing)["status"]) == "pending":
        raise HTTPException(409, "Już się zgłosiłeś na ten mecz.")

    if existing:
        # Wycofane zgłoszenie wolno złożyć jeszcze raz - to ta sama osoba przy
        # tej samej ofercie, więc wskrzeszamy wiersz zamiast mnożyć historię.
        claim_id = int(_row(existing)["id"])
        await database.execute(
            update(match_market_claims)
            .where(match_market_claims.c.id == claim_id)
            .values(
                status="pending",
                note=_s(req.note) or None,
                conflicts_json=conflicts,
                updated_at=func.now(),
            )
        )
    else:
        claim_id = await database.fetch_val(
            insert(match_market_claims)
            .values(
                offer_id=offer_id,
                judge_id=actor.judge_id,
                note=_s(req.note) or None,
                status="pending",
                conflicts_json=conflicts,
            )
            .returning(match_market_claims.c.id)
        )

    await _log(
        "claim_created",
        province=province,
        actor=actor,
        offer=offer,
        message=_s(req.note),
        payload={"conflicts": len(conflicts), "again": bool(existing)},
    )
    await _notify(
        await _approvers_of(province),
        text_claim_created(offer, actor.full_name),
        offer,
    )
    return {"id": claim_id, "status": "pending", "conflicts": conflicts}


@router.delete("/offers/{offer_id}/claims/me", summary="Wycofaj swoje zgłoszenie")
async def withdraw_claim(offer_id: int, actor: Actor = Depends(market_actor)) -> Dict[str, Any]:
    _require_province(actor)
    row = await database.fetch_one(
        select(match_market_claims).where(
            and_(
                match_market_claims.c.offer_id == offer_id,
                match_market_claims.c.judge_id == actor.judge_id,
            )
        )
    )
    if not row:
        raise HTTPException(404, "Nie masz zgłoszenia na tę ofertę.")
    claim = _row(row)
    target = next_claim_status(claim["status"], "withdraw")
    if not target:
        raise HTTPException(409, "Tego zgłoszenia nie da się już wycofać.")
    await database.execute(
        update(match_market_claims)
        .where(match_market_claims.c.id == claim["id"])
        .values(status=target, updated_at=func.now())
    )
    # Dziennik potrzebuje meczu, a zgłoszenie zna tylko ofertę - dociągamy ją
    # osobno, bo to jedyne miejsce, które jej nie czytało.
    parent = await database.fetch_one(
        select(match_market_offers).where(match_market_offers.c.id == offer_id)
    )
    if parent:
        await _log(
            "claim_withdrawn",
            province=_s(_row(parent)["province"]),
            actor=actor,
            offer=_row(parent),
        )
    return {"id": claim["id"], "status": target}


# ─────────────────────────── decyzja obsadowego ───────────────────────────


#: Po ilu minutach zapis w bazie zwiazku uznajemy za PORZUCONY.
#:
#: Stan `applying` zamyka oferte na czas zapisu i tylko to samo wywolanie
#: potrafi go zdjac. Gdy nasz proces przerwal sie w trakcie (restart, zerwane
#: polaczenie z telefonem), wiersz zostawal w `applying` NA ZAWSZE: mecz ani nie
#: wracal na gielde, ani nie byl zapisany, a oddajacy nie mial go jak wycofac.
#: Piec minut to zapas na wolna odpowiedz ZPRP i na powtorne logowanie.
STALE_APPLY_MINUTES = 5


class _ClaimImpossible(Exception):
    """Chętny stoi już w tym meczu - wyjątek wewnętrzny `approve_offer`.

    Rzucany W transakcji, obsługiwany POZA nią: wycofanie zgłoszenia ma zostać
    w bazie, a wyjątek w środku transakcji cofnąłby je razem z resztą.
    """

    def __init__(self, claim: Dict[str, Any], offer: Dict[str, Any], name: str, role: str):
        super().__init__(role)
        self.claim = claim
        self.offer = offer
        self.name = name
        self.role = role


def _apply_is_stale(updated_at: Any, now: datetime) -> bool:
    """Czy `applying` na tym wierszu to slad po przerwanym zapisie."""
    if not isinstance(updated_at, datetime):
        return True
    stamp = updated_at if updated_at.tzinfo else updated_at.replace(tzinfo=timezone.utc)
    return stamp + timedelta(minutes=STALE_APPLY_MINUTES) <= now


async def _require_approver(actor: Actor, province: str) -> None:
    # Odznaki uprawnione do rozstrzygania wybiera okręg w konfiguracji -
    # domyślnie sam obsadowy, ale bywa też Komisja czy inna rola okręgowa.
    cfg = await _config(province)
    allowed = cfg["approver_badges"]
    if not may_approve(
        is_admin=actor.is_admin,
        province=province,
        judge_province=actor.province,
        badges_raw=actor.badges,
        allowed_badges=allowed,
    ):
        raise HTTPException(
            403,
            "Rozstrzyganie wymian należy do administratora i do sędziów z odznaką "
            f"{' / '.join(allowed)} w tym okręgu.",
        )


@router.get("/offers/{offer_id}", summary="Zgłoszenie w całości - widok decyzji")
async def get_offer(offer_id: int, actor: Actor = Depends(market_actor)) -> Dict[str, Any]:
    row = await database.fetch_one(
        select(match_market_offers).where(match_market_offers.c.id == offer_id)
    )
    if not row:
        raise HTTPException(404, "Nie ma takiej oferty.")
    offer = _row(row)
    province = _s(offer["province"])

    mine = _s(offer["from_judge_id"]) == actor.judge_id
    cfg = await _config(province)
    approver = may_approve(
        is_admin=actor.is_admin,
        province=province,
        judge_province=actor.province,
        badges_raw=actor.badges,
        allowed_badges=cfg["approver_badges"],
    )
    if not mine and not approver and actor.province != province:
        raise HTTPException(403, "To zgłoszenie należy do innego okręgu.")

    claims = [
        _row(r)
        for r in await database.fetch_all(
            select(match_market_claims)
            .where(match_market_claims.c.offer_id == offer_id)
            .order_by(match_market_claims.c.created_at.asc())
        )
    ]
    cards = await _judges_by_id(
        [_s(offer["from_judge_id"])] + [_s(c["judge_id"]) for c in claims]
    )

    # Kolizje liczymy ŚWIEŻO, a nie z chwili zgłoszenia: między jednym a drugim
    # obsadowy mógł dopisać chętnemu inny mecz tego dnia.
    #
    # Pytającego dokładamy ZAWSZE. `myConflicts` niżej brało się z tej samej
    # tablicy, więc dopóki ktoś się nie zgłosił, jego własne kolizje wychodziły
    # puste - czyli dokładnie wtedy, gdy są mu potrzebne.
    who = {
        _s(c["judge_id"]): _s((cards.get(_s(c["judge_id"])) or {}).get("full_name"))
        for c in claims
    }
    who[actor.judge_id] = actor.full_name
    fresh = await _same_day_matches(
        province, who, offer.get("match_at"), _s(offer["match_id"])
    )

    payload = await _offer_payload(
        offer,
        cards,
        claims,
        viewer_id=actor.judge_id,
        my_crew_label=(await _viewer_roles(province, [_s(offer["match_id"])], actor)).get(
            _s(offer["match_id"]), ""
        ),
    )
    # Do rozstrzygniecia jest oferta otwarta ORAZ ta z PORZUCONYM zapisem: bez
    # tego drugiego przypadku utknietej wymiany nie ma jak odzyskac z aplikacji.
    payload["canApprove"] = approver and (
        _s(offer["status"]) == "open"
        or (
            _s(offer["status"]) == "applying"
            and _apply_is_stale(offer.get("updated_at"), _now())
        )
    )

    # Komplet chetnych - z nazwiskami, notatkami i cudzym terminarzem - widza
    # WYLACZNIE ci, ktorzy maja nim rozstrzygac: obsadowy, administrator i sam
    # oddajacy. Sedzia z okregu, ktory tylko oglada oferte, dostaje sam licznik.
    # Kolizje to rozpiska czyjegos weekendu, a nie element oferty.
    if approver or mine:
        payload["claims"] = [
            {
                "id": c["id"],
                "status": _s(c["status"]),
                "note": _s(c.get("note")) or None,
                "createdAt": _iso(c.get("created_at")),
                "person": _person(_s(c["judge_id"]), cards.get(_s(c["judge_id"]))),
                "conflicts": fresh.get(_s(c["judge_id"]), []),
            }
            for c in claims
        ]
    else:
        payload["claims"] = []

    # Wlasne kolizje dostaje kazdy - to jego wlasny terminarz i to jest
    # informacja, ktorej potrzebuje ZANIM sie zglosi.
    payload["myConflicts"] = fresh.get(actor.judge_id, [])
    payload["slotHolder"] = slot_holder_name(
        state_dict(offer.get("match_snapshot")), offer["slot"]
    )

    # Mecz mógł zostać PRZENIESIONY po wystawieniu oferty. Kafel pokazuje migawkę
    # z chwili wystawienia - na to zgadzał się oddający i tego nie ruszamy - więc
    # bieżący termin dokładamy osobno i TYLKO wtedy, gdy się różni. Bez tego
    # chętny zgłaszał się na godzinę, której już nie ma.
    live = await database.fetch_one(
        select(province_matches.c.match_at, province_matches.c.state_json).where(
            and_(
                province_matches.c.province == province,
                province_matches.c.match_id == _s(offer["match_id"]),
            )
        )
    )
    live_row = _row(live) if live else {}
    live_at = live_row.get("match_at")
    live_state = state_dict(live_row.get("state_json"))
    payload["matchNow"] = (
        {
            "matchAt": _iso(live_at),
            "hall": " ".join(
                x
                for x in (
                    _s(live_state.get("Hala_nazwa")),
                    _s(live_state.get("Hala_miasto")),
                )
                if x
            ),
        }
        if live_at is not None and live_at != offer.get("match_at")
        else None
    )
    return payload


@router.post("/offers/{offer_id}/reject", summary="Odrzuć wymianę")
async def reject_offer(
    offer_id: int, req: RejectRequest, actor: Actor = Depends(market_actor)
) -> Dict[str, Any]:
    async with database.transaction():
        row = await database.fetch_one(
            select(match_market_offers).where(match_market_offers.c.id == offer_id).with_for_update()
        )
        if not row:
            raise HTTPException(404, "Nie ma takiej oferty.")
        offer = _row(row)
        await _require_approver(actor, _s(offer["province"]))
        target = next_offer_status(offer["status"], "reject")
        if not target:
            raise HTTPException(409, "Ta oferta została już rozstrzygnięta.")
        await database.execute(
            update(match_market_offers)
            .where(match_market_offers.c.id == offer_id)
            .values(
                status=target,
                decided_by=actor.judge_id,
                decided_at=func.now(),
                error=_s(req.reason) or None,
                updated_at=func.now(),
            )
        )
        # Kogo to obchodzi: oddajacy i ci, ktorych zgloszenie WLASNIE gasimy.
        # Wczesniej powiadomienie szlo do wszystkich wierszy, wiec ktos, kto
        # wycofal zgloszenie tygodnie temu, dostawal wiadomosc o cudzej decyzji.
        interested = [
            _s(_row(r)["judge_id"])
            for r in await database.fetch_all(
                select(match_market_claims.c.judge_id)
                .where(match_market_claims.c.offer_id == offer_id)
                .where(match_market_claims.c.status.in_(("pending", "chosen")))
            )
        ]
        await database.execute(
            update(match_market_claims)
            .where(match_market_claims.c.offer_id == offer_id)
            .where(match_market_claims.c.status == "pending")
            .values(status="declined", updated_at=func.now())
        )

    reason = _s(req.reason)
    # Nazwisko oddającego, żeby powiadomienie mówiło, KTO zostaje przy meczu -
    # jedno zapytanie na czynność, która i tak dzieje się rzadko.
    giver_card = (await _judges_by_id([_s(offer["from_judge_id"])])).get(
        _s(offer["from_judge_id"])
    ) or {}
    await _log(
        "decision_rejected",
        province=_s(offer["province"]),
        actor=actor,
        offer=offer,
        subject_id=_s(offer["from_judge_id"]),
        ok=False,
        message=reason,
        payload={"claimsDropped": len(interested)},
    )
    await _notify(
        [_s(offer["from_judge_id"])] + interested,
        text_offer_rejected(offer, _s(giver_card.get("full_name")), reason),
        offer,
    )
    return {"id": offer_id, "status": target}


@router.post("/offers/{offer_id}/approve", summary="Zatwierdź wymianę i zapisz ją w ZPRP")
async def approve_offer(
    offer_id: int,
    req: ApproveRequest,
    actor: Actor = Depends(market_actor),
    settings: Settings = Depends(get_settings),
) -> Dict[str, Any]:
    """Jedyne miejsce, z którego giełda pisze do bazy związku.

    Kolejność jest tu istotna: najpierw ZAMYKAMY ofertę stanem `applying` w
    osobnej transakcji, dopiero potem idziemy do ZPRP. Zapis trwa kilka sekund i
    przez ten czas nikt inny nie może wejść na to samo zgłoszenie - a gdyby
    trzymać transakcję otwartą przez całe wywołanie HTTP, blokowalibyśmy wiersz
    na czas cudzego serwera.
    """
    try:
        async with database.transaction():
            row = await database.fetch_one(
                select(match_market_offers).where(match_market_offers.c.id == offer_id).with_for_update()
            )
            if not row:
                raise HTTPException(404, "Nie ma takiej oferty.")
            offer = _row(row)
            province = _s(offer["province"])
            await _require_approver(actor, province)

            stale = _s(offer["status"]) == "applying" and _apply_is_stale(
                offer.get("updated_at"), _now()
            )
            claim_row = await database.fetch_one(
                select(match_market_claims).where(
                    and_(
                        match_market_claims.c.id == req.claim_id,
                        match_market_claims.c.offer_id == offer_id,
                    )
                )
            )
            if not claim_row:
                raise HTTPException(404, "Nie ma takiego zgłoszenia przy tej ofercie.")
            claim = _row(claim_row)
            # Przy drugiej probie zgloszenie jest juz `chosen` - to ten sam chetny,
            # ten sam mecz, tylko zapis nie doszedl do konca.
            allowed = ("pending", "chosen") if stale else ("pending",)
            if _s(claim["status"]) not in allowed:
                raise HTTPException(409, "To zgłoszenie zostało już rozstrzygnięte.")

            # Druga proba dla zapisu, ktory UTKNAL (`stale` wyzej). Zwykle `applying`
            # znaczy "trwa", ale gdy nasze wywolanie przerwalo sie w polowie, nikt tego
            # wiersza juz nie ruszy. Po `STALE_APPLY_MINUTES` wolno wiec sprobowac
            # ponownie: skutek zapisu jest ten sam (to samo nazwisko w tym samym
            # gniezdzie), a `expect` sprawdza po drodze, kto siedzi tam dzisiaj.
            target = next_offer_status(offer["status"], "approve") or (
                "applying" if stale else None
            )
            if not target:
                raise HTTPException(409, "Ta oferta została już rozstrzygnięta.")

            # KOLIZJE PRZELICZAMY TERAZ, nie z chwili zgłoszenia. Obsadowy
            # zatwierdza wymiany jedna po drugiej i to WŁAŚNIE poprzednia decyzja
            # mogła dać temu sędziemu mecz w tym dniu - giełda zapisuje ją także do
            # migawki (`_sync_slot_holder`), więc widzimy ją od razu. Zgłoszenie
            # sprzed godziny nie wie o niczym, co stało się po nim.
            #
            # Kolizja WSTRZYMUJE zapis. Obsadowy może przejść nad nią świadomie
            # (`force`), bo wie o okręgu rzeczy, których nie wie terminarz - i to
            # przejście idzie do dziennika.
            taker_card = (await _judges_by_id([_s(claim["judge_id"])])).get(
                _s(claim["judge_id"])
            ) or {}
            # CHĘTNY NIE MOŻE JUŻ STAĆ W TYM MECZU. Zgłoszenie było ważne, gdy je
            # składał; od tego czasu mógł wejść do tej obsady inną wymianą albo
            # ręcznie w bazie związku. Jeden człowiek nie stanie w dwóch gniazdach,
            # więc to nie jest ostrzeżenie (jak kolizja), tylko odmowa bez „mimo":
            # zgłoszenie schodzi samo, a chętny dostaje o tym wiadomość. To samo
            # pytanie zada raz jeszcze formularz ZPRP w chwili zapisu
            # (`forbid_elsewhere`) - migawka jest sprzed chwili, formularz z tej
            # sekundy.
            taken_role = (
                await _roles_of(
                    province,
                    [_s(offer["match_id"])],
                    _s(claim["judge_id"]),
                    _s(taker_card.get("full_name")),
                )
            ).get(_s(offer["match_id"]), "")
            if taken_role:
                raise _ClaimImpossible(
                    claim, offer, _s(taker_card.get("full_name")), taken_role
                )
            clash = (
                await _same_day_matches(
                    province,
                    {_s(claim["judge_id"]): _s(taker_card.get("full_name"))},
                    offer.get("match_at"),
                    _s(offer["match_id"]),
                )
            ).get(_s(claim["judge_id"]), [])
            if clash and not req.force:
                raise HTTPException(
                    409,
                    detail={
                        "code": "SAME_DAY_CONFLICT",
                        "message": (
                            "Ten sędzia ma już mecz tego dnia: "
                            f"{conflict_sentence(clash)}. Zapis wstrzymany."
                        ),
                        "conflicts": [dict(card) for card in clash],
                    },
                )

            await database.execute(
                update(match_market_offers)
                .where(match_market_offers.c.id == offer_id)
                .values(
                    status=target,
                    decided_by=actor.judge_id,
                    decided_at=func.now(),
                    error=None,
                    updated_at=func.now(),
                )
            )
            await database.execute(
                update(match_market_claims)
                .where(match_market_claims.c.id == claim["id"])
                .values(status="chosen", updated_at=func.now())
            )
    except _ClaimImpossible as blocked:
        # Poza transakcją, bo wyjątek w jej środku cofnąłby to wycofanie.
        await database.execute(
            update(match_market_claims)
            .where(match_market_claims.c.id == blocked.claim["id"])
            .values(
                status=next_claim_status("pending", "decline") or "declined",
                updated_at=func.now(),
            )
        )
        who = blocked.name or "Ten sędzia"
        await _log(
            "claim_withdrawn",
            province=province,
            actor=actor,
            offer=blocked.offer,
            subject_id=_s(blocked.claim["judge_id"]),
            subject_name=blocked.name,
            ok=False,
            message=(
                f"Zgłoszenie zeszło przy zatwierdzaniu: {who} stoi już w tym meczu "
                f"jako {blocked.role}."
            ),
            payload={"code": "ALREADY_IN_CREW", "role": blocked.role},
        )
        await _notify(
            [_s(blocked.claim["judge_id"])],
            text_claim_impossible(blocked.offer, blocked.role),
            blocked.offer,
        )
        raise HTTPException(
            409,
            detail={
                "code": "ALREADY_IN_CREW",
                "message": (
                    f"{who} stoi już w tym meczu jako {blocked.role}, więc nie może "
                    "wziąć drugiego gniazda. Zgłoszenie zostało wycofane."
                ),
            },
        )

    cfg = await _config(province)
    creds = assign_credentials(province, cfg["assign_account_mode"])
    cards = await _judges_by_id([_s(offer["from_judge_id"]), _s(claim["judge_id"])])
    giver = cards.get(_s(offer["from_judge_id"])) or {}
    taker = cards.get(_s(claim["judge_id"])) or {}

    # DECYZJA idzie do dziennika osobno od jej SKUTKU w bazie związku. To dwie
    # różne rzeczy i przy nieudanym zapisie tylko tak widać, że obsadowy zrobił
    # swoje, a nie przeszło coś dalej.
    await _log(
        "decision_approved",
        province=province,
        actor=actor,
        offer=offer,
        subject_id=_s(claim["judge_id"]),
        subject_name=_s(taker.get("full_name")),
        payload={
            "claimId": int(claim["id"]),
            "retry": bool(stale),
            # Zatwierdzenie NAD kolizją to inna decyzja niż zwykłe - dziennik
            # ma o niej mówić wprost, razem z tym, ile meczów tego dnia było.
            "forced": bool(clash),
            "conflicts": len(clash),
        },
    )

    async def fail(message: str, code: str, role: str = "") -> Dict[str, Any]:
        """Oferta wraca na giełdę, chętny do puli, a obsadowy dostaje powód.

        Wyjątek: chętny, który stoi już w tym meczu (formularz ZPRP zobaczył
        to w chwili zapisu, kod ALREADY_IN_CREW), NIE wraca do puli - jego
        zgłoszenie schodzi, a on dostaje o tym wiadomość z nazwą roli.
        """
        await database.execute(
            update(match_market_offers)
            .where(match_market_offers.c.id == offer_id)
            .values(
                status=next_offer_status("applying", "apply_failed") or "open",
                error=message,
                updated_at=func.now(),
            )
        )
        impossible = code == "ALREADY_IN_CREW"
        await database.execute(
            update(match_market_claims)
            .where(match_market_claims.c.id == claim["id"])
            .values(
                status=(
                    (next_claim_status("pending", "decline") or "declined")
                    if impossible
                    else (next_claim_status("chosen", "release") or "pending")
                ),
                updated_at=func.now(),
            )
        )
        if impossible:
            await _notify(
                [_s(claim["judge_id"])], text_claim_impossible(offer, role), offer
            )
        await _notify([actor.judge_id], text_apply_failed(offer, message), offer)
        await _log(
            "zprp_failed",
            province=province,
            actor=actor,
            offer=offer,
            subject_id=_s(claim["judge_id"]),
            subject_name=_s(taker.get("full_name")),
            ok=False,
            message=message,
            payload={"code": code},
        )
        logger.warning("giełda: zapis nieudany offer=%s code=%s %s", offer_id, code, message)
        return {"id": offer_id, "status": "open", "applied": False, "code": code, "error": message}

    if not creds["configured"]:
        return await fail(
            "Ten okręg nie ma jeszcze konta obsadowego na serwerze, więc zmiany nie "
            "ma jak zapisać w bazie związku.",
            "NO_ACCOUNT",
        )

    holder = slot_holder_name(state_dict(offer.get("match_snapshot")), offer["slot"])
    if not holder:
        # Migawka mogla dopasowac gniazdo po NUMERZE i nie miec nazwiska. Bez
        # `expect` zapis nie sprawdza, kto siedzi w gniezdzie DZIS - a to jedyne,
        # przed czym ten straznik chroni: nadpisaniem swiezszej decyzji podjetej
        # poza aplikacja. Dosypujemy nazwisko z biezacego stanu meczu.
        current = await database.fetch_one(
            select(province_matches.c.state_json).where(
                and_(
                    province_matches.c.province == province,
                    province_matches.c.match_id == _s(offer["match_id"]),
                )
            )
        )
        holder = slot_holder_name(
            apply_known_swaps(
                state_dict((_row(current) if current else {}).get("state_json")),
                (await _applied_swaps(province, [_s(offer["match_id"])])).get(
                    _s(offer["match_id"]), ()
                ),
            ),
            offer["slot"],
        )
    if not holder:
        return await fail(
            "Nie wiem, kto zajmuje dziś to gniazdo w bazie związku, a bez tego "
            "zapis mógłby nadpisać świeższą decyzję obsadowego. Odśwież mecze "
            "okręgu i spróbuj ponownie.",
            "SLOT_UNKNOWN",
        )
    select_name = slot_select_name(offer["slot"])
    taker_name = _s(taker.get("full_name"))
    if not taker_name:
        return await fail(
            "Nie znam nazwiska tego sędziego na liście okręgu, a bez niego nie da się "
            "wskazać go w formularzu ZPRP.",
            "NO_NAME",
        )

    # Mecz spoza obsady okręgu: zapis idzie TRASĄ SĘDZIEGO (lista meczów
    # oddającego -> strona meczu -> formularz), a boiskowe gniazdo tylko przy
    # włączonej wymianie takich meczów - okręg mógł ją wyłączyć już po
    # wystawieniu oferty i wtedy decyzja ma się o to rozbić tu, nie w ZPRP.
    managed = is_managed_by_province(offer.get("match_code"), cfg["managed_prefixes"])
    if (
        not managed
        and _s(offer["slot"]) in FIELD_SLOTS
        and not cfg["foreign_matches_enabled"]
    ):
        return await fail(assignability_message("FOREIGN_OFF"), "FOREIGN_OFF")

    try:
        async with AsyncClient(
            base_url=settings.ZPRP_BASE_URL, follow_redirects=True, timeout=60.0
        ) as client:
            cookies = await _login_zprp(client, creds["username"], creds["password"])
            user = ""
            referer = ""
            if not managed:
                route = await walk_judge_route(
                    client,
                    cookies,
                    judge_id=_s(offer["from_judge_id"]),
                    id_zawody=_s(offer["match_id"]),
                    season_label=zprp_season_label(_now()),
                    log_prefix=f"gielda/trasa/offer-{offer_id}",
                )
                if not route["ok"]:
                    return await fail(
                        _s(route.get("message")) or assignability_message(route.get("reason")),
                        _s(route.get("reason")) or "NO_FORM",
                    )
                user = _s(route.get("user"))
                referer = _s(route.get("detail_path"))
            result = await apply_referee_assignment(
                client,
                cookies,
                _s(offer["match_id"]),
                {select_name: ("", taker_name)},
                user=user,
                referer=referer,
                expect=(select_name, holder),
                # Giełda nie zna numeru opcji - podaje samo nazwisko. Bez tego
                # nienalezione nazwisko wysłałoby pustą wartość, czyli WYCZYŚCIŁO
                # gniazdo zamiast je przejąć.
                require_name_match=True,
                # Chętny nie może stać już w innym gnieździe tego meczu -
                # formularz widzi obsadę z tej sekundy, migawka sprzed chwili.
                forbid_elsewhere=taker_name,
                log_prefix=f"gielda/offer-{offer_id}",
            )
    except Exception as exc:  # noqa: BLE001
        logger.exception("giełda: zapis do ZPRP wywrócił się")
        return await fail(f"Baza związku nie odpowiedziała: {exc}", "ZPRP_ERROR")

    if not result.get("success"):
        return await fail(
            _s(result.get("error")) or "Zapis nie potwierdził się w bazie związku.",
            _s(result.get("code")) or "VERIFICATION_FAILED",
            role=crew_label(result.get("role")) if result.get("role") else "",
        )

    await database.execute(
        update(match_market_offers)
        .where(match_market_offers.c.id == offer_id)
        .values(
            status=next_offer_status("applying", "applied") or "done",
            applied_at=func.now(),
            error=None,
            updated_at=func.now(),
        )
    )
    await database.execute(
        update(match_market_claims)
        .where(match_market_claims.c.offer_id == offer_id)
        .where(match_market_claims.c.status == "pending")
        .values(status="declined", updated_at=func.now())
    )

    # Nazwisko bierzemy z WERYFIKACJI formularza, a nie z listy okręgu: to ta
    # postać („NAZWISKO Imię") stoi w migawce i zapisze ją potem monitor.
    # Nazwisko z listy okręgu bywa odwrócone i ta sama obsada wyglądałaby na
    # dwa różne stany.
    verified = (result.get("verified_slots") or {}).get(
        SELECT_TO_SLOT.get(select_name, select_name), {}
    )
    patched = await _sync_slot_holder(
        province,
        _s(offer["match_id"]),
        _s(offer["slot"]),
        _s(claim["judge_id"]),
        _s(verified.get("name")) or taker_name,
    )

    await _log(
        "zprp_applied",
        province=province,
        actor=actor,
        offer=offer,
        subject_id=_s(claim["judge_id"]),
        subject_name=taker_name,
        ok=True,
        payload={"from": _s(giver.get("full_name")), "slotLabel": slot_label(offer["slot"])},
    )

    await _notify([_s(claim["judge_id"])], text_taker_won(offer), offer)
    await _notify(
        [_s(offer["from_judge_id"])],
        text_giver_released(offer, taker_name),
        offer,
    )
    others = await database.fetch_all(
        select(match_market_claims.c.judge_id)
        .where(match_market_claims.c.offer_id == offer_id)
        .where(match_market_claims.c.status == "declined")
    )
    await _notify(
        [_s(_row(r)["judge_id"]) for r in others],
        text_claim_lost(offer),
        offer,
    )
    # Reszta obsady - drugi sędzia, stolik, delegat. Wcześniej mówił im o tym
    # monitor, gdy zauważył różnicę w migawce; skoro migawka jest już
    # poprawiona, nie ma czego zauważyć, więc wiadomość należy do giełdy. Przy
    # okazji dochodzi natychmiast, a nie po przebiegu monitora.
    await _notify(
        crew_judge_ids(
            patched,
            exclude=[_s(offer["from_judge_id"]), _s(claim["judge_id"])],
        ),
        text_crew_changed(offer, taker_name, _s(giver.get("full_name"))),
        offer,
    )

    return {
        "id": offer_id,
        "status": "done",
        "applied": True,
        "from": _person(_s(offer["from_judge_id"]), giver),
        "to": _person(_s(claim["judge_id"]), taker),
    }


# ─────────────────────────── panel administratora ───────────────────────────


@router.get("/admin/provinces", summary="Stan giełdy i kont w województwach")
async def admin_provinces(actor: Actor = Depends(market_actor)) -> Dict[str, Any]:
    if not may_manage_config(is_admin=actor.is_admin):
        raise HTTPException(403, "Ten widok należy do administratora aplikacji.")

    configs = {
        _s(_row(r)["province"]): _row(r)
        for r in await database.fetch_all(select(province_module_config))
    }
    pending = {
        _s(_row(r)["province"]): int(_row(r)["n"])
        for r in await database.fetch_all(
            select(match_market_offers.c.province, func.count().label("n"))
            .where(match_market_offers.c.status == "open")
            .group_by(match_market_offers.c.province)
        )
    }

    from app.zprp_accounts import PROVINCE_ENV_SUFFIXES

    out = []
    for province in sorted(PROVINCE_ENV_SUFFIXES):
        cfg = configs.get(province, {})
        mode = _s(cfg.get("assign_account_mode")) or "own"
        out.append(
            {
                "province": province,
                "marketEnabled": bool(cfg.get("market_enabled", False)),
                "deadlineHours": normalize_deadline_hours(
                    cfg.get("offer_deadline_hours", DEFAULT_DEADLINE_HOURS)
                ),
                "assignAccountMode": mode,
                "approverBadges": normalize_approver_badges(cfg.get("approver_badges")),
                "foreignMatchesEnabled": bool(cfg.get("foreign_matches_enabled", False)),
                "managedPrefixes": managed_prefixes_for(province, cfg.get("managed_prefixes")),
                "managedPrefixesDefault": managed_prefixes_for(province),
                "managedPrefixesCustom": normalize_prefixes(cfg.get("managed_prefixes")) is not None,
                "accounts": account_status(province, mode),
                "openOffers": pending.get(province, 0),
                "updatedBy": _s(cfg.get("updated_by")) or None,
                "updatedAt": _iso(cfg.get("updated_at")),
            }
        )
    return {"provinces": out}


@router.get(
    "/admin/provinces/{province}/journal",
    summary="Dziennik giełdy w województwie - kto, kiedy, co",
)
async def admin_journal(
    province: str,
    group: str = Query("", description="Grupa zdarzen: offers|claims|decisions|config. Pusto = wszystkie."),
    q: str = Query("", description="Szukanie po nazwisku, numerze meczu albo tresci wpisu."),
    since: str = Query("", description="Od tej daty (ISO). Pusto = bez dolnej granicy."),
    until: str = Query("", description="Do tej daty (ISO). Pusto = bez gornej granicy."),
    limit: int = Query(80, ge=1, le=400),
    before_id: int = Query(0, ge=0, description="Strona nastepna: id ostatniego wpisu poprzedniej."),
    actor: Actor = Depends(market_actor),
) -> Dict[str, Any]:
    """Pelna historia gieldy jednego okregu, od najnowszego wpisu.

    Nalezy do ADMINISTRATORA APLIKACJI, nie do obsadowego: to rejestr czyjejs
    pracy, razem z powodami odrzucen i trescia notatek. Obsadowy widzi to, co
    dotyczy jego decyzji, w widoku samej oferty.

    Wpisy sa niezmienne i nie znikaja razem z oferta, wiec dziennik pokazuje
    rowniez sprawy dawno zamkniete - dlatego strona jest wprost ograniczona, a
    kolejna dochodzi przez `before_id` (nie offsetem: dopisany w tym czasie wpis
    przesunalby cala liste i jeden by sie zgubil).
    """
    if not may_manage_config(is_admin=actor.is_admin):
        raise HTTPException(403, "Dziennik giełdy należy do administratora aplikacji.")
    key = normalize_province(province)
    if not key:
        raise HTTPException(400, "Nie znam takiego województwa.")

    query = select(match_market_events).where(match_market_events.c.province == key)

    wanted = _s(group)
    if wanted:
        kinds = kinds_in_group(wanted)
        if not kinds:
            raise HTTPException(400, "Nie znam takiej grupy zdarzeń.")
        query = query.where(match_market_events.c.kind.in_(kinds))

    needle = _s(q)
    if needle:
        # Szukamy po tym, co administrator ma pod reka: nazwisko (sprawcy albo
        # osoby, ktorej sprawa dotyczy), numer meczu i tresc wpisu - tam siedza
        # powody odrzucen i kody odmowy ZPRP.
        like = f"%{needle.lower()}%"
        query = query.where(
            or_(
                func.lower(func.coalesce(match_market_events.c.actor_name, "")).like(like),
                func.lower(func.coalesce(match_market_events.c.subject_name, "")).like(like),
                func.lower(func.coalesce(match_market_events.c.match_code, "")).like(like),
                func.lower(func.coalesce(match_market_events.c.message, "")).like(like),
                func.coalesce(match_market_events.c.match_id, "").like(f"%{needle}%"),
            )
        )

    def parse_stamp(raw: str, field: str) -> Optional[datetime]:
        text_value = _s(raw)
        if not text_value:
            return None
        try:
            stamp = datetime.fromisoformat(text_value.replace("Z", "+00:00"))
        except ValueError:
            raise HTTPException(400, f"Data w polu {field} nie jest poprawna.")
        return stamp if stamp.tzinfo else stamp.replace(tzinfo=timezone.utc)

    lower = parse_stamp(since, "since")
    upper = parse_stamp(until, "until")
    if lower:
        query = query.where(match_market_events.c.created_at >= lower)
    if upper:
        query = query.where(match_market_events.c.created_at <= upper)
    if before_id:
        query = query.where(match_market_events.c.id < before_id)

    rows = await database.fetch_all(
        query.order_by(match_market_events.c.id.desc()).limit(limit)
    )
    events = [_row(r) for r in rows]

    # Liczniki grup licza sie na TYM SAMYM sicie co lista, ale BEZ pigulki grupy:
    # pigulka ma mowic, ile jest do zobaczenia po jej dotknieciu, a nie ile
    # zostalo po jej wlasnym odsiewie.
    counts_query = select(
        match_market_events.c.kind, func.count().label("n")
    ).where(match_market_events.c.province == key)
    if needle:
        like = f"%{needle.lower()}%"
        counts_query = counts_query.where(
            or_(
                func.lower(func.coalesce(match_market_events.c.actor_name, "")).like(like),
                func.lower(func.coalesce(match_market_events.c.subject_name, "")).like(like),
                func.lower(func.coalesce(match_market_events.c.match_code, "")).like(like),
                func.lower(func.coalesce(match_market_events.c.message, "")).like(like),
                func.coalesce(match_market_events.c.match_id, "").like(f"%{needle}%"),
            )
        )
    if lower:
        counts_query = counts_query.where(match_market_events.c.created_at >= lower)
    if upper:
        counts_query = counts_query.where(match_market_events.c.created_at <= upper)
    by_kind = {
        _s(_row(r)["kind"]): int(_row(r)["n"])
        for r in await database.fetch_all(counts_query.group_by(match_market_events.c.kind))
    }

    return {
        "province": key,
        "events": [
            {
                "id": int(e["id"]),
                "kind": _s(e["kind"]),
                "offerId": int(e["offer_id"]) if e.get("offer_id") is not None else None,
                "matchId": _s(e.get("match_id")) or None,
                "matchCode": _s(e.get("match_code")) or None,
                "slot": _s(e.get("slot")) or None,
                "slotLabel": slot_label(e.get("slot")) if e.get("slot") else None,
                "actorId": _s(e.get("actor_judge_id")) or None,
                "actorName": _s(e.get("actor_name")) or None,
                "subjectId": _s(e.get("subject_judge_id")) or None,
                "subjectName": _s(e.get("subject_name")) or None,
                "ok": e.get("ok"),
                "message": _s(e.get("message")) or None,
                "payload": state_dict(e.get("payload")),
                "at": _iso(e.get("created_at")),
            }
            for e in events
        ],
        "byKind": by_kind,
        "total": sum(by_kind.values()),
        # Pusto = nie ma nastepnej strony; inaczej to `before_id` do kolejnego pytania.
        "nextBefore": int(events[-1]["id"]) if len(events) == limit else None,
    }


@router.put("/admin/provinces/{province}", summary="Ustawienia giełdy w województwie")
async def admin_set_province(
    province: str, req: ProvinceConfigRequest, actor: Actor = Depends(market_actor)
) -> Dict[str, Any]:
    if not may_manage_config(is_admin=actor.is_admin):
        raise HTTPException(403, "Te ustawienia należą do administratora aplikacji.")
    key = normalize_province(province)
    if not key:
        raise HTTPException(400, "Nie znam takiego województwa.")

    mode = _s(req.assign_account_mode)
    if mode and mode not in ("own", "same_as_sync"):
        raise HTTPException(400, "Tryb konta to own albo same_as_sync.")

    current = await database.fetch_one(
        select(province_module_config).where(province_module_config.c.province == key)
    )
    values: Dict[str, Any] = {"updated_by": actor.judge_id}
    if req.market_enabled is not None:
        values["market_enabled"] = bool(req.market_enabled)
    if req.offer_deadline_hours is not None:
        values["offer_deadline_hours"] = normalize_deadline_hours(req.offer_deadline_hours)
    if mode:
        values["assign_account_mode"] = mode
    if req.approver_badges is not None:
        # Pusty wybór NIE wyłącza rozstrzygania - normalizacja wraca do odznaki
        # obsadowego, żeby okręg nie został z giełdą, której nikt nie domknie.
        values["approver_badges"] = normalize_approver_badges(req.approver_badges)
    if req.foreign_matches_enabled is not None:
        values["foreign_matches_enabled"] = bool(req.foreign_matches_enabled)
    if req.reset_managed_prefixes:
        # NULL w kolumnie = katalog domyślny z liścia reguł.
        values["managed_prefixes"] = None
    elif req.managed_prefixes is not None:
        values["managed_prefixes"] = normalize_prefixes(req.managed_prefixes) or []

    if current:
        await database.execute(
            update(province_module_config)
            .where(province_module_config.c.province == key)
            .values(**values, updated_at=func.now())
        )
    else:
        await database.execute(
            insert(province_module_config).values(province=key, **values)
        )

    await _log(
        "config_changed",
        province=key,
        actor=actor,
        message=config_diff_message(
            _row(current) if current else None,
            {k: v for k, v in values.items() if k != "updated_by"},
        ),
        payload={"fields": [k for k in values if k != "updated_by"]},
    )

    cfg = await _config(key)
    return {
        "province": key,
        "marketEnabled": cfg["market_enabled"],
        "deadlineHours": cfg["offer_deadline_hours"],
        "assignAccountMode": cfg["assign_account_mode"],
        "approverBadges": cfg["approver_badges"],
        "foreignMatchesEnabled": cfg["foreign_matches_enabled"],
        "managedPrefixes": cfg["managed_prefixes"],
        "managedPrefixesDefault": managed_prefixes_for(key),
        "managedPrefixesCustom": cfg["managed_prefixes_custom"],
        "accounts": account_status(key, cfg["assign_account_mode"]),
    }


@router.post(
    "/admin/provinces/{province}/route-check",
    summary="Sprawdź trasę sędziego do meczu spoza obsady okręgu - bez zapisu",
)
async def admin_route_check(
    province: str,
    req: RouteCheckRequest,
    actor: Actor = Depends(market_actor),
    settings: Settings = Depends(get_settings),
) -> Dict[str, Any]:
    """Przechodzi trasę sędziego krok po kroku i mówi, co widzi.

    Czy ZPRP przyjmie ZAPIS dla meczu spoza województwa konta, wie dopiero
    pierwsza prawdziwa wymiana - ale wszystko przed zapisem (lista meczów
    sędziego, przycisk „Sędziowie", formularz z listami, kto stoi w gniazdach)
    da się obejrzeć bez dotykania obsady. Administrator włącza wymianę takich
    meczów po tym raporcie, nie na ślepo. Niczego nie zapisujemy: ani w bazie
    związku, ani w pamięci sondy, ani w dzienniku - to podgląd.
    """
    if not may_manage_config(is_admin=actor.is_admin):
        raise HTTPException(403, "To sprawdzenie należy do administratora aplikacji.")
    key = normalize_province(province)
    if not key:
        raise HTTPException(400, "Nie znam takiego województwa.")
    code = _s(req.match_code)
    if not code:
        raise HTTPException(400, "Podaj numer meczu, np. IMD/3.")
    judge = _s(req.judge_id) or actor.judge_id
    cfg = await _config(key)
    creds = assign_credentials(key, cfg["assign_account_mode"])
    if not creds["configured"]:
        raise HTTPException(409, assignability_message("NO_ACCOUNT"))

    report: Dict[str, Any] = {
        "province": key,
        "judgeId": judge,
        "judgeName": "",
        "matchCode": code,
        "matchId": "",
        "season": "",
        "when": "",
        "teams": "",
        "level": league_level(code),
        "managed": is_managed_by_province(code, cfg["managed_prefixes"]),
        "foreignEnabled": cfg["foreign_matches_enabled"],
        "user": "",
        "steps": [],
        "slots": {},
        "verdict": {"assignable": None, "reason": "UNCHECKED", "message": ""},
    }
    prefix = f"gielda/trasa/{key}"
    try:
        async with AsyncClient(
            base_url=settings.ZPRP_BASE_URL, follow_redirects=True, timeout=60.0
        ) as client:
            try:
                cookies = await _login_zprp(client, creds["username"], creds["password"])
            except HTTPException as exc:
                report["steps"].append(
                    {
                        "key": "login",
                        "ok": False,
                        "title": "Logowanie do bazy związku",
                        "detail": _s(exc.detail),
                    }
                )
                report["verdict"] = {
                    "assignable": None,
                    "reason": "PROBE_FAILED",
                    "message": assignability_message("PROBE_FAILED"),
                }
                return report
            route = await walk_judge_route(
                client,
                cookies,
                judge_id=judge,
                match_code=code,
                season_label=zprp_season_label(_now()),
                log_prefix=prefix,
            )
            report.update(
                {
                    "judgeName": _s(route.get("judge_name")),
                    "matchId": _s(route.get("id_zawody")),
                    "season": _s(route.get("season")),
                    "when": _s(route.get("when")),
                    "teams": " - ".join(
                        p for p in (_s(route.get("host")), _s(route.get("guest"))) if p
                    ),
                    "user": _s(route.get("user")),
                    "steps": list(route.get("steps") or []),
                }
            )
            if not route["ok"]:
                report["verdict"] = {
                    "assignable": False,
                    "reason": _s(route.get("reason")) or "NO_FORM",
                    "message": _s(route.get("message")),
                }
                return report
            form = await probe_assignment_rights(
                client,
                cookies,
                _s(route["id_zawody"]),
                user=_s(route.get("user")),
                referer=_s(route.get("detail_path")),
                log_prefix=prefix,
            )
            ok = bool(form.get("assignable"))
            slots = form.get("slots") or {}
            holders = "; ".join(
                f"{crew_label(label)}: {_s(data.get('holder')) or 'nikt'}"
                for label, data in slots.items()
            )
            report["steps"].append(
                {
                    "key": "form",
                    "ok": ok,
                    "title": "Formularz obsady",
                    "detail": (
                        f"{int(form.get('option_count') or 0)} sędziów na listach. {holders}"
                        if ok
                        else _s(form.get("message"))
                    ),
                }
            )
            report["slots"] = slots
            report["verdict"] = {
                "assignable": ok,
                "reason": _s(form.get("reason")) or ("OK" if ok else "NO_FORM"),
                "message": "" if ok else _s(form.get("message")),
            }
    except Exception as exc:  # noqa: BLE001
        logger.warning("gielda: sprawdzenie trasy %s/%s nieudane: %s", key, code, exc)
        report["steps"].append(
            {
                "key": "network",
                "ok": False,
                "title": "Baza związku",
                "detail": f"Nie odpowiedziała: {exc}",
            }
        )
        report["verdict"] = {
            "assignable": None,
            "reason": "PROBE_FAILED",
            "message": assignability_message("PROBE_FAILED"),
        }
    logger.info(
        "gielda: trasa %s sedzia=%s mecz=%s -> %s",
        key, judge, code, report["verdict"]["reason"],
    )
    return report
