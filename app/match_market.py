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
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Query
from httpx import AsyncClient
from pydantic import BaseModel
from sqlalchemy import and_, func, insert, or_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.db import (
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
from app.match_market_access import (
    APPROVER_BADGE,
    approver_judge_ids,
    may_approve,
    may_manage_config,
)
from app.match_market_rules import (
    ASSIGNABILITY_TTL_HOURS,
    DEFAULT_DEADLINE_HOURS,
    PROBE_BATCH_LIMIT,
    SLOT_STATE_FIELDS,
    assignability_is_fresh,
    assignability_message,
    can_offer,
    deadline_for,
    market_pushes_allowed,
    may_claim,
    names_match,
    next_claim_status,
    next_offer_status,
    normalize_deadline_hours,
    slot_holder_name,
    slot_is_tradeable,
    slot_label,
    slot_select_name,
    slots_held_by,
)
from app.proel_auth import is_admin
from app.push.push import send_push_to_judges
from app.zprp.assignments import (
    _login_zprp,
    apply_referee_assignment,
    probe_assignment_rights,
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

    @property
    def is_approver(self) -> bool:
        return may_approve(
            is_admin=self.is_admin,
            province=self.province,
            judge_province=self.province,
            badges_raw=self.badges,
        )


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
    state = state or {}
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


#: Pola stanu meczu, ktore mowia "ten czlowiek tu jest".
#:
#: Gniazda gieldowe PLUS delegat: delegata gielda nie wymienia, ale delegowanie
#: na dwa mecze tego samego dnia jest kolizja dokladnie tak samo.
_ROLE_STATE_FIELDS: Tuple[Tuple[str, str], ...] = tuple(SLOT_STATE_FIELDS.values()) + (
    ("NrSedzia_delegat", "NrSedzia_delegat_nazwisko"),
)


def _holds_any_role(state: Dict[str, Any], judge_id: str, full_name: str) -> bool:
    """Czy ten sedzia jest przy tym meczu w JAKIEJKOLWIEK roli.

    Numer przed nazwiskiem, jak w `slots_held_by`: gdy stan niesie numer, on
    rozstrzyga, a nazwisko zostaje dla meczow, ktorych monitor nie sprawdzil
    gleboko.
    """
    wanted = _s(judge_id)
    for id_field, name_field in _ROLE_STATE_FIELDS:
        raw_id = _s((state or {}).get(id_field))
        if raw_id:
            if wanted and raw_id == wanted:
                return True
            continue
        if full_name and names_match((state or {}).get(name_field), full_name):
            return True
    return False


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
    out: Dict[str, List[Dict[str, str]]] = {}
    for raw in rows:
        data = _row(raw)
        state = data.get("state_json") or {}
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

#: Ile meczow terminarza przegladamy, szukajac swoich.
#:
#: Wojewodztwo rozgrywa w sezonie rzedu kilkuset spotkan; ten limit jest
#: bezpiecznikiem, a nie miara. Gdyby okazal sie ciasny, lista skroci sie od
#: konca - czyli od meczow najdalszych, ktorych i tak nie da sie jeszcze oddac.
MY_MATCHES_SCAN_LIMIT = 600


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
    if _s(verdict.get("reason")) == "PROBE_FAILED":
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
) -> Dict[str, Dict[str, Any]]:
    """Pyta baze zwiazku o wskazane mecze - jedno logowanie na cala paczke.

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

    try:
        async with AsyncClient(
            base_url=settings.ZPRP_BASE_URL, follow_redirects=True, timeout=45.0
        ) as client:
            cookies = await _login_zprp(client, creds["username"], creds["password"])

            async def one(match_id: str) -> None:
                async with gate:
                    try:
                        verdict = await probe_assignment_rights(
                            client,
                            cookies,
                            match_id,
                            slot=slot,
                            log_prefix=f"gielda/sonda/{province}",
                        )
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

            await asyncio.gather(*(one(m) for m in targets))
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
) -> None:
    """Twarda bramka przed wystawieniem meczu. Odmowa mowi, dlaczego.

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
    )
    answer = fresh.get(_s(match_id)) or {}
    if answer.get("assignable"):
        return
    raise HTTPException(
        409, _s(answer.get("message")) or assignability_message(answer.get("reason"))
    )


# ─────────────────────────── powiadomienia ───────────────────────────


def _offer_data(offer: Dict[str, Any]) -> Dict[str, str]:
    """Ładunek push-a - stąd dispatcher deep-linków wie, co otworzyć."""
    return {
        "kind": "match_market",
        "offerId": str(offer.get("id")),
        "province": _s(offer.get("province")),
        "matchId": _s(offer.get("match_id")),
        "matchNumber": _s(offer.get("match_code")),
    }


def _offer_line(offer: Dict[str, Any]) -> str:
    """„OSK/12 · sędzia 1" - jedna linijka opisu do treści powiadomienia."""
    code = _s(offer.get("match_code")) or "mecz"
    return f"{code} · {slot_label(offer.get('slot'))}"


async def _notify(judge_ids: List[str], title: str, body: str, offer: Dict[str, Any]) -> None:
    """Wysyłka, która nigdy nie wywraca operacji, przy której powstała."""
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
    rows = await database.fetch_all(
        select(
            province_judges.c.judge_id,
            province_judges.c.province,
            province_judges.c.badges,
        ).where(province_judges.c.province == province)
    )
    return approver_judge_ids([_row(r) for r in rows], province)


# ─────────────────────────── modele ───────────────────────────


class CreateOfferRequest(BaseModel):
    match_id: str
    slot: str
    reason: Optional[str] = None


class ClaimRequest(BaseModel):
    note: Optional[str] = None


class ApproveRequest(BaseModel):
    claim_id: int


class RejectRequest(BaseModel):
    reason: Optional[str] = None


class ProvinceConfigRequest(BaseModel):
    market_enabled: Optional[bool] = None
    offer_deadline_hours: Optional[int] = None
    assign_account_mode: Optional[str] = None


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
    return {
        "judgeId": actor.judge_id,
        "province": actor.province,
        "fullName": actor.full_name,
        "photoUrl": actor.photo_url,
        "knownInProvince": actor.known and bool(actor.province),
        "isApprover": actor.is_approver,
        "isAdmin": actor.is_admin,
        "enabled": bool(cfg and cfg["market_enabled"]),
        "deadlineHours": cfg["offer_deadline_hours"] if cfg else DEFAULT_DEADLINE_HOURS,
        "approverBadge": APPROVER_BADGE,
        "accountReady": account_ready,
    }


# ─────────────────────────── moje mecze ───────────────────────────


@router.get("/my-matches", summary="Moje najbliższe mecze - co da się oddać")
async def my_matches(
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
    province = _require_province(actor)
    cfg = await _require_enabled(province)
    now = _now()

    # Czytamy TERMINARZ okregu, a nie liste `province_match_judges`.
    #
    # Tamta tabela powstaje z listy meczow sedziego, ktora monitor pobiera
    # wylacznie dla sedziow majacych zarejestrowany token push - a token powstaje
    # dopiero, gdy ktos zgodzi sie na powiadomienia. Sedzia, ktory odmowil, nie
    # mial tam ani jednego wiersza i gielda pokazywala mu pusta liste bez slowa
    # wyjasnienia. Terminarz wojewodztwa jest niezalezny od tego, kto ma
    # aplikacje: wypelnia go pelny przebieg monitora kontem okregu.
    #
    # O tym, ktory mecz jest MOJ, rozstrzyga `slots_held_by` - numer sedziego
    # przed nazwiskiem, dokladnie jak przy wystawianiu oferty. Dzieki temu lista
    # i bramka `POST /offers` odpowiadaja na to samo pytanie tak samo.
    horizon = now + timedelta(days=MY_MATCHES_HORIZON_DAYS)
    rows = await database.fetch_all(
        select(
            province_matches.c.match_id,
            province_matches.c.match_code,
            province_matches.c.match_at,
            province_matches.c.state_json,
            province_matches.c.approved,
        )
        .where(province_matches.c.province == province)
        .where(province_matches.c.active.is_(True))
        .where(
            or_(
                province_matches.c.match_at.is_(None),
                and_(
                    province_matches.c.match_at >= now,
                    province_matches.c.match_at <= horizon,
                ),
            )
        )
        .order_by(province_matches.c.match_at.asc().nulls_last())
        .limit(MY_MATCHES_SCAN_LIMIT)
    )

    match_ids = [_s(_row(r)["match_id"]) for r in rows]
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

    mine: List[Tuple[Dict[str, Any], Dict[str, Any], List[str]]] = []
    for raw in rows:
        data = _row(raw)
        state = data.get("state_json") or {}
        held = slots_held_by(state, actor.judge_id, actor.full_name)
        if not held:
            # Sędzia jest przy meczu (wie o tym `province_match_judges`), ale w
            # gnieździe giełdowym go nie ma - czyli jest delegatem. Nie ma tu
            # czego oddać.
            continue
        mine.append((data, state, held))

    # Uprawnienia okręgu. Werdykty z pamięci są darmowe; `verify=1` dopytuje
    # bazę związku o te mecze, których jeszcze nie znamy - najbliższe najpierw,
    # bo `rows` przyszły posortowane po dacie.
    creds = assign_credentials(province, cfg["assign_account_mode"])
    account_ready = bool(creds["configured"])
    mode = _s(creds["mode"])
    ids = [_s(d["match_id"]) for d, _st, _h in mine]
    cached = await _cached_verdicts(province, ids, mode, now) if account_ready else {}
    missing = [m for m in ids if m not in cached]
    probed: Dict[str, Dict[str, Any]] = {}
    if verify and account_ready and missing:
        probed = await _probe(province, mode, creds, missing[:PROBE_BATCH_LIMIT], settings)

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
    for data, state, held in mine:
        match_id = _s(data["match_id"])
        verdict = verdict_for(match_id)
        if verdict["assignable"] is None:
            unchecked += 1
            # "Pytalismy i nie doszlo" to inna wiadomosc niz "jeszcze nie
            # pytalismy" - pierwsza mowi o awarii po drugiej stronie.
            if verdict["reason"] == "PROBE_FAILED":
                probe_failed += 1
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
            }
        )
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
    }


# ─────────────────────────── oferty ───────────────────────────


async def _offer_payload(
    offer: Dict[str, Any],
    cards: Dict[str, Dict[str, Any]],
    claims: List[Dict[str, Any]],
    *,
    viewer_id: str,
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
        "match": _match_view(offer.get("match_snapshot") or {}, offer.get("match_at")),
        "from": _person(_s(offer.get("from_judge_id")), cards.get(_s(offer.get("from_judge_id")))),
        "isMine": _s(offer.get("from_judge_id")) == _s(viewer_id),
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

    return {
        "scope": scope,
        "offers": [
            await _offer_payload(
                r, cards, claims.get(int(r["id"]), []), viewer_id=actor.judge_id
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

    match = await database.fetch_one(
        select(province_matches).where(
            and_(
                province_matches.c.province == province,
                province_matches.c.match_id == _s(req.match_id),
            )
        )
    )
    if not match:
        raise HTTPException(404, "Nie znam tego meczu w Twoim okręgu.")
    data = _row(match)
    state = data.get("state_json") or {}

    if slot not in slots_held_by(state, actor.judge_id, actor.full_name):
        raise HTTPException(403, "To nie jest Twoje gniazdo w tym meczu.")
    if data.get("approved"):
        raise HTTPException(409, "Protokół tego meczu jest już zatwierdzony.")
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
    await _require_assignable(province, cfg, _s(req.match_id), settings, slot=slot)

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
    # Zainteresowani to sędziowie okręgu, którzy mają aplikację i nie wyłączyli
    # powiadomień giełdy - reszta i tak zobaczy ofertę przy najbliższym wejściu
    # na ekran.
    await _notify(
        await _broadcast_targets(province, actor.judge_id),
        "🔁 Mecz do wzięcia",
        f"{actor.full_name or 'Sędzia'} oddaje {_offer_line(offer)}.",
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

    await _notify(
        interested,
        "↩️ Mecz wrócił do właściciela",
        f"{actor.full_name or 'Sędzia'} wycofał {_offer_line(offer)}.",
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

    await _notify(
        await _approvers_of(province),
        "🙋 Zgłoszenie na mecz",
        f"{actor.full_name or 'Sędzia'} chce wziąć {_offer_line(offer)}.",
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


def _apply_is_stale(updated_at: Any, now: datetime) -> bool:
    """Czy `applying` na tym wierszu to slad po przerwanym zapisie."""
    if not isinstance(updated_at, datetime):
        return True
    stamp = updated_at if updated_at.tzinfo else updated_at.replace(tzinfo=timezone.utc)
    return stamp + timedelta(minutes=STALE_APPLY_MINUTES) <= now


async def _require_approver(actor: Actor, province: str) -> None:
    if not may_approve(
        is_admin=actor.is_admin,
        province=province,
        judge_province=actor.province,
        badges_raw=actor.badges,
    ):
        raise HTTPException(
            403,
            "Rozstrzyganie wymian należy do administratora i do sędziów z odznaką "
            f"{APPROVER_BADGE} w tym okręgu.",
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
    approver = may_approve(
        is_admin=actor.is_admin,
        province=province,
        judge_province=actor.province,
        badges_raw=actor.badges,
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

    payload = await _offer_payload(offer, cards, claims, viewer_id=actor.judge_id)
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
    payload["slotHolder"] = slot_holder_name(offer.get("match_snapshot") or {}, offer["slot"])

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
    live_state = live_row.get("state_json") or {}
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
    await _notify(
        [_s(offer["from_judge_id"])] + interested,
        "🚫 Wymiana odrzucona",
        f"{_offer_line(offer)} zostaje bez zmian." + (f" Powód: {reason}" if reason else ""),
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

    cfg = await _config(province)
    creds = assign_credentials(province, cfg["assign_account_mode"])
    cards = await _judges_by_id([_s(offer["from_judge_id"]), _s(claim["judge_id"])])
    giver = cards.get(_s(offer["from_judge_id"])) or {}
    taker = cards.get(_s(claim["judge_id"])) or {}

    async def fail(message: str, code: str) -> Dict[str, Any]:
        """Oferta wraca na giełdę, chętny do puli, a obsadowy dostaje powód."""
        await database.execute(
            update(match_market_offers)
            .where(match_market_offers.c.id == offer_id)
            .values(
                status=next_offer_status("applying", "apply_failed") or "open",
                error=message,
                updated_at=func.now(),
            )
        )
        await database.execute(
            update(match_market_claims)
            .where(match_market_claims.c.id == claim["id"])
            .values(status=next_claim_status("chosen", "release") or "pending", updated_at=func.now())
        )
        await _notify(
            [actor.judge_id],
            "⚠️ Wymiana niezapisana",
            f"{_offer_line(offer)}: {message}",
            offer,
        )
        logger.warning("giełda: zapis nieudany offer=%s code=%s %s", offer_id, code, message)
        return {"id": offer_id, "status": "open", "applied": False, "code": code, "error": message}

    if not creds["configured"]:
        return await fail(
            "Ten okręg nie ma jeszcze konta obsadowego na serwerze, więc zmiany nie "
            "ma jak zapisać w bazie związku.",
            "NO_ACCOUNT",
        )

    holder = slot_holder_name(offer.get("match_snapshot") or {}, offer["slot"])
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
            (_row(current) if current else {}).get("state_json") or {}, offer["slot"]
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

    try:
        async with AsyncClient(
            base_url=settings.ZPRP_BASE_URL, follow_redirects=True, timeout=60.0
        ) as client:
            cookies = await _login_zprp(client, creds["username"], creds["password"])
            result = await apply_referee_assignment(
                client,
                cookies,
                _s(offer["match_id"]),
                {select_name: ("", taker_name)},
                expect=(select_name, holder),
                # Giełda nie zna numeru opcji - podaje samo nazwisko. Bez tego
                # nienalezione nazwisko wysłałoby pustą wartość, czyli WYCZYŚCIŁO
                # gniazdo zamiast je przejąć.
                require_name_match=True,
                log_prefix=f"gielda/offer-{offer_id}",
            )
    except Exception as exc:  # noqa: BLE001
        logger.exception("giełda: zapis do ZPRP wywrócił się")
        return await fail(f"Baza związku nie odpowiedziała: {exc}", "ZPRP_ERROR")

    if not result.get("success"):
        return await fail(
            _s(result.get("error")) or "Zapis nie potwierdził się w bazie związku.",
            _s(result.get("code")) or "VERIFICATION_FAILED",
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

    line = _offer_line(offer)
    await _notify(
        [_s(claim["judge_id"])],
        "✅ Masz nowy mecz",
        f"{line} jest Twój. Obsadę zapisano w bazie związku.",
        offer,
    )
    await _notify(
        [_s(offer["from_judge_id"])],
        "✅ Mecz oddany",
        f"{line} przejmuje {taker_name}.",
        offer,
    )
    others = await database.fetch_all(
        select(match_market_claims.c.judge_id)
        .where(match_market_claims.c.offer_id == offer_id)
        .where(match_market_claims.c.status == "declined")
    )
    await _notify(
        [_s(_row(r)["judge_id"]) for r in others],
        "🔁 Mecz zajęty",
        f"{line} trafił do innego sędziego.",
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
                "accounts": account_status(province, mode),
                "openOffers": pending.get(province, 0),
                "updatedBy": _s(cfg.get("updated_by")) or None,
                "updatedAt": _iso(cfg.get("updated_at")),
            }
        )
    return {"provinces": out}


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

    cfg = await _config(key)
    return {
        "province": key,
        "marketEnabled": cfg["market_enabled"],
        "deadlineHours": cfg["offer_deadline_hours"],
        "assignAccountMode": cfg["assign_account_mode"],
        "accounts": account_status(key, cfg["assign_account_mode"]),
    }
