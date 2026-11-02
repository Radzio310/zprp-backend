"""Kalendarze drugorzędne Google: silnik (zapisy wydarzeń, ustawienia, przenoszenie).

Silnik nie importuje `app.db` ani bibliotek Google. Dostaje `Deps` z dwoma
portami, więc cały przebieg sprawdza test na atrapie Google, bez sieci:

* `deps.store`  - dostęp do bazy (implementacja: `calendar_secondary_store`),
* `deps.api_current(user)` / `deps.api_parked(user)` - klient Google dla
  bieżącego i zaparkowanego (starego) tokenu (implementacja:
  `calendar_secondary_google`).

Porty store (wszystko async):
  get_setup, upsert_setup, set_calendar_id (zapis warunkowy), get_tokens,
  save_tokens, delete_tokens, park_tokens, clear_park, list_mappings,
  get_mapping, save_mapping, delete_mapping, delete_mappings_for_calendar,
  try_start_job (warunkowy), update_job.

Porty api (async, błąd Google = `GoogleError`):
  get_calendar, insert_calendar, delete_calendar, patch_calendar_list,
  get_event, insert_event, update_event, delete_event, list_events.
"""

from __future__ import annotations

import asyncio
import datetime
import logging
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

from app.calendar_event_ids import google_event_id
from app.calendar_secondary_rules import (
    CALENDAR_NAMES,
    CALENDAR_TIMEZONE,
    DEFAULT_COLORS,
    JOB_STALE_SECONDS,
    KINDS,
    LEFTOVER_NOTE,
    MODES,
    GoogleError,
    SecondaryError,
    access_level,
    converted_event_body,
    district_access_error,
    foreground_for,
    google_error_message,
    has_primary_access,
    is_beach_key,
    is_movable_match_event,
    job_is_stale,
    job_public,
    kind_for_target,
    kinds_for_mode,
    match_event_body,
    needs_migration,
    resolve_target,
    sanitize_colors,
    sanitize_reminders,
    target_from_title,
    transparency,
    uses_secondary,
)

logger = logging.getLogger(__name__)

SETUP_DEFAULTS: dict[str, Any] = {
    "mode": "two",
    "busy": True,
    "email": None,
    "whistle_id": None,
    "stopwatch_id": None,
    "shared_id": None,
    "whistle_color": None,
    "stopwatch_color": None,
    "shared_color": None,
    "whistle_refill": False,
    "stopwatch_refill": False,
    "shared_refill": False,
    "migrated": False,
    "park_access": None,
    "park_refresh": None,
    "park_expires": None,
    "park_scope": None,
    "job_kind": None,
    "job_state": None,
    "job_total": 0,
    "job_done": 0,
    "job_skipped": 0,
    "job_failed": 0,
    "job_error": None,
    "job_kept": None,
    "job_note": None,
    "legacy_left": False,
    "color_pending": None,
    "job_heartbeat": None,
}


@dataclass
class Deps:
    store: Any
    flag: bool
    api_current: Callable[[str], Awaitable[Any]]
    api_parked: Callable[[str], Awaitable[Any]]
    now: Callable[[], datetime.datetime] = lambda: datetime.datetime.now(
        datetime.timezone.utc
    )


@dataclass
class Plan:
    """Decyzja trasowania: `kind` None = kalendarz główny (primary)."""

    kind: str | None


_LOCKS: dict[tuple[str, str], asyncio.Lock] = {}


def _lock(user: str, key: str) -> asyncio.Lock:
    return _LOCKS.setdefault((user, key), asyncio.Lock())


async def _setup(deps: Deps, user: str) -> dict:
    row = await deps.store.get_setup(user)
    return {**SETUP_DEFAULTS, **(dict(row) if row else {})}


def _color_of(setup: dict, kind: str) -> str:
    return setup.get(f"{kind}_color") or DEFAULT_COLORS[kind]


# ── Trasowanie ─────────────────────────────────────────────────────────────
async def plan_write(
    deps: Deps, user: str, summary: str | None, target: str | None
) -> Plan | None:
    """None = stara ścieżka (flaga wyłączona albo konto legacy)."""
    if not deps.flag or is_beach_key(user):
        return None
    tokens = await deps.store.get_tokens(user)
    if not tokens:
        return None
    level = access_level(tokens.get("scope"))
    if level == "legacy":
        return None
    if level == "none":
        raise SecondaryError(
            403,
            "calendar_scope_missing",
            "Zgoda Google nie obejmuje kalendarzy BAZY. Połącz kalendarz ponownie.",
        )
    resolved = resolve_target(summary, target)
    if resolved == "primary":
        if level != "district":
            raise district_access_error()
        return Plan(kind=None)
    setup = await _setup(deps, user)
    return Plan(kind=kind_for_target(resolved, setup["mode"]))


async def account_uses_secondary(deps: Deps, user: str) -> bool:
    if not deps.flag or is_beach_key(user):
        return False
    tokens = await deps.store.get_tokens(user)
    return bool(tokens and uses_secondary(True, user, tokens.get("scope")))


async def primary_body_extras(deps: Deps, user: str, reminders: list[dict]) -> dict:
    """Pola treści dla wpisu w kalendarzu głównym konta po przejściu:
    przypomnienia (do 5, popup/email) i zajętość z ustawień konta."""
    overrides = sanitize_reminders(reminders)
    setup = await _setup(deps, user)
    return {
        "reminders": {"useDefault": False, "overrides": overrides},
        "transparency": transparency(setup["busy"]),
    }


async def require_primary_read(deps: Deps, user: str) -> None:
    """GET /events, /labels: tylko legacy albo district, inaczej 403."""
    if not deps.flag or is_beach_key(user):
        return
    tokens = await deps.store.get_tokens(user)
    if not tokens:
        return
    if not has_primary_access(tokens.get("scope")):
        raise district_access_error()


# ── Kalendarze ─────────────────────────────────────────────────────────────
async def apply_color(
    deps: Deps, user: str, api: Any, kind: str, calendar_id: str, color: str | None = None
) -> str | None:
    """Kolor kalendarza na liście konta (dowolny hex). Zwraca ostrzeżenie albo None.

    Niepowodzenie zapisujemy w `color_pending`: kolor jest ponawiany przy
    kolejnym zapisie meczu i przy GET /calendar/setup."""
    setup = await _setup(deps, user)
    hex_color = color or _color_of(setup, kind)
    pending = {k for k in (setup.get("color_pending") or "").split(",") if k}
    try:
        await api.patch_calendar_list(
            calendar_id,
            {"backgroundColor": hex_color, "foregroundColor": foreground_for(hex_color)},
        )
    except GoogleError as exc:
        logger.info("Kolor kalendarza %s nie zapisany: %s", kind, exc.status)
        if kind not in pending:
            await deps.store.upsert_setup(user, color_pending=",".join(sorted(pending | {kind})))
        return (
            f"Google nie zapisał koloru kalendarza {CALENDAR_NAMES[kind]} (błąd {exc.status}). "
            "Kolor jest zapamiętany w BAZIE, ale w Google może wyglądać inaczej. "
            "BAZA spróbuje go ustawić ponownie przy następnym zapisie meczu albo otwarciu ustawień kalendarza."
        )
    if kind in pending:
        rest = ",".join(sorted(pending - {kind})) or None
        await deps.store.upsert_setup(user, color_pending=rest)
    return None


async def retry_pending_colors(deps: Deps, user: str, api: Any, kinds=KINDS) -> list[str]:
    """Ponawia kolory, których Google wcześniej nie zapisał. Zwraca ostrzeżenia."""
    setup = await _setup(deps, user)
    out: list[str] = []
    for kind in (k for k in (setup.get("color_pending") or "").split(",") if k in kinds):
        cal_id = setup.get(f"{kind}_id")
        if cal_id:
            warn = await apply_color(deps, user, api, kind, cal_id)
            if warn:
                out.append(warn)
    return out


async def _create_calendar(api: Any, kind: str) -> str:
    created = await api.insert_calendar(
        {
            "summary": CALENDAR_NAMES[kind],
            "description": "Mecze z aplikacji BAZA. Kalendarz zakłada i prowadzi BAZA.",
            "timeZone": CALENDAR_TIMEZONE,
        }
    )
    cal_id = (created or {}).get("id")
    if not cal_id:
        raise SecondaryError(
            502, "calendar_create_failed", "Google nie zwrócił identyfikatora nowego kalendarza."
        )
    return cal_id


async def ensure_calendar(
    deps: Deps, user: str, api: Any, kind: str, warnings: list[str] | None = None
) -> str:
    """Id kalendarza danego rodzaju; zakłada, gdy go nie ma (pod zamkiem, zapis warunkowy)."""
    setup = await _setup(deps, user)
    existing = setup.get(f"{kind}_id")
    if existing:
        return existing
    async with _lock(user, kind):
        setup = await _setup(deps, user)
        if setup.get(f"{kind}_id"):
            return setup[f"{kind}_id"]
        try:
            new_id = await _create_calendar(api, kind)
        except GoogleError as exc:
            raise SecondaryError(
                502, "calendar_create_failed", google_error_message(exc, "zakładanie kalendarza BAZY")
            ) from exc
        # Najpierw utrwal id, potem kolor (kolejność jak w Communio).
        won = await deps.store.set_calendar_id(user, kind, new_id, None)
        if not won:
            await _best_effort_delete_calendar(api, new_id)
            return (await _setup(deps, user))[f"{kind}_id"]
        warn = await apply_color(deps, user, api, kind, new_id)
        if warn and warnings is not None:
            warnings.append(warn)
        return new_id


async def _best_effort_delete_calendar(api: Any, calendar_id: str) -> None:
    try:
        await api.delete_calendar(calendar_id)
    except GoogleError as exc:
        logger.info("Nie udało się skasować zbędnego kalendarza: %s", exc.status)


async def _calendar_gone(api: Any, calendar_id: str) -> bool:
    try:
        await api.get_calendar(calendar_id)
    except GoogleError as exc:
        return exc.gone
    return False


async def recreate_calendar(
    deps: Deps, user: str, api: Any, kind: str, old_id: str, warnings: list[str] | None = None
) -> str:
    """Kalendarz usunięty ręcznie: zakładamy od nowa i oznaczamy do uzupełnienia."""
    async with _lock(user, kind):
        current = (await _setup(deps, user)).get(f"{kind}_id")
        if current and current != old_id:
            return current  # ktoś już odtworzył
        try:
            new_id = await _create_calendar(api, kind)
        except GoogleError as exc:
            raise SecondaryError(
                502, "calendar_create_failed", google_error_message(exc, "odtwarzanie kalendarza BAZY")
            ) from exc
        won = await deps.store.set_calendar_id(user, kind, new_id, old_id)
        if not won:
            await _best_effort_delete_calendar(api, new_id)
            return (await _setup(deps, user))[f"{kind}_id"]
        await deps.store.delete_mappings_for_calendar(user, old_id)
        await deps.store.upsert_setup(user, **{f"{kind}_refill": True})
        warn = await apply_color(deps, user, api, kind, new_id)
        if warn and warnings is not None:
            warnings.append(warn)
        return new_id


async def adopt_calendars(
    deps: Deps, user: str, api: Any, kinds: tuple[str, ...]
) -> list[str]:
    """Po (ponownym) połączeniu: zapamiętany kalendarz działa = przejęcie, 403/404 = nowy."""
    warnings: list[str] = []
    for kind in kinds:
        setup = await _setup(deps, user)
        cal_id = setup.get(f"{kind}_id")
        if cal_id:
            try:
                await api.get_calendar(cal_id)
                continue
            except GoogleError as exc:
                if exc.status not in (403, 404, 410):
                    raise SecondaryError(
                        502,
                        "calendar_check_failed",
                        google_error_message(exc, "sprawdzanie kalendarza BAZY"),
                    ) from exc
                await deps.store.set_calendar_id(user, kind, None, cal_id)
                if exc.gone:
                    await deps.store.delete_mappings_for_calendar(user, cal_id)
                    await deps.store.upsert_setup(user, **{f"{kind}_refill": True})
        await ensure_calendar(deps, user, api, kind)
    return warnings


# ── Zapis wydarzeń ─────────────────────────────────────────────────────────
async def _put_event(
    deps: Deps,
    user: str,
    api: Any,
    kind: str,
    cal_id: str,
    event_id: str,
    body: dict,
    existing_event_id: str | None,
    warnings: list[str] | None = None,
) -> tuple[str, str]:
    """Wstaw/zaktualizuj wydarzenie; kalendarz usunięty ręcznie jest odtwarzany."""
    confirmed = {**body, "status": "confirmed"}
    for attempt in (1, 2):
        try:
            if existing_event_id:
                try:
                    saved = await api.update_event(cal_id, existing_event_id, confirmed)
                    return saved["id"], cal_id
                except GoogleError as exc:
                    if not exc.gone:
                        raise
                existing_event_id = None  # wpis usunięty ręcznie: wstawiamy od nowa
            try:
                saved = await api.insert_event(cal_id, {**body, "id": event_id})
            except GoogleError as exc:
                if exc.status != 409:
                    raise
                saved = await api.update_event(cal_id, event_id, confirmed)
            return saved["id"], cal_id
        except GoogleError as exc:
            if exc.gone and attempt == 1 and await _calendar_gone(api, cal_id):
                cal_id = await recreate_calendar(deps, user, api, kind, cal_id, warnings)
                existing_event_id = None
                continue
            raise
    raise GoogleError(500, "Nie udało się zapisać wydarzenia w Google.")


async def _primary_api(deps: Deps, user: str, tokens: dict | None, setup: dict) -> Any | None:
    """Klient do kalendarza głównego: bieżący token z dostępem, inaczej zaparkowany."""
    if tokens and has_primary_access(tokens.get("scope")):
        return await deps.api_current(user)
    if setup.get("park_access"):
        return await deps.api_parked(user)
    return None


async def _primary_api_safe(deps: Deps, user: str, tokens: dict | None, setup: dict) -> Any | None:
    """Jak `_primary_api`, ale cofnięty albo nieodświeżalny token = brak dostępu (None)."""
    try:
        return await _primary_api(deps, user, tokens, setup)
    except (SecondaryError, GoogleError) as exc:
        logger.info("Dostęp do kalendarza głównego niedostępny: %s", type(exc).__name__)
        return None


async def _delete_old(
    deps: Deps, user: str, old_cal: str | None, old_event_id: str
) -> str | None:
    """Kasuje poprzednie miejsce wpisu po zapisie w nowym. Zwraca ostrzeżenie albo None.

    Nigdy nie rzuca: zapis nowego wpisu już się udał, więc problem ze sprzątaniem
    wraca jako `warning`, a nie jako błąd 5xx."""
    try:
        return await _delete_old_inner(deps, user, old_cal, old_event_id)
    except (SecondaryError, GoogleError) as exc:
        logger.warning("Sprzątanie starego wpisu nie powiodło się: %s", type(exc).__name__)
        return "Nie udało się skasować poprzedniego wpisu w Google. Nowy wpis został zapisany."


async def _delete_old_inner(
    deps: Deps, user: str, old_cal: str | None, old_event_id: str
) -> str | None:
    tokens = await deps.store.get_tokens(user)
    setup = await _setup(deps, user)
    if old_cal is None:
        api = await _primary_api_safe(deps, user, tokens, setup)
        if api is None:
            logger.warning("Brak dostępu do kalendarza głównego: stary wpis %s zostaje", old_event_id)
            return "Poprzedni wpis został w kalendarzu głównym (BAZA nie ma już do niego dostępu)."
        target_cal = "primary"
    else:
        api = await deps.api_current(user)
        target_cal = old_cal
    try:
        await api.delete_event(target_cal, old_event_id)
    except GoogleError as exc:
        if exc.gone:
            return None
        logger.warning("Nie udało się skasować starego wpisu: %s", exc.status)
        return google_error_message(exc, "usuwanie poprzedniego wpisu")
    return None


async def write_event(
    deps: Deps,
    user: str,
    plan: Plan,
    match_id: str,
    *,
    summary: str,
    start: datetime.datetime,
    end: datetime.datetime,
    location: str,
    reminders: list[dict],
) -> dict:
    """POST/PUT /calendar/events na kalendarz drugorzędny. Zmiana celu: wstaw, potem skasuj."""
    assert plan.kind is not None
    overrides = sanitize_reminders(reminders)
    setup = await _setup(deps, user)
    api = await deps.api_current(user)
    kind = plan.kind
    warnings: list[str] = []
    cal_id = await ensure_calendar(deps, user, api, kind, warnings)
    if kind in (setup.get("color_pending") or "").split(","):
        warnings += await retry_pending_colors(deps, user, api, (kind,))
    body = match_event_body(
        summary=summary,
        start=start.isoformat(),
        end=end.isoformat(),
        location=location,
        reminders=overrides,
        busy=setup["busy"],
    )
    row = await deps.store.get_mapping(user, match_id)
    existing = row["event_id"] if row and row.get("calendar_id") == cal_id else None
    try:
        new_id, new_cal = await _put_event(
            deps, user, api, kind, cal_id, google_event_id(user, match_id), body, existing, warnings
        )
    except GoogleError as exc:
        raise SecondaryError(
            502, "google_write_failed", google_error_message(exc, "zapis wydarzenia")
        ) from exc
    await deps.store.save_mapping(user, match_id, new_id, new_cal)
    result: dict = {"eventId": new_id}
    if row and not (row.get("calendar_id") == new_cal and row["event_id"] == new_id):
        warning = await _delete_old(deps, user, row.get("calendar_id"), row["event_id"])
        if warning:
            warnings.append(warning)
    if warnings:
        result["warning"] = " ".join(dict.fromkeys(warnings))
    return result


async def previous_placement(deps: Deps, user: str, match_id: str) -> dict | None:
    return await deps.store.get_mapping(user, match_id)


async def cleanup_previous(deps: Deps, user: str, prev: dict | None) -> str | None:
    """Po zapisie w kalendarzu głównym: skasuj wpis, który leżał w drugorzędnym."""
    if prev and prev.get("calendar_id"):
        return await _delete_old(deps, user, prev["calendar_id"], prev["event_id"])
    return None


async def remove_event(deps: Deps, user: str, match_id: str) -> None:
    """DELETE /calendar/events/{match_id} dla konta po przejściu. Idempotentne."""
    row = await deps.store.get_mapping(user, match_id)
    if not row:
        return
    cal = row.get("calendar_id")
    tokens = await deps.store.get_tokens(user)
    if not tokens:
        raise SecondaryError(404, "calendar_not_connected", "Kalendarz nie połączony")
    setup = await _setup(deps, user)
    if cal is None:
        api = await _primary_api_safe(deps, user, tokens, setup)
        if api is None:
            # Wpis leży w kalendarzu głównym, a BAZA nie ma do niego dostępu:
            # jawny 403, mapowanie ZOSTAJE (nic nie znika po cichu).
            raise district_access_error()
        cal = "primary"
    else:
        api = await deps.api_current(user)
    try:
        await api.delete_event(cal, row["event_id"])
    except GoogleError as exc:
        if not exc.gone:
            if cal == "primary" and exc.status in (401, 403):
                raise district_access_error() from exc
            raise SecondaryError(
                502, "google_delete_failed", google_error_message(exc, "usuwanie wydarzenia")
            ) from exc
    await deps.store.delete_mapping(user, match_id)


# ── Ustawienia ─────────────────────────────────────────────────────────────
async def setup_view(deps: Deps, user: str) -> dict:
    tokens = await deps.store.get_tokens(user)
    setup = await _setup(deps, user)
    if (
        setup.get("color_pending")
        and tokens
        and uses_secondary(deps.flag, user, tokens.get("scope"))
    ):
        try:
            await retry_pending_colors(deps, user, await deps.api_current(user))
        except (SecondaryError, GoogleError) as exc:
            logger.info("Ponowienie kolorów nieudane: %s", type(exc).__name__)
        setup = await _setup(deps, user)
    connected = bool(tokens)
    calendars: list[dict] = []
    if deps.flag and not is_beach_key(user):
        for kind in kinds_for_mode(setup["mode"]):
            calendars.append(
                {
                    "kind": kind,
                    "name": CALENDAR_NAMES[kind],
                    "color": _color_of(setup, kind),
                    "missing": bool(setup.get(f"{kind}_refill")),
                }
            )
    return {
        "feature_enabled": bool(deps.flag),
        "connected": connected,
        "email": setup["email"],
        "needs_migration": needs_migration(
            deps.flag, connected, user, bool(setup["migrated"])
        ),
        "mode": setup["mode"],
        "busy": bool(setup["busy"]),
        # Dostęp do kalendarza głównego: legacy albo district.
        "district_access": bool(connected and has_primary_access(tokens.get("scope"))),
        "calendars": calendars,
        "job": job_public(setup),
    }


async def put_setup(deps: Deps, user: str, patch: dict) -> tuple[dict, list[str], bool]:
    """PUT /calendar/setup. Zwraca (widok, ostrzeżenia, czy_uruchomić_zadanie)."""
    if not deps.flag or is_beach_key(user):
        raise SecondaryError(
            404, "feature_disabled", "Kalendarze drugorzędne Google są wyłączone."
        )
    setup = await _setup(deps, user)
    fields: dict[str, Any] = {}
    mode = patch.get("mode")
    mode_change = False
    if mode is not None:
        if mode not in MODES:
            raise SecondaryError(400, "invalid_mode", "Układ: two (dwa kalendarze) albo one (jeden wspólny).")
        mode_change = mode != setup["mode"]
        if mode_change:
            if setup["job_state"] == "running" and not job_is_stale(setup, deps.now()):
                raise SecondaryError(
                    409,
                    "job_running",
                    "Trwa przenoszenie wpisów. Poczekaj na jego koniec i zmień układ ponownie.",
                )
            fields["mode"] = mode
    colors = sanitize_colors(patch.get("colors"))
    for kind, hx in colors.items():
        fields[f"{kind}_color"] = hx
    if patch.get("busy") is not None:
        fields["busy"] = bool(patch["busy"])
    for kind in patch.get("refilled") or []:
        if kind not in KINDS:
            raise SecondaryError(400, "invalid_refilled", f"Nieznany kalendarz: {kind}.")
        fields[f"{kind}_refill"] = False
    if fields:
        await deps.store.upsert_setup(user, **fields)

    warnings: list[str] = []
    start_job = False
    tokens = await deps.store.get_tokens(user)
    if tokens and uses_secondary(True, user, tokens.get("scope")):
        api = await deps.api_current(user)
        new_mode = fields.get("mode", setup["mode"])
        warnings += await adopt_calendars(deps, user, api, kinds_for_mode(new_mode))
        fresh = await _setup(deps, user)
        for kind in colors:
            cal_id = fresh.get(f"{kind}_id")
            if cal_id:
                warn = await apply_color(deps, user, api, kind, cal_id, colors[kind])
                if warn:
                    warnings.append(warn)
        if fresh["migrated"]:
            # Zawsze, gdy w mapowaniach zostały wpisy z kalendarzy starego układu
            # (także po przerwanym zadaniu), nie tylko przy samej zmianie trybu.
            old_ids = _old_mode_ids(fresh, fresh["mode"])
            moves = [
                r for r in await deps.store.list_mappings(user) if r.get("calendar_id") in old_ids
            ]
            if moves:
                start_job = await _start_job(deps, user, "mode")
    return await setup_view(deps, user), warnings, start_job


def _old_mode_ids(setup: dict, new_mode: str) -> set[str]:
    old_kinds = kinds_for_mode("two" if new_mode == "one" else "one")
    return {setup[f"{k}_id"] for k in old_kinds if setup.get(f"{k}_id")}


# ── Połączenie, rozłączenie ────────────────────────────────────────────────
async def after_connect(
    deps: Deps,
    user: str,
    *,
    previous: dict | None,
    new_tokens: dict,
    email: str | None,
) -> tuple[bool, list[str]]:
    """Pełne połączenie: zapis zgody i kalendarze. Zwraca (czy_przenosić, ostrzeżenia)."""
    await save_connection(deps, user, previous=previous, new_tokens=new_tokens, email=email)
    return await finish_connection(deps, user)


async def save_connection(
    deps: Deps,
    user: str,
    *,
    previous: dict | None,
    new_tokens: dict,
    email: str | None,
) -> None:
    """Część callbacku OAuth bez rozmowy z Google: sama baza, więc trwa chwilę.

    Stary token (legacy albo district) idzie do osobnego miejsca na czas zadania,
    zanim nowy go nadpisze. Pierwsze połączenie nie ma czego przenosić.
    """
    setup = await _setup(deps, user)
    new_level = access_level(new_tokens.get("scope"))
    fields: dict[str, Any] = {}
    if previous is None:
        # migrated=True nie może maskować mapowań z kalendarza głównego: gdy
        # takie zostały, zadanie przejdzie po nich (albo powie, że nie może).
        has_primary_rows = any(
            not r.get("calendar_id") for r in await deps.store.list_mappings(user)
        )
        fields["migrated"] = not has_primary_rows
    elif not setup["migrated"] and new_level == "matches" and has_primary_access(
        previous.get("scope")
    ):
        # Nowy token po ponownej zgodzie z dostępem do primary zastępuje stary park.
        await deps.store.park_tokens(
            user,
            access=previous["access_token"],
            refresh=previous["refresh_token"],
            expires_at=previous["expires_at"],
            scope=previous.get("scope"),
        )
    if setup["park_access"] and has_primary_access(new_tokens.get("scope")):
        await deps.store.clear_park(user)  # nowy token sam ma dostęp do primary
    if email:
        fields["email"] = email
    await deps.store.save_tokens(
        user,
        new_tokens["access_token"],
        new_tokens["refresh_token"],
        new_tokens["expires_at"],
        new_tokens.get("scope"),
    )
    if fields:
        await deps.store.upsert_setup(user, **fields)


async def finish_connection(deps: Deps, user: str) -> tuple[bool, list[str]]:
    """Reszta po zgodzie, już w tle: kalendarze u Google i decyzja o przenoszeniu."""
    warnings: list[str] = []
    try:
        api = await deps.api_current(user)
        fresh = await _setup(deps, user)
        warnings += await adopt_calendars(deps, user, api, kinds_for_mode(fresh["mode"]))
    except SecondaryError as exc:
        # Nie blokujemy powrotu z Google: kalendarze powstaną przy pierwszym zapisie.
        logger.warning("Kalendarze BAZY po połączeniu: %s", exc.message)
        warnings.append(exc.message)
    final = await _setup(deps, user)
    if final["legacy_left"]:
        await deps.store.upsert_setup(user, legacy_left=False)
        if final["migrated"]:
            # Po rozłączeniu dawne wpisy mogły zostać: mówimy o tym prosto.
            await deps.store.update_job(
                user,
                job_kind="migrate",
                job_state="done",
                job_total=0,
                job_done=0,
                job_skipped=0,
                job_failed=0,
                job_error=None,
                job_kept=[],
                job_note=LEFTOVER_NOTE,
                job_heartbeat=deps.now(),
            )
    start = bool(not final["migrated"])
    if start:
        start = await _start_job(deps, user, "migrate")
    return start, warnings


async def _forget_primary_match_entries(
    deps: Deps, user: str, tokens: dict, setup: dict, delete: bool
) -> list[str]:
    """Rozłączenie: przyszłe wpisy meczów z kalendarza głównego.

    delete=True kasuje je w Google; w każdym razie zapominamy ich mapowania, żeby
    ponowne połączenie nie zrobiło duplikatu. Gdy nie da się ich sprawdzić albo
    zostają w Google, zapisujemy `legacy_left`, by po ponownym połączeniu powiedzieć
    to prosto (job.note). Stary token NIE jest zatrzymywany."""
    rows = [r for r in await deps.store.list_mappings(user) if not r.get("calendar_id")]
    if not rows:
        return []
    api = await _primary_api_safe(deps, user, tokens, setup)
    if api is None:
        await deps.store.upsert_setup(user, legacy_left=True)
        return [
            "BAZA nie ma dostępu do kalendarza głównego Google, więc dawne wpisy z meczami "
            "mogły tam zostać. Usuń je ręcznie, jeśli się pojawią."
        ]
    try:
        future = await _future_match_events(api, deps.now())
    except GoogleError as exc:
        await deps.store.upsert_setup(user, legacy_left=True)
        return [
            "Nie udało się sprawdzić dawnych wpisów w kalendarzu głównym: "
            + google_error_message(exc, "sprawdzanie wpisów")
        ]
    warnings: list[str] = []
    left = False
    for row in rows:
        if row["event_id"] not in future:
            continue
        if delete:
            try:
                await api.delete_event("primary", row["event_id"])
            except GoogleError as exc:
                if not exc.gone:
                    warnings.append(
                        "Nie udało się usunąć wpisu meczu z kalendarza głównego: "
                        + google_error_message(exc, "usuwanie wpisu")
                    )
                    left = True
                    continue
        else:
            left = True
        await deps.store.delete_mapping(user, row["match_id"])
    if left:
        await deps.store.upsert_setup(user, legacy_left=True)
    return warnings


async def disconnect(
    deps: Deps, user: str, remove_calendars: bool | None
) -> tuple[bool, list[str]]:
    """Rozłączenie konta (flaga włączona). Zwraca (czy_było_połączone, ostrzeżenia).

    Błąd po cofnięciu zgody w Google nie blokuje rozłączenia: tokeny, park i stan
    zadania znikają zawsze, a problemy wracają jako ostrzeżenia."""
    tokens = await deps.store.get_tokens(user)
    if not tokens:
        return False, []
    warnings: list[str] = []
    setup = await _setup(deps, user)
    if remove_calendars and uses_secondary(True, user, tokens.get("scope")):
        api = None
        try:
            api = await deps.api_current(user)
        except (SecondaryError, GoogleError) as exc:
            warnings.append(
                "Nie udało się usunąć kalendarzy BAZY w Google (dostęp mógł zostać cofnięty). "
                "Usuń je ręcznie w Kalendarzu Google."
            )
            logger.info("Rozłączanie bez dostępu do Google: %s", type(exc).__name__)
        for kind in KINDS if api is not None else ():
            cal_id = setup.get(f"{kind}_id")
            if not cal_id:
                continue
            try:
                await api.delete_calendar(cal_id)
            except GoogleError as exc:
                if not exc.gone:
                    # Kalendarz zostaje, więc id pamiętamy: przy ponownym połączeniu go przejmiemy.
                    warnings.append(
                        f"Nie udało się usunąć kalendarza {CALENDAR_NAMES[kind]}: "
                        + google_error_message(exc, "usuwanie kalendarza")
                    )
                    continue
            await deps.store.set_calendar_id(user, kind, None, cal_id)
            await deps.store.delete_mappings_for_calendar(user, cal_id)
    warnings += await _forget_primary_match_entries(
        deps, user, tokens, setup, delete=bool(remove_calendars)
    )
    # Rozłączenie przerywa zadanie, a stary token nie ma już po co leżeć.
    if setup.get("job_state") == "running":
        await deps.store.update_job(
            user,
            job_state="failed",
            job_error="Konto Google zostało rozłączone w trakcie przenoszenia.",
        )
    if setup.get("park_access"):
        await deps.store.clear_park(user)
    await deps.store.delete_tokens(user)
    return True, warnings


# ── Zadanie w tle ──────────────────────────────────────────────────────────
async def _start_job(deps: Deps, user: str, kind: str) -> bool:
    setup = await _setup(deps, user)
    carry = (
        int(setup["job_done"] or 0)
        if setup["job_kind"] == kind and setup["job_state"] in ("failed", "running")
        else 0
    )
    return bool(
        await deps.store.try_start_job(
            user, kind, deps.now(), JOB_STALE_SECONDS, carry
        )
    )


async def start_migration(deps: Deps, user: str) -> tuple[dict | None, bool]:
    """POST /calendar/migrate: startuje albo wznawia. Zwraca (job, czy_uruchomić)."""
    if not deps.flag or is_beach_key(user):
        raise SecondaryError(
            404, "feature_disabled", "Kalendarze drugorzędne Google są wyłączone."
        )
    tokens = await deps.store.get_tokens(user)
    if not tokens:
        raise SecondaryError(
            409, "calendar_not_connected", "Najpierw połącz kalendarz Google w Ustawieniach."
        )
    if not uses_secondary(True, user, tokens.get("scope")):
        raise SecondaryError(
            409,
            "reconnect_required",
            "Aby przenieść mecze do kalendarzy BAZY, połącz konto Google ponownie i zaakceptuj nową zgodę.",
        )
    setup = await _setup(deps, user)
    if setup["job_kind"] == "mode" and (
        setup["job_state"] == "failed" or job_is_stale(setup, deps.now())
    ):
        # Przerwane przenoszenie po zmianie układu wznawiamy jako "mode".
        started = await _start_job(deps, user, "mode")
        return job_public(await _setup(deps, user)), started
    if setup["migrated"]:
        return job_public(setup), False
    started = await _start_job(deps, user, "migrate")
    return job_public(await _setup(deps, user)), started


async def _future_match_events(api: Any, now: datetime.datetime) -> dict[str, dict]:
    """Przyszłe wydarzenia z tytułem meczu w kalendarzu głównym, jednym zapytaniem."""
    items = await api.list_events("primary", 2500, now.isoformat())
    return {
        e["id"]: e for e in items if e.get("id") and is_movable_match_event(e, now)
    }


async def _moved_index(deps: Deps, user: str, api: Any, setup: dict) -> dict[str, str]:
    """{event_id: calendar_id} przyszłych wpisów w kalendarzach BAZY (już przeniesione)."""
    out: dict[str, str] = {}
    for kind in KINDS:
        cal_id = setup.get(f"{kind}_id")
        if not cal_id:
            continue
        try:
            items = await api.list_events(cal_id, 2500, deps.now().isoformat())
        except GoogleError as exc:
            if exc.gone:
                continue
            raise
        for e in items:
            if e.get("id") and e.get("status") != "cancelled":
                out[e["id"]] = cal_id
    return out


def _same_mapping(fresh: dict | None, row: dict) -> bool:
    return bool(
        fresh
        and fresh.get("event_id") == row["event_id"]
        and (fresh.get("calendar_id") or None) == (row.get("calendar_id") or None)
    )


async def _move_row(
    deps: Deps,
    user: str,
    *,
    job_kind: str,
    src_api: Any,
    dst_api: Any,
    row: dict,
    setup: dict,
    ev: dict | None = None,
) -> str:
    """Przenosi jeden wpis. `ev` (migracja) pochodzi z jednej listy, bez events.get."""
    match_id = row["match_id"]
    src_cal = "primary" if job_kind == "migrate" else row["calendar_id"]
    if ev is None:
        try:
            ev = await src_api.get_event(src_cal, row["event_id"])
            if ev.get("status") == "cancelled":
                raise GoogleError(404)
        except GoogleError as exc:
            if not exc.gone:
                raise
            # Usunięty ręcznie albo już przeniesiony (przerwanie po skasowaniu starego).
            moved = await _moved_index(deps, user, dst_api, setup)
            did = google_event_id(user, match_id)
            if did in moved:
                await deps.store.save_mapping(user, match_id, did, moved[did])
                return "done"
            await deps.store.delete_mapping(user, match_id)
            return "skipped"
    # Wyścig: aplikacja mogła w trakcie zapisać ten mecz gdzie indziej.
    if not _same_mapping(await deps.store.get_mapping(user, match_id), row):
        return "skipped"
    target = target_from_title(ev.get("summary"))
    if target == "primary":
        target = "whistle"
    kind = kind_for_target(target, setup["mode"])
    assert kind is not None
    cal_id = await ensure_calendar(deps, user, dst_api, kind)
    body = converted_event_body(ev, setup["busy"])
    new_id, new_cal = await _put_event(
        deps, user, dst_api, kind, cal_id, google_event_id(user, match_id), body, None
    )
    if not _same_mapping(await deps.store.get_mapping(user, match_id), row):
        return "skipped"  # zmieniło się po wstawieniu: nie kasujemy ani nie nadpisujemy
    # Dopiero po zapisie w nowym kasujemy stary; mapowanie na końcu (wznawialne).
    try:
        await src_api.delete_event(src_cal, row["event_id"])
    except GoogleError as exc:
        if not exc.gone:
            raise
    await deps.store.save_mapping(user, match_id, new_id, new_cal)
    return "done"


async def run_job(deps: Deps, user: str) -> dict | None:
    """Wykonuje zadanie `running` (migrate albo mode). Nigdy nie rzuca: błąd trafia do stanu."""
    try:
        return await _run_job(deps, user)
    except Exception as exc:  # noqa: BLE001 - zero cichych blokad: zapis do stanu zadania
        logger.exception("Zadanie kalendarza %s nie powiodło się", user)
        message = exc.message if isinstance(exc, SecondaryError) else (
            f"Przenoszenie przerwane nieoczekiwanym błędem ({type(exc).__name__}). "
            "Możesz wznowić je ponownie."
        )
        await deps.store.update_job(user, job_state="failed", job_error=message)
        return job_public(await _setup(deps, user))


async def _run_job(deps: Deps, user: str) -> dict | None:
    setup = await _setup(deps, user)
    if setup["job_state"] != "running":
        return job_public(setup)
    job_kind = setup["job_kind"]
    tokens = await deps.store.get_tokens(user)
    if not tokens:
        raise SecondaryError(409, "calendar_not_connected", "Konto Google nie jest połączone.")
    dst_api = await deps.api_current(user)
    mappings = await deps.store.list_mappings(user)
    # (wiersz, wydarzenie z listy) do przeniesienia; (wiersz, kalendarz) już przeniesione
    todo: list[tuple[dict, dict | None]] = []
    already: list[tuple[dict, str]] = []
    note: str | None = None
    src_api = dst_api
    if job_kind == "migrate":
        null_rows = [r for r in mappings if not r.get("calendar_id")]
        src_api = await _primary_api_safe(deps, user, tokens, setup)
        if src_api is None:
            if null_rows:
                note = LEFTOVER_NOTE
        else:
            try:
                future = await _future_match_events(src_api, deps.now())
                moved = await _moved_index(deps, user, dst_api, setup)
            except GoogleError as exc:
                raise SecondaryError(
                    502, "google_list_failed", google_error_message(exc, "przeglądanie kalendarza głównego")
                ) from exc
            for r in null_rows:
                if r["event_id"] in future:
                    todo.append((r, future[r["event_id"]]))
                elif google_event_id(user, r["match_id"]) in moved:
                    already.append((r, moved[google_event_id(user, r["match_id"])]))
                # reszta to niedyspozycje i historia: nie wchodzą do liczb
    else:
        old_ids = _old_mode_ids(setup, setup["mode"])
        todo = [(r, None) for r in mappings if r.get("calendar_id") in old_ids]
    carry = int(setup["job_done"] or 0)
    done, skipped, failed = carry, 0, 0
    last_error: str | None = None
    await deps.store.update_job(
        user,
        job_total=carry + len(todo) + len(already),
        job_skipped=0,
        job_failed=0,
        job_error=None,
    )
    for row, cal_id in already:
        await deps.store.save_mapping(user, row["match_id"], google_event_id(user, row["match_id"]), cal_id)
        done += 1
    aborted = False
    for index, (row, ev) in enumerate(todo):
        try:
            outcome = await _move_row(
                deps, user, job_kind=job_kind, src_api=src_api, dst_api=dst_api, row=row, setup=setup, ev=ev
            )
        except GoogleError as exc:
            failed += 1
            last_error = google_error_message(exc, "przenoszenie wpisów")
            if exc.status in (401, 403):
                failed += len(todo) - index - 1
                aborted = True
        except SecondaryError as exc:
            failed += 1
            last_error = exc.message
        except Exception as exc:  # noqa: BLE001
            logger.exception("Przenoszenie wpisu %s nie powiodło się", row.get("match_id"))
            failed += 1
            last_error = f"Nie udało się przenieść jednego z wpisów ({type(exc).__name__})."
        else:
            if outcome == "done":
                done += 1
            else:
                skipped += 1
        await deps.store.update_job(
            user,
            job_done=done,
            job_skipped=skipped,
            job_failed=failed,
            job_error=last_error,
            job_heartbeat=deps.now(),
        )
        if aborted:
            break
    if failed:
        await deps.store.update_job(
            user, job_state="failed", job_error=last_error or "Część wpisów nie została przeniesiona."
        )
        return job_public(await _setup(deps, user))
    if job_kind == "migrate":
        await deps.store.clear_park(user)
        await deps.store.upsert_setup(user, migrated=True)
    else:
        await _drop_empty_old_calendars(deps, user, dst_api, setup)
    await deps.store.update_job(
        user,
        job_state="done",
        job_done=done,
        job_skipped=skipped,
        job_error=None,
        job_note=note,
        job_heartbeat=deps.now(),
    )
    return job_public(await _setup(deps, user))


async def _drop_empty_old_calendars(deps: Deps, user: str, api: Any, setup: dict) -> None:
    """Po zmianie układu kasuje opuszczone kalendarze, ale tylko puste."""
    kept: list[dict] = []
    for cal_id in _old_mode_ids(setup, setup["mode"]):
        kind = next(k for k in KINDS if setup.get(f"{k}_id") == cal_id)
        try:
            if await api.list_events(cal_id, 1):
                # Ktoś dopisał coś ręcznie: nie kasujemy cudzych wpisów, ale mówimy o tym.
                kept.append({"kind": kind, "name": CALENDAR_NAMES[kind]})
                continue
            await api.delete_calendar(cal_id)
        except GoogleError as exc:
            if not exc.gone:
                logger.info("Stary kalendarz %s zostaje: %s", kind, exc.status)
                kept.append({"kind": kind, "name": CALENDAR_NAMES[kind]})
                continue
        await deps.store.set_calendar_id(user, kind, None, cal_id)
    await deps.store.update_job(user, job_kept=kept)
