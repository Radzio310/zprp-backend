# app/proel_zprp.py
#
# Proxy do oficjalnego API ProEl na baza.zprp.pl (/api/proel/v1/).
#
# Po co proxy, skoro aplikacja mogłaby wołać baza.zprp.pl sama: każde żądanie
# inicjujące sesję wymaga statycznego `app_key`, a klucz wkompilowany w APK
# jest kluczem publicznym — do wyjęcia jednym unzipem. `PROEL_APP_KEY` żyje
# więc wyłącznie w env na Railway i tylko ten moduł go dotyka. Aplikacja
# dostaje z powrotem `hash_sesji`, który sam w sobie daje dostęp tylko do
# JEDNEGO meczu.
#
# Dwa warianty autoryzacji upstreamu (dokumentacja v1.8):
#   A (token meczu):     {app_key, token_proel: "X8R2K", id_zawody: 0, nr_sedzia: ""}
#   B (mecz + sędzia):   {app_key, token_proel: "", id_zawody: 12345, nr_sedzia: "12345"}
# Sukces: {status: "success", message, hash_sesji, mecz_info: {IdZawody}}.
# Sesja jest przesuwna (+1 h na każde żądanie); wygaśnięcie → 401 SESSION_EXPIRED.
#
# Endpointy wysyłki wyników dojdą w API później — ten moduł jest projektowany
# tak, żeby dodanie ich było tylko kolejnym `_post_upstream`.

from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict, Optional, Tuple

import httpx
from fastapi import APIRouter, File, Form, Header, HTTPException, Request, UploadFile
from pydantic import BaseModel

from app.proel_users import rate_limit

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/proel/zprp", tags=["ProEl: ZPRP API"])

_UPSTREAM_TIMEOUT_S = 15.0

#: Token meczu: 5 znaków A–Z/0–9. Walidujemy PRZED żądaniem — literówka nie
#: powinna kosztować ani wywołania upstreamu, ani wpisu do limitera.
TOKEN_RE = re.compile(r"^[A-Z0-9]{5}$")

# Limity prób autoryzacji per IP. Token ma 36^5 ≈ 60 mln kombinacji — przy
# 40/h zgadywanie zajmuje ~170 lat, a prawdziwy użytkownik, który dwa razy
# machnął się w literce, nawet ich nie zauważy.
TOKEN_LIMITS = (("proel_auth_token_ip", 8, 60), ("proel_auth_token_ip_h", 40, 3600))
JUDGE_LIMITS = (("proel_auth_judge_ip", 20, 60),)


def _base_url() -> str:
    return (
        os.getenv("PROEL_ZPRP_BASE_URL", "https://baza.zprp.pl/api/proel/v1")
        .rstrip("/")
    )


async def _post_upstream(endpoint: str, payload: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    """Jedyny punkt sieciowy modułu — testy podmieniają wyłącznie tę funkcję.

    Zwraca (status, json|{}). Wyjątki sieciowe przechodzą wyżej i są mapowane
    w `_call_upstream` — tu ich nie tykamy, żeby monkeypatch w testach mógł
    symulować także timeouty.
    """
    async with httpx.AsyncClient(timeout=_UPSTREAM_TIMEOUT_S) as client:
        resp = await client.post(f"{_base_url()}/{endpoint}", json=payload)
    try:
        data = resp.json()
    except Exception:
        data = {}
    return resp.status_code, data if isinstance(data, dict) else {}


async def _call_upstream(endpoint: str, payload: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    """Wywołanie z mapowaniem błędów transportu na kody dla aplikacji."""
    try:
        return await _post_upstream(endpoint, payload)
    except httpx.TimeoutException:
        logger.warning("ProEl ZPRP upstream timeout endpoint=%s", endpoint)
        raise HTTPException(
            status_code=504,
            detail={"code": "UPSTREAM_TIMEOUT", "message": "Serwer ZPRP nie odpowiada. Spróbuj ponownie."},
        )
    except httpx.HTTPError as exc:
        logger.warning("ProEl ZPRP upstream network error endpoint=%s err=%s", endpoint, type(exc).__name__)
        raise HTTPException(
            status_code=502,
            detail={"code": "UPSTREAM_ERROR", "message": "Błąd połączenia z serwerem ZPRP."},
        )


def _client_ip(request: Optional[Request], forwarded: Optional[str]) -> str:
    # X-Forwarded-For: client, proxy1, proxy2 — bierzemy pierwszy (wzorzec
    # z app/beach/auth_email.py; na Railway to jedyne prawdziwe IP klienta).
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request is not None and request.client:
        return request.client.host or ""
    return ""


def _require_app_key() -> str:
    key = (os.getenv("PROEL_APP_KEY") or "").strip()
    if not key:
        # 503, nie 500: to brak konfiguracji po naszej stronie, a aplikacja ma
        # pokazać „chwilowo niedostępne", nie „błąd”.
        raise HTTPException(
            status_code=503,
            detail={"code": "PROEL_CONFIG", "message": "Integracja ZPRP nie jest skonfigurowana na serwerze."},
        )
    return key


class ZprpAuthRequest(BaseModel):
    """Wariant A: samo `token`. Wariant B: `id_zawody` + `nr_sedzia`."""

    token: Optional[str] = None
    id_zawody: Optional[int] = None
    nr_sedzia: Optional[str] = None


class ZprpLogoutRequest(BaseModel):
    hash_sesji: str


def _normalized_token(raw: Optional[str]) -> str:
    return (raw or "").strip().upper()


async def authorize(payload: ZprpAuthRequest, client_ip: str) -> Dict[str, Any]:
    """Rdzeń autoryzacji — wydzielony z trasy, żeby testował się bez FastAPI.

    Kolejność jest częścią zabezpieczenia: najpierw walidacja kształtu (zero
    kosztów), potem limiter (zapis próby NIEZALEŻNIE od wyniku — brute force
    liczy się próbami, nie sukcesami), dopiero na końcu upstream.
    """
    token = _normalized_token(payload.token)
    variant_a = bool(token)
    variant_b = payload.id_zawody is not None and bool(str(payload.nr_sedzia or "").strip())

    if not variant_a and not variant_b:
        raise HTTPException(
            status_code=400,
            detail={"code": "BAD_REQUEST", "message": "Podaj token meczu albo IdZawody z numerem sędziego."},
        )
    if variant_a and not TOKEN_RE.match(token):
        raise HTTPException(
            status_code=400,
            detail={"code": "BAD_TOKEN", "message": "Token meczu ma 5 znaków: litery i cyfry."},
        )

    app_key = _require_app_key()

    limits = TOKEN_LIMITS if variant_a else JUDGE_LIMITS
    for scope, limit, window in limits:
        await rate_limit.enforce(scope, client_ip, limit, window)
    for scope, _limit, _window in limits:
        await rate_limit.record(scope, client_ip)

    if variant_a:
        upstream_payload = {"app_key": app_key, "token_proel": token, "id_zawody": 0, "nr_sedzia": ""}
    else:
        upstream_payload = {
            "app_key": app_key,
            "token_proel": "",
            "id_zawody": int(payload.id_zawody or 0),
            "nr_sedzia": str(payload.nr_sedzia or "").strip(),
        }

    status, data = await _call_upstream("auth.php", upstream_payload)

    if status == 200 and str(data.get("status") or "").lower() == "success":
        mecz_info = data.get("mecz_info") or {}
        id_zawody = mecz_info.get("IdZawody")
        try:
            id_zawody = int(id_zawody)
        except (TypeError, ValueError):
            id_zawody = int(payload.id_zawody or 0) or None
        return {
            "status": "success",
            "hash_sesji": str(data.get("hash_sesji") or ""),
            "id_zawody": id_zawody,
            "message": str(data.get("message") or ""),
        }

    if status == 401:
        # Jednolity komunikat niezależnie od tego, CO było złe — informacja
        # „token istnieje, ale nie twój" byłaby prezentem dla zgadującego.
        raise HTTPException(
            status_code=401,
            detail={
                "code": "INVALID_CREDENTIALS",
                "message": "Nieprawidłowy token meczu."
                if variant_a
                else "Brak uprawnień do tego meczu.",
            },
        )
    if status == 403:
        # INVALID_APP_IDENTIFIER = zły app_key albo ProEl wyłączony po ich
        # stronie. To NASZ problem konfiguracyjny, nie użytkownika — stąd 502
        # i alarmowy log (sygnał do rotacji klucza).
        logger.error("ProEl ZPRP odrzucił app_key (INVALID_APP_IDENTIFIER) — sprawdź PROEL_APP_KEY")
        raise HTTPException(
            status_code=502,
            detail={"code": "PROEL_CONFIG", "message": "Serwer ZPRP odrzucił aplikację. Zgłoś to administratorowi BAZY."},
        )
    if status == 400:
        raise HTTPException(
            status_code=400,
            detail={"code": "BAD_REQUEST", "message": "Serwer ZPRP odrzucił żądanie (zła struktura)."},
        )

    logger.warning("ProEl ZPRP auth: nieoczekiwany status=%s", status)
    raise HTTPException(
        status_code=502,
        detail={"code": "UPSTREAM_ERROR", "message": "Nieoczekiwana odpowiedź serwera ZPRP."},
    )


async def close_session(hash_sesji: str) -> Dict[str, Any]:
    """Logout: 404 upstreamu to też sukces — sesja i tak jest martwa."""
    cleaned = (hash_sesji or "").strip()
    if not cleaned:
        raise HTTPException(
            status_code=400,
            detail={"code": "BAD_REQUEST", "message": "Brak hash_sesji."},
        )
    _require_app_key()
    status, _data = await _call_upstream("logout.php", {"hash_sesji": cleaned})
    if status == 200:
        return {"status": "success", "already_expired": False}
    if status == 404:
        return {"status": "success", "already_expired": True}
    logger.warning("ProEl ZPRP logout: nieoczekiwany status=%s", status)
    raise HTTPException(
        status_code=502,
        detail={"code": "UPSTREAM_ERROR", "message": "Nieoczekiwana odpowiedź serwera ZPRP."},
    )


@router.post(
    "/auth",
    summary="Autoryzacja meczu w ZPRP: token meczu (A) albo IdZawody+nr sędziego (B)",
)
async def zprp_auth(
    payload: ZprpAuthRequest,
    request: Request,
    x_forwarded_for: Optional[str] = Header(None),
):
    return await authorize(payload, _client_ip(request, x_forwarded_for))


@router.post(
    "/logout",
    summary="Zamknięcie sesji ZPRP (best-effort — wygasła też liczy się za sukces)",
)
async def zprp_logout(payload: ZprpLogoutRequest):
    return await close_session(payload.hash_sesji)


# ─────────────────────────── wynik skrócony ───────────────────────────
#
# `summary.php` aktualizuje WYŁĄCZNIE te kolumny, których klucze przyszły
# w żądaniu, a pusty string ustawia NULL. To rozróżnienie jest tu sednem:
# „nie wiem" (klucz pominięty) to co innego niż „ma być puste" (klucz z ""),
# i tylko aplikacja wie, które jest które. Dlatego proxy NIE uzupełnia
# brakujących pól ani nie zamienia None na "" - przepuszcza dokładnie to,
# co dostało, po sprawdzeniu, że nazwa klucza jest ze słownika ZPRP.

#: Pola przyjmowane przez summary.php (dokumentacja v2.0). Biała lista, bo
#: literówka w nazwie klucza po stronie aplikacji byłaby po cichu ignorowana
#: przez upstream - a sędzia zobaczyłby „zapisano" przy niezapisanym polu.
SUMMARY_FIELDS = frozenset(
    {
        "data_fakt",
        "wynik_gosp_pol", "wynik_gosc_pol",
        "wynik_gosp_full", "wynik_gosc_full",
        "wynik_bramki_gosp", "wynik_bramki_gosc",
        "dogrywka_1_pol_gosp", "dogrywka_1_pol_gosc",
        "dogrywka_1_full_gosp", "dogrywka_1_full_gosc",
        "dogrywka_2_pol_gosp", "dogrywka_2_pol_gosc",
        "dogrywka_2_full_gosp", "dogrywka_2_full_gosc",
        "dogrywka_karne_gosp", "dogrywka_karne_gosc",
        "karne_ile_gosp", "karne_bramki_gosp",
        "karne_ile_gosc", "karne_bramki_gosc",
        "timeout1_gosp_ii", "timeout1_gosp_ss",
        "timeout2_gosp_ii", "timeout2_gosp_ss",
        "timeout3_gosp_ii", "timeout3_gosp_ss",
        "timeout1_gosc_ii", "timeout1_gosc_ss",
        "timeout2_gosc_ii", "timeout2_gosc_ss",
        "timeout3_gosc_ii", "timeout3_gosc_ss",
        "widzowie",
    }
)


class ZprpSummaryRequest(BaseModel):
    hash_sesji: str
    #: Tylko klucze do zapisania. Pominięty klucz = pole nietknięte,
    #: klucz z "" = pole wyczyszczone (NULL) po stronie ZPRP.
    fields: Dict[str, str]


async def submit_summary(payload: ZprpSummaryRequest) -> Dict[str, Any]:
    """Rdzeń wysyłki wyniku skróconego - wydzielony z trasy dla testów."""
    hash_sesji = (payload.hash_sesji or "").strip()
    if not hash_sesji:
        raise HTTPException(
            status_code=400,
            detail={"code": "BAD_REQUEST", "message": "Brak hash_sesji."},
        )

    unknown = sorted(set(payload.fields or {}) - SUMMARY_FIELDS)
    if unknown:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "BAD_FIELDS",
                "message": f"Nieznane pola wyniku skróconego: {', '.join(unknown)}.",
            },
        )
    if not payload.fields:
        raise HTTPException(
            status_code=400,
            detail={"code": "BAD_REQUEST", "message": "Pusty zestaw pól do zapisania."},
        )

    _require_app_key()

    upstream_payload: Dict[str, Any] = {"hash_sesji": hash_sesji}
    upstream_payload.update({k: str(v) for k, v in payload.fields.items()})

    status, data = await _call_upstream("summary.php", upstream_payload)

    if status == 200 and str(data.get("status") or "").lower() == "success":
        return {"status": "success", "message": str(data.get("message") or "")}

    if status == 401:
        # Sesja wygasła. Aplikacja umie się przelogować z zapamiętanego
        # materiału i ponowić - dlatego kod przechodzi do niej NIETKNIĘTY,
        # zamiast zostać spłaszczony do ogólnego „brak uprawnień".
        raise HTTPException(
            status_code=401,
            detail={
                "code": str(data.get("code") or "SESSION_EXPIRED"),
                "message": "Sesja ZPRP wygasła.",
            },
        )
    if status == 403:
        # Rozróżnienie kluczowe dla komunikatu: PROTOCOL_LOCKED to stan MECZU
        # (protokół zatwierdzony w ZPRP), a nie błąd sędziego ani nasz. Stąd
        # 409 Conflict - aplikacja gasi przycisk i tłumaczy, dlaczego.
        code = str(data.get("code") or "").upper()
        if code == "PROTOCOL_LOCKED" or not code:
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "PROTOCOL_LOCKED",
                    "message": "Protokół tego meczu jest już zatwierdzony w ZPRP - wyniku nie da się zmienić.",
                },
            )
        logger.error("ProEl ZPRP summary odrzucone (403 %s) - sprawdź PROEL_APP_KEY", code)
        raise HTTPException(
            status_code=502,
            detail={"code": "PROEL_CONFIG", "message": "Serwer ZPRP odrzucił aplikację. Zgłoś to administratorowi BAZY."},
        )
    if status == 400:
        raise HTTPException(
            status_code=400,
            detail={"code": "BAD_REQUEST", "message": "Serwer ZPRP odrzucił dane wyniku skróconego."},
        )

    logger.warning("ProEl ZPRP summary: nieoczekiwany status=%s", status)
    raise HTTPException(
        status_code=502,
        detail={"code": "UPSTREAM_ERROR", "message": "Nieoczekiwana odpowiedź serwera ZPRP."},
    )


@router.post(
    "/summary",
    summary="Zapis wyniku skróconego w ZPRP (aktualizacja częściowa)",
)
async def zprp_summary(payload: ZprpSummaryRequest):
    return await submit_summary(payload)


# ─────────────────────── statystyki zawodnika ───────────────────────
#
# `player_stats.php` działa tak samo jak `summary.php`: aktualizuje wyłącznie
# przysłane klucze. Różnica jest w adresowaniu - wpis wskazuje się TRÓJKĄ
# (id_zawody, id_zespol, id_zawodnik), a nie samą sesją, bo jeden mecz ma dwa
# składy po kilkunastu zawodników.
#
# `id_zawodnik` to identyfikator z bazy ZPRP, nie numer koszulki. Aplikacja
# bierze go z rosteru `pokaz_mecze_szczegoly.php`, gdzie jest KLUCZEM wpisu.
# Numer koszulki jedzie osobno, w polu `NrKoszulki2`, i służy do zapisania go
# w protokole - nie do wskazania zawodnika.

#: Pola przyjmowane przez player_stats.php (dokumentacja v2.0). Biała lista
#: z tego samego powodu co przy wyniku: literówkę upstream zignorowałby po
#: cichu, a sędzia zobaczyłby „zapisano" przy niezapisanej karze.
PLAYER_STATS_FIELDS = frozenset(
    {
        "NrKoszulki2",
        "wyjscie",
        "bramki",
        "upomnienie",
        "2minuty",
        "dyskwalifikacja",
        "kd",
        "karne_liczba",
        "karne_bramki",
        "karne_liczba_seria",
        "karne_bramki_seria",
    }
)


class ZprpPlayerStatsRequest(BaseModel):
    hash_sesji: str
    id_zawody: int
    id_zespol: int
    id_zawodnik: int
    #: Tylko pola do zmiany - reszta statystyk zawodnika zostaje nietknięta.
    fields: Dict[str, str]


async def submit_player_stats(payload: ZprpPlayerStatsRequest) -> Dict[str, Any]:
    """Rdzeń zapisu statystyk jednego zawodnika - wydzielony z trasy dla testów."""
    hash_sesji = (payload.hash_sesji or "").strip()
    if not hash_sesji:
        raise HTTPException(
            status_code=400,
            detail={"code": "BAD_REQUEST", "message": "Brak hash_sesji."},
        )

    unknown = sorted(set(payload.fields or {}) - PLAYER_STATS_FIELDS)
    if unknown:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "BAD_FIELDS",
                "message": f"Nieznane pola statystyk zawodnika: {', '.join(unknown)}.",
            },
        )
    if not payload.fields:
        raise HTTPException(
            status_code=400,
            detail={"code": "BAD_REQUEST", "message": "Pusty zestaw pól do zapisania."},
        )

    _require_app_key()

    upstream_payload: Dict[str, Any] = {
        "hash_sesji": hash_sesji,
        "id_zawody": int(payload.id_zawody),
        "id_zespol": int(payload.id_zespol),
        "id_zawodnik": int(payload.id_zawodnik),
    }
    upstream_payload.update({k: str(v) for k, v in payload.fields.items()})

    status, data = await _call_upstream("player_stats.php", upstream_payload)

    if status == 200 and str(data.get("status") or "").lower() == "success":
        return {"status": "success", "message": str(data.get("message") or "")}

    if status == 401:
        raise HTTPException(
            status_code=401,
            detail={
                "code": str(data.get("code") or "SESSION_EXPIRED"),
                "message": "Sesja ZPRP wygasła.",
            },
        )
    if status == 404:
        # „Nie ma takiego zawodnika w kadrze tego meczu" to NIE jest awaria do
        # ponowienia ani powód, żeby przerwać wysyłkę całego składu. Aplikacja
        # ma pominąć tego jednego i powiedzieć sędziemu, kogo nie zapisała -
        # dlatego kod przechodzi osobno, a nie jako ogólny błąd.
        raise HTTPException(
            status_code=404,
            detail={
                "code": "PLAYER_NOT_IN_SQUAD",
                "message": "Tego zawodnika nie ma w kadrze meczu po stronie ZPRP.",
            },
        )
    if status == 403:
        code = str(data.get("code") or "").upper()
        if code == "PROTOCOL_LOCKED" or not code:
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "PROTOCOL_LOCKED",
                    "message": "Protokół tego meczu jest już zatwierdzony w ZPRP - danych nie da się zmienić.",
                },
            )
        logger.error("ProEl ZPRP player_stats odrzucone (403 %s) - sprawdź PROEL_APP_KEY", code)
        raise HTTPException(
            status_code=502,
            detail={"code": "PROEL_CONFIG", "message": "Serwer ZPRP odrzucił aplikację. Zgłoś to administratorowi BAZY."},
        )
    if status == 400:
        raise HTTPException(
            status_code=400,
            detail={"code": "BAD_REQUEST", "message": "Serwer ZPRP odrzucił statystyki zawodnika."},
        )

    logger.warning("ProEl ZPRP player_stats: nieoczekiwany status=%s", status)
    raise HTTPException(
        status_code=502,
        detail={"code": "UPSTREAM_ERROR", "message": "Nieoczekiwana odpowiedź serwera ZPRP."},
    )


@router.post(
    "/player-stats",
    summary="Zapis statystyk jednego zawodnika w ZPRP (aktualizacja częściowa)",
)
async def zprp_player_stats(payload: ZprpPlayerStatsRequest):
    return await submit_player_stats(payload)


# ─────────────────────── załącznik (protokół) ───────────────────────
#
# `upload_attachment.php` jest jedynym endpointem, który nie jest JSON-em:
# przyjmuje multipart z polem plikowym `zalacznik`. Mecz wskazuje sama sesja,
# więc protokół zawsze ląduje przy tym meczu, do którego sędzia ma token.

#: ZPRP przyjmuje tylko te rozszerzenia. Sprawdzamy je u siebie, żeby zły plik
#: kosztował jedno „nie" od razu, a nie wysyłkę kilku megabajtów w obie strony.
ATTACHMENT_EXTENSIONS = {".pdf", ".jpg", ".jpeg"}
#: Typ podajemy z ROZSZERZENIA, nie z tego, co przysłała aplikacja - React
#: Native potrafi wysłać „application/octet-stream" dla wszystkiego.
ATTACHMENT_CONTENT_TYPES = {
    ".pdf": "application/pdf",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
}
#: Protokół z generatora waży ~200 kB, skan z telefonu kilka MB. 20 MB to
#: granica, powyżej której to na pewno nie jest protokół.
ATTACHMENT_MAX_BYTES = 20 * 1024 * 1024
#: Wysyłka pliku ma prawo trwać dłużej niż zapytanie o wynik.
_UPLOAD_TIMEOUT_S = 60.0


def _attachment_extension(filename: str) -> str:
    name = (filename or "").strip().lower()
    dot = name.rfind(".")
    return name[dot:] if dot > 0 else ""


async def _post_upstream_file(
    endpoint: str,
    data: Dict[str, str],
    *,
    filename: str,
    content: bytes,
    content_type: str,
) -> Tuple[int, Dict[str, Any]]:
    """Multipartowy odpowiednik `_post_upstream` - też jeden punkt sieciowy."""
    async with httpx.AsyncClient(timeout=_UPLOAD_TIMEOUT_S) as client:
        resp = await client.post(
            f"{_base_url()}/{endpoint}",
            data=data,
            files={"zalacznik": (filename, content, content_type)},
        )
    try:
        parsed = resp.json()
    except Exception:
        parsed = {}
    return resp.status_code, parsed if isinstance(parsed, dict) else {}


async def upload_attachment(
    *,
    hash_sesji: str,
    nazwa: str,
    filename: str,
    content: bytes,
) -> Dict[str, Any]:
    """Rdzeń wysyłki załącznika - wydzielony z trasy dla testów."""
    session = (hash_sesji or "").strip()
    if not session:
        raise HTTPException(
            status_code=400,
            detail={"code": "BAD_REQUEST", "message": "Brak hash_sesji."},
        )

    ext = _attachment_extension(filename)
    if ext not in ATTACHMENT_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "BAD_FILE",
                "message": "ZPRP przyjmuje tylko pliki PDF i JPG.",
            },
        )
    if not content:
        raise HTTPException(
            status_code=400,
            detail={"code": "BAD_FILE", "message": "Pusty plik protokołu."},
        )
    if len(content) > ATTACHMENT_MAX_BYTES:
        raise HTTPException(
            status_code=413,
            detail={
                "code": "FILE_TOO_LARGE",
                "message": "Plik jest za duży, żeby wysłać go do ZPRP.",
            },
        )

    _require_app_key()

    label = (nazwa or "").strip() or "Protokół zawodów"

    try:
        status, data = await _post_upstream_file(
            "upload_attachment.php",
            {"hash_sesji": session, "nazwa": label},
            filename=filename,
            content=content,
            content_type=ATTACHMENT_CONTENT_TYPES[ext],
        )
    except httpx.TimeoutException:
        logger.warning("ProEl ZPRP upload timeout (%s B)", len(content))
        raise HTTPException(
            status_code=504,
            detail={"code": "UPSTREAM_TIMEOUT", "message": "Serwer ZPRP nie odpowiada. Spróbuj ponownie."},
        )
    except httpx.HTTPError as exc:
        logger.warning("ProEl ZPRP upload network error err=%s", type(exc).__name__)
        raise HTTPException(
            status_code=502,
            detail={"code": "UPSTREAM_ERROR", "message": "Błąd połączenia z serwerem ZPRP."},
        )

    if status == 200 and str(data.get("status") or "").lower() == "success":
        return {"status": "success", "message": str(data.get("message") or "")}

    if status == 401:
        raise HTTPException(
            status_code=401,
            detail={
                "code": str(data.get("code") or "SESSION_EXPIRED"),
                "message": "Sesja ZPRP wygasła.",
            },
        )
    if status == 403:
        code = str(data.get("code") or "").upper()
        if code == "PROTOCOL_LOCKED" or not code:
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "PROTOCOL_LOCKED",
                    "message": "Protokół tego meczu jest już zatwierdzony w ZPRP - załącznika nie da się dodać.",
                },
            )
        logger.error("ProEl ZPRP upload odrzucony (403 %s) - sprawdź PROEL_APP_KEY", code)
        raise HTTPException(
            status_code=502,
            detail={"code": "PROEL_CONFIG", "message": "Serwer ZPRP odrzucił aplikację. Zgłoś to administratorowi BAZY."},
        )
    if status == 400:
        # Upstream wie o pliku więcej niż my (np. uszkodzony PDF) - jego
        # komunikat jest konkretniejszy niż nasze „coś nie tak".
        raise HTTPException(
            status_code=400,
            detail={
                "code": "BAD_FILE",
                "message": str(data.get("message") or "Serwer ZPRP odrzucił plik protokołu."),
            },
        )

    logger.warning("ProEl ZPRP upload: nieoczekiwany status=%s", status)
    raise HTTPException(
        status_code=502,
        detail={"code": "UPSTREAM_ERROR", "message": "Nieoczekiwana odpowiedź serwera ZPRP."},
    )


@router.post(
    "/attachment",
    summary="Wysyłka pliku protokołu (PDF/JPG) jako załącznika meczu w ZPRP",
)
async def zprp_attachment(
    hash_sesji: str = Form(...),
    nazwa: str = Form(""),
    zalacznik: UploadFile = File(...),
):
    content = await zalacznik.read()
    return await upload_attachment(
        hash_sesji=hash_sesji,
        nazwa=nazwa,
        filename=zalacznik.filename or "protokol.pdf",
        content=content,
    )
