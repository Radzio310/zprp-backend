# app/results.py

import base64
import json
import logging
import random
import re
import time
import unicodedata
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlencode

from bs4 import BeautifulSoup
from fastapi import APIRouter, Depends, HTTPException, Query, Path as ApiPath
from pathlib import Path as SysPath
from httpx import AsyncClient
from pydantic import BaseModel

from cryptography.hazmat.primitives.asymmetric import padding

from app.deps import Settings, get_rsa_keys, get_settings
from app.utils import fetch_with_correct_encoding
from starlette.background import BackgroundTask

from openpyxl.styles import Alignment, Font
import copy
from openpyxl.drawing.image import Image

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Results"])

class ShortResultRequest(BaseModel):
    username: str    # Base64-RSA
    password: str    # Base64-RSA
    details_path: str
    wynik_gosp_pol: str
    wynik_gosc_pol: str
    wynik_gosp_full: str
    wynik_gosc_full: str
    dogrywka_karne_gosp: str
    dogrywka_karne_gosc: str
    karne_ile_gosp: str
    karne_bramki_gosp: str
    karne_ile_gosc: str
    karne_bramki_gosc: str
    timeout1_gosp_ii: str
    timeout1_gosp_ss: str
    timeout2_gosp_ii: str
    timeout2_gosp_ss: str
    timeout3_gosp_ii: str
    timeout3_gosp_ss: str
    timeout1_gosc_ii: str
    timeout1_gosc_ss: str
    timeout2_gosc_ii: str
    timeout2_gosc_ss: str
    timeout3_gosc_ii: str
    timeout3_gosc_ss: str
    widzowie: Optional[str] = ""


def _decrypt_field(enc_b64: str, private_key) -> str:
    """
    Odszyfrowuje pole zaszyfrowane RSA+Base64.
    """
    try:
        cipher = base64.b64decode(enc_b64)
        plain = private_key.decrypt(
            cipher,
            padding.PKCS1v15()
        )
        return plain.decode('utf-8')
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Błąd deszyfrowania: {e}")


async def _login_and_client(user: str, pwd: str, settings: Settings) -> AsyncClient:
    client = AsyncClient(
        base_url=settings.ZPRP_BASE_URL,
        follow_redirects=True
    )
    resp_login, _ = await fetch_with_correct_encoding(
        client,
        "/login.php",
        method="POST",
        data={"login": user, "haslo": pwd, "from": "/index.php?"},
    )
    if "/index.php" not in resp_login.url.path:
        await client.aclose()
        logger.error("Logowanie nie powiodło się dla user %s", user)
        raise HTTPException(status_code=401, detail="Logowanie nie powiodło się")
    client.cookies.update(resp_login.cookies)
    return client


async def _submit_short_result(
    client: AsyncClient,
    match_id: str,
    user: str,
    overrides: Dict[str, str],
) -> bool:
    # 1) Otwórz modal 'Wynik skrócony'
    initial_data = {
        "IdZawody": match_id,
        "akcja": "WynikSkrocony",
        "user": user,
    }
    _, html = await fetch_with_correct_encoding(
        client,
        "/zawody_WynikSkrocony.php",
        method="POST",
        data=initial_data,
    )
    soup = BeautifulSoup(html, "html.parser")
    form = soup.find("form", {"name": "zawody_WynikSkrocony"})
    if not form:
        return False

    # 2) Parsowanie pól formularza
    form_fields: Dict[str, str] = {}
    for inp in form.find_all(["input", "select", "textarea"]):
        name = inp.get("name")
        if not name:
            continue
        if inp.name == "select":
            opt = inp.find("option", selected=True)
            form_fields[name] = opt.get("value", "") if opt else ""
        elif inp.name == "textarea":
            form_fields[name] = inp.text or ""
        else:
            form_fields[name] = inp.get("value", "") or ""

    # 3) Nadpisanie wybranych pól
    form_fields.update(overrides)

    # 4) Zatwierdzenie zmian
    body = urlencode(form_fields, encoding="iso-8859-2", errors="replace")
    headers = {"Content-Type": "application/x-www-form-urlencoded; charset=ISO-8859-2"}
    resp = await client.request(
        "POST",
        "/zawody_WynikSkrocony.php",
        content=body.encode("ascii"),
        headers=headers,
        cookies=client.cookies,
    )

    text = resp.content.decode("iso-8859-2", errors="replace")
    if resp.status_code != 200:
        raise RuntimeError(f"Błąd HTTP {resp.status_code}: {text[:200]}")

    # jeżeli pojawił się komunikat „Zapisano zmiany” → sukces
    return "Zapisano zmiany" in text

import unicodedata

def _norm(s: str) -> str:
    """lower + usunięcie znaków diakrytycznych, by porównania były odporne na warianty."""
    if not s:
        return ""
    s = unicodedata.normalize("NFKD", s)
    s = "".join(ch for ch in s if not unicodedata.combining(ch))
    return s.lower()

def _is_host_swapped(soup: BeautifulSoup) -> bool:
    """
    Elastyczne wykrywanie zmiany gospodarza:
    1) dowolny <img> ze źródłem zawierającym 'zmiana' (np. 'pliki/zmiana.png')
    2) alt/title zawierające rdzenie 'zmian' i 'gospod' (np. 'nastapila zmiana gospodarza')
    3) fallback: sam tekst strony z taką frazą (na wypadek braku obrazka)
    """
    # 1) Po nazwie pliku/ścieżce (najstabilniejsze)
    for img in soup.find_all("img"):
        src_norm = _norm(img.get("src", ""))
        if "zmiana" in src_norm:   # łapie też '.../Zmiana.png', '.../ico-zmiana.svg' itd.
            return True

        # 2) Po alt/title (luźne dopasowanie rdzeni)
        meta = _norm((img.get("alt") or "") + " " + (img.get("title") or ""))
        if ("zmian" in meta) and ("gospod" in meta):
            return True

    # 3) Fallback: tekstowy komunikat na stronie
    page_text = _norm(soup.get_text(" ", strip=True))
    if ("zmian" in page_text) and ("gospod" in page_text):
        return True

    return False


def _swap_gosp_gosc(overrides: Dict[str, str]) -> Dict[str, str]:
    """
    Zamienia wartości par kluczy *_gosp* ↔ *_gosc* w słowniku overrides.
    Działa dla wszystkich wariantów nazw (np. *_full, *_pol, *_ii, *_ss, itp.).
    """
    swapped = overrides.copy()
    visited = set()

    for k in list(overrides.keys()):
        if k in visited:
            continue
        if "gosp" in k:
            twin = k.replace("gosp", "gosc")
            if twin in overrides:
                swapped[k], swapped[twin] = overrides[twin], overrides[k]
                visited.add(k)
                visited.add(twin)
        elif "gosc" in k:
            twin = k.replace("gosc", "gosp")
            if twin in overrides:
                swapped[k], swapped[twin] = overrides[twin], overrides[k]
                visited.add(k)
                visited.add(twin)

    return swapped


@router.post(
    "/judge/results/short",
    summary="Zapisz wynik skrócony meczu",
)
async def short_result(
    req: ShortResultRequest,
    settings: Settings = Depends(get_settings),
    keys=Depends(get_rsa_keys),       # tu pobieramy (private_key, public_key)
):
    private_key, _ = keys
    # 1) odszyfruj login i hasło
    user_plain = _decrypt_field(req.username, private_key)
    pass_plain = _decrypt_field(req.password, private_key)

    try:
        client = await _login_and_client(user_plain, pass_plain, settings)
        try:
            # 2) Wejdź na stronę szczegółów meczu
            details_url = _details_path_to_url(req.details_path)
            resp, html = await fetch_with_correct_encoding(
                client,
                details_url,
                method="GET",
                cookies=client.cookies,
            )
            soup = BeautifulSoup(html, "html.parser")
            host_swapped = _is_host_swapped(soup)

            # 3) sprawdź dostępność przycisku/modalu
            if not soup.find("button", class_="przycisk3", string="Wynik skrócony"):
                return {"success": False, "error": "Wynik skrócony niedostępny"}

            # 4) Wyciągnij IdZawody
            match_id = _extract_match_id(req.details_path)

            # 5) Przygotuj overrides (w tym wynik_bramki_* z wynik_*_full)
            overrides = {
                "wynik_gosp_pol": req.wynik_gosp_pol,
                "wynik_gosc_pol": req.wynik_gosc_pol,
                "wynik_gosp_full": req.wynik_gosp_full,
                "wynik_gosc_full": req.wynik_gosc_full,
                "wynik_bramki_gosp": req.wynik_gosp_full,
                "wynik_bramki_gosc": req.wynik_gosc_full,
                "dogrywka_karne_gosp": req.dogrywka_karne_gosp,
                "dogrywka_karne_gosc": req.dogrywka_karne_gosc,
                "karne_ile_gosp": req.karne_ile_gosp,
                "karne_bramki_gosp": req.karne_bramki_gosp,
                "karne_ile_gosc": req.karne_ile_gosc,
                "karne_bramki_gosc": req.karne_bramki_gosc,
                "timeout1_gosp_ii": req.timeout1_gosp_ii,
                "timeout1_gosp_ss": req.timeout1_gosp_ss,
                "timeout2_gosp_ii": req.timeout2_gosp_ii,
                "timeout2_gosp_ss": req.timeout2_gosp_ss,
                "timeout3_gosp_ii": req.timeout3_gosp_ii,
                "timeout3_gosp_ss": req.timeout3_gosp_ss,
                "timeout1_gosc_ii": req.timeout1_gosc_ii,
                "timeout1_gosc_ss": req.timeout1_gosc_ss,
                "timeout2_gosc_ii": req.timeout2_gosc_ii,
                "timeout2_gosc_ss": req.timeout2_gosc_ss,
                "timeout3_gosc_ii": req.timeout3_gosc_ii,
                "timeout3_gosc_ss": req.timeout3_gosc_ss,
                "widzowie": req.widzowie or ""
            }

            if host_swapped:
                overrides = _swap_gosp_gosc(overrides)

            ok = await _submit_short_result(
                client,
                match_id=match_id,
                user=user_plain,
                overrides=overrides,
            )
        finally:
            await client.aclose()

        if not ok:
            return {"success": False, "error": "Zapis nie powiódł się"}
        return {"success": True}

    except HTTPException:
        raise
    except Exception as e:
        logger.error("short_result error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Nie udało się zapisać wyniku skróconego: {e}")


# =========================
# NEW - protokół pełny
# =========================

# =========================
# New model: Protocol save
# =========================

class ProtocolSaveRequest(BaseModel):
    username: str              # Base64-RSA
    password: str              # Base64-RSA
    details_path: str          # np. "a=zawody&b=protokol&Filtr_sezon=...&IdZawody=..."
    data_json: Dict[str, Any]  # cały JSON meczu (jak w przykładzie)


def _details_path_to_url(details_path: str) -> str:
    dp = (details_path or "").strip()
    if not dp:
        raise HTTPException(400, "details_path jest pusty")

    if dp.startswith("http://") or dp.startswith("https://"):
        m = re.match(r"^https?://[^/]+(?P<path>/.*)$", dp)
        return m.group("path") if m else dp

    if dp.startswith("/index.php"):
        return dp
    if dp.startswith("index.php"):
        return "/" + dp
    if dp.startswith("/"):
        return dp
    return f"/index.php?{dp}"


def _extract_match_id(details_path: str) -> str:
    q = details_path
    if "?" in q:
        q = q.split("?", 1)[1]
    params = parse_qs(q)
    match_id = params.get("IdZawody", [None])[0]
    if not match_id:
        raise HTTPException(400, "Brak parametru IdZawody w details_path")
    return str(match_id)


# ============================================================
# PROTOCOL SAVE (4 BLOCKS) + DELTA MODE
#
# Zmiana wg Twojej obserwacji:
# - Nazwa drużyny do identyfikacji bloków ma sens wyłącznie w:
#   (a) nagłówku tabeli zawodników danej drużyny
#   (b) nagłówku tabeli osób towarzyszących danej drużyny
# - Ignorujemy “zestawienie drużyn grających” na górze strony.
#
# Mapowanie:
# - zawodnicy mapowani po numerze koszulki (NrKoszulki2 value)
# - jeśli ProEl ma numer, którego nie ma w tabeli -> skip (idziemy dalej)
# - jeśli numer koszulki jest zdublowany w HTML -> bierzemy pierwszy napotkany (resztę ignorujemy)
#
# Zapis:
# - zapiszProtok  -> zawody_zapisz2.php (ad1..ad4)
# - zapiszProtok4 -> zawody_zapisz4.php (ad1..ad8)
#
# DELTA:
# - wysyłamy tylko jeśli docelowa wartość != DOM
# ============================================================

PLAYERS_FIELD_TO_KIND = {
    "bramki": "goals",
    "wyjscie": "entered",  # checkbox "W" (played/entered)
    "upomnienie": "warn",  # warning checkbox
    "2minuty": "p2",       # count of 2'
    "dyskwalifikacja": "disq",  # D
    "karne_liczba": "pk_total",
    "karne_bramki": "pk_goals",
    "karne_liczba_seria": "so_total",
    "karne_bramki_seria": "so_goals",
    # "kd": (intentionally not forced here)
}

COMP_CHECKBOX_VALUE_TO_KIND = {
    "1": "warn",  # U
    "2": "p2",    # 2'
    "3": "disq",  # D
}


def _count_nonempty_penalties(ps: Dict[str, Any]) -> int:
    c = 0
    for k in ("penalty1", "penalty2", "penalty3"):
        v = ps.get(k)
        if isinstance(v, str) and v.strip():
            c += 1
    return c


def _truthy(v: Any) -> bool:
    if v is None:
        return False
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v != 0
    if isinstance(v, str):
        return v.strip() != ""
    return True


def _build_event_counters(data_json: Dict[str, Any]) -> Dict[str, Dict[str, Dict[str, int]]]:
    """
    Counters from `protocol` section:
      - warning count (type == warning)
      - penalty kick totals/goals (type == penaltyKickScored / penaltyKickMissed)
      - companion 2' (type == penalty1/2/3) also counted here as p2_events
      - disqualification count (type == disqualification)
    Keys:
      team: host/guest
      player: str(number) or "A".."E"
    """
    counters: Dict[str, Dict[str, Dict[str, int]]] = {"host": {}, "guest": {}}
    prot = data_json.get("protocol") or []

    for ev in prot:
        if not isinstance(ev, dict):
            continue
        team = ev.get("team")
        if team not in ("host", "guest"):
            continue
        player = ev.get("player")
        if player is None:
            continue

        key = str(player).strip().upper() if isinstance(player, str) else str(int(player))

        if key not in counters[team]:
            counters[team][key] = {
                "warning": 0,
                "pk_total": 0,
                "pk_goals": 0,
                "p2_events": 0,     # for companions (and fallback)
                "disq": 0,
            }

        t = ev.get("type")

        if t == "warning":
            counters[team][key]["warning"] += 1
        elif t == "penaltyKickScored":
            counters[team][key]["pk_total"] += 1
            counters[team][key]["pk_goals"] += 1
        elif t == "penaltyKickMissed":
            counters[team][key]["pk_total"] += 1
        elif t in ("penalty1", "penalty2", "penalty3"):
            counters[team][key]["p2_events"] += 1
        elif t == "disqualification":
            counters[team][key]["disq"] += 1

    return counters


def _build_shootout_counters(data_json: Dict[str, Any]) -> Dict[str, Dict[str, Dict[str, int]]]:
    shoot: Dict[str, Dict[str, Dict[str, int]]] = {"host": {}, "guest": {}}
    pshots = data_json.get("penaltyShots") or {}
    for team in ("host", "guest"):
        arr = pshots.get(team) or []
        for item in arr:
            if not isinstance(item, dict):
                continue
            p = item.get("player")
            if p is None:
                continue
            key = str(int(p))
            if key not in shoot[team]:
                shoot[team][key] = {"so_total": 0, "so_goals": 0}
            shoot[team][key]["so_total"] += 1
            shoot[team][key]["so_goals"] += 1 if int(item.get("result") or 0) == 1 else 0
    return shoot


def _build_stats_map(data_json: Dict[str, Any]) -> Dict[str, Dict[str, Dict[str, Any]]]:
    """
    Output:
      out["host"]["11"] = {goals, entered, warn, p2, disq, pk_total, pk_goals, so_total, so_goals}
      out["host"]["C"]  = {warn, p2, disq} (companions A..E)
    """
    eventc = _build_event_counters(data_json)
    shootc = _build_shootout_counters(data_json)

    out: Dict[str, Dict[str, Dict[str, Any]]] = {"host": {}, "guest": {}}

    # ---- players (numbers) ----
    for team, stats_list_key in (("host", "hostPlayerStats"), ("guest", "guestPlayerStats")):
        arr = data_json.get(stats_list_key) or []
        for ps in arr:
            if not isinstance(ps, dict):
                continue
            num = ps.get("number")
            if num is None:
                continue
            k = str(int(num))

            goals = int(ps.get("goals") or 0)
            entered = bool(ps.get("entered")) if "entered" in ps else False
            p2 = _count_nonempty_penalties(ps)
            disq = _truthy(ps.get("disqualification")) or _truthy(ps.get("disqualificationDesc"))

            w = eventc.get(team, {}).get(k, {}).get("warning", 0)
            pk_total = eventc.get(team, {}).get(k, {}).get("pk_total", 0)
            pk_goals = eventc.get(team, {}).get(k, {}).get("pk_goals", 0)
            so_total = shootc.get(team, {}).get(k, {}).get("so_total", 0)
            so_goals = shootc.get(team, {}).get(k, {}).get("so_goals", 0)

            out[team][k] = {
                "goals": goals,
                "entered": entered,
                "warn": w > 0,
                "p2": p2,
                "disq": disq,
                "pk_total": pk_total,
                "pk_goals": pk_goals,
                "so_total": so_total,
                "so_goals": so_goals,
            }

    # ---- companions A..E ----
    mc = data_json.get("matchConfig") or {}
    valid_letters = {"A", "B", "C", "D", "E"}

    for team in ("host", "guest"):
        comp_key = f"{team}Companions"
        comps = mc.get(comp_key) or []

        for c in comps:
            if not isinstance(c, dict):
                continue
            cid = str(c.get("id") or "").strip().upper()
            if cid not in valid_letters:
                continue

            warn_cfg = bool(c.get("warned")) if "warned" in c else False
            warn_ev = eventc.get(team, {}).get(cid, {}).get("warning", 0) > 0
            warn = warn_cfg or warn_ev

            p2_cfg = len(c.get("penaltyTimes") or []) if isinstance(c.get("penaltyTimes"), list) else 0
            p2_ev = eventc.get(team, {}).get(cid, {}).get("p2_events", 0)
            p2 = max(p2_cfg, p2_ev)

            disq = eventc.get(team, {}).get(cid, {}).get("disq", 0) > 0

            out[team][cid] = {
                "warn": warn,
                "p2": p2,
                "disq": disq,
            }

    return out


def _split_js_args(argstr: str) -> List[str]:
    s = argstr.strip()
    out: List[str] = []
    buf = []
    in_q: Optional[str] = None
    esc = False

    for ch in s:
        if esc:
            buf.append(ch)
            esc = False
            continue
        if ch == "\\":
            buf.append(ch)
            esc = True
            continue
        if in_q:
            buf.append(ch)
            if ch == in_q:
                in_q = None
            continue
        if ch in ("'", '"'):
            buf.append(ch)
            in_q = ch
            continue
        if ch == ",":
            out.append("".join(buf).strip())
            buf = []
            continue
        buf.append(ch)

    if buf:
        out.append("".join(buf).strip())
    return out


def _unquote_js(s: str) -> str:
    s2 = s.strip()
    if len(s2) >= 2 and ((s2[0] == "'" and s2[-1] == "'") or (s2[0] == '"' and s2[-1] == '"')):
        return s2[1:-1]
    return s2


def _extract_zapisz2_args(js: str) -> Optional[List[str]]:
    if not js:
        return None
    m = re.search(r"zapiszProtok\s*\(\s*(.*?)\s*\)", js, flags=re.IGNORECASE | re.DOTALL)
    if not m:
        return None
    args = _split_js_args(m.group(1))
    if len(args) < 4:
        return None
    return args[:4]


def _extract_zapisz4_args(js: str) -> Optional[List[str]]:
    if not js:
        return None
    m = re.search(r"zapiszProtok4\s*\(\s*(.*?)\s*\)", js, flags=re.IGNORECASE | re.DOTALL)
    if not m:
        return None
    args = _split_js_args(m.group(1))
    if len(args) < 8:
        return None
    return args[:8]


def _js_token_eval(token: str, *, value_str: str, checked: bool) -> str:
    t = token.strip()
    if re.fullmatch(r"this\.value", t, flags=re.IGNORECASE):
        return value_str
    if re.fullmatch(r"this\.checked", t, flags=re.IGNORECASE):
        return "true" if checked else "false"
    return _unquote_js(t)


async def _save_via_zapisz2(
    client: AsyncClient,
    args4: List[str],
    *,
    value_str: str,
    checked: bool,
) -> Tuple[bool, str]:
    payload = {
        "ad1": _js_token_eval(args4[0], value_str=value_str, checked=checked),
        "ad2": _js_token_eval(args4[1], value_str=value_str, checked=checked),
        "ad3": _js_token_eval(args4[2], value_str=value_str, checked=checked),
        "ad4": _js_token_eval(args4[3], value_str=value_str, checked=checked),
        "sid": str(random.random()),
    }
    _, text = await fetch_with_correct_encoding(
        client,
        "/zawody_zapisz2.php",
        method="POST",
        data=payload,
        cookies=client.cookies,
    )
    t = (text or "").strip()
    ok = (t == "OK") or ("OK" in t and "ERROR" not in t)
    return ok, t[:200]


async def _save_via_zapisz4(
    client: AsyncClient,
    args8: List[str],
    *,
    value_str: str,
    checked: bool,
) -> Tuple[bool, str]:
    payload = {
        "ad1": _js_token_eval(args8[0], value_str=value_str, checked=checked),
        "ad2": _js_token_eval(args8[1], value_str=value_str, checked=checked),
        "ad3": _js_token_eval(args8[2], value_str=value_str, checked=checked),
        "ad4": _js_token_eval(args8[3], value_str=value_str, checked=checked),
        "ad5": _js_token_eval(args8[4], value_str=value_str, checked=checked),
        "ad6": _js_token_eval(args8[5], value_str=value_str, checked=checked),
        "ad7": _js_token_eval(args8[6], value_str=value_str, checked=checked),
        "ad8": _js_token_eval(args8[7], value_str=value_str, checked=checked),
        "sid": str(random.random()),
    }
    _, text = await fetch_with_correct_encoding(
        client,
        "/zawody_zapisz4.php",
        method="POST",
        data=payload,
        cookies=client.cookies,
    )
    t = (text or "").strip()
    ok = (t == "OK") or ("OK" in t and "ERROR" not in t)
    return ok, t[:200]


def _normalize_space(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip())


def _table_text(table) -> str:
    return _normalize_space(table.get_text(" ", strip=True))


import os
import uuid

# =========================
# DEBUG helpers (Railway logs)
# =========================

def _dbg_enabled() -> bool:
    """
    W Railway ustaw env:
      RESULTS_PROTOCOL_DEBUG=1
    aby włączyć bardzo obszerny log.
    """
    v = (os.getenv("RESULTS_PROTOCOL_DEBUG") or "").strip().lower()
    return v in ("1", "true", "yes", "on")


def _dbg(msg: str, **kw):
    if not _dbg_enabled():
        return
    if kw:
        try:
            extras = " ".join([f"{k}={repr(v)[:400]}" for k, v in kw.items()])
        except Exception:
            extras = ""
        logger.warning("[protocol-debug] %s | %s", msg, extras)  # <-- WARNING
    else:
        logger.warning("[protocol-debug] %s", msg)               # <-- WARNING


def _short_html(el, limit: int = 240) -> str:
    try:
        s = str(el)
    except Exception:
        return ""
    s = re.sub(r"\s+", " ", s).strip()
    return s[:limit]


def _summarize_table_candidate(table, host_name: str, guest_name: str, team_header_min_colspan: int) -> Dict[str, Any]:
    rows = _iter_team_blocks_rows_by_order(
        table,
        team_header_min_colspan=team_header_min_colspan,
        debug_tag="candidate",
    )

    teams = {t for (t, _) in rows}
    jersey_inputs = len(table.find_all("input", attrs={"name": re.compile(r"^NrKoszulki2\d+$")}))
    has_z2 = bool(
        table.find(attrs={"onchange": re.compile(r"zapiszProtok\s*\(", re.IGNORECASE)})
        or table.find(attrs={"onclick": re.compile(r"zapiszProtok\s*\(", re.IGNORECASE)})
    )
    has_z4 = bool(table.find(attrs={"onclick": re.compile(r"zapiszProtok4\s*\(", re.IGNORECASE)}))
    # prosta "głębokość" zagnieżdżeń
    nested_tables = len(table.find_all("table"))

    return {
        "teams": sorted(list(teams)),
        "rows": len(rows),
        "jersey_inputs": jersey_inputs,
        "has_z2": has_z2,
        "has_z4": has_z4,
        "nested_tables": nested_tables,
        "sample_text": _table_text(table)[:240],
    }


# =========================
# TABLE FINDERS (with verbose logs)
# =========================

def _find_players_table(soup: BeautifulSoup, *, host_name: str, guest_name: str):
    """
    Wybiera najlepszą tabelę zawodników wg scoringu.
    Loguje kandydatów i finalny wybór.
    """
    best = None
    best_score = -1
    best_summary = None

    cand_idx = 0
    for table in soup.find_all("table"):
        if not table.find("input", attrs={"name": re.compile(r"^NrKoszulki2\d+$")}):
            continue
        if not (
            table.find(attrs={"onchange": re.compile(r"zapiszProtok\s*\(", re.IGNORECASE)})
            or table.find(attrs={"onclick": re.compile(r"zapiszProtok\s*\(", re.IGNORECASE)})
        ):
            continue

        cand_idx += 1
        summary = _summarize_table_candidate(table, host_name, guest_name, team_header_min_colspan=15)
        teams = set(summary["teams"])

        score = 0
        if "host" in teams:
            score += 1000
        if "guest" in teams:
            score += 1000

        score += summary["rows"]

        # mocna kara za "tabelę-kontener" z masą zagnieżdżeń
        score -= 50 * int(summary["nested_tables"] or 0)

        # kara za layout / menu / “API | rozgrywki…”
        sample_l = (summary.get("sample_text") or "").lower()
        if "api | rozgrywki" in sample_l:
            score -= 500


        _dbg(
            "players_table candidate",
            idx=cand_idx,
            score=score,
            teams=summary["teams"],
            rows=summary["rows"],
            jersey_inputs=summary["jersey_inputs"],
            nested_tables=summary["nested_tables"],
            has_z2=summary["has_z2"],
            sample_text=summary["sample_text"],
        )

        if score > best_score:
            best_score = score
            best = table
            best_summary = summary

    _dbg(
        "players_table chosen",
        best_score=best_score,
        best_summary=best_summary,
        found=("yes" if best else "no"),
    )
    return best


def _find_companions_table(soup: BeautifulSoup, *, host_name: str, guest_name: str):
    """
    Stabilne znalezienie tabeli 'Osoby towarzyszące' dla ZPRP.

    W realnym HTML masz:
      <td colspan="3">
        Osoby towarzyszące:
        <table> ... (nagłówki drużyn colspan=10, kolumny Osoba/Funkcja/... + checkboxy zapiszProtok4) ...
        </table>
      </td>

    Czyli: tabela jest ZAGNIEŻDŻONA wewnątrz tego samego <td>, a nie "po markerze".
    """

    def _norm_no_diacritics(s: str) -> str:
        # odporne na polskie znaki + różne encodowania
        s = (s or "").strip()
        s = unicodedata.normalize("NFKD", s)
        s = "".join(ch for ch in s if not unicodedata.combining(ch))
        s = s.lower()
        s = re.sub(r"\s+", " ", s)
        return s

    def _has_z4(table) -> bool:
        return bool(table and table.find(attrs={"onclick": re.compile(r"zapiszProtok4\s*\(", re.IGNORECASE)}))

    def _has_team_header_colspan10(table) -> bool:
        if not table:
            return False
        for tr in table.find_all("tr"):
            hn = _extract_team_header_name_from_tr(tr, team_header_min_colspan=10)
            if hn:
                return True
        return False

    def _looks_like_companions_table(table) -> bool:
        """
        Minimalne, ale trafne warunki dla Twojego HTML:
        - musi zawierać zapiszProtok4 (checkboxy U/2'/D)
        - musi mieć nagłówki drużyn w wierszach <td colspan="10"><b>...</b>
        - musi zawierać nagłówki 'Osoba' i 'Funkcja' (często są w rowspans)
        """
        if not table:
            return False
        if not _has_z4(table):
            return False
        if not _has_team_header_colspan10(table):
            return False

        txt = _norm_no_diacritics(_table_text(table))
        if ("osoba" not in txt) or ("funkcja" not in txt):
            return False

        # "Kary" zwykle występuje, ale różne encodowania mogą je psuć – nie blokujemy twardo.
        # Jeśli chcesz twardo, odkomentuj:
        # if "kary" not in txt:
        #     return False

        return True

    # ------------------------------------------------------------
    # 1) TRYB PEWNY: znajdź kontener z tekstem "Osoby towarzyszące"
    #    i weź tabelę zagnieżdżoną w środku.
    # ------------------------------------------------------------
    best = None
    best_score = -1
    best_summary = None
    cand_idx = 0

    # Szukamy tagów (np. td), w których tekst zawiera frazę.
    # Uwaga: w HTML bywa "Osoby towarzysz\u0105ce:" albo krzaki po ISO-8859-2,
    # dlatego dopasowujemy po rdzeniu "osoby towarzysz".
    for tag in soup.find_all(["td", "div", "span", "p"]):
        t = _norm_no_diacritics(tag.get_text(" ", strip=True))
        if "osoby towarzysz" not in t:
            continue

        # najczęściej tabela jest bezpośrednio w tym tagu (td colspan="3")
        inner_tables = tag.find_all("table")
        if not inner_tables:
            continue

        for tbl in inner_tables:
            if not _looks_like_companions_table(tbl):
                continue

            cand_idx += 1
            summary = _summarize_table_candidate(tbl, host_name, guest_name, team_header_min_colspan=10)
            teams = set(summary["teams"])

            # scoring: preferuj tabelę, która ma oba bloki (host+guest), ale nie wymagaj
            score = 0
            if "host" in teams:
                score += 1000
            if "guest" in teams:
                score += 1000
            score += int(summary["rows"] or 0)
            score -= 50 * int(summary["nested_tables"] or 0)

            _dbg(
                "companions_table candidate (container)",
                idx=cand_idx,
                score=score,
                teams=summary["teams"],
                rows=summary["rows"],
                nested_tables=summary["nested_tables"],
                has_z4=summary["has_z4"],
                sample_text=summary["sample_text"],
            )

            if score > best_score:
                best = tbl
                best_score = score
                best_summary = summary

    _dbg(
        "companions_table chosen (container)",
        best_score=best_score,
        best_summary=best_summary,
        found=("yes" if best else "no"),
    )
    if best:
        return best

    # ------------------------------------------------------------
    # 2) FALLBACK: globalny skan po wszystkich tabelach
    # ------------------------------------------------------------
    best = None
    best_score = -1
    best_summary = None
    cand_idx = 0

    for table in soup.find_all("table"):
        if not _looks_like_companions_table(table):
            continue

        cand_idx += 1
        summary = _summarize_table_candidate(table, host_name, guest_name, team_header_min_colspan=10)
        teams = set(summary["teams"])

        score = 0
        if "host" in teams:
            score += 1000
        if "guest" in teams:
            score += 1000
        score += int(summary["rows"] or 0)
        score -= 50 * int(summary["nested_tables"] or 0)

        _dbg(
            "companions_table candidate (fallback)",
            idx=cand_idx,
            score=score,
            teams=summary["teams"],
            rows=summary["rows"],
            nested_tables=summary["nested_tables"],
            has_z4=summary["has_z4"],
            sample_text=summary["sample_text"],
        )

        if score > best_score:
            best = table
            best_score = score
            best_summary = summary

    _dbg(
        "companions_table chosen (fallback)",
        best_score=best_score,
        best_summary=best_summary,
        found=("yes" if best else "no"),
    )
    return best


# =========================
# TEAM BLOCKS (verbose)
# =========================

def _iter_team_blocks_rows(
    table,
    *,
    host_name: str,
    guest_name: str,
    team_header_min_colspan: int,
    debug_tag: str = "main",
) -> List[Tuple[str, Any]]:
    """
    Zwraca listę (team, tr) tylko gdy current_team jest host/guest.
    Loguje wykryte nagłówki i mapping do teamów.
    """
    out: List[Tuple[str, Any]] = []
    current_team: Optional[str] = None

    if _dbg_enabled():
        _dbg(
            "iter_team_blocks_rows start",
            debug_tag=debug_tag,
            team_header_min_colspan=team_header_min_colspan,
            host_name=host_name,
            guest_name=guest_name,
            table_sample=_table_text(table)[:200],
        )

    seen_headers = 0
    for tr_i, tr in enumerate(table.find_all("tr")):
        header_name = _extract_team_header_name_from_tr(tr, team_header_min_colspan=team_header_min_colspan)
        if header_name:
            seen_headers += 1
            matched = _team_from_header_text(header_name, host_name, guest_name)
            _dbg(
                "team header detected",
                debug_tag=debug_tag,
                tr_index=tr_i,
                header_name=header_name,
                matched_team=matched,
                tr_html=_short_html(tr),
            )
            current_team = matched  # może być None
            continue

        if current_team in ("host", "guest"):
            out.append((current_team, tr))

    if _dbg_enabled():
        c_host = sum(1 for t, _ in out if t == "host")
        c_guest = sum(1 for t, _ in out if t == "guest")
        _dbg(
            "iter_team_blocks_rows end",
            debug_tag=debug_tag,
            headers_seen=seen_headers,
            rows_total=len(out),
            rows_host=c_host,
            rows_guest=c_guest,
        )

    return out

def _iter_team_blocks_rows_by_order(
    table,
    *,
    team_header_min_colspan: int,
    debug_tag: str = "main",
) -> List[Tuple[str, Any]]:
    """
    Zwraca listę (team, tr) na podstawie KOLEJNOŚCI nagłówków drużyn:
      - pierwszy wykryty nagłówek drużyny => host
      - drugi wykryty nagłówek drużyny   => guest
    Ignoruje dopasowanie po nazwie (odpornie na mojibake typu 'Zag³êbie').
    """
    out: List[Tuple[str, Any]] = []
    current_team: Optional[str] = None
    header_index = -1  # 0->host, 1->guest

    if _dbg_enabled():
        _dbg(
            "iter_team_blocks_rows_by_order start",
            debug_tag=debug_tag,
            team_header_min_colspan=team_header_min_colspan,
            table_sample=_table_text(table)[:200],
        )

    for tr_i, tr in enumerate(table.find_all("tr")):
        header_name = _extract_team_header_name_from_tr(tr, team_header_min_colspan=team_header_min_colspan)
        if header_name:
            header_index += 1
            if header_index == 0:
                current_team = "host"
            elif header_index == 1:
                current_team = "guest"
            else:
                current_team = None  # kolejne nagłówki ignorujemy

            _dbg(
                "team header detected (by_order)",
                debug_tag=debug_tag,
                tr_index=tr_i,
                header_name=header_name,
                assigned_team=current_team,
                tr_html=_short_html(tr),
            )
            continue

        if current_team in ("host", "guest"):
            out.append((current_team, tr))

    if _dbg_enabled():
        c_host = sum(1 for t, _ in out if t == "host")
        c_guest = sum(1 for t, _ in out if t == "guest")
        _dbg(
            "iter_team_blocks_rows_by_order end",
            debug_tag=debug_tag,
            headers_seen=header_index + 1,
            rows_total=len(out),
            rows_host=c_host,
            rows_guest=c_guest,
        )

    return out



# =========================
# INPUT COLLECTORS (verbose)
# =========================

def _collect_players_inputs(
    soup: BeautifulSoup,
    *,
    host_name: str,
    guest_name: str,
) -> Dict[Tuple[str, str, str], Dict[str, Any]]:
    table = _find_players_table(soup, host_name=host_name, guest_name=guest_name)
    if not table:
        _dbg("collect_players_inputs: no table found")
        return {}

    result: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    seen_jerseys: Dict[str, set] = {"host": set(), "guest": set()}

    rows = _iter_team_blocks_rows_by_order(
        table,
        team_header_min_colspan=15,
        debug_tag="players",
    )


    jersey_seen_counts = {"host": 0, "guest": 0}
    row_with_jersey_counts = {"host": 0, "guest": 0}

    for team, tr in rows:
        jersey_inp = None

        # find jersey input (field == NrKoszulki2)
        for inp in tr.find_all(["input", "select", "textarea"]):
            js = inp.get("onchange") or inp.get("onclick") or ""
            if "zapiszProtok" not in js:
                continue
            args4 = _extract_zapisz2_args(js)
            if not args4:
                continue
            field = _unquote_js(args4[1]).strip()
            if field == "NrKoszulki2":
                jersey_inp = inp
                break

        if not jersey_inp:
            continue

        jersey_val = (jersey_inp.get("value") or "").strip()
        if not re.fullmatch(r"\d{1,3}", jersey_val):
            _dbg("players row jersey invalid", team=team, jersey_val=jersey_val, tr_html=_short_html(tr))
            continue

        jersey = str(int(jersey_val))
        row_with_jersey_counts[team] += 1

        if jersey in seen_jerseys[team]:
            _dbg("players row jersey duplicate in HTML", team=team, jersey=jersey, tr_html=_short_html(tr))
            continue
        seen_jerseys[team].add(jersey)
        jersey_seen_counts[team] += 1

        # collect mapped inputs (kinds)
        for inp in tr.find_all(["input", "select", "textarea"]):
            js = inp.get("onchange") or inp.get("onclick") or ""
            if "zapiszProtok" not in js:
                continue
            args4 = _extract_zapisz2_args(js)
            if not args4:
                continue
            field = _unquote_js(args4[1]).strip()
            if field == "NrKoszulki2":
                continue
            kind = PLAYERS_FIELD_TO_KIND.get(field)
            if not kind:
                continue

            key = (team, jersey, kind)
            if key in result:
                _dbg("players input duplicate key ignored", team=team, jersey=jersey, kind=kind, field=field)
                continue

            result[key] = {"inp": inp, "field": field, "args4": args4}
            _dbg(
                "players input mapped",
                team=team,
                jersey=jersey,
                kind=kind,
                field=field,
                dom_value=_current_text_value(inp),
                dom_checked=_is_checked_dom(inp),
                args4=args4,
            )

    _dbg(
        "collect_players_inputs summary",
        total=len(result),
        host_keys=sum(1 for k in result.keys() if k[0] == "host"),
        guest_keys=sum(1 for k in result.keys() if k[0] == "guest"),
        jerseys_host=sorted(list(seen_jerseys["host"]))[:80],
        jerseys_guest=sorted(list(seen_jerseys["guest"]))[:80],
        rows_with_jersey_host=row_with_jersey_counts["host"],
        rows_with_jersey_guest=row_with_jersey_counts["guest"],
    )
    return result


def _collect_companion_inputs(
    soup: BeautifulSoup,
    *,
    host_name: str,
    guest_name: str,
) -> Dict[Tuple[str, str, str], Dict[str, Any]]:
    table = _find_companions_table(soup, host_name=host_name, guest_name=guest_name)
    if not table:
        _dbg("collect_companion_inputs: no table found")
        return {}

    letter_col = _find_letter_col_index(table)
    result: Dict[Tuple[str, str, str], Dict[str, Any]] = {}

    rows = _iter_team_blocks_rows_by_order(
        table,
        team_header_min_colspan=10,
        debug_tag="companions",
    )

    for team, tr in rows:
        tds = tr.find_all("td")
        if not tds or len(tds) < 3:
            continue

        letter = None
        if letter_col is not None and letter_col < len(tds):
            letter = _extract_letter_from_cell(tds[letter_col])
        else:
            for td in tds:
                cand = _extract_letter_from_cell(td)
                if cand:
                    letter = cand
                    break

        if not letter:
            continue

        for inp in tr.find_all("input"):
            js = inp.get("onclick") or ""
            if "zapiszProtok4" not in js:
                continue
            args8 = _extract_zapisz4_args(js)
            if not args8:
                continue

            v = (inp.get("value") or "").strip()
            kind = COMP_CHECKBOX_VALUE_TO_KIND.get(v)
            if not kind:
                continue

            key = (team, letter, kind)
            if key in result:
                _dbg("companions input duplicate key ignored", team=team, letter=letter, kind=kind)
                continue

            result[key] = {"inp": inp, "args8": args8, "checkbox_value": v}
            _dbg(
                "companions input mapped",
                team=team,
                letter=letter,
                kind=kind,
                checkbox_value=v,
                dom_checked=_is_checked_dom(inp),
                args8=args8,
            )

    _dbg(
        "collect_companion_inputs summary",
        total=len(result),
        host_keys=sum(1 for k in result.keys() if k[0] == "host"),
        guest_keys=sum(1 for k in result.keys() if k[0] == "guest"),
        letter_col=letter_col,
    )
    return result


def _norm_team_name(s: str) -> str:
    s = (s or "").strip().lower()
    s = unicodedata.normalize("NFKD", s)
    s = "".join(ch for ch in s if not unicodedata.combining(ch))
    s = re.sub(r"[^a-z0-9]+", "", s)
    return s


def _team_from_header_text(header_txt: str, host_name: str, guest_name: str) -> Optional[str]:
    """
    Dopasowanie po nazwie drużyny z nagłówka <b>...</b>.
    Bez fallbacków: jeśli nie pasuje do host ani guest -> None.
    """
    ht = _norm_team_name(header_txt)
    h = _norm_team_name(host_name)
    g = _norm_team_name(guest_name)

    if not ht:
        return None

    has_h = bool(h and (ht == h or h in ht or ht in h))
    has_g = bool(g and (ht == g or g in ht or ht in g))

    if has_h and has_g:
        # nagłówek nie powinien zawierać obu nazw (w praktyce ignorujemy taki wiersz)
        return None
    if has_h:
        return "host"
    if has_g:
        return "guest"
    return None


def _extract_team_header_name_from_tr(tr, *, team_header_min_colspan: int) -> Optional[str]:
    """
    Prawdziwy nagłówek sekcji drużyny w ZPRP:
      - komórka td/th z dużym colspan (players ~15, companions ~10)
      - w środku <b>NAZWA DRUŻYNY</b>
    """
    for cell in tr.find_all(["td", "th"]):
        try:
            cs = int(cell.get("colspan") or 0)
        except Exception:
            cs = 0
        if cs < int(team_header_min_colspan or 0):
            continue

        b = cell.find("b")
        if not b:
            continue

        name = _normalize_space(b.get_text(" ", strip=True))
        if not name:
            continue

        # odfiltruj wiersze typu "Osoby towarzyszące:" jeśli kiedykolwiek trafią tu przez colspan
        if "osoby towarzysz" in name.lower():
            continue

        return name

    return None


def _find_letter_col_index(table) -> Optional[int]:
    for tr in table.find_all("tr"):
        cells = tr.find_all(["th", "td"])
        if not cells:
            continue
        row_text = _normalize_space(tr.get_text(" ", strip=True)).lower()
        if "kolejność" in row_text and "klik" in row_text and "sortowanie" in row_text:
            for i, c in enumerate(cells):
                t = _normalize_space(c.get_text(" ", strip=True)).lower()
                if "kolejność" in t and "sortowanie" in t:
                    return i
    return None


def _extract_letter_from_cell(td) -> Optional[str]:
    sel = td.find("select")
    if sel:
        opt = sel.find("option", selected=True)
        v = (opt.get("value") if opt else "") or ""
        v = v.strip().upper()
        if re.fullmatch(r"[A-E]", v):
            return v
    txt = _normalize_space(td.get_text(" ", strip=True)).upper()
    if re.fullmatch(r"[A-E]", txt):
        return txt
    if "ZGŁOŚ" in txt or "ZGLOS" in txt:
        return None
    return None

def _desired_value_for_player_kind(st: Dict[str, Any], kind: str) -> Any:
    if kind == "goals":
        return int(st.get("goals") or 0)
    if kind == "entered":
        return bool(st.get("entered") or False)
    if kind == "warn":
        return bool(st.get("warn") or False)
    if kind == "p2":
        return int(st.get("p2") or 0)
    if kind == "disq":
        return bool(st.get("disq") or False)
    if kind == "pk_total":
        return int(st.get("pk_total") or 0)
    if kind == "pk_goals":
        return int(st.get("pk_goals") or 0)
    if kind == "so_total":
        return int(st.get("so_total") or 0)
    if kind == "so_goals":
        return int(st.get("so_goals") or 0)
    return None


def _desired_value_for_companion_kind(st: Dict[str, Any], kind: str) -> bool:
    if kind == "warn":
        return bool(st.get("warn") or False)
    if kind == "p2":
        return int(st.get("p2") or 0) >= 1
    if kind == "disq":
        return bool(st.get("disq") or False)
    return False


# -------------------------
# DELTA helpers
# -------------------------

_NUMERIC_KINDS = {"goals", "p2", "pk_total", "pk_goals", "so_total", "so_goals"}


def _is_checked_dom(inp) -> bool:
    """
    In BeautifulSoup DOM of HTML:
      checked can be: checked="checked" / checked (attribute exists) / value in some cases.
    We treat attribute presence as True.
    """
    if inp is None:
        return False
    if inp.has_attr("checked"):
        return True
    v = (inp.get("checked") or "").strip().lower()
    return v in ("checked", "true", "1", "yes")


def _current_text_value(inp) -> str:
    if inp is None:
        return ""
    if inp.name == "textarea":
        return (inp.text or "").strip()
    if inp.name == "select":
        opt = inp.find("option", selected=True)
        return ((opt.get("value", "") if opt else "") or "").strip()
    return (inp.get("value") or "").strip()


def _norm_num_str(s: str) -> int:
    """
    Treat empty / '0' / '00' as 0.
    Non-numeric -> raises.
    """
    s2 = (s or "").strip()
    if s2 == "":
        return 0
    s2 = s2.replace("\xa0", "").strip()
    return int(s2)


def _desired_str_for_numeric(desired_int: int) -> str:
    # In ZPRP protocol, "0" is commonly represented as empty.
    return "" if int(desired_int) == 0 else str(int(desired_int))


def _delta_equal_player(inp, kind: str, desired: Any) -> bool:
    t = (inp.get("type") or "").lower()

    # checkbox kinds
    if t == "checkbox":
        cur = _is_checked_dom(inp)
        des = bool(desired)
        return cur == des

    # numeric kinds
    cur_s = _current_text_value(inp)
    if kind in _NUMERIC_KINDS:
        try:
            cur_i = _norm_num_str(cur_s)
            des_i = int(desired or 0)
            return cur_i == des_i
        except Exception:
            return cur_s.strip() == _desired_str_for_numeric(int(desired or 0)).strip()

    # fallback as text
    return cur_s.strip() == (str(desired) if desired is not None else "").strip()


def _delta_equal_companion(inp, desired_checked: bool) -> bool:
    return _is_checked_dom(inp) == bool(desired_checked)


async def _apply_protocol_updates_4blocks(
    client: AsyncClient,
    soup: BeautifulSoup,
    stats_map: Dict[str, Dict[str, Dict[str, Any]]],
    *,
    host_name: str,
    guest_name: str,
) -> Dict[str, Any]:
    """
    Wersja z bardzo obszernym loggingiem:
    - ile inputów znaleziono per team
    - jakie jersey w HTML wykryto
    - dla KAŻDEGO update: current vs desired, delta-skip, payload/args, response
    """

    # request correlation id (żebyś mógł filtrować logi jednego requestu)
    req_id = str(uuid.uuid4())[:8]
    _dbg("apply_protocol start", req_id=req_id, host_name=host_name, guest_name=guest_name)

    players_inputs = _collect_players_inputs(soup, host_name=host_name, guest_name=guest_name)
    comp_inputs = _collect_companion_inputs(soup, host_name=host_name, guest_name=guest_name)

    players_inputs_host = sum(1 for k in players_inputs.keys() if k[0] == "host")
    players_inputs_guest = sum(1 for k in players_inputs.keys() if k[0] == "guest")
    comp_inputs_host = sum(1 for k in comp_inputs.keys() if k[0] == "host")
    comp_inputs_guest = sum(1 for k in comp_inputs.keys() if k[0] == "guest")

    _dbg(
        "inputs counts",
        req_id=req_id,
        players_inputs_total=len(players_inputs),
        players_inputs_host=players_inputs_host,
        players_inputs_guest=players_inputs_guest,
        companions_inputs_total=len(comp_inputs),
        companions_inputs_host=comp_inputs_host,
        companions_inputs_guest=comp_inputs_guest,
    )

    updated = 0
    skipped = 0
    failed: List[Dict[str, Any]] = []
    missing: List[Dict[str, Any]] = []
    skipped_items: List[Dict[str, Any]] = []

    player_kinds_order = ["goals", "entered", "warn", "p2", "disq", "pk_total", "pk_goals", "so_total", "so_goals"]
    comp_kinds_order = ["warn", "p2", "disq"]

    # ---- players ----
    for team in ("host", "guest"):
        team_stats = stats_map.get(team) or {}
        _dbg("team players processing", req_id=req_id, team=team, players_in_stats=len(team_stats))

        for key, st in team_stats.items():
            if not re.fullmatch(r"\d{1,3}", str(key)):
                continue
            jersey = str(int(key))

            for kind in player_kinds_order:
                desired = _desired_value_for_player_kind(st, kind)
                if desired is None:
                    continue

                meta = players_inputs.get((team, jersey, kind))
                if not meta:
                    missing.append({"section": "players", "team": team, "player": jersey, "kind": kind})
                    _dbg("MISSING players input", req_id=req_id, team=team, jersey=jersey, kind=kind, desired=desired)
                    continue

                inp = meta["inp"]
                args4 = meta["args4"]

                cur_val = _current_text_value(inp)
                cur_checked = _is_checked_dom(inp)

                # DELTA: skip if already equal
                if _delta_equal_player(inp, kind, desired):
                    skipped += 1
                    skipped_items.append({"section": "players", "team": team, "player": jersey, "kind": kind})
                    continue

                inp_type = (inp.get("type") or "").lower()
                if inp_type == "checkbox":
                    checked = bool(desired)
                    value_str = (inp.get("value") or "1").strip()
                else:
                    checked = False
                    if kind in _NUMERIC_KINDS:
                        value_str = _desired_str_for_numeric(int(desired or 0))
                    else:
                        value_str = str(desired)

                _dbg(
                    "UPDATE players sending",
                    req_id=req_id,
                    team=team,
                    jersey=jersey,
                    kind=kind,
                    desired=desired,
                    cur_val=cur_val,
                    cur_checked=cur_checked,
                    send_value=value_str,
                    send_checked=checked,
                    args4=args4,
                )

                ok, resp_txt = await _save_via_zapisz2(client, args4, value_str=value_str, checked=checked)
                if ok:
                    updated += 1
                    _dbg(
                        "UPDATE players OK",
                        req_id=req_id,
                        team=team,
                        jersey=jersey,
                        kind=kind,
                        resp=resp_txt,
                    )
                else:
                    failed.append({
                        "section": "players",
                        "team": team,
                        "player": jersey,
                        "kind": kind,
                        "sent_value": value_str,
                        "sent_checked": checked,
                        "resp": resp_txt,
                    })
                    _dbg(
                        "UPDATE players FAIL",
                        req_id=req_id,
                        team=team,
                        jersey=jersey,
                        kind=kind,
                        resp=resp_txt,
                    )

    # ---- companions A..E ----
    for team in ("host", "guest"):
        team_stats = stats_map.get(team) or {}
        _dbg("team companions processing", req_id=req_id, team=team, items_in_stats=len(team_stats))

        for key, st in team_stats.items():
            if not re.fullmatch(r"[A-E]", str(key).upper()):
                continue
            letter = str(key).upper()

            for kind in comp_kinds_order:
                desired_checked = _desired_value_for_companion_kind(st, kind)
                meta = comp_inputs.get((team, letter, kind))
                if not meta:
                    missing.append({"section": "companions", "team": team, "player": letter, "kind": kind})
                    _dbg("MISSING companions input", req_id=req_id, team=team, letter=letter, kind=kind, desired=desired_checked)
                    continue

                inp = meta["inp"]
                args8 = meta["args8"]
                cur_checked = _is_checked_dom(inp)
                value_str = (inp.get("value") or "").strip()

                if _delta_equal_companion(inp, desired_checked):
                    skipped += 1
                    skipped_items.append({"section": "companions", "team": team, "player": letter, "kind": kind})
                    _dbg(
                        "SKIP delta companions",
                        req_id=req_id,
                        team=team,
                        letter=letter,
                        kind=kind,
                        desired=desired_checked,
                        cur_checked=cur_checked,
                        args8=args8,
                    )
                    continue

                _dbg(
                    "UPDATE companions sending",
                    req_id=req_id,
                    team=team,
                    letter=letter,
                    kind=kind,
                    desired=desired_checked,
                    cur_checked=cur_checked,
                    send_checked=desired_checked,
                    checkbox_value=value_str,
                    args8=args8,
                )

                ok, resp_txt = await _save_via_zapisz4(client, args8, value_str=value_str, checked=desired_checked)
                if ok:
                    updated += 1
                    _dbg("UPDATE companions OK", req_id=req_id, team=team, letter=letter, kind=kind, resp=resp_txt)
                else:
                    failed.append({
                        "section": "companions",
                        "team": team,
                        "player": letter,
                        "kind": kind,
                        "sent_value": value_str,
                        "sent_checked": desired_checked,
                        "resp": resp_txt,
                    })
                    _dbg("UPDATE companions FAIL", req_id=req_id, team=team, letter=letter, kind=kind, resp=resp_txt)

    _dbg(
        "apply_protocol end",
        req_id=req_id,
        updated_cells=updated,
        skipped_cells=skipped,
        failed=len(failed),
        missing=len(missing),
        players_inputs_host=players_inputs_host,
        players_inputs_guest=players_inputs_guest,
        companions_inputs_host=comp_inputs_host,
        companions_inputs_guest=comp_inputs_guest,
    )

    return {
        "updated_cells": updated,
        "skipped_cells": skipped,
        "failed": failed,
        "missing": missing,
        "skipped": skipped_items,
        "debug": {
            "req_id": req_id,
            "host_name": host_name,
            "guest_name": guest_name,
            "players_inputs_host": players_inputs_host,
            "players_inputs_guest": players_inputs_guest,
            "companions_inputs_host": comp_inputs_host,
            "companions_inputs_guest": comp_inputs_guest,
            "players_inputs_total": len(players_inputs),
            "companions_inputs_total": len(comp_inputs),
        },
    }


@router.post(
    "/judge/results/protocol",
    summary="Zapisz protokół na baza.zprp.pl na podstawie data_json (zawodnicy + osoby towarzyszące; 4 bloki; delta)",
)
async def save_protocol_from_json(
    req: ProtocolSaveRequest,
    settings: Settings = Depends(get_settings),
    keys=Depends(get_rsa_keys),
):
    logger.warning(
        "[protocol-debug] ENTER save_protocol_from_json env=%r enabled=%s",
        os.getenv("RESULTS_PROTOCOL_DEBUG"),
        _dbg_enabled(),
    )
    private_key, _ = keys
    user_plain = _decrypt_field(req.username, private_key)
    pass_plain = _decrypt_field(req.password, private_key)

    match_id = _extract_match_id(req.details_path)

    data_json = req.data_json or {}
    if not isinstance(data_json, dict):
        raise HTTPException(400, "data_json musi być obiektem JSON")

    try:
        client = await _login_and_client(user_plain, pass_plain, settings)
        try:
            details_url = _details_path_to_url(req.details_path)
            _, html = await fetch_with_correct_encoding(
                client,
                details_url,
                method="GET",
                cookies=client.cookies,
            )
            soup = BeautifulSoup(html, "html.parser")

            stats_map = _build_stats_map(data_json)
            mc = data_json.get("matchConfig") or {}
            host_name = mc.get("hostTeamName") or ""
            guest_name = mc.get("guestTeamName") or ""

            result = await _apply_protocol_updates_4blocks(
                client,
                soup,
                stats_map,
                host_name=host_name,
                guest_name=guest_name,
            )
        finally:
            await client.aclose()

        failed = result.get("failed") or []
        success = (len(failed) == 0)

        return {
            "success": success,
            "match_id": match_id,
            **result,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error("save_protocol_from_json error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Nie udało się zapisać protokołu: {e}")

# ============================================================
# EXPORT PROTOCOL PDF FROM ProEl data_json -> XLSX TEMPLATE -> PDF
# ============================================================

import os
import math
import shutil
import subprocess
import tempfile

from fastapi.responses import FileResponse
from openpyxl import load_workbook
from io import BytesIO
import zipfile

def _load_template_media_bytes(template_path: str) -> Dict[str, bytes]:
    """
    Czyta wszystkie pliki xl/media/* z szablonu XLSX do pamięci.
    Klucz: 'xl/media/image1.png'
    """
    media: Dict[str, bytes] = {}
    with zipfile.ZipFile(template_path, "r") as z:
        for name in z.namelist():
            if name.startswith("xl/media/"):
                media[name] = z.read(name)
    return media


def _rehydrate_images_in_workbook(wb, media: Dict[str, bytes]) -> None:
    """
    Podmienia obrazy w każdym arkuszu na takie, które trzymają dane w BytesIO,
    żeby wb.save() nie próbował czytać z zamkniętego strumienia.
    """
    for ws in wb.worksheets:
        imgs = list(getattr(ws, "_images", []) or [])
        if not imgs:
            continue

        # usuń stare
        ws._images = []

        for img in imgs:
            # openpyxl trzyma ścieżkę jako '/xl/media/imageX.png'
            path = (getattr(img, "path", "") or "").lstrip("/")
            blob = media.get(path)

            if not blob:
                # jeśli z jakiegoś powodu nie ma w media, to lepiej pominąć niż wywalić save()
                logger.warning("Protocol PDF: missing media for image path=%r", path)
                continue

            bio = BytesIO(blob)
            new_img = Image(bio)
            new_img.width = img.width
            new_img.height = img.height
            new_img.anchor = copy.deepcopy(img.anchor)

            ws.add_image(new_img)


def _copy_images_safe(src_ws, dst_ws):
    """
    Kopiuje obrazy, zakładając że src_ws ma już rehydratowane obrazy (ref=BytesIO).
    """
    for img in getattr(src_ws, "_images", []) or []:
        data: Optional[bytes] = None

        ref = getattr(img, "ref", None)
        if ref is not None and hasattr(ref, "getvalue"):
            data = ref.getvalue()

        if not data:
            # fallback (powinno już być bezpieczne po rehydratacji)
            try:
                data = img._data()
            except Exception as e:
                logger.warning("Protocol PDF: could not clone image: %s", e)
                continue

        bio = BytesIO(data)
        new_img = Image(bio)
        new_img.width = img.width
        new_img.height = img.height
        new_img.anchor = copy.deepcopy(img.anchor)

        dst_ws.add_image(new_img)


class ProtocolPdfRequest(BaseModel):
    data_json: Dict[str, Any]  # dokładnie ten sam JSON ProEl


def _ms_to_mmss(ms: Optional[int]) -> str:
    if ms is None:
        return ""
    try:
        ms_i = int(ms)
    except Exception:
        return ""
    if ms_i < 0:
        ms_i = 0
    mm = ms_i // 60000
    ss = (ms_i % 60000) // 1000
    return f"{mm:02d}:{ss:02d}"


def _event_minute_from_ms(ms: int) -> int:
    # minute numbering: 0:00 => 1, 53:12 => 54 (floor + 1)
    try:
        ms_i = int(ms)
    except Exception:
        ms_i = 0
    if ms_i < 0:
        ms_i = 0
    return (ms_i // 60000) + 1


def _safe_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return default


def _get_match_core(data_json: Dict[str, Any]) -> Dict[str, Any]:
    mc = data_json.get("matchConfig") or {}
    return {
        "matchNumber": (mc.get("matchNumber") or "").strip(),
        "hostName": (mc.get("hostTeamName") or "").strip(),
        "guestName": (mc.get("guestTeamName") or "").strip(),
        "halfTimeMin": _safe_int(mc.get("halfTime") or 30, 30),
        "scoreHost": _safe_int(data_json.get("scoreHost"), 0),
        "scoreGuest": _safe_int(data_json.get("scoreGuest"), 0),
        "halfScoreHost": _safe_int((data_json.get("halfScore") or {}).get("host"), 0),
        "halfScoreGuest": _safe_int((data_json.get("halfScore") or {}).get("guest"), 0),
        "hostPlayers": list(mc.get("hostPlayers") or []),
        "guestPlayers": list(mc.get("guestPlayers") or []),
        "venueAddress": (mc.get("venueAddress") or "").strip(),
        "referee1": (mc.get("referee1") or "").strip(),
        "referee2": (mc.get("referee2") or "").strip(),
        "delegate": (mc.get("delegate") or "").strip(),
        "timekeeper": (mc.get("timekeeper") or "").strip(),
        "secretary": (mc.get("secretary") or "").strip(),
        "hostPlayerCards": list(mc.get("hostPlayerCards") or []),
        "guestPlayerCards": list(mc.get("guestPlayerCards") or []),
        "hostCompanions": list(mc.get("hostCompanions") or []),
        "guestCompanions": list(mc.get("guestCompanions") or []),

    }


def _place_timeouts(ws, *, team_timeouts: Dict[str, Any], half_ms: int, is_host: bool) -> None:
    """
    Wypełnia czasy zgodnie z Twoimi regułami, ale uproszczone do logiki:
    - w 1. połowie: pierwszy timeout do (row10), drugi do (row11)
    - w 2. połowie: pierwszy timeout do (row10), drugi do (row11)
    Zgadza się z opisanymi przypadkami (max 2 czasy na połowę).
    """
    t1 = team_timeouts.get("first")
    t2 = team_timeouts.get("second")
    t3 = team_timeouts.get("third")
    times = [t for t in [t1, t2, t3] if t is not None]

    # sort rosnąco po czasie (ms)
    def _as_int(x):
        try:
            return int(x)
        except Exception:
            return 10**18

    times.sort(key=_as_int)

    half1 = [t for t in times if _as_int(t) < half_ms]
    half2 = [t for t in times if _as_int(t) >= half_ms]

    # host: half1 -> AL10/AL11, half2 -> AW10/AW11
    # guest: half1 -> AU10/AU11, half2 -> BF10/BF11
    if is_host:
        h1_cells = ["AL10", "AL11"]
        h2_cells = ["AW10", "AW11"]
    else:
        h1_cells = ["AU10", "AU11"]
        h2_cells = ["BF10", "BF11"]

    # 1. połowa
    if len(half1) == 0:
        # Nie wzięto żadnego czasu w 1. połowie - wpisujemy "---" w AL10 i AL11
        ws[h1_cells[0]].value = "---"
        ws[h1_cells[1]].value = "---"
    elif len(half1) == 1:
        # Wzięto tylko 1 czas - wpisujemy w AL10 oraz AL11
        ws[h1_cells[0]].value = _ms_to_mmss(half1[0])
        ws[h1_cells[1]].value = "---"
    else:
        # Wzięto dwa czasy - wpisujemy oba
        ws[h1_cells[0]].value = _ms_to_mmss(half1[0])
        ws[h1_cells[1]].value = _ms_to_mmss(half1[1])

    # 2. połowa
    if len(half2) == 0:
        # Nie wzięto żadnego czasu w 2. połowie - wpisujemy "---" w AW10 i AW11
        ws[h2_cells[0]].value = "---"
        ws[h2_cells[1]].value = "---"
    elif len(half2) == 1:
        # Wzięto tylko 1 czas w 2. połowie - wpisujemy w AW10 oraz AW11
        ws[h2_cells[0]].value = _ms_to_mmss(half2[0])
        ws[h2_cells[1]].value = "---"
    else:
        # Wzięto dwa czasy w 2. połowie - wpisujemy oba
        ws[h2_cells[0]].value = _ms_to_mmss(half2[0])
        ws[h2_cells[1]].value = _ms_to_mmss(half2[1])


def _player_stats_map(data_json: Dict[str, Any], team: str) -> Dict[int, Dict[str, Any]]:
    key = "hostPlayerStats" if team == "host" else "guestPlayerStats"
    arr = data_json.get(key) or []
    out: Dict[int, Dict[str, Any]] = {}
    for ps in arr:
        if not isinstance(ps, dict):
            continue
        n = ps.get("number")
        if n is None:
            continue
        try:
            out[int(n)] = ps
        except Exception:
            continue
    return out

def _player_fullname_map_from_cards(cards: List[Any]) -> Dict[int, str]:
    out: Dict[int, str] = {}
    for c in cards or []:
        if not isinstance(c, dict):
            continue
        n = c.get("number")
        if n is None:
            continue
        try:
            num = int(n)
        except Exception:
            continue
        name = (c.get("fullName") or "").strip()
        if name:
            out[num] = name
    return out


def _player_fullname_map_from_stats(stats_by_number: Dict[int, Dict[str, Any]]) -> Dict[int, str]:
    out: Dict[int, str] = {}
    for num, ps in (stats_by_number or {}).items():
        if not isinstance(ps, dict):
            continue
        name = (ps.get("fullName") or "").strip()
        if name:
            out[int(num)] = name
    return out


def _pick_companion_time(c: Dict[str, Any], *keys: str) -> str:
    for k in keys:
        v = c.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""

def _companion_penalty_strings(comp_list: List[Any]) -> Dict[str, Dict[str, str]]:
    """
    Zwraca mapę:
      "A".."E" -> {"warn": "U - MM:SS" | "---", "p2": "2' - MM:SS" | "---", "disq": "D - MM:SS" | "---"}
    Źródła:
      - upomnienie: warned + warnTime/warningTime/warnedTime (jeśli istnieje)
      - 2 minuty: penaltyTimes[0] (pierwsza 2')
      - dyskwalifikacja: red + redTime
    """
    out: Dict[str, Dict[str, str]] = {}
    for c in comp_list or []:
        if not isinstance(c, dict):
            continue
        cid = str(c.get("id") or "").strip().upper()
        if cid not in ("A", "B", "C", "D", "E"):
            continue

        # --- warning ---
        warned = bool(c.get("warned")) if "warned" in c else bool(c.get("warn")) if "warn" in c else False
        warn_time = _pick_companion_time(c, "warnTime", "warningTime", "warnedTime", "warning")
        warn_str = f"U - {warn_time}" if (warned and warn_time) else ("U - __:__" if warned else "")

        # --- 2' ---
        p_times = c.get("penaltyTimes") if isinstance(c.get("penaltyTimes"), list) else []
        p2_time = ""
        if p_times:
            first = p_times[0]
            if isinstance(first, str) and first.strip():
                p2_time = first.strip()
        # czasem możesz mieć boola "twoMinutes" bez listy — wtedy wpisz placeholder
        two_min = bool(c.get("twoMinutes")) if "twoMinutes" in c else False
        p2_str = f"2' - {p2_time}" if p2_time else ("2' - __:__" if two_min else "")

        # --- disq (red) ---
        red = bool(c.get("red")) if "red" in c else bool(c.get("disq")) if "disq" in c else False
        red_time = _pick_companion_time(c, "redTime", "disqTime", "disqualificationTime")
        disq_str = f"D - {red_time}" if (red and red_time) else ("D - __:__" if red else "")

        out[cid] = {"warn": warn_str, "p2": p2_str, "disq": disq_str}

    return out

def _companion_fullname_map(comp_list: List[Any]) -> Dict[str, str]:
    """
    Zwraca mapę: "A".."E" -> "NAZWISKO Imię"
    """
    out: Dict[str, str] = {}
    for c in comp_list or []:
        if not isinstance(c, dict):
            continue
        cid = str(c.get("id") or "").strip().upper()
        if cid not in ("A", "B", "C", "D", "E"):
            continue
        name = (c.get("fullName") or "").strip()
        if name:
            out[cid] = name
    return out

def _companion_meta_map(comp_list: List[Any]) -> Dict[str, Dict[str, str]]:
    """
    Zwraca mapę: "A".."E" -> {"function": "...", "license": "..."}
    """
    out: Dict[str, Dict[str, str]] = {}
    for c in comp_list or []:
        if not isinstance(c, dict):
            continue
        cid = str(c.get("id") or "").strip().upper()
        if cid not in ("A", "B", "C", "D", "E"):
            continue

        func = (c.get("function") or "").strip()
        lic = (c.get("license") or "").strip()

        out[cid] = {"function": func, "license": lic}
    return out


def _fill_players_block(
    ws,
    *,
    players: List[Any],
    stats_by_number: Dict[int, Dict[str, Any]],
    fullnames_by_number: Dict[int, str],
    start_row: int,
    end_row: int,
) -> None:
    """
    Kolumny wg Twojej specyfikacji:
      - A: numer
      - Q: wejście "W" / "-"
      - S: bramki liczba / "-"
      - U: upomnienie "[minuta]'" / "-"
      - W: 2' #1 (MM:SS) / "---"
      - Z: 2' #2 / "---"
      - AC: 2' #3 / "---"
      - AF: dyskwalifikacja lub dysq z opisem / "---"
      - AI: zawsze "---"
    """
    nums: List[int] = []
    for p in players or []:
        try:
            nums.append(int(p))
        except Exception:
            continue
    nums = sorted(set(nums))

    max_rows = (end_row - start_row + 1)
    nums = nums[:max_rows]

    for i in range(max_rows):
        row = start_row + i
        ws[f"AI{row}"].value = "---"  # zawsze

        if i >= len(nums):
            # zostaw pusto jeśli mniej zawodników
            ws[f"A{row}"].value = "--"
            ws[f"C{row}"].value = "-------------------------------------------"
            ws[f"Q{row}"].value = "-"
            ws[f"S{row}"].value = "-"
            ws[f"U{row}"].value = "-"
            ws[f"W{row}"].value = "---"
            ws[f"Z{row}"].value = "---"
            ws[f"AC{row}"].value = "---"
            ws[f"AF{row}"].value = "---"
            continue

        num = nums[i]
        ps = stats_by_number.get(num) or {}

        entered = bool(ps.get("entered") or False)
        goals = _safe_int(ps.get("goals") or 0, 0)
        warning = ps.get("warning")  # w ProEl bywa "12'"
        penalty1 = (ps.get("penalty1") or "").strip()
        penalty2 = (ps.get("penalty2") or "").strip()
        penalty3 = (ps.get("penalty3") or "").strip()
        disq_time = (ps.get("disqualification") or "").strip()
        disq_desc = (ps.get("disqualificationDesc") or "").strip()
        has_red = bool(ps.get("hasRedCard") or False)

        ws[f"A{row}"].value = num
        ws[f"C{row}"].value = (fullnames_by_number.get(num) or "")
        ws[f"Q{row}"].value = "W" if entered else "-"
        ws[f"S{row}"].value = goals if goals > 0 else "-"
        ws[f"U{row}"].value = str(warning).strip() if isinstance(warning, str) and warning.strip() else "-"

        ws[f"W{row}"].value = penalty1 if penalty1 else "---"
        ws[f"Z{row}"].value = penalty2 if penalty2 else "---"
        ws[f"AC{row}"].value = penalty3 if penalty3 else "---"

        if disq_time or disq_desc:
            if disq_time and disq_desc:
                ws[f"AF{row}"].value = f"{disq_time} {disq_desc}"
            elif disq_time:
                ws[f"AF{row}"].value = disq_time
            elif disq_desc:
                ws[f"AF{row}"].value = disq_desc
        else:
            ws[f"AF{row}"].value = "---"


TIMELINE_START_ROW = 15
TIMELINE_END_ROW = 63
TIMELINE_SKIP_ROWS = {31, 57}

TIMELINE_ROWS = [r for r in range(TIMELINE_START_ROW, TIMELINE_END_ROW + 1) if r not in TIMELINE_SKIP_ROWS]
TIMELINE_MAX_ROWS = len(TIMELINE_ROWS)  # było 47, teraz będzie 45


def _extract_timeline_events(data_json: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Zwraca (evs1, evs2) dla typów: goal, penaltyKickScored, penaltyKickMissed,
    posortowane rosnąco po time (ms).
    """
    prot = data_json.get("protocol") or []
    evs1: List[Dict[str, Any]] = []
    evs2: List[Dict[str, Any]] = []

    for ev in prot:
        if not isinstance(ev, dict):
            continue
        t = ev.get("type")
        if t not in ("goal", "penaltyKickScored", "penaltyKickMissed"):
            continue
        half = ev.get("half")
        if half == 1:
            evs1.append(ev)
        elif half == 2:
            evs2.append(ev)

    def _ev_ms(e: Dict[str, Any]) -> int:
        return _safe_int(e.get("time") or 0, 0)

    evs1.sort(key=_ev_ms)
    evs2.sort(key=_ev_ms)
    return evs1, evs2


def _advance_scores_for_events(
    evs: List[Dict[str, Any]],
    start_host: int,
    start_guest: int,
) -> Tuple[int, int]:
    """
    Przelicza score po zdarzeniach (liczymy tylko goal i penaltyKickScored).
    penaltyKickMissed nie zmienia wyniku.
    """
    h = _safe_int(start_host, 0)
    g = _safe_int(start_guest, 0)

    for ev in evs:
        if not isinstance(ev, dict):
            continue
        t = ev.get("type")
        team = ev.get("team")
        if t == "goal" or t == "penaltyKickScored":
            if team == "host":
                h += 1
            elif team == "guest":
                g += 1

    return h, g


def _fill_timeline_half_chunk(
    ws,
    *,
    evs: List[Dict[str, Any]],
    start_row: int,
    end_row: int,
    half_ms: int,
    start_score_host: int,
    start_score_guest: int,
    col_minute: str,
    col_host_action: str,
    col_host_score: str,
    col_guest_score: str,
    col_guest_action: str,
) -> Tuple[int, int]:
    def _ev_ms(e: Dict[str, Any]) -> int:
        return _safe_int(e.get("time") or 0, 0)

    h_score = _safe_int(start_score_host, 0)
    g_score = _safe_int(start_score_guest, 0)

    # bierzemy tylko te wiersze, które faktycznie wolno ruszać
    rows = [r for r in TIMELINE_ROWS if start_row <= r <= end_row]

    def _write_blank(r: int) -> None:
        ws[f"{col_minute}{r}"].value = "--"
        ws[f"{col_host_action}{r}"].value = "--"
        ws[f"{col_host_score}{r}"].value = "--"
        ws[f"{col_guest_score}{r}"].value = "--"
        ws[f"{col_guest_action}{r}"].value = "--"

    # 1) wypełnij eventami tyle ile się da
    i = 0
    for ev in evs:
        if i >= len(rows):
            break
        r = rows[i]

        ms = _ev_ms(ev)
        minute = _event_minute_from_ms(ms)

        team = ev.get("team")
        player = ev.get("player")
        t = ev.get("type")

        _write_blank(r)  # default

        ws[f"{col_minute}{r}"].value = str(minute)

        host_action = ""
        guest_action = ""

        if player is not None:
            ptxt = str(player).strip()
            if isinstance(t, str) and t.startswith("penaltyKick"):
                ptxt = f"{ptxt}K"
            if team == "host":
                host_action = ptxt
            elif team == "guest":
                guest_action = ptxt

        ws[f"{col_host_action}{r}"].value = host_action if host_action else "--"
        ws[f"{col_guest_action}{r}"].value = guest_action if guest_action else "--"

        if t in ("goal", "penaltyKickScored"):
            if team == "host":
                h_score += 1
            elif team == "guest":
                g_score += 1
            ws[f"{col_host_score}{r}"].value = str(h_score)
            ws[f"{col_guest_score}{r}"].value = str(g_score)
        else:
            ws[f"{col_host_score}{r}"].value = "--"
            ws[f"{col_guest_score}{r}"].value = "--"

        i += 1

    # 2) resztę dozwolonych wierszy wyczyść na "--"
    while i < len(rows):
        _write_blank(rows[i])
        i += 1

    return h_score, g_score


def _fill_timeline_pages(
    ws_page1,
    ws_page2,
    *,
    data_json: Dict[str, Any],
    half_ms: int,
    half_score_host: int,
    half_score_guest: int,
) -> bool:
    """
    Wypełnia przebieg na stronie 1 i (opcjonalnie) kontynuację na stronie 2.
    Zwraca True jeśli powstała strona 2 (overflow), inaczej False.
    """
    evs1, evs2 = _extract_timeline_events(data_json)

    overflow1 = len(evs1) > TIMELINE_MAX_ROWS
    overflow2 = len(evs2) > TIMELINE_MAX_ROWS
    needs_page2 = overflow1 or overflow2

    # podział na chunk'i
    evs1_p1 = evs1[:TIMELINE_MAX_ROWS]
    evs1_p2 = evs1[TIMELINE_MAX_ROWS:]
    evs2_p1 = evs2[:TIMELINE_MAX_ROWS]
    evs2_p2 = evs2[TIMELINE_MAX_ROWS:]

    # --- PAGE 1 ---
    # 1 połowa startuje od 0:0
    _fill_timeline_half_chunk(
        ws_page1,
        evs=evs1_p1,
        start_row=TIMELINE_START_ROW,
        end_row=TIMELINE_END_ROW,
        half_ms=half_ms,
        start_score_host=0,
        start_score_guest=0,
        col_minute="AL",
        col_host_action="AN",
        col_host_score="AP",
        col_guest_score="AS",
        col_guest_action="AU",
    )

    # 2 połowa startuje od halfScore
    _fill_timeline_half_chunk(
        ws_page1,
        evs=evs2_p1,
        start_row=TIMELINE_START_ROW,
        end_row=TIMELINE_END_ROW,
        half_ms=half_ms,
        start_score_host=_safe_int(half_score_host, 0),
        start_score_guest=_safe_int(half_score_guest, 0),
        col_minute="AW",
        col_host_action="AY",
        col_host_score="BA",
        col_guest_score="BD",
        col_guest_action="BF",
    )

    if not needs_page2:
        return False

        # --- PAGE 2 ---
    if ws_page2 is None:
        # teoretycznie nie powinno się zdarzyć, ale bezpiecznie
        return False

    # jeśli nie ma kontynuacji danej połowy -> i tak wypełniamy "--"
    # 1 połowa (kontynuacja): start score musi być po evs1_p1
    h1_after, g1_after = _advance_scores_for_events(evs1_p1, 0, 0)
    _fill_timeline_half_chunk(
        ws_page2,
        evs=evs1_p2,
        start_row=TIMELINE_START_ROW,
        end_row=TIMELINE_END_ROW,
        half_ms=half_ms,
        start_score_host=h1_after,
        start_score_guest=g1_after,
        col_minute="AL",
        col_host_action="AN",
        col_host_score="AP",
        col_guest_score="AS",
        col_guest_action="AU",
    )

    # 2 połowa (kontynuacja): start score musi być po evs2_p1 (od halfScore)
    h2_start = _safe_int(half_score_host, 0)
    g2_start = _safe_int(half_score_guest, 0)
    h2_after, g2_after = _advance_scores_for_events(evs2_p1, h2_start, g2_start)

    _fill_timeline_half_chunk(
        ws_page2,
        evs=evs2_p2,
        start_row=TIMELINE_START_ROW,
        end_row=TIMELINE_END_ROW,
        half_ms=half_ms,
        start_score_host=h2_after,
        start_score_guest=g2_after,
        col_minute="AW",
        col_host_action="AY",
        col_host_score="BA",
        col_guest_score="BD",
        col_guest_action="BF",
    )

    return True


def _convert_xlsx_to_pdf(xlsx_path: str, out_dir: str) -> str:
    """
    Konwersja przez LibreOffice:
      soffice --headless --convert-to pdf --outdir <out_dir> <xlsx_path>
    Zwraca ścieżkę do PDF.
    """
    soffice = shutil.which("soffice") or shutil.which("libreoffice")
    if not soffice:
        raise RuntimeError("Brak LibreOffice (soffice) w środowisku. Doinstaluj libreoffice w Dockerfile.")

    # LO w kontenerze często próbuje pisać do HOME — zabezpieczamy to envem
    env = os.environ.copy()
    env.setdefault("HOME", "/tmp")
    env.setdefault("XDG_CACHE_HOME", "/tmp")
    env.setdefault("XDG_CONFIG_HOME", "/tmp")

    profile_dir = os.path.join(out_dir, "lo_profile")
    os.makedirs(profile_dir, exist_ok=True)

    cmd = [
        soffice,
        "--headless",
        "--nologo",
        "--nolockcheck",
        "--nodefault",
        "--norestore",
        f"-env:UserInstallation=file://{profile_dir}",
        "--convert-to",
        "pdf",
        "--outdir",
        out_dir,
        xlsx_path,
    ]


    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        timeout=90,  # ważne: żeby request nie wisiał wiecznie
    )

    if proc.returncode != 0:
        raise RuntimeError(
            f"LibreOffice convert failed (code={proc.returncode}). "
            f"stderr={proc.stderr[:500]} stdout={proc.stdout[:200]}"
        )

    base = os.path.splitext(os.path.basename(xlsx_path))[0]
    pdf_path = os.path.join(out_dir, base + ".pdf")

    if not os.path.exists(pdf_path):
        # fallback: znajdź najbardziej pasujący PDF w out_dir
        pdfs = [p for p in os.listdir(out_dir) if p.lower().endswith(".pdf")]
        if len(pdfs) == 1:
            pdf_path = os.path.join(out_dir, pdfs[0])
        else:
            # spróbuj dopasować po base
            cand = [p for p in pdfs if os.path.splitext(p)[0] == base]
            if len(cand) == 1:
                pdf_path = os.path.join(out_dir, cand[0])
            else:
                raise RuntimeError(f"Nie znaleziono wyjściowego PDF po konwersji. Pliki: {pdfs[:10]}")

    return pdf_path

def _parse_penalty_score(penalty_score: str) -> Tuple[int, int]:
    """
    "5 - 4" / "5-4" -> (5,4)
    """
    s = (penalty_score or "").strip()
    if not s:
        return (0, 0)
    m = re.search(r"(\d+)\s*-\s*(\d+)", s)
    if not m:
        return (0, 0)
    return int(m.group(1)), int(m.group(2))


def _shootout_needed(data_json: Dict[str, Any]) -> bool:
    """
    Karne tylko gdy:
      - wynik końcowy remis
      - i jest penaltyScore albo penaltyShots
    """
    try:
        sh = int(data_json.get("scoreHost") or 0)
        sg = int(data_json.get("scoreGuest") or 0)
    except Exception:
        sh, sg = 0, 0

    if sh != sg:
        return False

    ps = (data_json.get("penaltyScore") or "").strip()
    shots = data_json.get("penaltyShots") or {}
    has_shots = bool((shots.get("host") or []) or (shots.get("guest") or []))
    return bool(ps) or has_shots


def _fill_shootout_page(ws, *, data_json: Dict[str, Any]) -> None:
    """
    Strona "RZUTY KARNE" w przebiegu (kolumny AL..AU, wiersze 15..61).
    Zaczynamy od wiersza 16.
    """
    # 1) Nagłówek: merge + tekst
    ws.merge_cells("AL15:AV15")
    ws["AL15"].value = "RZUTY KARNE"
    ws["AL15"].alignment = Alignment(horizontal="center", vertical="center")
    ws["AL15"].font = Font(bold=True)

    # 2) Wyczyść/ustaw "--" w obu blokach przebiegu żeby nie było śmieci z kopiowanego arkusza
    # lewy blok (AL..AU)
    for r in range(16, 62):
        ws[f"AL{r}"].value = "--"
        ws[f"AN{r}"].value = "--"
        ws[f"AP{r}"].value = "--"
        ws[f"AS{r}"].value = "--"
        ws[f"AU{r}"].value = "--"

    # prawy blok (AW..BF) – na stronie karnych nie używamy, więc czyścimy
    for r in range(15, 62):
        ws[f"AW{r}"].value = "--"
        ws[f"AY{r}"].value = "--"
        ws[f"BA{r}"].value = "--"
        ws[f"BD{r}"].value = "--"
        ws[f"BF{r}"].value = "--"

    # 3) Dane karnych
    shots = data_json.get("penaltyShots") or {}
    host_arr = shots.get("host") or []
    guest_arr = shots.get("guest") or []

    # ile serii (po 1 strzale na drużynę)
    series_count = max(len(host_arr), len(guest_arr))
    if series_count <= 0:
        return

    # 4) Wpisy od wiersza 16, po 2 wiersze na serię
    row = 16
    host_score = 0
    guest_score = 0

    def _shot(arr, idx) -> Optional[Dict[str, Any]]:
        if idx < 0 or idx >= len(arr):
            return None
        x = arr[idx]
        return x if isinstance(x, dict) else None

    # co 5 serii zmiana startującego:
    # serie 1-5: host first
    # serie 6-10: guest first
    # serie 11-15: host first
    # itd.
    # W tej sekcji w kodzie odpowiedzialnej za ustawianie kolejności drużyn do wykonywania karnych

    # Odczytanie drużyny rozpoczynającej karne z JSON
    penalty_starter_team = data_json.get("penaltyStarterTeam", "guest")

    # Zmienna do kontrolowania, która drużyna jako pierwsza wykonuje rzuty karne
    flip = False  # Flaga do przełączania kolejności

    # Co 5 kolejek zmieniamy drużynę zaczynającą karne
    for s in range(1, series_count + 1):
        if row > 61:
            break  # brak miejsca w szablonie

        idx = s - 1

        # Zmiana kolejności co 5 serii
        if (s - 1) // 5 % 2 == 1:
            flip = not flip

        # Jeśli 'penaltyStarterTeam' to 'guest', to 'guest' zaczyna
        first_team = penalty_starter_team if not flip else ("guest" if penalty_starter_team == "host" else "host")
        second_team = "guest" if first_team == "host" else "host"

        def write_team_shot(team: str, series_no: int):
            nonlocal row, host_score, guest_score
            if row > 61:
                return

            ws[f"AL{row}"].value = str(series_no)

            if team == "host":
                sh = _shot(host_arr, idx)
                player = sh.get("player") if sh else None
                result = int(sh.get("result") or 0) if sh else 0

                ws[f"AN{row}"].value = str(int(player)) if player is not None else "--"
                ws[f"AU{row}"].value = "--"

                if result == 1:
                    host_score += 1
                    ws[f"AP{row}"].value = str(host_score)
                    ws[f"AS{row}"].value = str(guest_score)   # <-- pokaż wynik przeciwnika
                else:
                    ws[f"AP{row}"].value = "--"
                    ws[f"AS{row}"].value = "--"


            else:
                sh = _shot(guest_arr, idx)
                player = sh.get("player") if sh else None
                result = int(sh.get("result") or 0) if sh else 0

                ws[f"AN{row}"].value = "--"
                ws[f"AU{row}"].value = str(int(player)) if player is not None else "--"

                if result == 1:
                    guest_score += 1
                    ws[f"AP{row}"].value = str(host_score)    # <-- pokaż wynik gospodarza
                    ws[f"AS{row}"].value = str(guest_score)
                else:
                    ws[f"AP{row}"].value = "--"
                    ws[f"AS{row}"].value = "--"

            row += 1

        # 1) pierwszy strzał w serii
        write_team_shot(first_team, s)
        # 2) drugi strzał w serii
        write_team_shot(second_team, s)

from datetime import datetime, date
from io import BytesIO
from typing import Callable

# jeśli masz pillow (zwykle jest), to da nam rozmiar obrazka do skalowania
try:
    from PIL import Image as PILImage
except Exception:
    PILImage = None


BACKEND_STATIC_PREFIX = "https://zprp-backend-production.up.railway.app"


def _full_static_url(rel_or_abs: str) -> str:
    """
    '/static/xxx.png' -> 'https://.../static/xxx.png'
    jeśli już jest absolutny URL -> zwraca bez zmian
    """
    s = (rel_or_abs or "").strip()
    if not s:
        return ""
    if s.startswith("http://") or s.startswith("https://"):
        return s
    if not s.startswith("/"):
        s = "/" + s
    return BACKEND_STATIC_PREFIX + s


def _fmt_date_ddmmyyyy(iso_ymd: str) -> str:
    """
    '2026-02-23' -> '23.02.2026'
    """
    s = (iso_ymd or "").strip()
    if not s:
        return ""
    try:
        d = datetime.strptime(s, "%Y-%m-%d").date()
        return d.strftime("%d.%m.%Y")
    except Exception:
        return ""


def _fmt_time_hhmm(hhmm: str) -> str:
    """
    '18:00' -> '18:00' (waliduje format)
    """
    s = (hhmm or "").strip()
    if not s:
        return ""
    try:
        t = datetime.strptime(s, "%H:%M").time()
        return t.strftime("%H:%M")
    except Exception:
        return ""


def _set_yes_no_x(ws, *, yes_cell: str, no_cell: str, value: Any, yes_when_true: bool = True) -> None:
    """
    Wstawia "X" do pary komórek (tak/nie albo brak/verte).
    Jeśli value truthy -> X do yes_cell (gdy yes_when_true=True), inaczej do no_cell.
    """
    v = bool(value) if value is not None else False
    ws[yes_cell].value = ""
    ws[no_cell].value = ""
    if yes_when_true:
        ws[yes_cell].value = "X" if v else ""
        ws[no_cell].value = "" if v else "X"
    else:
        # odwrotna logika (raczej niepotrzebna tutaj, ale zostawiam)
        ws[yes_cell].value = "" if v else "X"
        ws[no_cell].value = "X" if v else ""


async def _fetch_png_bytes(url: str) -> bytes:
    """
    Pobiera obraz PNG/JPG z URL. Zwraca bytes albo b'' gdy brak/nieprawidłowy.
    """
    u = (url or "").strip()
    if not u:
        return b""
    try:
        async with AsyncClient(follow_redirects=True, timeout=15.0) as c:
            r = await c.get(u)
            if r.status_code != 200:
                return b""
            return r.content or b""
    except Exception:
        return b""


def _add_signature_image(
    ws,
    *,
    image_bytes: bytes,
    anchor_cell: str,
    max_width_px: int = 220,
    max_height_px: int = 90,
) -> bool:
    """
    Wstawia obraz do arkusza, zakotwiczony w anchor_cell (czyli "nad tą komórką").
    Skaluje, żeby zmieścił się w max_width/max_height (px).
    Zwraca True jeśli dodano.
    """
    if not image_bytes:
        return False

    bio = BytesIO(image_bytes)
    img = Image(bio)

    # Skala (jeśli mamy PIL, weźmiemy faktyczny rozmiar)
    if PILImage is not None:
        try:
            bio2 = BytesIO(image_bytes)
            pil = PILImage.open(bio2)
            w, h = pil.size
            if w and h:
                scale = min(max_width_px / float(w), max_height_px / float(h), 1.0)
                img.width = int(w * scale)
                img.height = int(h * scale)
        except Exception:
            # fallback: zostaw rozmiar domyślny openpyxl
            pass
    else:
        # fallback bez PIL: ustaw “na oko”
        img.width = min(img.width or max_width_px, max_width_px)
        img.height = min(img.height or max_height_px, max_height_px)

    ws.add_image(img, anchor_cell)
    return True

def _safe_filename_from_match_number(match_number: str) -> str:
    base = (match_number or "mecz").strip().replace("/", "-")
    base = re.sub(r"[^0-9A-Za-z._-]+", "_", base)
    return f"protokol_{base}.pdf"

DOWNLOAD_DIR = "/tmp/protocol_downloads"
DOWNLOAD_TTL_SECONDS = 10 * 60  # 10 min

def _ensure_download_dir():
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)

def _cleanup_expired_downloads():
    try:
        _ensure_download_dir()
        now = time.time()
        for fn in os.listdir(DOWNLOAD_DIR):
            p = os.path.join(DOWNLOAD_DIR, fn)
            try:
                st = os.stat(p)
                if now - st.st_mtime > DOWNLOAD_TTL_SECONDS:
                    os.remove(p)
            except Exception:
                pass
    except Exception:
        pass


OFFICIAL_NAME_FALLBACK = "--------------------------"
OFFICIAL_CITY_FALLBACK = "     -------------     "
OFFICIAL_SIGN_FALLBACK = "-------"

def _fallback_text(v: Any, fallback: str) -> str:
    s = (v or "").strip() if isinstance(v, str) else str(v).strip() if v is not None else ""
    return s if s else fallback

def _set_cell_fallback(ws, cell: str, v: Any, fallback: str) -> None:
    ws[cell].value = _fallback_text(v, fallback)

@router.post(
    "/judge/results/protocol/pdf",
    summary="Generuj PDF z protokołu na podstawie data_json (ProEl) i szablonu XLSX",
)
async def generate_protocol_pdf(
    req: ProtocolPdfRequest,
):
    data_json = req.data_json or {}
    if not isinstance(data_json, dict):
        raise HTTPException(400, "data_json musi być obiektem JSON")

    # --- locate template ---
    template_path = SysPath(__file__).resolve().parent / "templates" / "protocol_template.xlsx"
    if not template_path.exists():
        raise HTTPException(
            500,
            f"Brak szablonu XLSX: {template_path}. Umieść plik w app/templates/protocol_template.xlsx i dodaj do repo.",
        )

    core = _get_match_core(data_json)
    half_ms = core["halfTimeMin"] * 60 * 1000

    # penalties totals
    pen = data_json.get("penaltyStats") or {}
    pen_h = pen.get("host") or {}
    pen_g = pen.get("guest") or {}
    pk_host_total = _safe_int(pen_h.get("total"), 0)
    pk_host_goals = _safe_int(pen_h.get("goals"), 0)
    pk_guest_total = _safe_int(pen_g.get("total"), 0)
    pk_guest_goals = _safe_int(pen_g.get("goals"), 0)

    # timeouts
    tt = data_json.get("teamTimeouts") or {}
    tt_host = tt.get("host") or {}
    tt_guest = tt.get("guest") or {}

    # players stats
    host_stats = _player_stats_map(data_json, "host")
    guest_stats = _player_stats_map(data_json, "guest")
    host_names = _player_fullname_map_from_cards(core.get("hostPlayerCards") or [])
    guest_names = _player_fullname_map_from_cards(core.get("guestPlayerCards") or [])

    if not host_names:
        host_names = _player_fullname_map_from_stats(host_stats)
    if not guest_names:
        guest_names = _player_fullname_map_from_stats(guest_stats)

    host_comp_names = _companion_fullname_map(core.get("hostCompanions") or [])
    guest_comp_names = _companion_fullname_map(core.get("guestCompanions") or [])

    host_comp_meta = _companion_meta_map(core.get("hostCompanions") or [])
    guest_comp_meta = _companion_meta_map(core.get("guestCompanions") or [])

    host_comp_pen = _companion_penalty_strings(core.get("hostCompanions") or [])
    guest_comp_pen = _companion_penalty_strings(core.get("guestCompanions") or [])

    # winner (A/B) – przy remisie rozstrzygamy z penaltyScore
    winner = ""
    if core["scoreHost"] > core["scoreGuest"]:
        winner = "A"
    elif core["scoreGuest"] > core["scoreHost"]:
        winner = "B"
    else:
        ph, pg = _parse_penalty_score(data_json.get("penaltyScore") or "")
        if ph > pg:
            winner = "A"
        elif pg > ph:
            winner = "B"
        else:
            winner = ""  # jeśli brak/niepoprawny penaltyScore


    try:
        td = tempfile.mkdtemp(prefix="protocol_")  # ✅ nie usuwa się samo
        safe_code = re.sub(r"[^0-9A-Za-z_-]+", "_", (core.get("matchNumber") or "mecz"))
        filled_xlsx = os.path.join(td, f"protocol_{safe_code}.xlsx")

        wb = load_workbook(str(template_path))

        # 🔥 kluczowe: zanim cokolwiek zapiszesz / skopiujesz arkusze, rehydratacja obrazów
        media = _load_template_media_bytes(str(template_path))
        _rehydrate_images_in_workbook(wb, media)

        ws = wb.active

        # --- extras (NOWE POLA Z data_json) ---
        mc = data_json.get("matchConfig") or {}
        extras = mc.get("extras") or {}

        # data/godzina
        ws["AB8"].value = _fmt_date_ddmmyyyy(extras.get("matchDate"))
        ws["AH8"].value = _fmt_time_hhmm(extras.get("matchTime"))

        # medyk
        medic = extras.get("medic") or {}
        ws["U61"].value = (medic.get("fullName") or "").strip()
        ws["U62"].value = (medic.get("number") or "").strip()

        # widzowie / pojemność
        ws["G62"].value = extras.get("spectatorsCount") if extras.get("spectatorsCount") is not None else ""
        ws["Q62"].value = extras.get("venueCapacity") if extras.get("venueCapacity") is not None else ""

        # szczegółowe uwagi sędziów: brak -> O61, verte -> S61
        # value: True => verte (S61), False/None => brak (O61)
        detailed_notes = bool(extras.get("detailedRefereeNotes")) if extras.get("detailedRefereeNotes") is not None else False
        ws["O61"].value = "X" if not detailed_notes else ""
        ws["S61"].value = "X" if detailed_notes else ""

        # rejestracja zawodów: tak -> O63, nie -> S63
        event_reg = bool(extras.get("eventRegistration")) if extras.get("eventRegistration") is not None else False
        ws["O63"].value = "X" if event_reg else ""
        ws["S63"].value = "X" if not event_reg else ""

        # dodatkowy raport: tak -> O64, nie -> S64
        extra_report = bool(extras.get("extraReport")) if extras.get("extraReport") is not None else False
        ws["O64"].value = "X" if extra_report else ""
        ws["S64"].value = "X" if not extra_report else ""

        # miejscowości sędziów (W66..W70)
        officials = extras.get("officials") or {}

        _set_cell_fallback(ws, "W66", (officials.get("referee1") or {}).get("city"), OFFICIAL_CITY_FALLBACK)
        _set_cell_fallback(ws, "W67", (officials.get("referee2") or {}).get("city"), OFFICIAL_CITY_FALLBACK)
        _set_cell_fallback(ws, "W68", (officials.get("secretary") or {}).get("city"), OFFICIAL_CITY_FALLBACK)
        _set_cell_fallback(ws, "W69", (officials.get("timekeeper") or {}).get("city"), OFFICIAL_CITY_FALLBACK)
        _set_cell_fallback(ws, "W70", (officials.get("delegate") or {}).get("city"), OFFICIAL_CITY_FALLBACK)

                # --- SIGNATURES (PNG z backendu) ---
        SIGN_ANCHORS = {
            "hostTeamSignature": "F29",
            "guestTeamSignature": "F55",
            "medic": "Z63",
            "referee1": "AI66",
            "referee2": "AI67",
            "secretary": "AI68",
            "timekeeper": "AI69",
            "delegate": "AI70",
        }

        # 1) podpisy drużyn
        host_sig_url = _full_static_url(extras.get("hostTeamSignature") or "")
        guest_sig_url = _full_static_url(extras.get("guestTeamSignature") or "")

        host_sig_bytes = await _fetch_png_bytes(host_sig_url)
        guest_sig_bytes = await _fetch_png_bytes(guest_sig_url)

        _add_signature_image(
            ws,
            image_bytes=host_sig_bytes,
            anchor_cell=SIGN_ANCHORS["hostTeamSignature"],
            max_width_px=80,
            max_height_px=35,
        )
        _add_signature_image(
            ws,
            image_bytes=guest_sig_bytes,
            anchor_cell=SIGN_ANCHORS["guestTeamSignature"],
            max_width_px=80,
            max_height_px=35,
        )

        # 2) podpis medyka
        medic_sig_url = _full_static_url((medic.get("signature") or "").strip())
        medic_sig_bytes = await _fetch_png_bytes(medic_sig_url)
        _add_signature_image(
            ws,
            image_bytes=medic_sig_bytes,
            anchor_cell=SIGN_ANCHORS["medic"],
            max_width_px=120,
            max_height_px=30,
        )

        # 3) podpisy officials
        def _off_sig_url(key: str) -> str:
            return _full_static_url((((officials.get(key) or {}).get("signature")) or "").strip())

        for key in ("referee1", "referee2", "secretary", "timekeeper", "delegate"):
            url = _off_sig_url(key)
            blob = await _fetch_png_bytes(url)

            ok = _add_signature_image(
                ws,
                image_bytes=blob,
                anchor_cell=SIGN_ANCHORS[key],
                max_width_px=70,
                max_height_px=14,
            )

            # jeśli nie dodano obrazka -> wstaw placeholder tekstowy w komórkę kotwiczącą
            if not ok:
                ws[SIGN_ANCHORS[key]].value = OFFICIAL_SIGN_FALLBACK


        # --- header mapping ---
        ws["AY1"].value = core["matchNumber"]
        ws["AL4"].value = core.get("venueAddress") or ""
        ws["C4"].value = core["hostName"]
        ws["D9"].value = core["hostName"]
        ws["C7"].value = core["guestName"]
        ws["D35"].value = core["guestName"]

        ws["AL6"].value = str(core["scoreHost"])
        ws["AQ6"].value = str(core["scoreGuest"])
        ws["AU6"].value = str(core["halfScoreHost"])
        ws["AY6"].value = str(core["halfScoreGuest"])
        ws["BB6"].value = winner

        # --- timeouts mapping ---
        _place_timeouts(ws, team_timeouts=tt_host, half_ms=half_ms, is_host=True)
        _place_timeouts(ws, team_timeouts=tt_guest, half_ms=half_ms, is_host=False)

        # --- penalties totals ---
        ws["AN65"].value = str(pk_host_total)
        ws["AR65"].value = str(pk_host_goals)
        ws["AY65"].value = str(pk_guest_total)
        ws["BC65"].value = str(pk_guest_goals)

        # --- players numbers + stats ---
        _fill_players_block(
            ws,
            players=core["hostPlayers"],
            stats_by_number=host_stats,
            fullnames_by_number=host_names,
            start_row=11,
            end_row=28,
        )
        _fill_players_block(
            ws,
            players=core["guestPlayers"],
            stats_by_number=guest_stats,
            fullnames_by_number=guest_names,
            start_row=37,
            end_row=54,
        )

        # Osoby towarzyszące gospodarzy
        ws["B29"].value  = host_comp_names.get("A", "")
        ws["K29"].value  = host_comp_names.get("B", "")
        ws["R29"].value  = host_comp_names.get("C", "")
        ws["Y29"].value  = host_comp_names.get("D", "")
        ws["AF29"].value = host_comp_names.get("E", "")

        # Osoby towarzyszące gości
        ws["B55"].value  = guest_comp_names.get("A", "")
        ws["K55"].value  = guest_comp_names.get("B", "")
        ws["R55"].value  = guest_comp_names.get("C", "")
        ws["Y55"].value  = guest_comp_names.get("D", "")
        ws["AF55"].value = guest_comp_names.get("E", "")

        # =========================
        # FUNKCJA + LICENCJA osób towarzyszących
        # (wg Twojego mapowania komórek)
        # =========================

        # GOSPODARZE:
        # A: function A30, license A31
        ws["A30"].value  = host_comp_meta.get("A", {}).get("function", "")
        ws["A31"].value  = host_comp_meta.get("A", {}).get("license", "")

        # B: function J30, license J31
        ws["J30"].value  = host_comp_meta.get("B", {}).get("function", "")
        ws["J31"].value  = host_comp_meta.get("B", {}).get("license", "")

        # C: function Q30, license Q31
        ws["Q30"].value  = host_comp_meta.get("C", {}).get("function", "")
        ws["Q31"].value  = host_comp_meta.get("C", {}).get("license", "")

        # D: function X30, license X31
        ws["X30"].value  = host_comp_meta.get("D", {}).get("function", "")
        ws["X31"].value  = host_comp_meta.get("D", {}).get("license", "")

        # E: function AE30, license AE31
        ws["AE30"].value = host_comp_meta.get("E", {}).get("function", "")
        ws["AE31"].value = host_comp_meta.get("E", {}).get("license", "")


        # GOŚCIE:
        # A: function A56, license A57
        ws["A56"].value  = guest_comp_meta.get("A", {}).get("function", "")
        ws["A57"].value  = guest_comp_meta.get("A", {}).get("license", "")

        # B: function J56, license J57
        ws["J56"].value  = guest_comp_meta.get("B", {}).get("function", "")
        ws["J57"].value  = guest_comp_meta.get("B", {}).get("license", "")

        # C: function Q56, license Q57
        ws["Q56"].value  = guest_comp_meta.get("C", {}).get("function", "")
        ws["Q57"].value  = guest_comp_meta.get("C", {}).get("license", "")

        # D: function X56, license X57
        ws["X56"].value  = guest_comp_meta.get("D", {}).get("function", "")
        ws["X57"].value  = guest_comp_meta.get("D", {}).get("license", "")

        # E: function AE56, license AE57
        ws["AE56"].value = guest_comp_meta.get("E", {}).get("function", "")
        ws["AE57"].value = guest_comp_meta.get("E", {}).get("license", "")


        # --- Kary osób towarzyszących (format: U/2'/D - MM:SS) ---

        # HOST A..E (row 31)
        ws["A32"].value  = host_comp_pen.get("A", {}).get("warn", "---")
        ws["D32"].value  = host_comp_pen.get("A", {}).get("p2", "---")
        ws["G32"].value  = host_comp_pen.get("A", {}).get("disq", "---")

        ws["J32"].value  = host_comp_pen.get("B", {}).get("warn", "---")
        ws["L32"].value  = host_comp_pen.get("B", {}).get("p2", "---")
        ws["O32"].value  = host_comp_pen.get("B", {}).get("disq", "---")

        ws["Q32"].value  = host_comp_pen.get("C", {}).get("warn", "---")
        ws["S32"].value  = host_comp_pen.get("C", {}).get("p2", "---")
        ws["V32"].value  = host_comp_pen.get("C", {}).get("disq", "---")

        ws["X32"].value  = host_comp_pen.get("D", {}).get("warn", "---")
        ws["Z32"].value  = host_comp_pen.get("D", {}).get("p2", "---")
        ws["AC32"].value = host_comp_pen.get("D", {}).get("disq", "---")

        ws["AE32"].value = host_comp_pen.get("E", {}).get("warn", "---")
        ws["AH32"].value = host_comp_pen.get("E", {}).get("p2", "---")
        ws["AJ32"].value = host_comp_pen.get("E", {}).get("disq", "---")

        # GUEST A..E (row 56)
        ws["A58"].value  = guest_comp_pen.get("A", {}).get("warn", "---")
        ws["D58"].value  = guest_comp_pen.get("A", {}).get("p2", "---")
        ws["G58"].value  = guest_comp_pen.get("A", {}).get("disq", "---")

        ws["J58"].value  = guest_comp_pen.get("B", {}).get("warn", "---")
        ws["L58"].value  = guest_comp_pen.get("B", {}).get("p2", "---")
        ws["O58"].value  = guest_comp_pen.get("B", {}).get("disq", "---")

        ws["Q58"].value  = guest_comp_pen.get("C", {}).get("warn", "---")
        ws["S58"].value  = guest_comp_pen.get("C", {}).get("p2", "---")
        ws["V58"].value  = guest_comp_pen.get("C", {}).get("disq", "---")

        ws["X58"].value  = guest_comp_pen.get("D", {}).get("warn", "---")
        ws["Z58"].value  = guest_comp_pen.get("D", {}).get("p2", "---")
        ws["AC58"].value = guest_comp_pen.get("D", {}).get("disq", "---")

        ws["AE58"].value = guest_comp_pen.get("E", {}).get("warn", "---")
        ws["AH58"].value = guest_comp_pen.get("E", {}).get("p2", "---")
        ws["AJ58"].value = guest_comp_pen.get("E", {}).get("disq", "---")

        # Sędziowie
        _set_cell_fallback(ws, "I66", core.get("referee1"), OFFICIAL_NAME_FALLBACK)
        _set_cell_fallback(ws, "I67", core.get("referee2"), OFFICIAL_NAME_FALLBACK)
        _set_cell_fallback(ws, "I68", core.get("secretary"), OFFICIAL_NAME_FALLBACK)
        _set_cell_fallback(ws, "I69", core.get("timekeeper"), OFFICIAL_NAME_FALLBACK)
        _set_cell_fallback(ws, "I70", core.get("delegate"), OFFICIAL_NAME_FALLBACK)

        # --- timeline (match events) + optional pages (overflow + shootout) ---
        evs1, evs2 = _extract_timeline_events(data_json)
        needs_timeline_page2 = (len(evs1) > TIMELINE_MAX_ROWS) or (len(evs2) > TIMELINE_MAX_ROWS)

        needs_shootout_page = _shootout_needed(data_json)

        # Tworzymy listę stron (arkuszy) w kolejności: 1, (2 - overflow), (shootout)
        pages = [ws]

        ws2 = None
        if needs_timeline_page2:
            ws2 = wb.copy_worksheet(ws)
            _copy_images_safe(ws, ws2)
            try:
                ws2.title = "Strona 2"
            except Exception:
                pass
            pages.append(ws2)

        ws_shoot = None
        if needs_shootout_page:
            ws_shoot = wb.copy_worksheet(ws)
            _copy_images_safe(ws, ws_shoot)
            try:
                ws_shoot.title = "Rzuty karne"
            except Exception:
                pass
            pages.append(ws_shoot)

        # 1) Ustaw numerację stron STRONA X/N na wszystkich
        total_pages = len(pages)
        if total_pages > 1:
            for i, p in enumerate(pages, start=1):
                p["AQ2"].value = f"STRONA {i}/{total_pages}"
        else:
            ws["AQ2"].value = ""

        # 2) Wypełnij przebieg meczu na stronach 1 oraz (opcjonalnie) 2
        if needs_timeline_page2 and ws2 is not None:
            _fill_timeline_pages(
                ws,
                ws2,
                data_json=data_json,
                half_ms=half_ms,
                half_score_host=core["halfScoreHost"],
                half_score_guest=core["halfScoreGuest"],
            )
        else:
            _fill_timeline_pages(
                ws,
                None,
                data_json=data_json,
                half_ms=half_ms,
                half_score_host=core["halfScoreHost"],
                half_score_guest=core["halfScoreGuest"],
            )

        # 3) Jeśli jest strona karnych – podmień przebieg na "RZUTY KARNE"
        if ws_shoot is not None:
            _fill_shootout_page(ws_shoot, data_json=data_json)


        wb.save(filled_xlsx)

        # --- convert to PDF ---
        pdf_path = _convert_xlsx_to_pdf(filled_xlsx, td)

        # przygotuj plik do pobrania po tokenie
        _cleanup_expired_downloads()
        _ensure_download_dir()

        token = str(uuid.uuid4())
        filename = _safe_filename_from_match_number(core.get("matchNumber") or "mecz")

        # zapisujemy finalny plik w /tmp (nie usuwamy go BackgroundTask od razu)
        download_path = os.path.join(DOWNLOAD_DIR, f"{token}.pdf")
        shutil.copyfile(pdf_path, download_path)

        # sprzątnij roboczy katalog po konwersji (xlsx + profile LO)
        shutil.rmtree(td, ignore_errors=True)

        # zwróć link do pobrania
        return {
            "success": True,
            "token": token,
            "filename": filename,
            "download_url": f"/judge/results/protocol/pdf/download/{token}?filename={filename}",
        }


    except HTTPException:
        raise
    except Exception as e:
        logger.error("generate_protocol_pdf error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Nie udało się wygenerować PDF: {e}")


from fastapi.responses import FileResponse

@router.get(
    "/judge/results/protocol/pdf/download/{token}",
    summary="Pobierz wygenerowany PDF protokołu (attachment)",
)
async def download_protocol_pdf(
    token: str = ApiPath(...),
    filename: str = Query("protokol.pdf"),
):
    _ensure_download_dir()
    file_path = os.path.join(DOWNLOAD_DIR, f"{token}.pdf")
    if not os.path.exists(file_path):
        raise HTTPException(404, "Plik wygasł lub nie istnieje")

    # nagłówki jak w excelu
    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "Cache-Control": "no-store",
    }

    # po pobraniu: możesz sprzątnąć (opcjonalnie)
    # UWAGA: czasem system pobierania może dociągać plik chwilę,
    # ale FileResponse(background=...) sprząta po zakończeniu odpowiedzi.
    return FileResponse(
        path=file_path,
        media_type="application/pdf",
        filename=filename,
        headers=headers,
        background=BackgroundTask(lambda: os.remove(file_path) if os.path.exists(file_path) else None),
    )