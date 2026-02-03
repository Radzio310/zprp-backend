# app/results.py

import base64
import logging
import random
import re
import unicodedata
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlencode

from bs4 import BeautifulSoup
from fastapi import APIRouter, Depends, HTTPException
from httpx import AsyncClient
from pydantic import BaseModel

from cryptography.hazmat.primitives.asymmetric import padding

from app.deps import Settings, get_rsa_keys, get_settings
from app.utils import fetch_with_correct_encoding
from starlette.background import BackgroundTask

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
            disq = bool(ps.get("hasRedCard")) or _truthy(ps.get("disqualification")) or _truthy(ps.get("disqualificationDesc"))

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


def _find_players_table(soup: BeautifulSoup):
    """
    Szukamy tabeli (zwykle zagnieżdżonej) dla zawodników:
    - ma input NrKoszulki2*
    - ma onchange/onclick z zapiszProtok(...)
    """
    for table in soup.find_all("table"):
        if not table.find("input", attrs={"name": re.compile(r"^NrKoszulki2\d+$")}):
            continue
        if table.find(attrs={"onchange": re.compile(r"zapiszProtok\s*\(", re.IGNORECASE)}) or table.find(
            attrs={"onclick": re.compile(r"zapiszProtok\s*\(", re.IGNORECASE)}
        ):
            return table
    return None


def _find_companions_table(soup: BeautifulSoup):
    """
    Tabela osób towarzyszących:
    - ma onclick zapiszProtok4(...)
    - ma nagłówki (Osoba/Funkcja/Kolejność...) w tekście
    """
    for table in soup.find_all("table"):
        if not table.find(attrs={"onclick": re.compile(r"zapiszProtok4\s*\(", re.IGNORECASE)}):
            continue
        txt = _table_text(table).lower()
        if "osoba" in txt and "funkcja" in txt and "kolejność" in txt:
            return table
    return None


def _norm_team_name(s: str) -> str:
    s = (s or "").strip().lower()
    s = unicodedata.normalize("NFKD", s)
    s = "".join(ch for ch in s if not unicodedata.combining(ch))
    s = re.sub(r"[^a-z0-9]+", "", s)
    return s


def _team_from_header_text(header_txt: str, host_name: str, guest_name: str) -> Optional[str]:
    """
    Dopasowanie “contains” (obie strony) – bo czasem dochodzą dopiski.
    Jeśli w tekście są OBIE drużyny (np. pasek "A vs B") -> ignorujemy (None).
    """
    ht = _norm_team_name(header_txt)
    h = _norm_team_name(host_name)
    g = _norm_team_name(guest_name)
    if not ht:
        return None

    has_h = bool(h and (h in ht or ht in h))
    has_g = bool(g and (g in ht or ht in g))

    if has_h and has_g:
        return None
    if has_h:
        return "host"
    if has_g:
        return "guest"
    return None


def _max_colspan_in_tr(tr) -> int:
    mx = 0
    for td in tr.find_all(["td", "th"]):
        try:
            cs = int(td.get("colspan") or 0)
        except Exception:
            cs = 0
        mx = max(mx, cs)
    return mx


def _iter_team_blocks_rows(
    table,
    *,
    host_name: str,
    guest_name: str,
    team_header_min_colspan: int,
) -> List[Tuple[str, Any]]:
    """
    Nowa logika bloków:
    - NIE opieramy się o “bgcolor/style + <b>” jako warunek ogólny.
    - Bierzemy tylko te wiersze nagłówkowe, które:
      (1) zawierają nazwę host lub guest (dokładnie wg _team_from_header_text)
      (2) wyglądają jak prawdziwy nagłówek sekcji w tej tabeli: colspan >= team_header_min_colspan
          (dla zawodników typowo 15, dla companions typowo 10)
    """
    out: List[Tuple[str, Any]] = []
    current_team: Optional[str] = None

    # fallback: jeśli nigdy nie trafimy dopasowania po nazwie (np. nazwy różne),
    # to host=1. header, guest=2. header (ale TYLKO dla headerów z colspan>=min)
    fallback_idx = 0

    for tr in table.find_all("tr"):
        row_txt = _normalize_space(tr.get_text(" ", strip=True))
        if not row_txt:
            continue

        cs = _max_colspan_in_tr(tr)
        if cs >= int(team_header_min_colspan or 0):
            matched = _team_from_header_text(row_txt, host_name, guest_name)
            if matched:
                current_team = matched
                continue

            # fallback tylko wtedy, gdy to wygląda jak “nagłówek drużyny” (duży colspan + zwykle <b>)
            if tr.find("b") and any(ch.isalpha() for ch in row_txt):
                # ale nie łapiemy np. "Osoby towarzyszące:" jako header drużyny,
                # bo tam tekst jest inny (choć w praktyce team header w nested table ma tylko team name).
                if "osoby towarzysz" not in row_txt.lower():
                    fallback_idx += 1
                    current_team = "host" if fallback_idx == 1 else "guest"
                    continue

        if current_team in ("host", "guest"):
            out.append((current_team, tr))

    return out


def _collect_players_inputs(
    soup: BeautifulSoup,
    *,
    host_name: str,
    guest_name: str,
) -> Dict[Tuple[str, str, str], Dict[str, Any]]:
    table = _find_players_table(soup)
    if not table:
        return {}

    result: Dict[Tuple[str, str, str], Dict[str, Any]] = {}

    # blokujemy duplikaty numerów “na serwerze” (w HTML) – bierzemy pierwszy napotkany wiersz na team
    seen_jerseys: Dict[str, set] = {"host": set(), "guest": set()}

    rows = _iter_team_blocks_rows(
        table,
        host_name=host_name,
        guest_name=guest_name,
        team_header_min_colspan=14,  # w praktyce jest 15, dajemy minimalnie 14 dla odporności
    )

    for team, tr in rows:
        jersey_inp = None

        # najpierw szukamy inputu z NrKoszulki2 w tym wierszu (po JS field, nie po name – bo name ma suffix id)
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
            continue
        jersey = str(int(jersey_val))

        # duplikat numeru w HTML: pierwszy wygrywa, resztę ignorujemy
        if jersey in seen_jerseys[team]:
            continue
        seen_jerseys[team].add(jersey)

        # collect pól tego wiersza
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
            # jeśli w HTML jest duplikat inputu (rzadkie, ale bywa) – pierwszy wygrywa
            if key in result:
                continue

            result[key] = {
                "inp": inp,
                "field": field,
                "args4": args4,
            }

    return result


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


def _collect_companion_inputs(
    soup: BeautifulSoup,
    *,
    host_name: str,
    guest_name: str,
) -> Dict[Tuple[str, str, str], Dict[str, Any]]:
    table = _find_companions_table(soup)
    if not table:
        return {}

    letter_col = _find_letter_col_index(table)
    result: Dict[Tuple[str, str, str], Dict[str, Any]] = {}

    rows = _iter_team_blocks_rows(
        table,
        host_name=host_name,
        guest_name=guest_name,
        team_header_min_colspan=9,  # w praktyce jest 10
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
            # duplikat checkboxa w HTML: pierwszy wygrywa
            if key in result:
                continue

            result[key] = {
                "inp": inp,
                "args8": args8,
                "checkbox_value": v,
            }

    return result


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
    # ⬇️ kluczowa zmiana: rozpoznajemy bloki po NAGŁÓWKACH z nazwą drużyny (players + companions)
    players_inputs = _collect_players_inputs(soup, host_name=host_name, guest_name=guest_name)
    comp_inputs = _collect_companion_inputs(soup, host_name=host_name, guest_name=guest_name)

    # --- DEBUG: ile komórek w ogóle wykryliśmy per team/sekcja ---
    players_inputs_host = sum(1 for k in players_inputs.keys() if k[0] == "host")
    players_inputs_guest = sum(1 for k in players_inputs.keys() if k[0] == "guest")
    comp_inputs_host = sum(1 for k in comp_inputs.keys() if k[0] == "host")
    comp_inputs_guest = sum(1 for k in comp_inputs.keys() if k[0] == "guest")

    updated = 0
    skipped = 0
    failed: List[Dict[str, Any]] = []
    missing: List[Dict[str, Any]] = []
    skipped_items: List[Dict[str, Any]] = []

    player_kinds_order = ["goals", "entered", "warn", "p2", "disq", "pk_total", "pk_goals", "so_total", "so_goals"]
    comp_kinds_order = ["warn", "p2", "disq"]

    # ---- players ----
    # Zasada: mapujemy wszystko co umiemy; brak numeru na stronie -> tylko “missing”, ale idziemy dalej.
    for team in ("host", "guest"):
        team_stats = stats_map.get(team) or {}
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
                    # numer z ProEl, którego nie ma w HTML -> skip
                    missing.append({"section": "players", "team": team, "player": jersey, "kind": kind})
                    continue

                inp = meta["inp"]
                args4 = meta["args4"]

                # DELTA: skip if already equal
                if _delta_equal_player(inp, kind, desired):
                    skipped += 1
                    skipped_items.append({"section": "players", "team": team, "player": jersey, "kind": kind})
                    continue

                inp_type = (inp.get("type") or "").lower()
                if inp_type == "checkbox":
                    checked = bool(desired)
                    # for this.value tokens, use element's value (usually "1")
                    value_str = (inp.get("value") or "1").strip()
                else:
                    checked = False
                    if kind in _NUMERIC_KINDS:
                        value_str = _desired_str_for_numeric(int(desired or 0))
                    else:
                        value_str = str(desired)

                ok, resp_txt = await _save_via_zapisz2(client, args4, value_str=value_str, checked=checked)
                if ok:
                    updated += 1
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

    # ---- companions A..E ----
    for team in ("host", "guest"):
        team_stats = stats_map.get(team) or {}
        for key, st in team_stats.items():
            if not re.fullmatch(r"[A-E]", str(key).upper()):
                continue
            letter = str(key).upper()

            for kind in comp_kinds_order:
                desired_checked = _desired_value_for_companion_kind(st, kind)

                meta = comp_inputs.get((team, letter, kind))
                if not meta:
                    missing.append({"section": "companions", "team": team, "player": letter, "kind": kind})
                    continue

                inp = meta["inp"]
                args8 = meta["args8"]
                value_str = (inp.get("value") or "").strip()

                # DELTA: skip if already equal
                if _delta_equal_companion(inp, desired_checked):
                    skipped += 1
                    skipped_items.append({"section": "companions", "team": team, "player": letter, "kind": kind})
                    continue

                ok, resp_txt = await _save_via_zapisz4(client, args8, value_str=value_str, checked=desired_checked)
                if ok:
                    updated += 1
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

    return {
        "updated_cells": updated,
        "skipped_cells": skipped,
        "failed": failed,
        "missing": missing,
        "skipped": skipped_items,
        "debug": {
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