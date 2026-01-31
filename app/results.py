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


# =========================
# Models (existing)
# =========================

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


# =========================
# New model: Protocol save
# =========================

class ProtocolSaveRequest(BaseModel):
    username: str              # Base64-RSA
    password: str              # Base64-RSA
    details_path: str          # np. "a=zawody&b=protokol&Filtr_sezon=...&IdZawody=..."
    data_json: Dict[str, Any]  # cały JSON meczu (jak w przykładzie)


# =========================
# Helpers: crypto + http
# =========================

def _decrypt_field(enc_b64: str, private_key) -> str:
    try:
        cipher = base64.b64decode(enc_b64)
        plain = private_key.decrypt(cipher, padding.PKCS1v15())
        return plain.decode("utf-8")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Błąd deszyfrowania: {e}")


async def _login_and_client(user: str, pwd: str, settings: Settings) -> AsyncClient:
    client = AsyncClient(base_url=settings.ZPRP_BASE_URL, follow_redirects=True)
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


# =========================
# Short result submit (existing)
# =========================

async def _submit_short_result(
    client: AsyncClient,
    match_id: str,
    user: str,
    overrides: Dict[str, str],
) -> bool:
    initial_data = {"IdZawody": match_id, "akcja": "WynikSkrocony", "user": user}
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

    form_fields.update(overrides)

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
    return "Zapisano zmiany" in text


@router.post("/judge/results/short", summary="Zapisz wynik skrócony meczu")
async def short_result(
    req: ShortResultRequest,
    settings: Settings = Depends(get_settings),
    keys=Depends(get_rsa_keys),
):
    private_key, _ = keys
    user_plain = _decrypt_field(req.username, private_key)
    pass_plain = _decrypt_field(req.password, private_key)

    try:
        client = await _login_and_client(user_plain, pass_plain, settings)
        try:
            details_url = _details_path_to_url(req.details_path)
            resp, html = await fetch_with_correct_encoding(
                client,
                details_url,
                method="GET",
                cookies=client.cookies,
            )
            soup = BeautifulSoup(html, "html.parser")

            if not soup.find("button", class_="przycisk3", string="Wynik skrócony"):
                return {"success": False, "error": "Wynik skrócony niedostępny"}

            match_id = _extract_match_id(req.details_path)

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
                "widzowie": req.widzowie or "",
            }

            ok = await _submit_short_result(client, match_id=match_id, user=user_plain, overrides=overrides)
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

# ============================================================
# EXPORT PROTOCOL PDF FROM ProEl data_json -> XLSX TEMPLATE -> PDF
# ============================================================

import os
import math
import shutil
import subprocess
import tempfile
from pathlib import Path

from fastapi.responses import FileResponse
from openpyxl import load_workbook


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
        # Nie wzięto żadnego czasu - wpisujemy "---" w AL10
        ws[h1_cells[0]].value = "---"
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
        # Nie wzięto żadnego czasu w 2. połowie - wpisujemy "---" w AW10
        ws[h2_cells[0]].value = "---"
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


def _fill_players_block(
    ws,
    *,
    players: List[Any],
    stats_by_number: Dict[int, Dict[str, Any]],
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
            ws[f"A{row}"].value = ""
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
        ws[f"Q{row}"].value = "W" if entered else "-"
        ws[f"S{row}"].value = goals if goals > 0 else "-"
        ws[f"U{row}"].value = str(warning).strip() if isinstance(warning, str) and warning.strip() else "-"

        ws[f"W{row}"].value = penalty1 if penalty1 else "---"
        ws[f"Z{row}"].value = penalty2 if penalty2 else "---"
        ws[f"AC{row}"].value = penalty3 if penalty3 else "---"

        if disq_time or disq_desc or has_red:
            if disq_time and disq_desc:
                ws[f"AF{row}"].value = f"{disq_time} {disq_desc}"
            elif disq_time:
                ws[f"AF{row}"].value = disq_time
            elif disq_desc:
                ws[f"AF{row}"].value = disq_desc
            else:
                ws[f"AF{row}"].value = "D"
        else:
            ws[f"AF{row}"].value = "---"


def _fill_timeline(
    ws,
    *,
    data_json: Dict[str, Any],
    half_ms: int,
    half_score_host: int,
    half_score_guest: int,
) -> None:
    """
    Przebieg meczu:
    - zapisujemy minutę jako liczba (floor(ms/60000)+1)
    - wiersze 15..61
    - połowa 1: AL (min), AN (host player/host action), AP (host score), AS (guest score)
    - połowa 2: AW (min), AY (host action), BA (host score), BD (guest score), BF (guest action)
    """
    prot = data_json.get("protocol") or []
    evs1 = []
    evs2 = []

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

    # sort po czasie rosnąco
    def _ev_ms(e):
        return _safe_int(e.get("time") or 0, 0)

    evs1.sort(key=_ev_ms)
    evs2.sort(key=_ev_ms)

    # ---- half 1 ----
    h_score = 0
    g_score = 0
    row = 15
    for ev in evs1:
        if row > 61:
            break
        ms = _ev_ms(ev)
        minute = _event_minute_from_ms(ms)

        team = ev.get("team")
        player = ev.get("player")
        t = ev.get("type")

        ws[f"AL{row}"].value = str(minute)

        # akcje w 1. połowie:
        # - gospodarz -> kolumna AN
        # - gość     -> kolumna AU
        host_action = ""
        guest_action = ""

        if player is not None:
            ptxt = str(player).strip()
            if t.startswith("penaltyKick"):
                ptxt = f"{ptxt}K"

            if team == "host":
                host_action = ptxt
            elif team == "guest":
                guest_action = ptxt

        # Dodajemy logikę, aby puste wartości były zastępowane "--"
        ws[f"AN{row}"].value = host_action if host_action else "--"
        ws[f"AU{row}"].value = guest_action if guest_action else "--"

        if t == "goal" or t == "penaltyKickScored":
            if team == "host":
                h_score += 1
            elif team == "guest":
                g_score += 1
            ws[f"AP{row}"].value = str(h_score)
            ws[f"AS{row}"].value = str(g_score)
        else:
            # penaltyKickMissed -> "--" / "--"
            ws[f"AP{row}"].value = "--"
            ws[f"AS{row}"].value = "--"

        row += 1

    # ---- half 2 ----
    h_score = _safe_int(half_score_host, 0)
    g_score = _safe_int(half_score_guest, 0)
    row = 15
    for ev in evs2:
        if row > 61:
            break
        ms = _ev_ms(ev)
        minute = _event_minute_from_ms(ms)

        team = ev.get("team")
        player = ev.get("player")
        t = ev.get("type")

        ws[f"AW{row}"].value = str(minute)

        # akcje w 2. połowie:
        # - gospodarz -> kolumna AY
        # - gość     -> kolumna BF
        host_action = ""
        guest_action = ""

        if player is not None:
            ptxt = str(player).strip()
            if t.startswith("penaltyKick"):
                ptxt = f"{ptxt}K"

            if team == "host":
                host_action = ptxt
            elif team == "guest":
                guest_action = ptxt

        # Dodajemy logikę, aby puste wartości były zastępowane "--"
        ws[f"AY{row}"].value = host_action if host_action else "--"
        ws[f"BF{row}"].value = guest_action if guest_action else "--"

        if t == "goal" or t == "penaltyKickScored":
            if team == "host":
                h_score += 1
            elif team == "guest":
                g_score += 1
            ws[f"BA{row}"].value = str(h_score)
            ws[f"BD{row}"].value = str(g_score)
        else:
            # penaltyKickMissed -> "--" / "--"
            ws[f"BA{row}"].value = "--"
            ws[f"BD{row}"].value = "--"

        row += 1


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
    template_path = Path(__file__).resolve().parent / "templates" / "protocol_template.xlsx"
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

    # winner
    winner = ""
    if core["scoreHost"] > core["scoreGuest"]:
        winner = "A"
    elif core["scoreGuest"] > core["scoreHost"]:
        winner = "B"

    try:
        td = tempfile.mkdtemp(prefix="protocol_")  # ✅ nie usuwa się samo
        safe_code = re.sub(r"[^0-9A-Za-z_-]+", "_", (core.get("matchNumber") or "mecz"))
        filled_xlsx = os.path.join(td, f"protocol_{safe_code}.xlsx")

        wb = load_workbook(str(template_path))
        ws = wb.active  # jeśli masz konkretny arkusz, zmień na wb["NazwaArkusza"]

        # --- header mapping ---
        ws["AY1"].value = core["matchNumber"]
        ws["C4"].value = core["hostName"]
        ws["D9"].value = core["hostName"]
        ws["C7"].value = core["guestName"]
        ws["D34"].value = core["guestName"]

        ws["AL6"].value = str(core["scoreHost"])
        ws["AQ6"].value = str(core["scoreGuest"])
        ws["AU6"].value = str(core["halfScoreHost"])
        ws["AY6"].value = str(core["halfScoreGuest"])
        ws["BB6"].value = winner

        # --- timeouts mapping ---
        _place_timeouts(ws, team_timeouts=tt_host, half_ms=half_ms, is_host=True)
        _place_timeouts(ws, team_timeouts=tt_guest, half_ms=half_ms, is_host=False)

        # --- penalties totals ---
        ws["AN63"].value = str(pk_host_total)
        ws["AR63"].value = str(pk_host_goals)
        ws["AY63"].value = str(pk_guest_total)
        ws["BC63"].value = str(pk_guest_goals)

        # --- players numbers + stats ---
        _fill_players_block(ws, players=core["hostPlayers"],  stats_by_number=host_stats,  start_row=11, end_row=28)
        _fill_players_block(ws, players=core["guestPlayers"], stats_by_number=guest_stats, start_row=36, end_row=53)

        # --- timeline (match events) ---
        _fill_timeline(
            ws,
            data_json=data_json,
            half_ms=half_ms,
            half_score_host=core["halfScoreHost"],
            half_score_guest=core["halfScoreGuest"],
        )

        wb.save(filled_xlsx)

        # --- convert to PDF ---
        pdf_path = _convert_xlsx_to_pdf(filled_xlsx, td)

        filename = f"protokol_{(core['matchNumber'] or 'mecz').replace('/', '-')}.pdf"
        return FileResponse(
            pdf_path,
            media_type="application/pdf",
            filename=filename,
            background=BackgroundTask(shutil.rmtree, td, ignore_errors=True),  # ✅ sprząta PO wysłaniu
        )


    except HTTPException:
        raise
    except Exception as e:
        logger.error("generate_protocol_pdf error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Nie udało się wygenerować PDF: {e}")
