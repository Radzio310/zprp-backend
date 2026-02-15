# app/zprp/schedule.py
from __future__ import annotations

import base64
import datetime
import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode

from bs4 import BeautifulSoup
from cryptography.hazmat.primitives.asymmetric import padding
from fastapi import APIRouter, Depends, HTTPException
from httpx import AsyncClient

from app.deps import Settings, get_settings, get_rsa_keys
from app.utils import fetch_with_correct_encoding
from app.schemas import ZprpScheduleScrapeRequest  # <- dodasz (opis niżej)

router = APIRouter()

# =========================
# Logger (Railway -> stdout)
# =========================
logger = logging.getLogger("app.zprp.schedule")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s [%(name)s] %(message)s"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

# =========================
# Regex / helpers
# =========================

_RE_INT = re.compile(r"(\d+)")
_RE_SCORE = re.compile(r"(\d+)\s*:\s*(\d+)")
_RE_HALF = re.compile(r"\(\s*(\d+)\s*:\s*(\d+)\s*\)")
_RE_PENS = re.compile(r"<\s*(\d+)\s*:\s*(\d+)\s*>")
_RE_DATE = re.compile(r"(\d{2})\.(\d{2})\.(\d{4})")
_RE_TIME = re.compile(r"\(\s*(\d{2}:\d{2})\s*\)")


def _now_iso() -> str:
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _clean_spaces(s: str) -> str:
    return re.sub(r"\s+", " ", s or "").strip()


def _safe_int(s: str, default: int = 0) -> int:
    if not s:
        return default
    m = _RE_INT.search(s)
    return int(m.group(1)) if m else default


def _text_lines(el) -> List[str]:
    if not el:
        return []
    raw = el.get_text("\n", strip=True)
    out: List[str] = []
    for ln in raw.split("\n"):
        ln2 = _clean_spaces(ln)
        if ln2:
            out.append(ln2)
    return out


def _looks_like_name(line: str) -> bool:
    if not line:
        return False
    low = line.lower()
    if "@" in line:
        return False
    if any(
        k in low
        for k in [
            "ustaw sędz",
            "ustaw sedz",
            "hala",
            "zapisz",
            "ukryj",
            "pokaż",
            "checkbox",
            "filtr",
        ]
    ):
        return False
    if re.search(r"\d{2,}", line):
        return False
    if " " not in line.strip():
        return False
    if not re.search(r"[A-Za-zĄĆĘŁŃÓŚŹŻąćęłńóśźż]", line):
        return False
    return True


def _parse_iso_datetime_from_td(td) -> str:
    if not td:
        return ""
    b = td.find("b")
    date_str = _clean_spaces(b.get_text(strip=True)) if b else ""
    if not date_str:
        txt = td.get_text(" ", strip=True)
        m = _RE_DATE.search(txt)
        date_str = m.group(0) if m else ""
    if not date_str:
        return ""
    txt2 = td.get_text(" ", strip=True)
    mtime = _RE_TIME.search(txt2)
    hhmm = mtime.group(1) if mtime else "00:00"
    m = _RE_DATE.search(date_str)
    if not m:
        return ""
    dd, mm, yyyy = m.group(1), m.group(2), m.group(3)
    return f"{yyyy}-{mm}-{dd} {hhmm}:00"


def _parse_hall(td) -> Dict[str, Any]:
    out = {
        "Hala_nazwa": "",
        "Hala_miasto": "",
        "Hala_ulica": "",
        "Hala_numer": "",
        "hala_pojemnosc": 0,
    }
    if not td:
        return out

    a = td.find("a", href=re.compile(r"maps", re.I))
    title = _clean_spaces(a.get("title", "")) if a else ""
    if title:
        parts = [_clean_spaces(p) for p in title.split(",") if _clean_spaces(p)]
        if len(parts) >= 3:
            out["Hala_nazwa"] = parts[0]
            out["Hala_miasto"] = parts[1]
            street = ", ".join(parts[2:])
            m = re.search(r"^(.*?)(\d+[A-Za-z]?)$", _clean_spaces(street))
            if m:
                out["Hala_ulica"] = _clean_spaces(m.group(1))
                out["Hala_numer"] = _clean_spaces(m.group(2))
            else:
                out["Hala_ulica"] = _clean_spaces(street)
        elif len(parts) == 2:
            out["Hala_nazwa"] = parts[0]
            out["Hala_miasto"] = parts[1]

    lines = _text_lines(td)
    cap = 0
    for ln in reversed(lines):
        if re.fullmatch(r"\d+", ln):
            cap = int(ln)
            break
    out["hala_pojemnosc"] = cap
    return out


def _parse_attendance(td) -> Dict[str, Any]:
    out = {"widzowie": 0, "widzowie_pct": None}
    if not td:
        return out
    txt = td.get_text(" ", strip=True)
    m = _RE_INT.search(txt)
    out["widzowie"] = int(m.group(1)) if m else 0
    mp = re.search(r"\(\s*(\d+)\s*%\s*\)", txt)
    out["widzowie_pct"] = int(mp.group(1)) if mp else None
    return out


def _parse_result(td) -> Dict[str, Any]:
    out = {
        "wynik_gosp_full": "",
        "wynik_gosc_full": "",
        "wynik_gosp_pol": "",
        "wynik_gosc_pol": "",
        "dogrywka_karne_gosp": None,
        "dogrywka_karne_gosc": None,
        "host_swapped": False,
    }
    if not td:
        return out

    if td.find("img", src=re.compile(r"zmiana\.png", re.I)):
        out["host_swapped"] = True

    txt = _clean_spaces(td.get_text(" ", strip=True))

    m = _RE_SCORE.search(txt)
    if m:
        out["wynik_gosp_full"] = m.group(1)
        out["wynik_gosc_full"] = m.group(2)

    mh = _RE_HALF.search(txt)
    if mh:
        out["wynik_gosp_pol"] = mh.group(1)
        out["wynik_gosc_pol"] = mh.group(2)

    mp = _RE_PENS.search(txt)
    if mp:
        out["dogrywka_karne_gosp"] = int(mp.group(1))
        out["dogrywka_karne_gosc"] = int(mp.group(2))

    return out


def _extract_idzawody_from_tr(tr) -> str:
    """
    Zwraca string z IdZawody jeśli uda się znaleźć, w przeciwnym razie "".
    """
    if not tr:
        return ""

    # 1) hidden input name="IdZawody"
    inp = tr.find("input", attrs={"name": "IdZawody"})
    if inp and inp.get("value"):
        return str(inp.get("value")).strip()

    # 2) regex po HTML
    html = str(tr)
    m = re.search(r'name=["\']IdZawody["\']\s+value=["\'](\d+)["\']', html, re.I)
    if m:
        return m.group(1)

    # 3) JS fallback: zapiszProtok3(191386,...)
    m2 = re.search(r"zapiszProtok3\(\s*(\d+)\s*,", html, re.I)
    if m2:
        return m2.group(1)

    return ""


def _parse_officials(td) -> Dict[str, str]:
    out = {
        "NrSedzia_pierwszy_nazwisko": "",
        "NrSedzia_drugi_nazwisko": "",
        "NrSedzia_delegat_nazwisko": "",
        "NrSedzia_sekretarz_nazwisko": "",
        "NrSedzia_czas_nazwisko": "",
    }
    if not td:
        return out

    lines = _text_lines(td)

    noise_prefixes = (
        "e-mail",
        "tel.",
        "tel:",
        "telefon",
        "kom.",
        "kom:",
        "mail",
        "www",
        "ukryj obsadę",
        "pokaż obsadę",
        "ustaw sędziów",
        "ustaw sedziow",
        "ustaw halę",
        "ustaw hale",
        "zapisz",
        "usuń",
        "usun",
    )

    clean_lines: List[str] = []
    for ln in lines:
        low = ln.lower()
        if any(low.startswith(p) for p in noise_prefixes):
            continue
        if "@" in ln:
            continue
        if re.fullmatch(r"[\+\d\-\s\(\)\/\.]{6,}", ln):
            continue
        clean_lines.append(ln)

    name_lines = [ln for ln in clean_lines if _looks_like_name(ln)]
    if name_lines:
        out["NrSedzia_pierwszy_nazwisko"] = name_lines[0]
    if len(name_lines) >= 2:
        out["NrSedzia_drugi_nazwisko"] = name_lines[1]

    def find_after_label(label_regex: str) -> str:
        for i, ln in enumerate(clean_lines):
            if re.search(label_regex, ln, re.I):
                for j in range(i + 1, min(i + 6, len(clean_lines))):
                    if _looks_like_name(clean_lines[j]):
                        return clean_lines[j]
        return ""

    out["NrSedzia_delegat_nazwisko"] = find_after_label(r"\bdelegat\b")
    out["NrSedzia_sekretarz_nazwisko"] = find_after_label(r"\bsekretarz\b")
    out["NrSedzia_czas_nazwisko"] = find_after_label(r"\bczas\b|\bmierz")
    return out


def _log_match_parse_info(
    *,
    match_obj: Dict[str, Any],
    parse_meta: Dict[str, Any],
    idx: int,
) -> None:
    """
    Loguje na INFO pełny snapshot meczu + jak został zparsowany.
    """
    payload = {
        "idx": idx,
        "match": match_obj,
        "parsed_from": parse_meta,
    }
    logger.info("ZPRP terminarz: parsed_match=%s", json.dumps(payload, ensure_ascii=False))


def _parse_matches_table(html: str) -> Dict[str, Dict[str, Any]]:
    soup = BeautifulSoup(html, "html.parser")
    out: Dict[str, Dict[str, Any]] = {}
    trs = soup.find_all("tr")
    synth_i = 0

    # debug: loguj maks 5 pierwszych pełnych meczów na wywołanie parsera
    debug_logged = 0
    DEBUG_LIMIT = 5

    for tr in trs:
        tds = tr.find_all("td", recursive=False)
        if not tds or len(tds) < 11:
            continue
        if any(td.has_attr("colspan") for td in tds):
            continue

        td_lp = tds[0]
        td_season = tds[1]
        td_kolejka = tds[2]
        td_code = tds[3]
        td_date = tds[4]
        td_hall = tds[5]
        td_att = tds[6]
        td_host = tds[7]
        td_res = tds[8]
        td_guest = tds[9]
        td_off = tds[10]

        lp_raw = td_lp.get_text(" ", strip=True)
        season_raw = td_season.get_text(" ", strip=True)
        code_raw = td_code.get_text(" ", strip=True)
        host_raw = td_host.get_text(" ", strip=True)
        guest_raw = td_guest.get_text(" ", strip=True)
        kolejka_raw = td_kolejka.get_text(" ", strip=True)
        date_td_raw = td_date.get_text(" ", strip=True)
        hall_td_raw = td_hall.get_text(" ", strip=True)
        att_td_raw = td_att.get_text(" ", strip=True)
        res_td_raw = td_res.get_text(" ", strip=True)
        off_td_raw = td_off.get_text(" ", strip=True)

        lp = _safe_int(lp_raw, 0)
        season_label = _clean_spaces(season_raw)
        code = _clean_spaces(code_raw)

        host_name = _clean_spaces(host_raw)
        guest_name = _clean_spaces(guest_raw)

        data_fakt = _parse_iso_datetime_from_td(td_date)

        hall = _parse_hall(td_hall)
        att = _parse_attendance(td_att)
        res = _parse_result(td_res)
        off = _parse_officials(td_off)

        kolejka_txt = _clean_spaces(kolejka_raw)
        m_kno = re.search(r"Kolejka\s+(\d+)", kolejka_txt, re.I)
        kolejka_no = int(m_kno.group(1)) if m_kno else None
        m_rng = re.search(r"\(\s*([^)]+)\s*\)", kolejka_txt)
        kolejka_range = _clean_spaces(m_rng.group(1)) if m_rng else ""

        # --- KLUCZOWA ZMIANA: rozdzielamy Id (unikalne) i IdZawody (numeryczne / None)
        idzawody_str = _extract_idzawody_from_tr(tr)
        if idzawody_str and re.fullmatch(r"\d+", idzawody_str):
            match_id = idzawody_str
            idzawody: Optional[str] = idzawody_str
            id_source = "IdZawody_from_dom"
        else:
            synth_i += 1
            match_id = f"synthetic:{season_label}:{code}:{lp}:{synth_i}"
            idzawody = None
            id_source = "synthetic_fallback"
        # ---

        match_obj: Dict[str, Any] = {
            "Id": match_id,
            "IdZawody": idzawody,
            "Lp": lp,
            "RozgrywkiCode": code,
            "season": season_label,
            "data_fakt": data_fakt,
            "runda": "",
            "kolejka": kolejka_range,
            "kolejka_no": kolejka_no,
            "ID_zespoly_gosp_ZespolNazwa": host_name,
            "ID_zespoly_gosc_ZespolNazwa": guest_name,
            "Hala_miasto": hall["Hala_miasto"],
            "Hala_nazwa": hall["Hala_nazwa"],
            "Hala_ulica": hall["Hala_ulica"],
            "Hala_numer": hall["Hala_numer"],
            "hala_pojemnosc": hall["hala_pojemnosc"],
            "widzowie": att["widzowie"],
            "widzowie_pct": att["widzowie_pct"],
            "wynik_gosp_full": res["wynik_gosp_full"],
            "wynik_gosc_full": res["wynik_gosc_full"],
            "wynik_gosp_pol": res["wynik_gosp_pol"],
            "wynik_gosc_pol": res["wynik_gosc_pol"],
            "dogrywka_karne_gosp": res["dogrywka_karne_gosp"],
            "dogrywka_karne_gosc": res["dogrywka_karne_gosc"],
            "host_swapped": res["host_swapped"],
            **off,
            # kompatybilność z Twoim JSON-em:
            "matchLink": "",
            "protocol_link": "",
            "protocol_status": "",
            "delegate_note": "",
            "fee": "",
        }

        out[match_id] = match_obj

        # =========================
        # DEBUG LOG: pierwsze 5 meczów z każdego parsowania tabeli
        # =========================
        if debug_logged < DEBUG_LIMIT:
            # Meta: co wczytaliśmy i jak
            parse_meta = {
                "id_source": id_source,
                "idzawody_extracted": idzawody_str or None,
                "raw_cells": {
                    "lp": _clean_spaces(lp_raw),
                    "season": _clean_spaces(season_raw),
                    "kolejka": _clean_spaces(kolejka_raw),
                    "code": _clean_spaces(code_raw),
                    "date_td_text": _clean_spaces(date_td_raw),
                    "hall_td_text": _clean_spaces(hall_td_raw),
                    "attendance_td_text": _clean_spaces(att_td_raw),
                    "host": _clean_spaces(host_raw),
                    "result_td_text": _clean_spaces(res_td_raw),
                    "guest": _clean_spaces(guest_raw),
                    "officials_td_text": _clean_spaces(off_td_raw),
                },
                "derived": {
                    "data_fakt": data_fakt,
                    "kolejka_no": kolejka_no,
                    "kolejka_range": kolejka_range,
                    "hall_parsed": hall,
                    "attendance_parsed": att,
                    "result_parsed": res,
                    "officials_parsed": off,
                },
            }

            _log_match_parse_info(match_obj=match_obj, parse_meta=parse_meta, idx=debug_logged + 1)
            debug_logged += 1

    return out


def _parse_select_options(sel) -> List[Tuple[str, str, bool]]:
    out: List[Tuple[str, str, bool]] = []
    if not sel:
        return out
    for opt in sel.find_all("option"):
        val = _clean_spaces(opt.get("value", ""))
        lab = _clean_spaces(opt.get_text(strip=True))
        if not lab and not val:
            continue
        out.append((val, lab, bool(opt.has_attr("selected"))))
    return out


def _detect_sex_from_kategoria_value(val: str, label: str) -> str:
    m = re.search(r"\|\s*([KM])\s*$", val or "", re.I)
    if m:
        return m.group(1).upper()
    low = (label or "").lower()
    if "kobiet" in low:
        return "K"
    if "mężczy" in low or "mezczy" in low:
        return "M"
    return ""


def _pick_season_id(
    seasons: List[Tuple[str, str, bool]],
    requested: Optional[str],
) -> str:
    picked = _clean_spaces(requested or "")
    if picked:
        if any(v == picked for (v, _, _) in seasons):
            return picked
        raise HTTPException(400, f"Nieprawidłowy season_id: {picked}")

    picked = (
        next((v for (v, _, sel) in seasons if sel and v), None)
        or next((v for (v, _, _) in seasons if v), None)
    )
    if not picked:
        raise HTTPException(500, "Nie udało się ustalić Filtr_sezon.")
    return picked


# =========================
# Auth helpers (RSA decrypt + login)
# =========================

def _decrypt_field(private_key, enc_b64: str) -> str:
    cipher = base64.b64decode(enc_b64)
    plain = private_key.decrypt(cipher, padding.PKCS1v15())
    return plain.decode("utf-8")


async def _login_zprp_and_get_cookies(
    client: AsyncClient,
    username: str,
    password: str,
) -> Dict[str, str]:
    resp_login, _ = await fetch_with_correct_encoding(
        client,
        "/login.php",
        method="POST",
        data={
            "login": username,
            "haslo": password,
            "from": "/index.php?",
        },
    )
    if "/index.php" not in resp_login.url.path:
        raise HTTPException(401, "Logowanie nie powiodło się")
    return dict(resp_login.cookies)


@router.post("/zprp/terminarz/meta")
async def get_terminarz_meta(
    payload: ZprpScheduleScrapeRequest,
    settings: Settings = Depends(get_settings),
    keys=Depends(get_rsa_keys),
):
    """
    Zwraca:
    - dostępne sezony
    - kategorie (Filtr_kategoria)
    - rozgrywki (IdRozgr) dla kategorii
    Opcjonalnie ogranicza się do:
    - payload.season_id
    - payload.filtr_kategoria (tylko jedna kategoria)
    """
    private_key, _ = keys

    try:
        user_plain = _decrypt_field(private_key, payload.username)
        pass_plain = _decrypt_field(private_key, payload.password)
    except Exception as e:
        raise HTTPException(400, f"Decryption error: {e}")

    async with AsyncClient(
        base_url=settings.ZPRP_BASE_URL,
        follow_redirects=True,
        timeout=60.0,
    ) as client:
        cookies = await _login_zprp_and_get_cookies(client, user_plain, pass_plain)

        _, html0 = await fetch_with_correct_encoding(
            client,
            "/index.php?a=terminarz",
            method="GET",
            cookies=cookies,
        )
        soup0 = BeautifulSoup(html0, "html.parser")

        sel_season = soup0.find("select", attrs={"name": "Filtr_sezon"})
        seasons = _parse_select_options(sel_season)
        if not seasons:
            raise HTTPException(500, "Nie znaleziono listy sezonów (Filtr_sezon).")

        picked_season = _pick_season_id(seasons, payload.season_id)

        sel_cat = soup0.find("select", attrs={"name": "Filtr_kategoria"})
        cats0 = _parse_select_options(sel_cat)
        cats_all = [(v, lab, sel) for (v, lab, sel) in cats0 if v and v != "0"]
        if not cats_all:
            raise HTTPException(500, "Nie znaleziono kategorii (Filtr_kategoria).")

        if payload.filtr_kategoria:
            cat_req = _clean_spaces(payload.filtr_kategoria)
            if not any(v == cat_req for (v, _, _) in cats_all):
                raise HTTPException(400, f"Nieprawidłowy filtr_kategoria: {cat_req}")
            cats = [(v, lab, sel) for (v, lab, sel) in cats_all if v == cat_req]
        else:
            cats = cats_all

        out: Dict[str, Any] = {
            "fetched_at": _now_iso(),
            "base_url": settings.ZPRP_BASE_URL,
            "Filtr_sezon": picked_season,
            "seasons_available": [
                {"value": v, "label": lab, "selected": sel} for (v, lab, sel) in seasons
            ],
            "categories": [],
        }

        for (cat_val, cat_label, cat_sel) in cats:
            sex = _detect_sex_from_kategoria_value(cat_val, cat_label)

            qs = {
                "a": "terminarz",
                "Filtr_sezon": picked_season,
                "Filtr_kategoria": cat_val,
                "IdRundy": "ALL",
            }
            path_cat = "/index.php?" + urlencode(qs, doseq=True)

            _, html_cat = await fetch_with_correct_encoding(
                client,
                path_cat,
                method="GET",
                cookies=cookies,
            )
            soup_cat = BeautifulSoup(html_cat, "html.parser")

            sel_rozgr = soup_cat.find("select", attrs={"name": "IdRozgr"})
            rozgr_opts0 = _parse_select_options(sel_rozgr)
            rozgr_opts = [(v, lab, sel) for (v, lab, sel) in rozgr_opts0 if v and v != "0"]

            out["categories"].append(
                {
                    "Filtr_kategoria": cat_val,
                    "label": cat_label,
                    "selected": cat_sel,
                    "sex": sex,
                    "competitions": [
                        {"IdRozgr": v, "label": lab, "selected": sel}
                        for (v, lab, sel) in rozgr_opts
                    ],
                    "competitions_count": len(rozgr_opts),
                }
            )

        return out


@router.post("/zprp/terminarz/scrape")
async def scrape_terminarz_full(
    payload: ZprpScheduleScrapeRequest,
    settings: Settings = Depends(get_settings),
    keys=Depends(get_rsa_keys),
):
    """
    - payload.username/password: RSA+base64 jak w edit_judge
    - payload.season_id: opcjonalne
    - backend sam loguje się do ZPRP i buduje pełny wynik
    """
    private_key, _ = keys

    try:
        user_plain = _decrypt_field(private_key, payload.username)
        pass_plain = _decrypt_field(private_key, payload.password)
    except Exception as e:
        raise HTTPException(400, f"Decryption error: {e}")

    async with AsyncClient(
        base_url=settings.ZPRP_BASE_URL,
        follow_redirects=True,
        timeout=60.0,
    ) as client:
        cookies = await _login_zprp_and_get_cookies(client, user_plain, pass_plain)

        _, html0 = await fetch_with_correct_encoding(
            client,
            "/index.php?a=terminarz",
            method="GET",
            cookies=cookies,
        )
        soup0 = BeautifulSoup(html0, "html.parser")

        sel_season = soup0.find("select", attrs={"name": "Filtr_sezon"})
        seasons = _parse_select_options(sel_season)
        if not seasons:
            raise HTTPException(500, "Nie znaleziono listy sezonów (Filtr_sezon).")

        picked_season = _clean_spaces(payload.season_id or "")
        if not picked_season:
            picked_season = (
                next((v for (v, _, sel) in seasons if sel and v), None)
                or next((v for (v, _, _) in seasons if v), None)
            )
        if not picked_season:
            raise HTTPException(500, "Nie udało się ustalić Filtr_sezon.")

        sel_cat = soup0.find("select", attrs={"name": "Filtr_kategoria"})
        cats0 = _parse_select_options(sel_cat)
        cats = [(v, lab, sel) for (v, lab, sel) in cats0 if v and v != "0"]
        if not cats:
            raise HTTPException(500, "Nie znaleziono kategorii (Filtr_kategoria).")

        result: Dict[str, Any] = {
            "fetched_at": _now_iso(),
            "base_url": settings.ZPRP_BASE_URL,
            "Filtr_sezon": picked_season,
            "seasons_available": [
                {"value": v, "label": lab, "selected": sel} for (v, lab, sel) in seasons
            ],
            "categories": [],
            "by_sex": {"K": [], "M": [], "": []},
        }

        for (cat_val, cat_label, _) in cats:
            sex = _detect_sex_from_kategoria_value(cat_val, cat_label)

            qs = {
                "a": "terminarz",
                "Filtr_sezon": picked_season,
                "Filtr_kategoria": cat_val,
                "IdRundy": "ALL",
            }
            path_cat = "/index.php?" + urlencode(qs, doseq=True)

            _, html_cat = await fetch_with_correct_encoding(
                client,
                path_cat,
                method="GET",
                cookies=cookies,
            )
            soup_cat = BeautifulSoup(html_cat, "html.parser")

            sel_rozgr = soup_cat.find("select", attrs={"name": "IdRozgr"})
            rozgr_opts0 = _parse_select_options(sel_rozgr)
            rozgr_opts = [(v, lab, sel) for (v, lab, sel) in rozgr_opts0 if v and v != "0"]

            cat_obj: Dict[str, Any] = {
                "Filtr_kategoria": cat_val,
                "label": cat_label,
                "sex": sex,
                "competitions": [],
            }

            for (rozgr_val, rozgr_label, _) in rozgr_opts:
                qs2 = {
                    "a": "terminarz",
                    "Filtr_sezon": picked_season,
                    "Filtr_kategoria": cat_val,
                    "IdRozgr": rozgr_val,
                    "IdRundy": "ALL",
                }
                path = "/index.php?" + urlencode(qs2, doseq=True)

                _, html = await fetch_with_correct_encoding(
                    client,
                    path,
                    method="GET",
                    cookies=cookies,
                )

                matches_map = _parse_matches_table(html)

                cat_obj["competitions"].append(
                    {
                        "IdRozgr": rozgr_val,
                        "label": rozgr_label,
                        "url": path,
                        "matches": matches_map,
                        "count": len(matches_map),
                    }
                )

            cat_obj["competitions_count"] = len(cat_obj["competitions"])
            cat_obj["matches_count"] = sum(int(c.get("count", 0)) for c in cat_obj["competitions"])

            result["categories"].append(cat_obj)
            result["by_sex"].setdefault(sex, []).append(cat_obj)

        result["summary"] = {
            "categories": len(result["categories"]),
            "competitions": sum(int(c.get("competitions_count", 0)) for c in result["categories"]),
            "matches": sum(int(c.get("matches_count", 0)) for c in result["categories"]),
        }

        return result


@router.post("/zprp/terminarz/scrape_slim")
async def scrape_terminarz_slim(
    payload: ZprpScheduleScrapeRequest,
    settings: Settings = Depends(get_settings),
    keys=Depends(get_rsa_keys),
):
    """
    Pobiera OSZCZĘDNIE:
    - jeśli payload.id_rozgr podane -> tylko jedna rozgrywka (IdRozgr) w danej kategorii
    - jeśli payload.filtr_kategoria podane -> cała kategoria (wszystkie rozgrywki w niej)
    W obu przypadkach: IdRundy=ALL.
    Wymagane:
    - filtr_kategoria musi być podane zawsze (bo IdRozgr bez kategorii nie jest stabilne na tej stronie)
    """
    private_key, _ = keys

    try:
        user_plain = _decrypt_field(private_key, payload.username)
        pass_plain = _decrypt_field(private_key, payload.password)
    except Exception as e:
        raise HTTPException(400, f"Decryption error: {e}")

    cat_val = _clean_spaces(payload.filtr_kategoria or "")
    if not cat_val:
        raise HTTPException(400, "Wymagane: payload.filtr_kategoria (np. '1|M').")

    async with AsyncClient(
        base_url=settings.ZPRP_BASE_URL,
        follow_redirects=True,
        timeout=60.0,
    ) as client:
        cookies = await _login_zprp_and_get_cookies(client, user_plain, pass_plain)

        _, html0 = await fetch_with_correct_encoding(
            client,
            "/index.php?a=terminarz",
            method="GET",
            cookies=cookies,
        )
        soup0 = BeautifulSoup(html0, "html.parser")

        sel_season = soup0.find("select", attrs={"name": "Filtr_sezon"})
        seasons = _parse_select_options(sel_season)
        if not seasons:
            raise HTTPException(500, "Nie znaleziono listy sezonów (Filtr_sezon).")
        picked_season = _pick_season_id(seasons, payload.season_id)

        sel_cat = soup0.find("select", attrs={"name": "Filtr_kategoria"})
        cats0 = _parse_select_options(sel_cat)
        cats_all = [(v, lab, sel) for (v, lab, sel) in cats0 if v and v != "0"]
        if not any(v == cat_val for (v, _, _) in cats_all):
            raise HTTPException(400, f"Nieprawidłowy filtr_kategoria: {cat_val}")

        cat_label = next((lab for (v, lab, _) in cats_all if v == cat_val), "")
        sex = _detect_sex_from_kategoria_value(cat_val, cat_label)

        qs_cat = {
            "a": "terminarz",
            "Filtr_sezon": picked_season,
            "Filtr_kategoria": cat_val,
            "IdRundy": "ALL",
        }
        path_cat = "/index.php?" + urlencode(qs_cat, doseq=True)

        _, html_cat = await fetch_with_correct_encoding(
            client,
            path_cat,
            method="GET",
            cookies=cookies,
        )
        soup_cat = BeautifulSoup(html_cat, "html.parser")

        sel_rozgr = soup_cat.find("select", attrs={"name": "IdRozgr"})
        rozgr_opts0 = _parse_select_options(sel_rozgr)
        rozgr_opts = [(v, lab, sel) for (v, lab, sel) in rozgr_opts0 if v and v != "0"]
        if not rozgr_opts:
            raise HTTPException(500, "Nie znaleziono rozgrywek (IdRozgr) dla tej kategorii.")

        wanted_id_rozgr = _clean_spaces(payload.id_rozgr or "")
        if wanted_id_rozgr:
            if not any(v == wanted_id_rozgr for (v, _, _) in rozgr_opts):
                raise HTTPException(400, f"Nieprawidłowy id_rozgr dla tej kategorii: {wanted_id_rozgr}")
            target_rozgr = [(v, lab, sel) for (v, lab, sel) in rozgr_opts if v == wanted_id_rozgr]
        else:
            target_rozgr = rozgr_opts

        competitions_out: List[Dict[str, Any]] = []
        total_matches = 0

        for (rozgr_val, rozgr_label, _) in target_rozgr:
            qs = {
                "a": "terminarz",
                "Filtr_sezon": picked_season,
                "Filtr_kategoria": cat_val,
                "IdRozgr": rozgr_val,
                "IdRundy": "ALL",
            }
            path = "/index.php?" + urlencode(qs, doseq=True)

            _, html = await fetch_with_correct_encoding(
                client,
                path,
                method="GET",
                cookies=cookies,
            )

            matches_map = _parse_matches_table(html)
            total_matches += len(matches_map)

            competitions_out.append(
                {
                    "IdRozgr": rozgr_val,
                    "label": rozgr_label,
                    "url": path,
                    "count": len(matches_map),
                    "matches": matches_map,
                }
            )

        return {
            "fetched_at": _now_iso(),
            "base_url": settings.ZPRP_BASE_URL,
            "Filtr_sezon": picked_season,
            "Filtr_kategoria": cat_val,
            "category_label": cat_label,
            "sex": sex,
            "IdRundy": "ALL",
            "mode": ("single_competition" if wanted_id_rozgr else "whole_category"),
            "competitions_count": len(competitions_out),
            "matches_count": total_matches,
            "competitions": competitions_out,
        }
