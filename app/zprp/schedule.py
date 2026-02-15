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
from app.schemas import ZprpScheduleScrapeRequest
from app.utils import fetch_with_correct_encoding

router = APIRouter()

# =========================
# Logger (Railway -> stdout)
# =========================
logger = logging.getLogger("app.zprp.schedule")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
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
    # telefony / numery
    if re.fullmatch(r"[\+\d\-\s\(\)\/\.]{6,}", line):
        return False
    # same liczby / procenty itp.
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
    Zwraca IdZawody jeśli uda się znaleźć, w przeciwnym razie "".
    Uwzględnia:
    - hidden input name="IdZawody" w formach UstawHale / UstawSedziow
    - onclick zapiszProtok3(IdZawody,...)
    """
    if not tr:
        return ""

    inp = tr.find("input", attrs={"name": "IdZawody"})
    if inp and inp.get("value"):
        return str(inp.get("value")).strip()

    html = str(tr)
    m = re.search(r'name=["\']IdZawody["\']\s+value=["\'](\d+)["\']', html, re.I)
    if m:
        return m.group(1)

    m2 = re.search(r"zapiszProtok3\(\s*(\d+)\s*,", html, re.I)
    if m2:
        return m2.group(1)

    return ""


def _normalize_name_line(s: str) -> str:
    s = _clean_spaces(s)
    # częsty przypadek: "KOWALCZYK Bartłomiej          L"
    s = re.sub(r"\s+[A-Za-z]$", "", s).strip()
    return s


def _extract_first_person_name_from_lines(lines: List[str]) -> str:
    """
    Zwraca pierwszą sensowną linię wyglądającą jak imię+nazwisko.
    """
    for ln in lines:
        low = ln.lower()
        if "@" in ln:
            continue
        if low.startswith(("tel", "telefon", "e-mail", "mail", "www")):
            continue
        if re.fullmatch(r"[\+\d\-\s\(\)\/\.]{6,}", ln):
            continue
        if _looks_like_name(ln):
            return _normalize_name_line(ln)
    return ""


def _split_td_by_top_level_hr(td) -> List[BeautifulSoup]:
    """
    Dzieli zawartość TD na segmenty po <hr> (normalnym), zostawiając <hr class="cienka-linia">
    do rozdziału sędziów w parze.
    """
    if not td:
        return []

    # kopiujemy do nowego soup, żeby bezpiecznie usuwać śmieci
    holder = BeautifulSoup("<div></div>", "html.parser")
    container = holder.div
    container.append(BeautifulSoup(str(td), "html.parser"))

    # TD jest wewnątrz container
    td2 = container.find("td")
    if not td2:
        # fallback: czasem dostaniemy fragment bez td
        td2 = container

    # usuń elementy techniczne/klikalne
    for sel in [
        "form",
        "button",
        "input",
        "select",
        "option",
        "span",
        "img",
        "script",
    ]:
        for el in td2.select(sel):
            el.decompose()

    # teraz split po <hr> bez class='cienka-linia'
    segments: List[List[str]] = [[]]
    # przechodzimy po dzieciach TD i budujemy tekst + <br> jako newline
    for node in td2.descendants:
        if getattr(node, "name", None) == "hr":
            cls = node.get("class") or []
            if "cienka-linia" in cls:
                # nie rozdziela ról (tylko parę)
                segments[-1].append("__HR_THIN__")
            else:
                # rozdziela role
                segments.append([])
        elif getattr(node, "name", None) == "br":
            segments[-1].append("\n")
        elif isinstance(node, str):
            txt = _clean_spaces(node)
            if txt:
                segments[-1].append(txt)

    # zamień segmenty na listę "linii"
    out_lines: List[List[str]] = []
    for seg in segments:
        joined = " ".join(seg)
        joined = joined.replace("__HR_THIN__", "\n__HR_THIN__\n")
        # normalizacja newline
        joined = re.sub(r"\s*\n\s*", "\n", joined).strip()
        lines = [ln.strip() for ln in joined.split("\n") if ln.strip()]
        out_lines.append(lines)

    return out_lines


def _parse_officials(td) -> Dict[str, str]:
    """
    Parsowanie zgodnie z ustaleniami:
    - w TD są śmieci techniczne (checkboxy/formy/spany) -> ignorujemy
    - role rozdzielone zwykłymi <hr />
    - para sędziowska rozdzielona <hr class='cienka-linia'>
    - mapowanie ról od dołu: ostatni=czas, przedostatni=sekretarz, trzeci od końca=delegat
    - jeśli brak IdZawody / brak obsady -> zwracamy puste stringi
    """
    out = {
        "NrSedzia_pierwszy_nazwisko": "",
        "NrSedzia_drugi_nazwisko": "",
        "NrSedzia_delegat_nazwisko": "",
        "NrSedzia_sekretarz_nazwisko": "",
        "NrSedzia_czas_nazwisko": "",
    }
    if not td:
        return out

    segments_lines = _split_td_by_top_level_hr(td)
    if not segments_lines:
        return out

    # 1) Para sędziowska = segment[0], wewnątrz rozdzielony "__HR_THIN__"
    first_seg = segments_lines[0] if len(segments_lines) >= 1 else []
    # rozdziel po thin-hr markerze
    judges_a: List[str] = []
    judges_b: List[str] = []
    cur = judges_a
    for ln in first_seg:
        if ln == "__HR_THIN__":
            cur = judges_b
            continue
        cur.append(ln)

    j1 = _extract_first_person_name_from_lines(judges_a)
    j2 = _extract_first_person_name_from_lines(judges_b)

    out["NrSedzia_pierwszy_nazwisko"] = j1
    out["NrSedzia_drugi_nazwisko"] = j2

    # 2) Pozostałe segmenty (role) -> wyciągnij nazwiska, odfiltruj puste
    role_names: List[str] = []
    for seg in segments_lines[1:]:
        name = _extract_first_person_name_from_lines(seg)
        if name:
            role_names.append(name)

    # mapowanie od dołu
    if len(role_names) >= 1:
        out["NrSedzia_czas_nazwisko"] = role_names[-1]
    if len(role_names) >= 2:
        out["NrSedzia_sekretarz_nazwisko"] = role_names[-2]
    if len(role_names) >= 3:
        out["NrSedzia_delegat_nazwisko"] = role_names[-3]

    return out


def _is_match_row(tr) -> bool:
    """
    Odfiltrowuje:
    - nagłówek tabeli ("Lp.")
    - separatory z colspan
    - nietypowe wiersze
    """
    if not tr:
        return False
    tds = tr.find_all("td", recursive=False)
    if not tds or len(tds) < 11:
        return False
    if any(td.has_attr("colspan") for td in tds):
        return False

    lp_raw = _clean_spaces(tds[0].get_text(" ", strip=True))
    # nagłówek: "Lp."
    if lp_raw.lower() in ("lp.", "lp"):
        return False
    # wiersz meczu: "56."
    if not re.fullmatch(r"\d+\.", lp_raw):
        return False

    return True


def _parse_matches_table(html: str) -> Dict[str, Dict[str, Any]]:
    soup = BeautifulSoup(html, "html.parser")
    out: Dict[str, Dict[str, Any]] = {}
    trs = soup.find_all("tr")
    synth_i = 0

    for tr in trs:
        if not _is_match_row(tr):
            continue

        tds = tr.find_all("td", recursive=False)

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

        # IdZawody może być lub nie – NIE pomijamy meczu bez IdZawody
        idzawody_str = _extract_idzawody_from_tr(tr)
        idzawody_str = idzawody_str.strip()
        has_idzawody = bool(idzawody_str and re.fullmatch(r"\d+", idzawody_str))

        if has_idzawody:
            match_id = idzawody_str  # stabilny klucz, zgodny z resztą systemu
            idzawody_field = idzawody_str
        else:
            synth_i += 1
            # stabilny-ish fallback (unikalny w obrębie fetchu)
            match_id = f"synthetic:{season_label}:{code}:{lp}:{synth_i}"
            idzawody_field = ""  # wymaganie: pole puste

        match_obj: Dict[str, Any] = {
            "Id": match_id,
            "IdZawody": idzawody_field,
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


def _pick_season_id(seasons: List[Tuple[str, str, bool]], requested: Optional[str]) -> str:
    picked = _clean_spaces(requested or "")
    if picked:
        if any(v == picked for (v, _, _) in seasons):
            return picked
        raise HTTPException(400, f"Nieprawidłowy season_id: {picked}")

    picked = next((v for (v, _, sel) in seasons if sel and v), None) or next(
        (v for (v, _, _) in seasons if v), None
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


async def _login_zprp_and_get_cookies(client: AsyncClient, username: str, password: str) -> Dict[str, str]:
    resp_login, _ = await fetch_with_correct_encoding(
        client,
        "/login.php",
        method="POST",
        data={"login": username, "haslo": password, "from": "/index.php?"},
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

        _, html0 = await fetch_with_correct_encoding(client, "/index.php?a=terminarz", method="GET", cookies=cookies)
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
            "seasons_available": [{"value": v, "label": lab, "selected": sel} for (v, lab, sel) in seasons],
            "categories": [],
        }

        for (cat_val, cat_label, cat_sel) in cats:
            sex = _detect_sex_from_kategoria_value(cat_val, cat_label)

            qs = {"a": "terminarz", "Filtr_sezon": picked_season, "Filtr_kategoria": cat_val, "IdRundy": "ALL"}
            path_cat = "/index.php?" + urlencode(qs, doseq=True)

            _, html_cat = await fetch_with_correct_encoding(client, path_cat, method="GET", cookies=cookies)
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
                    "competitions": [{"IdRozgr": v, "label": lab, "selected": sel} for (v, lab, sel) in rozgr_opts],
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
    FULL: iteruje po wszystkich kategoriach i rozgrywkach.
    WAŻNE:
    - pobiera też mecze bez IdZawody (IdZawody=""), nie pomija ich.
    - loguje tylko podsumowania (ile meczów / jaka kategoria), bez dumpów meczów.
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

        _, html0 = await fetch_with_correct_encoding(client, "/index.php?a=terminarz", method="GET", cookies=cookies)
        soup0 = BeautifulSoup(html0, "html.parser")

        sel_season = soup0.find("select", attrs={"name": "Filtr_sezon"})
        seasons = _parse_select_options(sel_season)
        if not seasons:
            raise HTTPException(500, "Nie znaleziono listy sezonów (Filtr_sezon).")

        picked_season = _pick_season_id(seasons, payload.season_id)

        sel_cat = soup0.find("select", attrs={"name": "Filtr_kategoria"})
        cats0 = _parse_select_options(sel_cat)
        cats = [(v, lab, sel) for (v, lab, sel) in cats0 if v and v != "0"]
        if not cats:
            raise HTTPException(500, "Nie znaleziono kategorii (Filtr_kategoria).")

        result: Dict[str, Any] = {
            "fetched_at": _now_iso(),
            "base_url": settings.ZPRP_BASE_URL,
            "Filtr_sezon": picked_season,
            "seasons_available": [{"value": v, "label": lab, "selected": sel} for (v, lab, sel) in seasons],
            "categories": [],
            "by_sex": {"K": [], "M": [], "": []},
        }

        total_matches_all = 0

        for (cat_val, cat_label, _) in cats:
            sex = _detect_sex_from_kategoria_value(cat_val, cat_label)

            qs = {"a": "terminarz", "Filtr_sezon": picked_season, "Filtr_kategoria": cat_val, "IdRundy": "ALL"}
            path_cat = "/index.php?" + urlencode(qs, doseq=True)

            _, html_cat = await fetch_with_correct_encoding(client, path_cat, method="GET", cookies=cookies)
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

            cat_total_matches = 0

            for (rozgr_val, rozgr_label, _) in rozgr_opts:
                qs2 = {
                    "a": "terminarz",
                    "Filtr_sezon": picked_season,
                    "Filtr_kategoria": cat_val,
                    "IdRozgr": rozgr_val,
                    "IdRundy": "ALL",
                }
                path = "/index.php?" + urlencode(qs2, doseq=True)

                _, html = await fetch_with_correct_encoding(client, path, method="GET", cookies=cookies)
                matches_map = _parse_matches_table(html)

                cnt = len(matches_map)
                cat_total_matches += cnt
                total_matches_all += cnt

                logger.info(
                    "ZPRP terminarz: FULL fetched matches=%d season=%s cat=%s (%s) rozgr=%s (%s)",
                    cnt,
                    picked_season,
                    cat_val,
                    cat_label,
                    rozgr_val,
                    rozgr_label,
                )

                cat_obj["competitions"].append(
                    {"IdRozgr": rozgr_val, "label": rozgr_label, "url": path, "matches": matches_map, "count": cnt}
                )

            cat_obj["competitions_count"] = len(cat_obj["competitions"])
            cat_obj["matches_count"] = cat_total_matches

            logger.info(
                "ZPRP terminarz: FULL category done season=%s cat=%s (%s) sex=%s competitions=%d matches=%d",
                picked_season,
                cat_val,
                cat_label,
                sex,
                cat_obj["competitions_count"],
                cat_total_matches,
            )

            result["categories"].append(cat_obj)
            result["by_sex"].setdefault(sex, []).append(cat_obj)

        result["summary"] = {
            "categories": len(result["categories"]),
            "competitions": sum(int(c.get("competitions_count", 0)) for c in result["categories"]),
            "matches": sum(int(c.get("matches_count", 0)) for c in result["categories"]),
        }

        logger.info(
            "ZPRP terminarz: FULL summary season=%s categories=%d competitions=%d matches=%d",
            picked_season,
            result["summary"]["categories"],
            result["summary"]["competitions"],
            result["summary"]["matches"],
        )

        return result


@router.post("/zprp/terminarz/scrape_slim")
async def scrape_terminarz_slim(
    payload: ZprpScheduleScrapeRequest,
    settings: Settings = Depends(get_settings),
    keys=Depends(get_rsa_keys),
):
    """
    LITE:
    - wymaga filtr_kategoria
    - jeśli id_rozgr podane -> tylko jedna rozgrywka
    - jeśli id_rozgr puste -> cała kategoria
    - zawsze IdRundy=ALL
    WAŻNE:
    - pobiera też mecze bez IdZawody (IdZawody=""), nie pomija ich.
    - loguje tylko podsumowania (ile meczów / jaka kategoria), bez dumpów meczów.
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

        _, html0 = await fetch_with_correct_encoding(client, "/index.php?a=terminarz", method="GET", cookies=cookies)
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

        qs_cat = {"a": "terminarz", "Filtr_sezon": picked_season, "Filtr_kategoria": cat_val, "IdRundy": "ALL"}
        path_cat = "/index.php?" + urlencode(qs_cat, doseq=True)

        _, html_cat = await fetch_with_correct_encoding(client, path_cat, method="GET", cookies=cookies)
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

            _, html = await fetch_with_correct_encoding(client, path, method="GET", cookies=cookies)
            matches_map = _parse_matches_table(html)
            cnt = len(matches_map)
            total_matches += cnt

            logger.info(
                "ZPRP terminarz: LITE fetched matches=%d season=%s cat=%s (%s) rozgr=%s (%s)",
                cnt,
                picked_season,
                cat_val,
                cat_label,
                rozgr_val,
                rozgr_label,
            )

            competitions_out.append(
                {"IdRozgr": rozgr_val, "label": rozgr_label, "url": path, "count": cnt, "matches": matches_map}
            )

        logger.info(
            "ZPRP terminarz: LITE summary season=%s cat=%s (%s) sex=%s competitions=%d matches=%d mode=%s",
            picked_season,
            cat_val,
            cat_label,
            sex,
            len(competitions_out),
            total_matches,
            ("single_competition" if wanted_id_rozgr else "whole_category"),
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
