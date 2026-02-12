# app/zprp/schedule.py
from __future__ import annotations

import re
import datetime
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Query
from httpx import AsyncClient
from bs4 import BeautifulSoup

from app.deps import get_settings, Settings
from app.auth import get_current_cookies
from app.utils import fetch_with_correct_encoding

router = APIRouter()

# =========================
# Helpers
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
    """
    BeautifulSoup element -> list of clean, non-empty lines.
    """
    if not el:
        return []
    raw = el.get_text("\n", strip=True)
    lines = []
    for ln in raw.split("\n"):
        ln2 = _clean_spaces(ln)
        if ln2:
            lines.append(ln2)
    return lines


def _looks_like_name(line: str) -> bool:
    """
    Loose heuristic for "NAZWISKO Imię" / "Nazwisko Imię".
    Reject emails, phones, UI labels, purely numeric, etc.
    """
    if not line:
        return False
    low = line.lower()
    if "@" in line:
        return False
    if any(k in low for k in ["ustaw sędz", "ustaw sedz", "hala", "zapisz", "ukryj", "pokaż", "checkbox", "filtr"]):
        return False
    if re.search(r"\d{2,}", line):
        return False
    # must contain at least one space (two words)
    if " " not in line.strip():
        return False
    # must contain letters
    if not re.search(r"[A-Za-zĄĆĘŁŃÓŚŹŻąćęłńóśźż]", line):
        return False
    return True


def _parse_iso_datetime_from_td(td) -> str:
    """
    td[4] contains something like:
      "sobota\n11.10.2025\n(12:00)"
    Return "YYYY-MM-DD HH:MM:SS" (no TZ).
    """
    if not td:
        return ""

    # best: date in <b>
    b = td.find("b")
    date_str = _clean_spaces(b.get_text(strip=True)) if b else ""
    if not date_str:
        # fallback: find first DD.MM.YYYY anywhere
        txt = td.get_text(" ", strip=True)
        m = _RE_DATE.search(txt)
        date_str = m.group(0) if m else ""

    if not date_str:
        return ""

    # time often in parentheses
    txt2 = td.get_text(" ", strip=True)
    mtime = _RE_TIME.search(txt2)
    hhmm = mtime.group(1) if mtime else "00:00"

    m = _RE_DATE.search(date_str)
    if not m:
        return ""
    dd, mm, yyyy = m.group(1), m.group(2), m.group(3)
    return f"{yyyy}-{mm}-{dd} {hhmm}:00"


def _parse_hall(td) -> Dict[str, Any]:
    """
    td[5]:
      - map link with title like "Hala sportowa POGOŃ Zabrze, Zabrze, Wolności 406"
      - capacity in next line
    """
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
        # often: name, city, street+num  (but sometimes 2 segments)
        parts = [_clean_spaces(p) for p in title.split(",") if _clean_spaces(p)]
        if len(parts) >= 3:
            out["Hala_nazwa"] = parts[0]
            out["Hala_miasto"] = parts[1]
            street = ", ".join(parts[2:])  # in case street itself has commas
            # split last token as number if possible
            m = re.search(r"^(.*?)(\d+[A-Za-z]?)$", _clean_spaces(street))
            if m:
                out["Hala_ulica"] = _clean_spaces(m.group(1))
                out["Hala_numer"] = _clean_spaces(m.group(2))
            else:
                out["Hala_ulica"] = _clean_spaces(street)
        elif len(parts) == 2:
            out["Hala_nazwa"] = parts[0]
            # second might be "Miasto" or "Ulica Nr"
            out["Hala_miasto"] = parts[1]

    # capacity: usually on second line inside td text
    lines = _text_lines(td)
    # try: last numeric-only line
    cap = 0
    for ln in reversed(lines):
        if re.fullmatch(r"\d+", ln):
            cap = int(ln)
            break
    out["hala_pojemnosc"] = cap
    return out


def _parse_attendance(td) -> Dict[str, Any]:
    """
    td[6]: "50\n(5%)" or "0\n(0%)" or empty.
    """
    out = {"widzowie": 0, "widzowie_pct": None}
    if not td:
        return out
    txt = td.get_text(" ", strip=True)
    # first int is attendance
    m = _RE_INT.search(txt)
    out["widzowie"] = int(m.group(1)) if m else 0
    mp = re.search(r"\(\s*(\d+)\s*%\s*\)", txt)
    out["widzowie_pct"] = int(mp.group(1)) if mp else None
    return out


def _parse_result(td) -> Dict[str, Any]:
    """
    td[8] contains:
      - full: "27 : 27"
      - half: "( 12 : 12 )"
      - penalties: "< 3 : 4 >" (this is what you want in dogrywka_karne_*)
      - swapped icon: img src contains zmiana.png
    """
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

    # full score: take FIRST "X : Y" outside parentheses if possible;
    # but simplest: first occurrence in text.
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
    Often present as hidden input in embedded forms:
      <input type="hidden" name="IdZawody" value="191320" />
    We'll scan entire row HTML as fallback.
    """
    if not tr:
        return ""
    inp = tr.find("input", attrs={"name": "IdZawody"})
    if inp and inp.get("value"):
        return str(inp.get("value")).strip()

    html = str(tr)
    m = re.search(r'name=["\']IdZawody["\']\s+value=["\'](\d+)["\']', html, re.I)
    return m.group(1) if m else ""


def _parse_officials(td) -> Dict[str, str]:
    """
    td[10] has lots of UI + emails/phones; we want just names:
      NrSedzia_pierwszy_nazwisko
      NrSedzia_drugi_nazwisko
      NrSedzia_delegat_nazwisko (optional)
      NrSedzia_sekretarz_nazwisko (optional)
      NrSedzia_czas_nazwisko (optional)
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

    # Prefer visible text lines; then filter to likely name lines.
    lines = _text_lines(td)

    # Drop obvious non-name noise
    noise_prefixes = (
        "e-mail", "tel.", "tel:", "telefon", "kom.", "kom:", "mail", "www",
        "ukryj obsadę", "pokaż obsadę", "ustaw sędziów", "ustaw sedziow", "ustaw halę", "ustaw hale",
        "zapisz", "usuń", "usun",
    )
    clean = []
    for ln in lines:
        low = ln.lower()
        if any(low.startswith(p) for p in noise_prefixes):
            continue
        if "@" in ln:
            continue
        # strip pure phones like "+48 123..."
        if re.fullmatch(r"[\+\d\-\s\(\)\/\.]{6,}", ln):
            continue
        clean.append(ln)

    name_lines = [ln for ln in clean if _looks_like_name(ln)]
    if name_lines:
        out["NrSedzia_pierwszy_nazwisko"] = name_lines[0]
    if len(name_lines) >= 2:
        out["NrSedzia_drugi_nazwisko"] = name_lines[1]

    # Optional roles: try to detect labels then next name line
    # Some pages may include literal labels like "Delegat" / "Sekretarz" / "Mierzący czas" etc.
    def find_after_label(label_regex: str) -> str:
        for i, ln in enumerate(clean):
            if re.search(label_regex, ln, re.I):
                # search forward for first name-like line
                for j in range(i + 1, min(i + 6, len(clean))):
                    if _looks_like_name(clean[j]):
                        return clean[j]
        return ""

    out["NrSedzia_delegat_nazwisko"] = find_after_label(r"\bdelegat\b")
    out["NrSedzia_sekretarz_nazwisko"] = find_after_label(r"\bsekretarz\b")
    out["NrSedzia_czas_nazwisko"] = find_after_label(r"\bczas\b|\bmierz")
    return out


def _parse_matches_table(html: str) -> Dict[str, Dict[str, Any]]:
    """
    Returns map: {IdZawody: matchObj} (if IdZawody missing, we synthesize key).
    """
    soup = BeautifulSoup(html, "html.parser")

    # Heuristic: the main matches table usually contains header "Lp" and 11 cells rows.
    # We'll simply walk all <tr> and pick those with >= 11 <td>.
    out: Dict[str, Dict[str, Any]] = {}
    trs = soup.find_all("tr")
    synth_i = 0

    for tr in trs:
        tds = tr.find_all("td", recursive=False)
        if not tds or len(tds) < 11:
            continue

        # separator rows often use colspan
        if any(td.has_attr("colspan") for td in tds):
            # but note: normal rows can still have colspan rarely; here it’s almost always a separator
            # so skip them.
            continue

        # columns by index
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

        lp = _safe_int(td_lp.get_text(" ", strip=True), 0)
        season_label = _clean_spaces(td_season.get_text(" ", strip=True))
        code = _clean_spaces(td_code.get_text(" ", strip=True))

        host_name = _clean_spaces(td_host.get_text(" ", strip=True))
        guest_name = _clean_spaces(td_guest.get_text(" ", strip=True))

        data_fakt = _parse_iso_datetime_from_td(td_date)

        hall = _parse_hall(td_hall)
        att = _parse_attendance(td_att)
        res = _parse_result(td_res)
        off = _parse_officials(td_off)

        # Kolejka parsing
        kolejka_txt = _clean_spaces(td_kolejka.get_text(" ", strip=True))
        m_kno = re.search(r"Kolejka\s+(\d+)", kolejka_txt, re.I)
        kolejka_no = int(m_kno.group(1)) if m_kno else None
        m_rng = re.search(r"\(\s*([^)]+)\s*\)", kolejka_txt)
        kolejka_range = _clean_spaces(m_rng.group(1)) if m_rng else ""

        match_id = _extract_idzawody_from_tr(tr)
        if not match_id:
            synth_i += 1
            match_id = f"synthetic:{season_label}:{code}:{lp}:{synth_i}"

        match_obj: Dict[str, Any] = {
            "Id": match_id,
            "Lp": lp,
            "RozgrywkiCode": code,
            "season": season_label,
            "data_fakt": data_fakt,
            "runda": "",  # not present here; keeping for compatibility
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
            # important: penalties as dogrywka_karne_*
            "dogrywka_karne_gosp": res["dogrywka_karne_gosp"],
            "dogrywka_karne_gosc": res["dogrywka_karne_gosc"],
            "host_swapped": res["host_swapped"],
            # officials
            **off,
            # links/status (not available here; keep keys for your JSON shape)
            "matchLink": "",
            "protocol_link": "",
            "protocol_status": "",
            "delegate_note": "",
            "fee": "",
        }

        out[match_id] = match_obj

    return out


def _parse_select_options(sel) -> List[Tuple[str, str, bool]]:
    """
    Returns list of (value, label, is_selected).
    Skips empty labels.
    """
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
    """
    In ZPRP you often get values like "123|K" or "123|M".
    If not, fallback from label.
    """
    m = re.search(r"\|\s*([KM])\s*$", val or "", re.I)
    if m:
        return m.group(1).upper()
    low = (label or "").lower()
    if "kobiet" in low:
        return "K"
    if "mężczy" in low or "mezczy" in low:
        return "M"
    return ""


# =========================
# Endpoint
# =========================

@router.get("/zprp/terminarz/scrape")
async def scrape_terminarz_full(
    season_id: Optional[str] = Query(default=None, description="Filtr_sezon (jeśli brak, weź wybrany domyślnie)"),
    cookies: dict = Depends(get_current_cookies),
    settings: Settings = Depends(get_settings),
):
    """
    Logika:
      - otwórz /index.php?a=terminarz
      - ustal season_id (selected option jeśli user nie poda)
      - pobierz listę kategorii (Filtr_kategoria) i dla każdej:
          - pobierz stronę żeby dostać IdRozgr options
          - iteruj rozgrywki i parsuj mecze z IdRundy=ALL
      - zwróć JSON z pełnym podziałem: sex (K/M) -> kategoria -> rozgrywki -> matches
    """
    async with AsyncClient(base_url=settings.ZPRP_BASE_URL, follow_redirects=True, timeout=60.0) as client:
        # 1) Open base terminarz
        _, html0 = await fetch_with_correct_encoding(
            client,
            "/index.php?a=terminarz",
            method="GET",
            cookies=cookies,
        )

        soup0 = BeautifulSoup(html0, "html.parser")

        # 2) Determine season_id
        sel_season = soup0.find("select", attrs={"name": "Filtr_sezon"})
        seasons = _parse_select_options(sel_season)
        if not seasons:
            raise HTTPException(500, "Nie znaleziono listy sezonów (Filtr_sezon).")

        picked_season = season_id
        if not picked_season:
            # take selected else first non-empty
            picked_season = next((v for (v, _, sel) in seasons if sel and v), None) or next((v for (v, _, _) in seasons if v), None)
        if not picked_season:
            raise HTTPException(500, "Nie udało się ustalić Filtr_sezon.")

        # 3) Categories list
        sel_cat = soup0.find("select", attrs={"name": "Filtr_kategoria"})
        cats0 = _parse_select_options(sel_cat)
        # drop empty / placeholder
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

        # 4) Iterate categories
        for (cat_val, cat_label, _) in cats:
            sex = _detect_sex_from_kategoria_value(cat_val, cat_label)

            # Fetch page to get IdRozgr options for this category
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

            # 5) Iterate competitions (IdRozgr)
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

                comp_obj: Dict[str, Any] = {
                    "IdRozgr": rozgr_val,
                    "label": rozgr_label,
                    "url": path,
                    "matches": matches_map,  # map: Id -> match object
                    "count": len(matches_map),
                }
                cat_obj["competitions"].append(comp_obj)

            # Summaries
            cat_obj["competitions_count"] = len(cat_obj["competitions"])
            cat_obj["matches_count"] = sum(int(c.get("count", 0)) for c in cat_obj["competitions"])

            result["categories"].append(cat_obj)
            result["by_sex"].setdefault(sex, []).append(cat_obj)

        # Global summary
        result["summary"] = {
            "categories": len(result["categories"]),
            "competitions": sum(int(c.get("competitions_count", 0)) for c in result["categories"]),
            "matches": sum(int(c.get("matches_count", 0)) for c in result["categories"]),
        }

        return result
