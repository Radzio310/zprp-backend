"""Parser protokołu ZPRP z warstwą tekstową PDF („Wczytaj składy", 02.11.2026) - bez AI, bez bazy, bez sieci.

Czyta PyMuPDF-em (NIE pdftotext: ten gubi polskie znaki, patrz pamięć `zprp-pdf-extraction-traps`). Wynik idzie do
`lineup_read_rules.build_result`, tak samo jak odczyt ze zdjęcia.

Znane pułapki protokołu, które tu obsługujemy:
  - drużyny wiążemy z NAGŁÓWKAMI tabel „A (nazwa) ..." i „B (nazwa) ...", nie z kolejnością ani położeniem na stronie,
  - osoby A-E mają literę przyklejoną do nazwiska bez spacji („A.NAZWISKO Imię"), funkcję i licencję w kolejnych wierszach
    TEJ SAMEJ kolumny, a w pustych miejscach stoją same etykiety „Nazwisko, imię - funkcja, numer licencji" (powtarzane),
  - licencja trenera ma prefiks kategorii („B  0544/2026"), osoby towarzyszącej bywa samą liczbą („0404/18"),
  - tabele czasu („Przebieg zawodów") są puste albo pełne dwukropków - czytamy wyłącznie lewą część tabeli składu,
  - kratki „x" przy rozgrywkach, płci i kategorii wieku to zwykłe znaki tekstu stojące tuż przed etykietą,
  - zielone ptaszki przy zawodnikach to w tym szablonie MAŁE OBRAZKI w kolumnie na lewo od numeru (jeden na wiersz).
    Wykrywamy je po obrazku/rysunku/znaku w wierszu i kolorze; gdy na stronie nie ma żadnego takiego znacznika, nie
    wiemy, czy szablon w ogóle je rysuje, więc zwracamy `checked: null` i `checks_detectable: null`.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from app.lineup_read_rules import MIN_TEXT_CHARS, STAFF_SLOTS, LineupError, build_result, find_license, split_name

#: Szerokość kolumny osoby A-E w protokole ZPRP (punkty PDF); słowa dalej od jej początku to już inna tabela.
COLUMN_WIDTH = 75.0
Word = Tuple[float, float, float, float, str]  # x0, y0, x1, y1, tekst
_HEAD = re.compile(r"^\s*([AB])\s*\(\s*nazwa\s*\)\s*(.*)$", re.I)
_STAFF_LABEL = re.compile(r"nazwisko,?\s*imi[ęe]\s*-\s*funkcja|numer\s+licencji|osoba\s+odpowiedzialna|nazwisko,\s*imi[ęe],\s*funkcja", re.I)
_STAFF_START = re.compile(r"^([A-E])\.\s*(\S.*)$")
_PLAYER_ROW = re.compile(r"^(\d{1,3})\s+(\S.*)$")
_TICK_CHARS = set("✓✔☑🗸")
_ROLE_PATTERNS = (
    ("sedzia", re.compile(r"^s[ęe]dzia\s+g[łl]{1,2}[oó]wny$", re.I)),
    ("sekretarz", re.compile(r"^sekretarz$", re.I)),
    ("czas", re.compile(r"^m\.?\s*czas$", re.I)),
    ("delegat", re.compile(r"^delegat(\s+zprp)?$", re.I)),
)
_STAGE_LABELS = (
    ("SUPERLIGA", r"superliga"), ("I LIGA", r"i\s+liga\b"), ("II LIGA", r"ii\s+liga\b"), ("PUCHAR POLSKI", r"puchar"),
    ("BARAŻE", r"bara[żz]e"), ("FINAŁ", r"fina[łl]$"), ("PÓŁFINAŁ", r"p[óo][łl]fina[łl]"), ("ĆWIERĆFINAŁ", r"[ćc]wier[ćc]fina[łl]"),
    ("ELIMINACJE", r"eliminacje"),
)
_AGE_LABELS = (
    ("SENIORZY", r"seniorzy"), ("JUNIORZY", r"juniorzy$"), ("JUNIORZY MŁODSI", r"juniorzy\s+m[łl]"),
    ("MŁODZICY", r"m[łl]odzicy"), ("DZIECI", r"dzieci"),
)


class _Line:
    __slots__ = ("words", "text", "x0", "y0", "x1", "y1")

    def __init__(self, words: List[Word]):
        self.words = sorted(words, key=lambda w: w[0])
        self.text = " ".join(w[4] for w in self.words)
        self.x0 = min(w[0] for w in words)
        self.x1 = max(w[2] for w in words)
        self.y0 = min(w[1] for w in words)
        self.y1 = max(w[3] for w in words)

    @property
    def cy(self) -> float:
        return (self.y0 + self.y1) / 2


def _clusters(words: List[Word], tol: float = 2.6) -> List[List[Word]]:
    """Słowa -> wiersze po pionowym środku (nie po blokach PDF: generatory dzielą je różnie)."""
    ordered = sorted(words, key=lambda w: ((w[1] + w[3]) / 2, w[0]))
    rows: List[List[Word]] = []
    centres: List[float] = []
    for word in ordered:
        centre = (word[1] + word[3]) / 2
        if rows and abs(centre - centres[-1]) <= tol:
            rows[-1].append(word)
            centres[-1] = (centres[-1] + centre) / 2
        else:
            rows.append([word])
            centres.append(centre)
    return [sorted(r, key=lambda w: w[0]) for r in rows]


def _lines(words: List[Word], gap: float = 14.0) -> List[_Line]:
    """Wiersze pocięte na komórki tam, gdzie odstęp poziomy przekracza `gap` - sąsiednie kolumny tabeli nie mogą zlewać
    się w jeden tekst."""
    cells: List[_Line] = []
    for row in _clusters(words):
        cell = [row[0]]
        for word in row[1:]:
            if word[0] - cell[-1][2] > gap:
                cells.append(_Line(cell))
                cell = [word]
            else:
                cell.append(word)
        cells.append(_Line(cell))
    return cells


def has_text_layer(pdf_bytes: bytes) -> bool:
    """Czy PDF ma wystarczająco tekstu, by czytać go regułami (skany mają tylko stopkę)."""
    import fitz

    with fitz.open(stream=pdf_bytes, filetype="pdf") as doc:
        chars = sum(len((page.get_text() or "").strip()) for page in doc)
        return doc.page_count > 0 and chars / doc.page_count >= MIN_TEXT_CHARS


# ─── Ptaszki ────────────────────────────────────────────────────────────────


def _green_ratio(pix: Any) -> Optional[Tuple[float, float]]:
    """(udział zielonych, udział czerwonych) wśród NIEbiałych pikseli; None, gdy obraz jest pusty/biały."""
    n, samples = pix.n, pix.samples
    if n < 3:
        return None
    step = max(1, (pix.width * pix.height) // 4000)
    ink = green = red = 0
    for i in range(0, pix.width * pix.height, step):
        r, g, b = samples[i * n], samples[i * n + 1], samples[i * n + 2]
        if r > 225 and g > 225 and b > 225:
            continue
        ink += 1
        if g > r + 25 and g > b + 25:
            green += 1
        elif r > g + 60 and r > b + 60:
            red += 1
    return (green / ink, red / ink) if ink >= 8 else None


#: Spreparowany PDF (do 16 MB) nie może wyczerpać pamięci ani czasu przy szukaniu ptaszków: obraz większy niż mały
#: znacznik jest pomijany bez dekodowania, a liczba obrazów i rysunków jest ograniczona.
#: Ptaszek w protokole ZPRP to JPEG 800x800 (640 tys. pikseli) rysowany w polu 11x11 pt, więc próg musi go przepuszczać.
MAX_BADGE_IMAGE_PIXELS = 2_000_000
MAX_BADGE_XREFS = 60
MAX_BADGE_IMAGE_INFOS = 400
MAX_BADGE_DRAWINGS = 4000


def _badge_marks(page: Any) -> List[Tuple[Tuple[float, float, float, float], Optional[bool]]]:
    """Małe kwadratowe znaczniki (obrazki i wypełnione rysunki) jako (bbox, True=zielony / False=czerwony / None=inny)."""
    import fitz

    marks: List[Tuple[Tuple[float, float, float, float], Optional[bool]]] = []
    cache: Dict[int, Optional[bool]] = {}
    for info in page.get_image_info(xrefs=True)[:MAX_BADGE_IMAGE_INFOS]:
        x0, y0, x1, y1 = info["bbox"]
        if not (3 <= x1 - x0 <= 24 and 3 <= y1 - y0 <= 24):
            continue
        xref = info.get("xref") or 0
        if xref not in cache:
            if len(cache) >= MAX_BADGE_XREFS or int(info.get("width") or 0) * int(info.get("height") or 0) > MAX_BADGE_IMAGE_PIXELS:
                cache[xref] = None  # za duży jak na znaczek albo za dużo różnych obrazów: „nie wiemy", bez dekodowania
                marks.append(((x0, y0, x1, y1), None))
                continue
            try:
                ratio = _green_ratio(fitz.Pixmap(page.parent, xref)) if xref else None
            except Exception:  # noqa: BLE001 - nieczytelny obraz to po prostu „nie wiemy"
                ratio = None
            cache[xref] = None if ratio is None else (True if ratio[0] >= 0.5 else (False if ratio[1] >= 0.5 else None))
        marks.append(((x0, y0, x1, y1), cache[xref]))
    for drawing in page.get_drawings()[:MAX_BADGE_DRAWINGS]:
        fill = drawing.get("fill")
        rect = drawing["rect"]
        if fill and 3 <= rect.width <= 24 and 3 <= rect.height <= 24 and drawing.get("type") in ("f", "fs"):
            r, g, b = fill[:3]
            if g > r + 0.1 and g > b + 0.1:
                marks.append(((rect.x0, rect.y0, rect.x1, rect.y1), True))
    return marks


# ─── Pola nagłówka ──────────────────────────────────────────────────────────


def _header(lines: List[_Line], full_text: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    found = re.search(r"IdZawody:\s*(\d+)", full_text)
    out["zprp_match_id"] = found.group(1) if found else None
    for line in lines:
        if re.match(r"^numer\s+meczu:?$", line.text.strip(), re.I) or re.match(r"^numer\s+meczu:", line.text.strip(), re.I):
            rest = re.sub(r"^numer\s+meczu:?\s*", "", line.text.strip(), flags=re.I)
            if not rest:
                label_end = max(w[2] for w in line.words if "meczu" in w[4].lower())
                near = [o for o in lines if o is not line and abs(o.cy - line.cy) <= 4 and o.x0 >= label_end - 1]
                rest = near[0].text if near else ""
            out["match_number"] = rest or None
            break
    head_lines = [ln for ln in lines if ln.y0 < 135]
    for line in head_lines:
        found = re.search(r"\bdata\s+(\d{1,2}[.\-/]\d{1,2}[.\-/]\d{4})", line.text, re.I)
        if found and "date" not in out:
            out["date"] = found.group(1)
        found = re.search(r"\bgodz\.?\s*(\d{1,2}[:.]\d{2})", line.text, re.I)
        if found and "time" not in out:
            out["time"] = found.group(1)
    # Hala i adres: wiersze pod etykietą „Miejsce rozgrywania zawodów (adres):".
    label = next((ln for ln in lines if re.search(r"miejsce\s+rozgrywania", ln.text, re.I)), None)
    if label is not None:
        below = [ln for ln in lines if label.y1 - 1 < ln.y0 < label.y1 + 40 and ln.x1 > label.x0 - 20 and ln.x0 >= label.x0 - 20
                 and not re.fullmatch(r"[:\s]*", ln.text) and not re.search(r"wynik|przerwy|korzy", ln.text, re.I)]
        texts = [ln.text for ln in below[:3]]
        if len(texts) >= 2:
            out["hall"], out["address"] = texts[0], " ".join(texts[1:])
        elif texts:
            key = "address" if re.search(r"\d{2}-\d{3}|\d", texts[0]) else "hall"
            out[key] = texts[0]
    # Nazwy z etykiet „Drużyna gospodarzy/gości:" (zapasowo - tabele mają własne nagłówki).
    for key, pattern in (("home_name", r"dru[żz]yna\s+gospodarzy"), ("away_name", r"dru[żz]yna\s+go[śs]ci")):
        lab = next((ln for ln in lines if re.search(pattern, ln.text, re.I)), None)
        if lab is not None:
            nxt = [ln for ln in lines if lab.y1 - 1 < ln.y0 < lab.y1 + 22 and abs(ln.x0 - lab.x0) < 20]
            if nxt:
                out[key] = nxt[0].text
    return out


def _competition(lines: List[_Line], ticks: List[Word]) -> Optional[Dict[str, Any]]:
    """Kratki „x" jako znaki tekstu stojące tuż przed etykietą w tym samym wierszu. None, gdy nie znaleziono żadnego."""
    zone = [ln for ln in lines if ln.y0 < 125]
    if not ticks:
        return None
    labels: List[Tuple[str, str, float, float, float]] = []  # grupa, nazwa, x0, y0, y1
    for ln in zone:
        txt = ln.text.strip()
        for name, pat in _STAGE_LABELS:
            if re.match(pat, txt, re.I):
                labels.append(("stage", name, ln.x0, ln.y0, ln.y1))
        for name, pat in _AGE_LABELS:
            if re.match(pat, txt, re.I):
                labels.append(("age", name, ln.x0, ln.y0, ln.y1))
        if txt in ("K", "M"):
            labels.append(("sex", txt, ln.x0, ln.y0, ln.y1))
    picked: Dict[str, List[str]] = {"stage": [], "age": [], "sex": []}
    for tick in ticks:
        centre = (tick[1] + tick[3]) / 2
        best = None
        for group, name, x0, y0, y1 in labels:
            gap = x0 - tick[2]
            if -2 <= gap <= 22 and abs((y0 + y1) / 2 - centre) <= 6:
                if best is None or gap < best[0]:
                    best = (gap, group, name)
        if best and best[2] not in picked[best[1]]:
            picked[best[1]].append(best[2])
    if not any(picked.values()):
        return None
    return {"stage": picked["stage"], "age": picked["age"], "sex": picked["sex"][0] if picked["sex"] else None}


# ─── Tabele składów ─────────────────────────────────────────────────────────


def _staff(words: List[Word], zone: List[_Line], cut_y: float, end_y: float) -> List[Dict[str, Any]]:
    """Osoby A-E: kolumny wyznaczone przez wiersze „X.NAZWISKO Imię"; funkcja i licencja z kolejnych wierszy kolumny."""
    anchors: List[Tuple[str, float, float]] = []  # litera, x0 słowa, y
    for ln in zone:
        if ln.cy < cut_y - 1:
            continue
        for w in ln.words:
            m = _STAFF_START.match(w[4])
            if m:
                anchors.append((m.group(1), w[0], ln.cy))
    if not anchors:
        return []
    anchors.sort(key=lambda a: a[1])
    first_y = min(a[2] for a in anchors)
    label_y = min((ln.y0 for ln in zone if ln.cy > first_y + 3 and _STAFF_LABEL.search(ln.text)), default=end_y)
    columns: Dict[str, List[Word]] = {a[0]: [] for a in anchors}
    for w in words:
        centre = (w[1] + w[3]) / 2
        if not (first_y - 3 <= centre < label_y):
            continue
        owner, owner_x = None, 0.0
        for letter, x0, _ in anchors:
            if w[0] >= x0 - 4:
                owner = letter
                owner_x = x0
        # Tabela czasu stoi po prawej: kolumna osoby nie sięga dalej niż jej szerokość w szablonie (~65 pt).
        if owner is not None and w[0] - owner_x > COLUMN_WIDTH:
            owner = None
        if owner is not None:
            columns[owner].append(w)
    out = []
    for letter, _, _ in anchors:
        rows = _lines(columns[letter])
        if not rows:
            continue
        first = rows[0].text
        m = re.match(r"^([A-E])\.\s*(.+)$", first)
        name = m.group(2) if m else first
        function_parts: List[str] = []
        license_text: Optional[str] = None
        for row in rows[1:]:
            lic = find_license(row.text)
            if lic and license_text is None:
                license_text = lic["license"]
                rest = (row.text[: lic["start"]] + " " + row.text[lic["end"]:]).strip()
                if rest:
                    function_parts.append(rest)
            else:
                function_parts.append(row.text)
        out.append({"slot": letter, "name": name, "function": " ".join(function_parts) or None,
                    "license": license_text, "confidence": 0.95})
    return out


def _team(letter: str, head: _Line, y_from: float, y_to: float, lines: List[_Line], words: List[Word],
          marks: List[Tuple[Tuple[float, float, float, float], Optional[bool]]], badge_cols_x: float) -> Dict[str, Any]:
    m = _HEAD.match(head.text)
    name = (m.group(2) if m else "").strip() or None
    zone = [ln for ln in lines if y_from <= ln.cy < y_to and ln is not head]
    person_y = [ln.y0 for ln in zone if _STAFF_START.match(ln.text) or _STAFF_LABEL.search(ln.text)]
    cut_y = min(person_y) if person_y else y_to
    zone_words = [w for w in words if y_from <= (w[1] + w[3]) / 2 < y_to]
    players: List[Dict[str, Any]] = []
    detectable = bool(marks)
    for ln in (_Line(r) for r in _clusters([w for w in zone_words if w[0] < 205])):
        if ln.cy >= cut_y - 1:
            continue
        left = ln.words
        text = " ".join(w[4] for w in left)
        if re.search(r"nazwisko|zawodnik|licencj|funkcj|dru[żz]yn", text, re.I) or re.fullmatch(r"nr\.?", text.strip(), re.I):
            continue
        m = _PLAYER_ROW.match(text)
        if not m:
            # Wiersz bez numeru w kolumnie nazwiska albo sam numer bez nazwiska: nigdy cicho nie znika (numer/nazwisko
            # zostaje puste i trafia do „nieczytelnych", więc ekran zatwierdzenia pokaże wiersz do uzupełnienia).
            alone = re.fullmatch(r"(\d{1,3})", text.strip())
            if alone:
                players.append({"number": int(alone.group(1)) if int(alone.group(1)) <= 99 else None, "name": None,
                                "confidence": 0.4, "checked": None})
            elif split_name(text) is not None:
                players.append({"number": None, "name": text.strip(), "confidence": 0.4, "checked": None})
            continue
        number, rest = int(m.group(1)), m.group(2)
        ticked: Optional[bool] = None
        if detectable:
            ticked = False
            for bbox, green in marks:
                if abs((bbox[1] + bbox[3]) / 2 - ln.cy) <= 6 and bbox[2] <= ln.x0 + 6:
                    ticked = True if green is True else (None if green is None else False)
                    break
        if any(ch in _TICK_CHARS for ch in ln.text):
            ticked, rest = True, "".join(c for c in rest if c not in _TICK_CHARS).strip()
        players.append({"number": number if number <= 99 else None, "name": rest, "confidence": 0.98, "checked": ticked})
    staff = _staff(zone_words, zone, cut_y, y_to)
    return {"name": name, "players": players, "staff": staff, "_detectable": detectable}


def _officials(lines: List[_Line], after_y: float) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for ln in lines:
        if ln.y0 < after_y:
            continue
        left = [w for w in ln.words if w[0] < 100]
        role_text = " ".join(w[4] for w in left)
        role = next((key for key, pat in _ROLE_PATTERNS if pat.match(role_text.strip())), None)
        if role is None:
            continue
        cut = next((w[0] for w in ln.words if w[0] >= 100 and re.search(r"miejscowo[śs][ćc]$", w[4], re.I)), 1e9)
        parts = [w[4] for w in ln.words if 100 <= w[0] < cut - 0.5]
        if parts and len(parts[-1]) == 1 and parts[-1].upper() == "O":
            parts = parts[:-1]
        name = " ".join(parts)
        if not name or re.fullmatch(r"[-_ ]+", name):
            continue
        out.append({"role": role, "name": name})
    judges = [o for o in out if o["role"] == "sedzia"]
    for index, item in enumerate(judges[:2]):
        item["role"] = f"sedzia{index + 1}"
    return [o for o in out if o["role"] != "sedzia"]


def parse_page(page: Any) -> Optional[Dict[str, Any]]:
    """Jedna strona -> {header, home, away, officials, checks_detectable} (jeszcze przed normalizacją) albo None, gdy to nie protokół."""
    raw_words = page.get_text("words") or []
    words: List[Word] = [(w[0], w[1], w[2], w[3], str(w[4])) for w in raw_words if str(w[4]).strip()]
    if not words:
        return None
    lines = _lines(words)
    full_text = "\n".join(ln.text for ln in lines)
    heads = [(m.group(1).upper(), ln) for ln in lines for m in [_HEAD.match(ln.text)] if m]
    letters = {h[0] for h in heads}
    if "A" not in letters or "B" not in letters:
        return None
    heads.sort(key=lambda h: h[1].y0)
    end_y = next((ln.y0 for ln in lines if re.search(r"szczeg[óo][łl]owe\s+uwagi", ln.text, re.I)), page.rect.height)
    marks = _badge_marks(page)
    teams: Dict[str, Dict[str, Any]] = {}
    for index, (letter, ln) in enumerate(heads):
        y_to = heads[index + 1][1].y0 if index + 1 < len(heads) else end_y
        if letter in teams:
            continue
        teams[letter] = _team(letter, ln, ln.y1, y_to, lines, words, marks, 0.0)
    header = _header(lines, full_text)
    ticks = [w for w in words if w[4].strip().lower() in ("x", "×", "✗") and w[3] - w[1] < 14 and w[1] < 125]
    header["competition"] = _competition(_lines([w for w in words if w not in ticks]), ticks)
    for key, letter in (("home_name", "A"), ("away_name", "B")):
        if teams[letter].get("name"):
            header[key] = teams[letter]["name"]
    officials = _officials([_Line(r) for r in _clusters(words)], end_y)
    detectable = any(t["_detectable"] for t in teams.values()) or None
    for team in teams.values():
        team.pop("_detectable", None)
    return {"header": header, "home": teams["A"], "away": teams["B"], "officials": officials, "checks_detectable": detectable}


def parse_pdf(pdf_bytes: bytes, *, max_pages: int = 4) -> Dict[str, Any]:
    """Cały PDF z tekstem -> wynik w kształcie `build_result`. Rzuca `LineupError(NOT_A_PROTOCOL)`, gdy żadna strona
    nie ma tabel „A (nazwa)" i „B (nazwa)"."""
    import fitz

    try:
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    except Exception as exc:  # noqa: BLE001
        raise LineupError(422, "PDF_UNREADABLE", "Nie udało się otworzyć PDF-a.") from exc
    with doc:
        if doc.needs_pass:
            raise LineupError(422, "PDF_ENCRYPTED", "PDF jest chroniony hasłem.")
        pages = [p for p in (parse_page(doc[i]) for i in range(min(doc.page_count, max_pages))) if p]
    if not pages:
        raise LineupError(422, "NOT_A_PROTOCOL", "W tym PDF-ie nie ma protokołu zawodów ZPRP ze składami.")
    first = pages[0]
    for extra in pages[1:]:
        for team in ("home", "away"):
            # Ten sam protokół powtórzony w jednym PDF-ie (np. kopia strony) nie dubluje wierszy.
            have = {(p.get("number"), re.sub(r"\s+", " ", str(p.get("name") or "")).strip().lower()) for p in first[team]["players"]}
            for p in extra[team]["players"]:
                key = (p.get("number"), re.sub(r"\s+", " ", str(p.get("name") or "")).strip().lower())
                if key not in have:
                    have.add(key)
                    first[team]["players"].append(p)
            have_s = {re.sub(r"\s+", " ", str(p.get("name") or "")).strip().lower() for p in first[team]["staff"]}
            for p in extra[team]["staff"]:
                key = re.sub(r"\s+", " ", str(p.get("name") or "")).strip().lower()
                if key not in have_s:
                    have_s.add(key)
                    first[team]["staff"].append(p)
        known = {o["role"] for o in first["officials"]}
        first["officials"] += [o for o in extra["officials"] if o["role"] not in known]
    return build_result(source="pdf_text", pages=len(pages), header=first["header"], home=first["home"], away=first["away"],
                        officials=first["officials"], checks_detectable=first["checks_detectable"])
