"""Raport o jednej osobie - szablon HTML (A4, dwie strony), z którego Edge robi PDF.

Język wizualny dokumentów BAZA Beach (`app/templates/podsumowanie_sezonu.html`):
ciemny pas nagłówka, nadtytuły sekcji z rozstrzeloną kapitalikową linijką,
kafle liczb, karty z akcentem po lewej - tu w barwach ProEla (bursztyn
#E8970A na grafitowym tle), czerwień tylko dla usunięcia, zieleń dla bramek.

Każdy napis z danych przechodzi przez `_e` (escape). Zdania są bezosobowe:
raport mówi, CO zapisano, kiedy i kto - nie ocenia.
"""
from __future__ import annotations

import base64
import html
import io
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import analiza as A
from dossier import BIERNIK, DOPELNIACZ

TU = Path(__file__).resolve().parent
ROOT = TU.parents[2]  # BAZA_ALL
LOGO_BAZA = [ROOT / "zprp-backend" / "app" / "templates" / "baza_logo.png",
             ROOT / "BAZA" / "assets" / "images" / "baza_logo_official.png"]
LOGO_PROEL = [ROOT / "BAZA" / "assets" / "images" / "PROEL.png",
              ROOT / "BAZA" / "assets" / "images" / "proel_small.png"]

ACCENT = "#E8970A"
EMBER = "#C2410C"
INK = "#15171C"
MUTED = "#6B6F7B"
RED = "#D92D20"
GREEN = "#15803D"


def _e(v: Any) -> str:
    return html.escape("" if v is None else str(v))


def _logo(kandydaci: List[Path], px: int = 220) -> str:
    """Logo jako data URI - zmniejszone, żeby raport nie ważył kilku MB."""
    for p in kandydaci:
        if not p.is_file():
            continue
        raw = p.read_bytes()
        try:
            from PIL import Image  # opcjonalnie: bez PIL-a idzie oryginał

            img = Image.open(io.BytesIO(raw)).convert("RGBA")
            img.thumbnail((px, px), Image.LANCZOS)
            buf = io.BytesIO()
            img.save(buf, format="PNG", optimize=True)
            raw = buf.getvalue()
        except Exception:  # noqa: BLE001
            pass
        return "data:image/png;base64," + base64.b64encode(raw).decode("ascii")
    return ""


def _sekundy(s: Optional[float]) -> str:
    if s is None:
        return "-"
    s = int(round(s))
    return f"{s // 60} min {s % 60} s" if s >= 60 else f"{s} s"


def _maly(t: str) -> str:
    return t if t.split(" ", 1)[0] in ("I", "II", "III") else t[:1].lower() + t[1:]


# ─────────────────────────── oś czasu meczu (SVG) ───────────────────────────

def _os_meczu(d: Dict[str, Any], od_ms: int, do_ms: int, *, wys: int, etykiety: bool) -> str:
    """Pas czasu meczu z karami (góra) i bramkami (dół). `etykiety` = wersja przybliżona."""
    W, L, R = 700, 58, 14
    plot = W - L - R

    def x(ms: float) -> float:
        return L + (min(max(ms, od_ms), do_ms) - od_ms) / max(1, do_ms - od_ms) * plot

    y_k, y_b, y_os = (38, 72, wys - 22) if etykiety else (24, 52, wys - 18)
    out: List[str] = [f'<svg viewBox="0 0 {W} {wys}" xmlns="http://www.w3.org/2000/svg" class="os">']
    # tory
    for y, napis in ((y_k, "KARY"), (y_b, "BRAMKI")):
        out.append(f'<line x1="{L}" y1="{y}" x2="{W - R}" y2="{y}" stroke="#E6E7EB" stroke-width="1"/>')
        out.append(f'<text x="0" y="{y + 3}" class="tor">{napis}</text>')
    # oś i podziałka
    out.append(f'<line x1="{L}" y1="{y_os}" x2="{W - R}" y2="{y_os}" stroke="#B9BCC6" stroke-width="1"/>')
    krok = 60_000 if (do_ms - od_ms) <= 15 * 60_000 else 10 * 60_000
    t = (od_ms // krok) * krok
    while t <= do_ms:
        if t >= od_ms:
            xx = x(t)
            out.append(f'<line x1="{xx:.1f}" y1="{y_os - 3}" x2="{xx:.1f}" y2="{y_os + 3}" stroke="#B9BCC6"/>')
            out.append(f'<text x="{xx:.1f}" y="{y_os + 14}" class="tick" text-anchor="middle">{A.mmss(t)[:-3] if krok >= 60_000 and t % 60_000 == 0 else A.mmss(t)}\'</text>')
        t += krok
    if od_ms < 30 * 60_000 < do_ms:
        xx = x(30 * 60_000)
        out.append(f'<line x1="{xx:.1f}" y1="10" x2="{xx:.1f}" y2="{y_os}" stroke="#C9CBD3" stroke-dasharray="3 3"/>')
        out.append(f'<text x="{xx + 4:.1f}" y="12" class="tick">przerwa</text>')

    g = d.get("glowne")
    # pas „kara stała w protokole" - od jej czasu do zegara przy usunięciu
    if g and g.get("usuniecie"):
        x0, x1 = x(g["klucz"][3]), x(g["usuniecie"]["zegar"] or g["klucz"][3])
        out.append(f'<rect x="{x0:.1f}" y="{y_k - 7}" width="{max(2, x1 - x0):.1f}" height="14" rx="7" fill="{RED}" opacity="0.13"/>')
        if etykiety:
            out.append(f'<text x="{x0 + 18:.1f}" y="{y_k - 12}" class="ann red">kara w protokole przez {_e(_sekundy(g.get("trwanie_s")))}</text>')
        out.append(f'<g transform="translate({x1:.1f},{y_k})"><circle r="7" fill="#fff" stroke="{RED}" stroke-width="1.6"/>'
                   f'<path d="M-3,-3 L3,3 M3,-3 L-3,3" stroke="{RED}" stroke-width="1.8" stroke-linecap="round"/></g>')
        if etykiety:
            out.append(f'<text x="{x1 + 10:.1f}" y="{y_k - 12}" class="ann red" text-anchor="end">usunięta przy {A.mmss(g["usuniecie"]["zegar"])}</text>')

    # kary
    for z in d["zyciorysy"]:
        if not z["kara"] or not od_ms <= z["klucz"][3] <= do_ms:
            continue
        xx = x(z["klucz"][3])
        skrot = A.KROTKO.get(z["rodzaj"], "?")
        if z["w_protokole"]:
            out.append(f'<g transform="translate({xx:.1f},{y_k})"><rect x="-12" y="-8" width="24" height="16" rx="4" fill="{ACCENT}"/>'
                       f'<text y="3.5" class="pen" text-anchor="middle" fill="#fff">{skrot}</text></g>')
        else:
            out.append(f'<g transform="translate({xx:.1f},{y_k})"><rect x="-12" y="-8" width="24" height="16" rx="4" fill="#fff" stroke="{RED}" stroke-width="1.4" stroke-dasharray="3 2"/>'
                       f'<text y="3.5" class="pen" text-anchor="middle" fill="{RED}">{skrot}</text></g>')
        if etykiety and od_ms <= z["klucz"][3] <= do_ms:
            out.append(f'<text x="{xx:.1f}" y="{y_k - 12 if not z["w_protokole"] and not g else y_k + 22}" class="ann" text-anchor="middle">{_e(z["czas_meczu"])}</text>')

    # bramki
    po = {id(z) for z in d.get("po_usunieciu") or []}
    nr = 0
    for z in d["zyciorysy"]:
        if z["rodzaj"] not in A.BRAMKI or not z["w_protokole"] or not od_ms <= z["klucz"][3] <= do_ms:
            continue
        xx = x(z["klucz"][3])
        if id(z) in po:
            out.append(f'<circle cx="{xx:.1f}" cy="{y_b}" r="7.5" fill="{GREEN}" stroke="#fff" stroke-width="1.5"/>')
            if etykiety:
                gora = nr % 2 == 0
                ty = y_b - 13 if gora else y_b + 17
                napis = f'{z["czas_meczu"]} · {z["wynik_po"].replace("-", ":")}' + (" ★" if z.get("decydujaca") else "")
                out.append(f'<text x="{xx:.1f}" y="{ty}" class="ann green" text-anchor="middle">{_e(napis)}</text>')
                nr += 1
        else:
            out.append(f'<circle cx="{xx:.1f}" cy="{y_b}" r="4.5" fill="{GREEN}" opacity="0.45"/>')
    out.append("</svg>")
    return "".join(out)


# ─────────────────────────── szablon ───────────────────────────

CSS = """
@page { size: A4; margin: 12mm 0 13mm 0;
  @bottom-left { content: "__STOPKA__"; font: 7.4pt 'Segoe UI', Arial, sans-serif; color: #A3A6B1; margin-left: 14mm; }
  @bottom-right { content: counter(page) " / " counter(pages); font: 7.4pt 'Segoe UI', Arial, sans-serif; color: #A3A6B1; margin-right: 14mm; }
}
@page :first { margin-top: 0; }
* { box-sizing: border-box; margin: 0; padding: 0; }
html { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
body { background: #fff; color: #15171C; font: 9pt/1.42 'Segoe UI', 'Helvetica Neue', Arial, sans-serif; }
.pad { padding: 0 14mm; }
.page2 { break-before: page; }

/* ── nagłówek ── */
.hero { position: relative; overflow: hidden; color: #fff; padding: 9mm 14mm 7mm;
  background: radial-gradient(120% 140% at 100% 0%, rgba(232,151,10,.55) 0%, rgba(194,65,12,.22) 34%, rgba(0,0,0,0) 62%),
              linear-gradient(160deg, #0E1014 0%, #1B1410 58%, #2A1708 100%); }
.hero::after { content: ""; position: absolute; left: 0; right: 0; bottom: 0; height: 3pt;
  background: linear-gradient(90deg, #E8970A, #F2B544 50%, #C2410C); }
.brand { display: flex; align-items: center; gap: 9pt; }
.brand .baza { width: 34pt; height: 34pt; border-radius: 50%; background: #fff; padding: 2pt; }
.brand .proel { width: 50pt; height: 50pt; margin-left: auto; }
.brand .txt { font-size: 7.6pt; font-weight: 800; letter-spacing: 2.6pt; text-transform: uppercase; color: rgba(255,255,255,.72); line-height: 1.5; }
.brand .txt b { color: #fff; letter-spacing: 3pt; }
.kicker { margin-top: 5mm; font-size: 7.6pt; font-weight: 800; letter-spacing: 3pt; text-transform: uppercase; color: #F2B544; }
.who { display: flex; align-items: center; gap: 14pt; margin-top: 4pt; }
.jersey { width: 62pt; height: 62pt; border-radius: 16pt; display: flex; align-items: center; justify-content: center;
  font-size: 34pt; font-weight: 900; letter-spacing: -1.5pt; color: #15171C;
  background: linear-gradient(145deg, #F7C25A, #E8970A 60%, #C2410C); box-shadow: 0 0 0 2pt rgba(255,255,255,.12); }
.who h1 { font-size: 27pt; font-weight: 900; letter-spacing: -1pt; line-height: 1.05; }
.who .role { font-size: 9pt; font-weight: 700; color: rgba(255,255,255,.78); margin-top: 3pt; }
.matchline { display: flex; align-items: center; gap: 10pt; margin-top: 5mm; padding-top: 3.5mm;
  border-top: .7pt solid rgba(255,255,255,.18); font-size: 8.4pt; color: rgba(255,255,255,.75); }
.matchline .score { margin-left: auto; font-size: 10pt; color: #fff; font-weight: 700; }
.matchline .score b { font-size: 15pt; font-weight: 900; letter-spacing: -.4pt; margin: 0 5pt; color: #F2B544; }

/* ── sedno ── */
.verdict { margin-top: 6mm; border-radius: 10pt; padding: 10pt 13pt 10pt 15pt; position: relative;
  background: linear-gradient(135deg, #FFF5F4 0%, #FFFBF5 100%); border: .8pt solid #F6C9C4; }
.verdict::before { content: ""; position: absolute; left: 0; top: 9pt; bottom: 9pt; width: 3.5pt; border-radius: 3pt; background: #D92D20; }
.verdict .eyebrow { color: #D92D20; }
.verdict p { font-size: 10pt; line-height: 1.5; margin-top: 3pt; font-weight: 500; }
.verdict b { font-weight: 800; }

.eyebrow { font-size: 6.9pt; font-weight: 900; letter-spacing: 2.6pt; text-transform: uppercase; color: #E8970A; }
h2 { font-size: 15pt; font-weight: 900; letter-spacing: -.5pt; margin-top: 1pt; }
.sec { margin-top: 5.5mm; }
.lead { color: #6B6F7B; font-size: 8.4pt; margin-top: 2pt; }

/* ── kafle ── */
.kpis { display: grid; grid-template-columns: repeat(4, 1fr); gap: 6pt; margin-top: 5mm; }
.kpi { border-radius: 9pt; padding: 8pt 10pt; background: #FAFAFB; border: .7pt solid #ECEDF0; border-left: 2.6pt solid #E8970A; }
.kpi .v { font-size: 18pt; font-weight: 900; letter-spacing: -.8pt; line-height: 1.1; }
.kpi .v small { font-size: 10pt; color: #A3A6B1; font-weight: 800; letter-spacing: 0; }
.kpi .l { font-size: 6.8pt; font-weight: 900; letter-spacing: 1.1pt; text-transform: uppercase; color: #6B6F7B; margin-top: 2pt; }
.kpi.red { border-left-color: #D92D20; } .kpi.red .v { color: #D92D20; }
.kpi.green { border-left-color: #15803D; } .kpi.green .v { color: #15803D; }

/* ── osie ── */
.chart { margin-top: 4pt; border: .7pt solid #ECEDF0; border-radius: 10pt; padding: 8pt 10pt 4pt; }
.chart .cap { font-size: 7pt; font-weight: 900; letter-spacing: 1.4pt; text-transform: uppercase; color: #A3A6B1; margin-bottom: 2pt; }
svg.os { width: 100%; height: auto; display: block; }
svg .tor { font: 800 7px 'Segoe UI', Arial; letter-spacing: 1.2px; fill: #A3A6B1; }
svg .tick { font: 600 7.5px 'Segoe UI', Arial; fill: #8B8F9A; }
svg .pen { font: 900 8.5px 'Segoe UI', Arial; }
svg .ann { font: 700 8px 'Segoe UI', Arial; fill: #4B4F5B; }
svg .ann.red { fill: #D92D20; } svg .ann.green { fill: #15803D; }
.legend { display: flex; gap: 12pt; font-size: 7.4pt; color: #6B6F7B; margin-top: 4pt; flex-wrap: wrap; }
.legend i { display: inline-block; width: 9pt; height: 9pt; border-radius: 2pt; vertical-align: -1.5pt; margin-right: 3pt; }

/* ── oś zapisu ── */
.tl { margin-top: 5pt; position: relative; }
.tl .row { display: grid; grid-template-columns: 50pt 16pt 1fr; gap: 0 6pt; break-inside: avoid; }
.tl .time { text-align: right; font-weight: 800; font-size: 8.6pt; font-variant-numeric: tabular-nums; padding-top: 5pt; }
.tl .time small { display: block; font-weight: 600; font-size: 7pt; color: #A3A6B1; }
.tl .rail { position: relative; }
.tl .rail::before { content: ""; position: absolute; left: 7pt; top: 0; bottom: 0; width: 1.4pt; background: #E6E7EB; }
.tl .row:first-child .rail::before { top: 9pt; } .tl .row:last-child .rail::before { bottom: auto; height: 9pt; }
.tl .dot { position: absolute; left: 2.5pt; top: 6.5pt; width: 10pt; height: 10pt; border-radius: 50%; background: #fff; border: 2.2pt solid #E8970A; }
.tl .card { margin: 1.5pt 0 2.5pt; padding: 3.5pt 9pt; border-radius: 8pt; background: #FAFAFB; border: .7pt solid #ECEDF0; }
.tl .card .t { font-weight: 800; font-size: 9pt; }
.tl .card .m { color: #6B6F7B; font-size: 7.8pt; margin-top: 1pt; }
.tl .card .c { font-size: 7.6pt; margin-top: 2pt; color: #4B4F5B; }
.tl .row.red .dot { border-color: #D92D20; background: #D92D20; } .tl .row.red .card { background: #FFF5F4; border-color: #F6C9C4; } .tl .row.red .t { color: #B42318; }
.tl .row.green .dot { border-color: #15803D; background: #15803D; } .tl .row.green .card { background: #F2FBF5; border-color: #BFE5CB; } .tl .row.green .t { color: #15803D; }
.tl .row.gap .card { background: none; border: 0; padding: 0 9pt; color: #A3A6B1; font-style: italic; font-size: 7.8pt; }
.tl .row.gap .dot { width: 6pt; height: 6pt; left: 4.5pt; top: 3pt; border-width: 1.4pt; border-color: #C9CBD3; }
.tl .row.gap .time { padding-top: 0; }

/* ── dwie kolumny ── */
.cols { display: grid; grid-template-columns: .8fr 1.2fr; gap: 9pt; margin-top: 4pt; }
.box { border: .7pt solid #ECEDF0; border-radius: 10pt; padding: 8pt 10pt; }
.box h3 { font-size: 7.2pt; font-weight: 900; letter-spacing: 1.6pt; text-transform: uppercase; color: #6B6F7B; margin-bottom: 5pt; }
.person { display: flex; gap: 8pt; align-items: flex-start; padding: 4pt 0; border-top: .6pt solid #F0F1F4; }
.person:first-of-type { border-top: 0; }
.avatar { flex: 0 0 22pt; height: 22pt; border-radius: 50%; display: flex; align-items: center; justify-content: center;
  font-size: 8pt; font-weight: 900; color: #fff; background: linear-gradient(145deg, #F2B544, #C2410C); }
.person .n { font-weight: 800; } .person .r { color: #6B6F7B; font-size: 7.6pt; }
.person .sum { font-size: 7.6pt; color: #4B4F5B; margin-top: 2pt; }
.person ul { margin: 2pt 0 0 0; list-style: none; font-size: 7.8pt; color: #4B4F5B; }
.person li { padding: 1pt 0; } .person li b { font-variant-numeric: tabular-nums; color: #15171C; margin-right: 4pt; }
.step { display: grid; grid-template-columns: 26pt 1fr auto; gap: 6pt; padding: 2.6pt 0; border-top: .6pt solid #F0F1F4; font-size: 7.8pt; align-items: baseline; }
.step:first-of-type { border-top: 0; }
.steps2 { display: grid; grid-template-columns: 1fr 1fr; column-gap: 14pt; grid-auto-flow: column;
  grid-template-rows: repeat(__WIERSZE__, auto); }
.steps2 .step { border-top: 0; border-bottom: .6pt solid #F0F1F4; }
.step .h { font-weight: 800; font-variant-numeric: tabular-nums; }
.step .w { color: #6B6F7B; font-size: 7.2pt; text-align: right; }
.step.key { background: linear-gradient(90deg, rgba(232,151,10,.10), rgba(232,151,10,0)); border-radius: 5pt; padding-left: 4pt; }

.why { margin-top: 4pt; display: grid; grid-template-columns: repeat(4, 1fr); gap: 5pt; }
.why div { border-radius: 8pt; padding: 6pt 8pt; background: #FAFAFB; border: .7pt solid #ECEDF0; font-size: 7.5pt; line-height: 1.35; color: #4B4F5B; }
.why b { display: block; font-size: 8pt; margin-bottom: 2pt; color: #15171C; }

.meta { margin-top: 4mm; padding-top: 4pt; border-top: .7pt solid #ECEDF0;
  font-size: 7.2pt; color: #6B6F7B; }
"""


def _podsumuj(czynnosci: List[Tuple[str, str]]) -> str:
    """„3 wpisania kar · 2 poprawki czasu · 1 usunięcie · 18:22-19:47"."""
    wp = sum(1 for _g, t in czynnosci if t.startswith("wpisanie"))
    po = sum(1 for _g, t in czynnosci if t.startswith(("poprawka", "zmiana")))
    us = sum(1 for _g, t in czynnosci if t.startswith(("usunięcie", "przeniesienie")))
    cz = []
    if wp:
        cz.append(f"{wp} {'wpisanie kary' if wp == 1 else 'wpisania kar' if wp < 5 else 'wpisań kar'}")
    if po:
        cz.append(f"{po} {'poprawka' if po == 1 else 'poprawki' if po < 5 else 'poprawek'}")
    if us:
        cz.append(f"{us} {'usunięcie' if us == 1 else 'usunięcia' if us < 5 else 'usunięć'}")
    if czynnosci:
        cz.append(f"{czynnosci[0][0][:5]}-{czynnosci[-1][0][:5]}")
    return " · ".join(cz)


def _inicjaly(nazwa: str) -> str:
    cz = [c for c in str(nazwa or "").split() if c]
    return "".join(c[0] for c in cz[:2]).upper() or "?"


def html_osoby(d: Dict[str, Any]) -> str:
    """Sama treść: bez podpisów, sum kontrolnych i numerów wersji (decyzja 09.10.2026)."""
    m, o, g = d["mecz"], d["osoba"], d.get("glowne")
    nazwa = o["nazwisko"] or f"nr {o['numer']}"
    kara_etyk = {"penalty3": "III kara 2 min", "disqualification": "Dyskwalifikacja", "disqualificationBlue": "Dyskwalifikacja z opisem"}
    host, guest = d["wynik_koncowy"]

    # ── sedno sprawy jednym akapitem
    if g and g.get("usuniecie"):
        u = g["usuniecie"]
        zdanie = (f"<b>{_e(kara_etyk.get(g['rodzaj'], g['opis']))}</b>"
                  + (" (= dyskwalifikacja)" if g["rodzaj"] == "penalty3" else "")
                  + f" z {_e(g['czas_meczu'])} była w protokole <b>{_e(_sekundy(g.get('trwanie_s')))}</b>. "
                  f"Usunięto ją o <b>{_e(A.godz(u['czas']))}</b>, przy zegarze {_e(A.mmss(u['zegar']))} i wyniku {_e(u['wynik'])}.")
        po = d.get("po_usunieciu") or []
        if po:
            pierwsza = po[0]
            zdanie += (f" <b>{_e(_sekundy(pierwsza['po_usunieciu_s']))} później</b> zapisano bramkę {_e(nazwa)} "
                       f"na {_e(pierwsza['wynik_po'].replace('-', ':'))}"
                       + (" - <b>decydującą o wyniku meczu</b>" if pierwsza.get("decydujaca") else ""))
            if len(po) > 1:
                reszta = po[1:]
                zdanie += ", a następnie " + ", ".join(
                    f"o {_e(A.godz(z['wpis']['czas']))} bramkę na {_e(z['wynik_po'].replace('-', ':'))}"
                    + (" - <b>decydującą o wyniku meczu</b>" if z.get("decydujaca") else "") for z in reszta)
            zdanie += "."
        kary_konc = sum(1 for z in d["zyciorysy"] if z["kara"] and z["w_protokole"])
        zdanie += f" W zatwierdzonym protokole i w bazie ZPRP zostały <b>{kary_konc} kary</b>." if kary_konc in (2, 3, 4) else \
            f" W zatwierdzonym protokole i w bazie ZPRP: kar - {kary_konc}."
    else:
        zdanie = "W zachowanej historii zapisu żadna kara tej osoby nie została usunięta ani przeniesiona."

    # ── kafle
    kary_max = sum(1 for z in d["zyciorysy"] if z["kara"])
    kary_konc = sum(1 for z in d["zyciorysy"] if z["kara"] and z["w_protokole"])
    kafle = [
        ("red" if kary_max != kary_konc else "", f"{kary_max} <small>→</small> {kary_konc}", "kary: mecz → protokół"),
        ("red", _sekundy(g.get("trwanie_s")) if g and g.get("trwanie_s") else "-", "kara w protokole"),
        ("green", str(len(d.get("po_usunieciu") or [])), "bramki po usunięciu"),
        ("", f"{d['usuniec_w_meczu']}", "usunięć zdarzeń w całym meczu"),
    ]

    # ── oś zapisu (godziny): każdy krok w kolejności zapisu
    wiersze: List[Tuple[Any, str, str, str, str, str]] = []  # (czas utc, klasa, godz, tytuł, meta, kontekst)

    autorzy = {e["autor"] for e in d["edytorzy"]} | {z["wpis"]["autor"] for z in d.get("po_usunieciu") or []}
    jeden = next(iter(autorzy)) if len(autorzy) == 1 else None

    def wiersz(klasa: str, ch: Dict[str, Any], tytul: str, kontekst: str = "", z_wynikiem: bool = True) -> None:
        meta = f"zegar {A.mmss(ch['zegar'])}" + (f" · wynik {ch['wynik']}" if z_wynikiem else "")
        if not jeden:
            meta += f" · zapisał {ch['autor']}" + (f" ({ch['rola']})" if ch.get("rola") else "")
        wiersze.append((A.czas_utc(ch["czas"]), klasa, A.godz(ch["czas"]), tytul, meta, kontekst))

    for z in d["zyciorysy"]:
        if not z["kara"]:
            continue
        kw = z["klucz_wpisu"]
        if z is g:
            kont = "; ".join(
                f"{k['czas_meczu']} {k['opis'].lower()}: {k['kto']}" + (f", wynik {k['wynik'].replace('-', ':')}" if k["wynik"] else "")
                for k in d["kontekst"][:4])
            wiersz("red", z["wpis"], f"Wpisano {BIERNIK.get(kw[0], kw[0])} ({A.mmss(kw[3])})"
                   + (" → dyskwalifikacja" if kw[0] == "penalty3" else ""),
                   ("W tej samej akcji: " + kont) if kont else "")
        else:
            wiersz("", z["wpis"], f"Wpisano {BIERNIK.get(kw[0], kw[0])} ({A.mmss(kw[3])})")
        for pp in z["poprawki"]:
            tytul = (f"Poprawka czasu {DOPELNIACZ.get(pp['z'][0], pp['z'][0])}: {A.mmss(pp['z'][3])} → {A.mmss(pp['na'][3])}"
                     if pp["rodzaj"] == "czas" else
                     f"Zmiana {DOPELNIACZ.get(pp['z'][0], pp['z'][0])} na {A.RODZAJE.get(pp['na'][0], pp['na'][0]).lower()}")
            wiersz("", pp, tytul, z_wynikiem=False)
        if z["usuniecie"]:
            wiersz("red", z["usuniecie"], f"Usunięto {BIERNIK.get(z['rodzaj'], z['rodzaj'])} z {z['czas_meczu']}"
                   + (" i dyskwalifikację" if z["rodzaj"] == "penalty3" else ""))
            n_mid = z.get("zdarzen_w_miedzyczasie")
            if n_mid:
                t_gap = A.czas_utc(z["usuniecie"]["czas"])
                wiersze.append((t_gap, "gap", "", f"przez {_sekundy(z.get('trwanie_s'))} kara stoi w protokole, "
                                f"do przebiegu dochodzi {n_mid} kolejnych zdarzeń meczu", "", ""))
        if z["przeniesienie"]:
            wiersz("red", z["przeniesienie"], f"Przeniesiono {BIERNIK.get(z['rodzaj'], z['rodzaj'])} na {z['przeniesienie']['na']}")
    for z in d.get("po_usunieciu") or []:
        wiersz("green", z["wpis"], f"Bramka {nazwa} na {z['wynik_po'].replace('-', ':')} ({z['czas_meczu']})"
               + (" - decydująca o wyniku" if z.get("decydujaca") else ""),
               f"{_sekundy(z['po_usunieciu_s'])} po usunięciu kary")
    # Przerwa („kara stoi") ma tę samą chwilę co usunięcie, ale stoi PRZED nim.
    wiersze.sort(key=lambda w: (w[0], 0 if w[1] == "gap" else 1))
    tl = "".join(
        f'<div class="row {k}"><div class="time">{_e(h)}</div><div class="rail"><span class="dot"></span></div>'
        f'<div class="card"><div class="t">{_e(t)}</div>'
        + (f'<div class="m">{_e(me)}</div>' if me else "")
        + (f'<div class="c">{_e(c)}</div>' if c else "")
        + "</div></div>"
        for _ts, k, h, t, me, c in wiersze)

    # ── kto dotykał
    ludzie = "".join(
        f'<div class="person"><div class="avatar">{_e(_inicjaly(e["autor"]))}</div><div>'
        f'<div class="n">{_e(e["autor"])}</div><div class="r">{_e(e["rola"] or "spoza obsady protokołu")}'
        + (f' · nr {_e(e["numer"])}' if e["numer"] else "") + (f' · urządzenie …{_e(e["urzadzenie"][-6:])}' if e["urzadzenie"] else "")
        + "</div>" + f'<div class="sum">{_e(_podsumuj(e["czynnosci"]))}</div>' + "</div></div>"
        for e in d["edytorzy"])

    # ── droga protokołu
    kroki = "".join(
        f'<div class="step{" key" if x["zdarzenie"] in ("match.approved", "zprp.players_sent") else ""}"><div class="h">{_e(A.godz(x["czas"])[:5])}</div>'
        f'<div>{_e(x["co"])}</div><div class="w">{_e(x["kto"])}' + (f' · {_e(x["rola"])}' if x["rola"] else "") + "</div></div>"
        for x in d["droga"])

    # ── dlaczego to istotne (fakty, bez ocen)
    why: List[Tuple[str, str]] = []
    if g and g["rodzaj"] == "penalty3":
        why.append(("Trzecia kara 2 min = dyskwalifikacja", "Po trzecim wykluczeniu zawodniczka nie może wrócić do gry - w karcie pojawiła się czerwona kartka."))
    if g and g.get("zdarzen_w_miedzyczasie"):
        why.append(("To nie była poprawka „na gorąco”", f"Kara stała w protokole {_sekundy(g.get('trwanie_s'))}; w tym czasie wpisano {g['zdarzen_w_miedzyczasie']} kolejnych zdarzeń, które zostały."))
    if g and g.get("usuniecie"):
        zostalo = max(0, 3_600_000 - int(g["usuniecie"]["zegar"] or 0)) / 1000
        remis = len(set(g["usuniecie"]["wynik"].split(":"))) == 1
        why.append(("Moment usunięcia", f"{_sekundy(zostalo)} przed końcem" + (f", przy remisie {g['usuniecie']['wynik']}" if remis else f", przy wyniku {g['usuniecie']['wynik']}") + "."))
    if d["usuniec_w_meczu"] == 1 and g:
        why.append(("Jedyne usunięcie w meczu", "Pozostałe zmiany w protokole tego meczu to wyłącznie poprawki czasu zdarzeń."))
    why_html = "".join(f"<div><b>{_e(t)}</b>{_e(s)}</div>" for t, s in why)

    obsada = " · ".join(f"{r}: {n}" for r, n in d["obsada"])

    plec = A.plec_z_kodu(m["numer"])
    rola_osoby = {"k": "Zawodniczka", "m": "Zawodnik"}.get(plec or "", "Zawodnik")
    stopka = f"BAZA · ProEl · {m['numer']} · {nazwa}".replace('"', "")

    return f"""<!doctype html><html lang="pl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(nazwa)} - {_e(m['numer'])} - historia zapisu</title>
<style>{CSS.replace("__STOPKA__", stopka).replace("__WIERSZE__", str(max(1, (len(d["droga"]) + 1) // 2)))}</style></head><body>

<header class="hero">
  <div class="brand">
    <img class="baza" src="{_logo(LOGO_BAZA, 160)}" alt="BAZA">
    <div class="txt"><b>BAZA</b> · ProEl<br>protokół elektroniczny</div>
    <img class="proel" src="{_logo(LOGO_PROEL, 200)}" alt="ProEl">
  </div>
  <div class="kicker">Historia zapisu protokołu elektronicznego</div>
  <div class="who">
    <div class="jersey">{_e(o['numer'])}</div>
    <div><h1>{_e(nazwa)}</h1>
      <div class="role">{_e(rola_osoby)} · {_e(o['druzyna_nazwa'])} ({_e(o['strona'])})</div></div>
  </div>
  <div class="matchline">
    <span>Mecz <b style="color:#fff">{_e(m['numer'])}</b> · {_e(m['data'])}{(' · ' + _e(m['hala'].split(',')[-1].strip())) if m['hala'] else ''}</span>
    <span class="score">{_e(m['gospodarze'])}<b>{_e(host)}:{_e(guest)}</b>{_e(m['goscie'])}</span>
  </div>
</header>

<main class="pad">
  <section class="verdict">
    <div class="eyebrow">Sedno sprawy</div>
    <p>{zdanie}</p>
  </section>

  <div class="kpis">{''.join(f'<div class="kpi {k}"><div class="v">{v}</div><div class="l">{_e(l)}</div></div>' for k, v, l in kafle)}</div>

  <section class="sec">
    <div class="eyebrow">Czas meczu</div>
    <h2>Gdzie to się wydarzyło</h2>
    <div class="chart"><div class="cap">Cały mecz · 0-60 min</div>{_os_meczu(d, 0, 3_600_000, wys=68, etykiety=False)}</div>
    {('<div class="chart" style="margin-top:6pt"><div class="cap">Przybliżenie · ' + _e(A.mmss(max(0, (g['klucz'][3] // 60000 - 1) * 60000))) + ' - 60:00</div>'
      + _os_meczu(d, max(0, (g['klucz'][3] // 60000 - 1) * 60000), 3_600_000, wys=118, etykiety=True) + '</div>') if g else ''}
    <div class="legend">
      <span><i style="background:{ACCENT}"></i>kara w zatwierdzonym protokole</span>
      <span><i style="background:#fff;border:1.2pt dashed {RED}"></i>kara usunięta</span>
      <span><i style="background:rgba(217,45,32,.18)"></i>czas, gdy kara stała w protokole</span>
      <span><i style="background:{GREEN};border-radius:50%"></i>bramka po usunięciu kary (★ decydująca)</span>
    </div>
  </section>

  {('<section class="sec"><div class="eyebrow">Dlaczego to istotne</div><div class="why">' + why_html + '</div></section>') if why_html else ''}

  <section class="page2">
    <div class="eyebrow">Historia zapisu</div>
    <h2>Jak zmieniał się protokół - krok po kroku</h2>
    <p class="lead">Godziny według zegara serwera ProEl (czas polski), „zegar” to czas meczu w chwili zapisu.{(' Wszystkie poniższe zapisy wykonano z urządzenia: <b style="color:#15171C">' + _e(jeden) + (' (' + _e(d['edytorzy'][0]['rola']) + (', nr ' + _e(d['edytorzy'][0]['numer']) if d['edytorzy'][0]['numer'] else '') + ')' if d['edytorzy'] and d['edytorzy'][0]['rola'] else '') + '</b>.') if jeden else ''}</p>
    <div class="tl">{tl}</div>
  </section>

  <section class="sec">
    <div class="eyebrow">Ludzie</div>
    <h2>Kto i kiedy</h2>
    {('<div class="box" style="margin-top:4pt"><h3>Droga protokołu po meczu</h3><div class="steps2">' + (kroki or '<div class="r">Brak wpisów.</div>') + '</div></div>')
      if jeden else
     ('<div class="cols"><div class="box"><h3>Kto edytował zapisy ' + _e(nazwa) + '</h3>' + (ludzie or '<div class="r">Brak edycji.</div>')
      + '</div><div class="box"><h3>Droga protokołu po meczu</h3>' + (kroki or '<div class="r">Brak wpisów.</div>') + '</div></div>')}
  </section>

  <section class="meta">
    <div><b>Obsada w protokole:</b> {_e(obsada)}</div>
  </section>
</main>
</body></html>"""
