"""Wydruk raportu - HTML pod A4, z którego przeglądarka robi PDF.

Bez szablonów i bez zależności: każdy napis z danych przechodzi przez
`_e` (escape), bo nazwiska i uwagi pochodzą od użytkowników.
Numeracja stron i stopka idą przez `@page` (Chromium 131+, czyli każdy
aktualny Edge i Chrome).
"""
from __future__ import annotations

import html
from datetime import datetime
from typing import Any, Dict, List, Optional

from app.raport_dowodowy.analiza import KROTKO, data_godz, godz, mmss

CSS = """
@page {
  size: A4;
  margin: 16mm 14mm 18mm 14mm;
  @bottom-left { content: "Raport __NR__ · BAZA ProEl"; font: 8pt 'Segoe UI', Arial, sans-serif; color: #6b7280; }
  @bottom-right { content: "Strona " counter(page) " z " counter(pages); font: 8pt 'Segoe UI', Arial, sans-serif; color: #6b7280; }
}
:root {
  --ink: #16191d; --muted: #5d6673; --rule: #d8dce2; --soft: #f4f6f8;
  --accent: #b36d00; --accent-soft: #fff5e3; --red: #b42318; --red-soft: #fdeceb;
  --amber-soft: #fff8e6; --blue: #1d4ed8;
}
* { box-sizing: border-box; }
html { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
body { margin: 0; background: #fff; color: var(--ink);
  font: 9.4pt/1.45 'Segoe UI', 'Helvetica Neue', Arial, sans-serif; }
.strona { max-width: 182mm; margin: 0 auto; }
h1, h2, h3 { font-family: Georgia, 'Times New Roman', serif; font-weight: 700; margin: 0; }
h2 { font-size: 12.5pt; margin: 18pt 0 6pt; padding-bottom: 3pt; border-bottom: 1.2pt solid var(--ink);
  break-after: avoid; }
h2 .nr { color: var(--accent); margin-right: 6pt; }
p { margin: 0 0 5pt; }
.naglowek { border-top: 4pt solid var(--accent); padding-top: 10pt; margin-bottom: 12pt; }
.naglowek .gora { display: flex; justify-content: space-between; align-items: baseline;
  font-size: 8.2pt; letter-spacing: .08em; text-transform: uppercase; color: var(--muted); }
.naglowek .marka b { color: var(--ink); letter-spacing: .12em; }
.naglowek h1 { font-size: 21pt; margin: 8pt 0 3pt; letter-spacing: -.01em; }
.naglowek .pod { font-size: 10.5pt; color: var(--muted); }
.siatka { display: grid; grid-template-columns: 1fr 1fr; gap: 0 18pt; border: 1pt solid var(--rule);
  border-radius: 3pt; padding: 8pt 11pt; }
.siatka div { display: flex; gap: 8pt; padding: 2.5pt 0; border-bottom: .6pt dotted var(--rule); }
.siatka div:nth-last-child(-n+2) { border-bottom: 0; }
.siatka dt { flex: 0 0 31mm; color: var(--muted); }
.siatka dd { margin: 0; font-weight: 600; }
.osoba { display: flex; justify-content: space-between; align-items: center; gap: 12pt;
  background: var(--soft); border-left: 3pt solid var(--accent); padding: 9pt 12pt; margin-top: 10pt; }
.osoba .kto { font-family: Georgia, serif; font-size: 15pt; font-weight: 700; }
.osoba .gdzie { color: var(--muted); }
.osoba .nr-koszulki { font-family: Georgia, serif; font-size: 26pt; font-weight: 700; color: var(--accent);
  line-height: 1; }
.ustalenia { list-style: none; counter-reset: u; padding: 0; margin: 0; }
.ustalenia li { counter-increment: u; position: relative; padding: 6pt 9pt 6pt 30pt; margin-bottom: 4pt;
  border: .8pt solid var(--rule); border-radius: 3pt; break-inside: avoid; }
.ustalenia li::before { content: counter(u); position: absolute; left: 8pt; top: 5.5pt; width: 15pt; height: 15pt;
  border-radius: 50%; background: var(--ink); color: #fff; font-size: 7.6pt; font-weight: 700;
  display: flex; align-items: center; justify-content: center; }
.ustalenia li.uwaga { background: var(--accent-soft); border-color: #f0c879; }
.ustalenia li.uwaga::before { background: var(--accent); }
table { width: 100%; border-collapse: collapse; font-size: 8.6pt; }
thead { display: table-header-group; }
th { text-align: left; font-weight: 600; color: var(--muted); font-size: 7.6pt; text-transform: uppercase;
  letter-spacing: .04em; border-bottom: 1pt solid var(--ink); padding: 3pt 5pt; }
td { border-bottom: .6pt solid var(--rule); padding: 3.5pt 5pt; vertical-align: top; }
tr { break-inside: avoid; }
tr.usun td { background: var(--red-soft); }
tr.usun td:first-child { box-shadow: inset 2.5pt 0 0 var(--red); }
tr.popr td { background: var(--amber-soft); }
tr.popr td:first-child { box-shadow: inset 2.5pt 0 0 var(--accent); }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; white-space: nowrap; }
.mono { font-family: Consolas, 'Courier New', monospace; font-size: 8pt; }
.cicho { color: var(--muted); }
.chip { display: inline-block; min-width: 18pt; text-align: center; padding: .5pt 4pt; border-radius: 2pt;
  font-weight: 700; font-size: 7.6pt; background: #e5e7eb; color: var(--ink); margin-right: 3pt; }
.chip.U { background: #fde68a; } .chip.D { background: #dc2626; color: #fff; }
.chip.DN { background: #1d4ed8; color: #fff; } .chip.Kd { background: #ede9fe; color: #5b21b6; }
.chip.B, .chip.m7 { background: #dcfce7; color: #166534; }
.zmiana { display: block; }
.zmiana.usun { color: var(--red); font-weight: 600; }
.krok { border: .8pt solid var(--rule); border-radius: 3pt; padding: 6pt 9pt; margin-bottom: 5pt; break-inside: avoid; }
.krok .meta { color: var(--muted); font-size: 8.2pt; margin-bottom: 2pt; }
.krok .z { padding-left: 10pt; position: relative; }
.krok .z::before { content: "•"; position: absolute; left: 1pt; color: var(--muted); }
.krok .z.osoby { font-weight: 700; color: var(--red); }
.krok .z.osoby::before { content: "▸"; color: var(--red); }
.uwagi-metodyczne { font-size: 8.2pt; color: var(--muted); border-top: .8pt solid var(--rule); padding-top: 6pt; }
.podpisy { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 16pt; margin-top: 26pt; break-inside: avoid; }
.podpisy div { border-top: .8pt solid var(--ink); padding-top: 3pt; font-size: 8pt; color: var(--muted); }
.podpisy b { display: block; color: var(--ink); font-size: 9pt; min-height: 12pt; }
.zalacznik { break-before: page; }
.puste { color: var(--muted); font-style: italic; }
"""


def _e(v: Any) -> str:
    return html.escape("" if v is None else str(v))


def _chip(rodzaj: str) -> str:
    skrot = KROTKO.get(rodzaj, "")
    if not skrot:
        return ""
    klasa = {"D+N": "DN", "7m": "m7", "7m×": "m7"}.get(skrot, skrot)
    return f'<span class="chip {klasa}">{_e(skrot)}</span>'


_SKROT_Z_OPISU = {
    "Upomnienie (żółta kartka)": "warning", "I kara 2 min": "penalty1", "II kara 2 min": "penalty2",
    "III kara 2 min": "penalty3", "Kara dodatkowa 2 min (Kd)": "penaltyExtra",
    "Dyskwalifikacja (czerwona kartka)": "disqualification",
    "Dyskwalifikacja z opisem (niebieska kartka)": "disqualificationBlue",
    "Bramka": "goal", "Rzut karny 7 m - bramka": "penaltyKickScored",
    "Rzut karny 7 m - niewykorzystany": "penaltyKickMissed",
}


def _wiersz_siatki(etykieta: str, wartosc: Any) -> str:
    return f"<div><dt>{_e(etykieta)}</dt><dd>{_e(wartosc) if wartosc not in (None, '') else '<span class=cicho>-</span>'}</dd></div>"


def _sekcja(nr: str, tytul: str, tresc: str, klasa: str = "") -> str:
    return f'<section class="{klasa}"><h2><span class="nr">{_e(nr)}</span>{_e(tytul)}</h2>{tresc}</section>'


def html_raportu(
    a: Dict[str, Any],
    *,
    numer_raportu: str,
    sha256: str,
    autor: Optional[str] = None,
    wygenerowano: Optional[datetime] = None,
) -> str:
    m = a["mecz"]
    o = a.get("osoba")
    z = a["zrodla"]
    teraz = (wygenerowano or datetime.now()).strftime("%d.%m.%Y %H:%M")
    czesci: List[str] = []

    tytul = "Raport z historii zapisu meczu"
    pod = f"Protokół elektroniczny ProEl · mecz {m['numer']} · {m['gospodarze']} - {m['goscie']}"
    if o:
        pod += f" · {o['etykieta']}"
    czesci.append(f"""
<header class="naglowek">
  <div class="gora"><span class="marka"><b>BAZA</b> · ProEl · protokół elektroniczny</span>
  <span>Raport nr <b>{_e(numer_raportu)}</b></span></div>
  <h1>{_e(tytul)}</h1>
  <div class="pod">{_e(pod)}</div>
</header>""")

    siatka = "".join([
        _wiersz_siatki("Numer meczu", m["numer"]),
        _wiersz_siatki("Id meczu ZPRP", m["id_zprp"]),
        _wiersz_siatki("Termin", m["data"]),
        _wiersz_siatki("Hala", m["hala"]),
        _wiersz_siatki("Gospodarze", m["gospodarze"]),
        _wiersz_siatki("Goście", m["goscie"]),
        _wiersz_siatki("Wynik końcowy", m["wynik"]),
        _wiersz_siatki("Status protokołu", m["status"]),
        _wiersz_siatki("Zatwierdził", f"{m['zatwierdzil']}, {data_godz(m['zatwierdzono'])}" if m["zatwierdzil"] else ""),
        _wiersz_siatki("Wersja zapisu", m["wersja"]),
        _wiersz_siatki("Sędziowie", ", ".join(x for x in (m["sedzia1"], m["sedzia2"]) if x)),
        _wiersz_siatki("Delegat", m["delegat"]),
        _wiersz_siatki("Sekretarz", m["sekretarz"]),
        _wiersz_siatki("Mierzący czas", m["mierzacy"]),
    ])
    czesci.append(f'<dl class="siatka">{siatka}</dl>')

    if o:
        czesci.append(f"""
<div class="osoba">
  <div><div class="cicho">{_e(o['rola'])} objęta raportem</div>
  <div class="kto">{_e(o['nazwisko'] or '(brak nazwiska w składzie)')}</div>
  <div class="gdzie">{_e(o['druzyna_nazwa'])} · {_e(o['strona'])}</div></div>
  <div class="nr-koszulki">{_e(o['numer'])}</div>
</div>""")

    nr = 1
    # ── ustalenia
    lista = "".join(f'<li class="{_e(u["waga"])}">{_e(u["tekst"])}</li>' for u in a["ustalenia"])
    czesci.append(_sekcja(f"{nr}.", "Najważniejsze ustalenia", f'<ol class="ustalenia">{lista}</ol>'))
    nr += 1

    if o:
        # ── stan końcowy
        if o["zdarzenia_koniec"]:
            wiersze = "".join(
                f"<tr><td>{_chip(_SKROT_Z_OPISU.get(zd['opis'], ''))}{_e(zd['opis'])}</td>"
                f"<td class=num>{_e(zd['czas'])}</td><td class=num>{_e(zd['polowa'] or '-')}</td>"
                f"<td class=num>{_e(zd['wynik'] or '-')}</td><td class=num>{_e(godz(zd['zapisano']))}</td></tr>"
                for zd in o["zdarzenia_koniec"])
            tabela = (f"<table><thead><tr><th>Zdarzenie</th><th class=num>Czas meczu</th><th class=num>Połowa</th>"
                      f"<th class=num>Wynik</th><th class=num>Zapisano o</th></tr></thead><tbody>{wiersze}</tbody></table>")
        else:
            tabela = '<p class="puste">Brak zdarzeń tej osoby w końcowym zapisie.</p>'
        wstep = (f"<p>Zdarzenia {_e(o['etykieta'])} w ostatniej wersji protokołu "
                 f"(status: {_e(m['status'].lower())}). Bramki w karcie zawodnika: <b>{_e(o['bramki'] or 0)}</b>.</p>")
        czesci.append(_sekcja(f"{nr}.", "Stan w końcowym zapisie protokołu", wstep + tabela))
        nr += 1

        # ── historia
        if o["historia"]:
            wiersze = []
            for i, h in enumerate(o["historia"], 1):
                me = h["meta"]
                klasa = "usun" if any(r in ("usuniete", "osoba", "rodzaj") for r in h["rodzaje"]) else (
                    "popr" if "czas" in h["rodzaje"] else "")
                zmiany = "".join(
                    f'<span class="zmiana{" usun" if t.startswith(("Usunięto", "Przeniesienie", "Zmiana rodzaju")) else ""}">{_e(t)}</span>'
                    for t in h["zmiany"])
                zrodlo = "" if me["zrodlo"] == "server" else " <span class=cicho>(z telefonu)</span>"
                wiersze.append(
                    f'<tr class="{klasa}"><td class=num>{i}</td><td class=num>{_e(godz(me["czas"]))}{zrodlo}</td>'
                    f'<td class=num>{_e(mmss(me["zegar"]))}</td><td class=num>{_e(me["wynik"])}</td>'
                    f'<td>{zmiany}</td><td>{_e(h["stan"])}</td><td>{_e(me["autor"] or "-")}</td>'
                    f'<td class="num mono">#{_e(me["id"])}<br><span class=cicho>v{_e(me["rev"])}</span></td></tr>')
            tabela = ("<table><thead><tr><th class=num>Lp.</th><th class=num>Godz. zapisu</th><th class=num>Zegar</th>"
                      "<th class=num>Wynik</th><th>Zmiana</th><th>Stan kar po zmianie</th><th>Zapisał</th>"
                      "<th class=num>Wersja</th></tr></thead><tbody>" + "".join(wiersze) + "</tbody></table>")
            legenda = ('<p class="cicho" style="margin-top:4pt">Czerwone tło: usunięcie, przeniesienie albo zmiana '
                       'rodzaju kary. Żółte tło: poprawka czasu. „Zegar" to czas meczu w chwili zapisu, '
                       '„Wersja" to numer migawki w archiwum i numer wersji treści.</p>')
        else:
            tabela, legenda = '<p class="puste">W zachowanej historii nie ma żadnej zmiany kar tej osoby.</p>', ""
        czesci.append(_sekcja(f"{nr}.", "Przebieg zmian kar wersja po wersji",
                              "<p>Każdy wiersz to zapis protokołu, który zmienił kary tej osoby, "
                              "albo jakakolwiek ingerencja w jej zdarzenia.</p>" + tabela + legenda))
        nr += 1

    # ── korekty w całym meczu
    if a["korekty"]:
        bloki = []
        for k in a["korekty"]:
            po = k["po"]
            zm = "".join(f'<div class="z{" osoby" if x["osoby"] else ""}">{_e(x["tekst"])}</div>' for x in k["zmiany"])
            bloki.append(
                f'<div class="krok"><div class="meta"><b>{_e(godz(po["czas"]))}</b> · zegar {_e(mmss(po["zegar"]))}'
                f' · wynik {_e(po["wynik"])} · zapisał {_e(po["autor"] or "-")}'
                f'{" (z telefonu)" if po["zrodlo"] != "server" else ""} · wersja #{_e(po["id"])}</div>{zm}</div>')
        tresc = ("<p>Zwykły przebieg meczu tylko dopisuje zdarzenia. Poniżej są wszystkie zapisy, w których "
                 "coś z przebiegu zniknęło albo się zmieniło - w całym meczu, nie tylko dla osoby objętej raportem"
                 + (" (jej zdarzenia wyróżnione)" if o else "") + ".</p>" + "".join(bloki))
    else:
        tresc = '<p class="puste">W zachowanej historii żaden zapis nie usunął ani nie zmienił zdarzenia z przebiegu.</p>'
    czesci.append(_sekcja(f"{nr}.", "Korekty przebiegu w całym meczu", tresc))
    nr += 1

    # ── kalendarium
    if a["kalendarium"]:
        wiersze = "".join(
            f"<tr><td class=num>{_e(data_godz(k['czas']))}</td><td>{_e(k['co'])}</td><td>{_e(k['kto'])}</td>"
            f"<td class=cicho>{_e(k['szczegoly'])}</td></tr>" for k in a["kalendarium"])
        tresc = ("<table><thead><tr><th class=num>Czas</th><th>Zdarzenie</th><th>Kto</th><th>Szczegóły</th></tr>"
                 f"</thead><tbody>{wiersze}</tbody></table>")
    else:
        tresc = '<p class="puste">Brak wpisów.</p>'
    czesci.append(_sekcja(f"{nr}.", "Kalendarium zapisu", tresc))
    nr += 1

    # ── PDF
    if a["pdf"]:
        wiersze = []
        for p in a["pdf"]:
            zg = {True: "zgodny", False: "RÓŻNI SIĘ", None: "-"}[p["zgodny"]]
            wydruk = "<br>".join(_e(w) for w in p.get("wydruk") or [])
            wiersze.append(
                f"<tr><td class=mono>{_e(p['kod'])}</td><td class=num>{_e(data_godz(p['czas']))}</td>"
                f"<td>{_e(p['kto'])}</td><td>{_e(zg)}{'<br><span class=cicho>' + wydruk + '</span>' if wydruk else ''}</td>"
                f"<td class=mono>{_e(p['pdf_sha256'][:16])}…<br>{'podpis RSA' if p['podpis'] else 'bez podpisu'}</td></tr>")
        tresc = ("<table><thead><tr><th>Kod</th><th class=num>Wygenerowano</th><th>Kto</th><th>Zgodność z zapisem</th>"
                 "<th>Skrót pliku</th></tr></thead><tbody>" + "".join(wiersze) + "</tbody></table>")
    else:
        tresc = '<p class="puste">Dla tego meczu nie wygenerowano protokołu PDF w aplikacji.</p>'
    czesci.append(_sekcja(f"{nr}.", "Wygenerowane protokoły PDF", tresc))
    nr += 1

    # ── źródła
    zrodla = "".join([
        _wiersz_siatki("Wersje w archiwum", f"{z['migawki']} (z treścią: {z['migawki_z_trescia']}, z telefonu: {z['migawki_urzadzenie']})"),
        _wiersz_siatki("Zakres wersji", f"{data_godz(z['pierwsza'])} - {godz(z['ostatnia'])}" if z["pierwsza"] else ""),
        _wiersz_siatki("Wpisy dziennika", z["dziennik"]),
        _wiersz_siatki("Spory / usunięcia", f"{z['spory']} / {z['usuniete']}"),
        _wiersz_siatki("Zrzut danych", data_godz(z["wykonano"])),
        _wiersz_siatki("Najbliższe wygaśnięcie", data_godz(z["najblizsze_wygasniecie"]) if z["najblizsze_wygasniecie"] else "brak (chronione)"),
    ])
    czesci.append(_sekcja(f"{nr}.", "Źródła danych i integralność", f"""
<dl class="siatka">{zrodla}</dl>
<p style="margin-top:7pt">Suma kontrolna SHA-256 pliku zrzutu, na którym oparto raport:</p>
<p class="mono">{_e(sha256)}</p>
<div class="uwagi-metodyczne">
<p><b>Metoda.</b> Raport porównuje kolejne wersje zapisu meczu przechowywane przez serwer ProEl
(każdy przyjęty zapis z telefonu prowadzącego tworzy wersję). Zmiana między dwiema sąsiednimi wersjami
jest opisana jako wpisanie, usunięcie, poprawka czasu (ta sama kara, przesunięcie do 2 minut), przeniesienie
na inną osobę albo zmiana rodzaju (ta sama chwila meczu). Godziny zapisów są czasem polskim według zegara
serwera; „z telefonu" oznacza wersję dosłaną po braku zasięgu z czasem urządzenia. Czas meczu to wskazanie
zegara meczowego aplikacji.</p>
<p><b>Zakres.</b> Raport przedstawia, co i kiedy zostało zapisane oraz przez kogo. Nie rozstrzyga, czy dana
zmiana była poprawieniem pomyłki, czy błędem - to ocena należąca do właściwego organu.</p>
</div>"""))

    czesci.append(f"""
<div class="podpisy">
  <div><b>{_e(autor or '')}</b>Sporządził(a)</div>
  <div><b>{_e(teraz)}</b>Data sporządzenia</div>
  <div><b></b>Podpis</div>
</div>""")

    # ── załącznik
    if a["dziennik"]:
        wiersze = "".join(
            f"<tr><td class=num>{_e(godz(d['od']))}{('<br><span class=cicho>do ' + _e(godz(d['do'])) + '</span>') if d['ile'] > 1 else ''}</td>"
            f"<td>{_e(d['co'])}{(' <b>×' + str(d['ile']) + '</b>') if d['ile'] > 1 else ''}</td>"
            f"<td>{_e(d['kto'])}{' ✓' if d['potwierdzony'] else ''}</td>"
            f"<td class=cicho>{_e(d['szczegoly'])}</td></tr>" for d in a["dziennik"])
        czesci.append(f"""
<section class="zalacznik"><h2><span class="nr">A.</span>Załącznik: pełny dziennik meczu</h2>
<p class="cicho">Wpisy w kolejności czasu. Serie identycznych wpisów złożone w jeden wiersz (×N).
Znak ✓ oznacza urządzenie potwierdzone w rejestrze aplikacji.</p>
<table><thead><tr><th class=num>Godz.</th><th>Zdarzenie</th><th>Kto</th><th>Szczegóły</th></tr></thead>
<tbody>{wiersze}</tbody></table></section>""")

    css = CSS.replace("__NR__", numer_raportu.replace('"', ""))
    return f"""<!doctype html>
<html lang="pl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(numer_raportu)} - {_e(tytul)}</title>
<style>{css}</style></head>
<body><main class="strona">{''.join(czesci)}</main></body></html>"""
