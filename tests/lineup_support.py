"""Syntetyczny protokół ZPRP jako PDF (zmyślone dane) - zaplecze testów „Wczytaj składy".

Układ odwzorowuje szablon (tabele A/B, osoby A-E z literą przyklejoną do nazwiska, etykiety powtarzane w pustych miejscach,
puste tabele czasu po prawej, kratki x, znaczniki przy zawodnikach), ale NIE zawiera żadnych prawdziwych nazwisk.
"""

import io

import fitz

HOME = "KS Testowo"
AWAY = "MKS Żółwiki"
HOME_PLAYERS = [
    (2, "KOWALEWSKI-NOWAK Zdzisław"), (3, "ŻÓŁTEK Błażej"), (7, "ŁOBODA Łukasz"), (9, "ŚWIT Ćwik"),
    (10, "DĄBROWA Józef"), (12, "MAZUR Ola"), (15, "VAN DER BERG Jan"), (91, "KRÓL Zbigniew"),
]
AWAY_PLAYERS = [(1, "ABRAMOWICZ Adam"), (4, "BĄK Michał"), (5, "ĆWIKŁA Paweł"), (11, "GĘSIOR Łukasz"), (25, "HUŁA Kornel"), (36, "ŻAK Ślusarz")]
HOME_STAFF = [("A", "TESTOWSKI Tomasz", "TRENER B", "B  0544/2026"), ("B", "PRÓBNY Piotr", "OSOBA TOWARZYSZĄCA", "0404/18")]
AWAY_STAFF = [
    ("A", "ŁĘCKI Adam", "TRENER A", "A 0001/2025"), ("B", "ŹRÓDŁO Ewa", "OSOBA TOWARZYSZĄCA", "0123/19"),
    ("C", "WĄS Bartosz", "OSOBA TOWARZYSZĄCA", "0456/2027"), ("D", "ŚLĄSKI Dariusz", "OSOBA TOWARZYSZĄCA", "0789/20"),
    ("E", "ÓŁTARZ Eryk", "OSOBA TOWARZYSZĄCA", "0999/17"),
]
OFFICIALS = [("sędzia główny", "SĘDZIOWSKI Sebastian"), ("sędzia główny", "ARBITER Ala"), ("sekretarz", "STOLIK Sylwia"),
             ("m. czas", "CZASOWY Cezary"), ("delegat ZPRP", "--------------------")]


def green_png() -> bytes:
    from PIL import Image

    out = io.BytesIO()
    Image.new("RGB", (40, 40), (30, 150, 40)).save(out, format="PNG")
    return out.getvalue()


def red_png() -> bytes:
    from PIL import Image

    out = io.BytesIO()
    Image.new("RGB", (40, 40), (200, 30, 30)).save(out, format="PNG")
    return out.getvalue()


def build_protocol(*, swap=False, home_players=HOME_PLAYERS, away_players=AWAY_PLAYERS, home_staff=HOME_STAFF, away_staff=AWAY_STAFF,
                   tick_mode="image", zprp_id="123456", match_number="JmK/7", empty_time_table=False, officials=OFFICIALS) -> bytes:
    """`swap` - tabela B stoi NAD tabelą A (wiązanie ma iść po nagłówku, nie po kolejności).
    `tick_mode`: "image" (zielony obrazek w wierszu), "drawing" (zielony prostokąt), "none" (brak znaczników),
    "mixed" (zielony przy pierwszym, czerwony przy drugim, reszta bez)."""
    doc = fitz.open()
    page = doc.new_page(width=595, height=842)
    font = fitz.Font("cjk")
    page.insert_font(fontname="N", fontbuffer=font.buffer)

    def text(x, y, value, size=7):
        page.insert_text((x, y), value, fontname="N", fontsize=size)

    text(472, 20, f"IdZawody: {zprp_id} | Wydrukowano: 02.11.2026 17:35:56" if zprp_id else "Wydrukowano: 02.11.2026 17:35:56")
    text(238, 30, "PROTOKÓŁ ZAWODÓW", 11)
    text(455, 28, "Numer meczu:")
    text(531, 28, match_number)
    text(30, 58, "A Drużyna gospodarzy:")
    text(31, 72, HOME)
    text(30, 92, "B Drużyna gości:")
    text(31, 106, AWAY)
    for label, x, y in (("SUPERLIGA", 198, 58), ("I LIGA GRUPA D", 198, 70), ("II LIGA", 198, 81), ("ELIMINACJE", 272, 92), ("SENIORZY", 346, 58),
                        ("JUNIORZY", 346, 70), ("K", 274, 104), ("M", 311, 104)):
        text(x, y, label)
    for x, y in ((188, 68), (262, 91), (303, 102), (335, 57)):
        text(x, y, "x")
    text(261, 115, "data 31.10.2026")
    text(334, 115, "godz. 18:00")
    text(439, 58, "Miejsce rozgrywania zawodów (adres):")
    text(458, 70, "Hala Łąkowa")
    text(449, 81, "Źródlana 5, 41-100 Łąkowo")
    text(454, 126, "Przebieg zawodów")
    if not empty_time_table:
        for index in range(60):
            text(452, 200 + index * 11.3, ":")
            text(542, 200 + index * 11.3, ":")
    text(401, 745, "Wynik końcowy:          :              do przerwy           :")

    def team(y0, letter, name, players, staff):
        text(31, y0 + 8, f"{letter} (nazwa) {name}")
        text(312, y0 + 8, "Kary")
        text(33, y0 + 20, "Nr")
        text(89, y0 + 20, "Nazwisko i imię zawodnika")
        for x, label in ((208, "W"), (226, "B"), (243, "U"), (266, "2'"), (351, "D"), (379, "Kd")):
            text(x, y0 + 20, label)
        y = y0 + 32
        for index, (number, person) in enumerate(players):
            text(37 if (number or 0) < 10 else 33, y, f"{number} {person}" if number is not None else person)
            mark = None
            if tick_mode == "image":
                mark = "green"
            elif tick_mode == "drawing":
                mark = "drawing"
            elif tick_mode == "mixed":
                mark = {0: "green", 1: "red"}.get(index)
            if mark == "drawing":
                page.draw_rect(fitz.Rect(17, y - 8, 28, y + 2), color=None, fill=(0.1, 0.6, 0.1))
            elif mark in ("green", "red"):
                page.insert_image(fitz.Rect(17, y - 8, 28, y + 2), stream=green_png() if mark == "green" else red_png())
            y += 11.3
        ys = y0 + 32 + 16 * 11.3 + 6
        for slot, person, function, license_text in staff:
            x = 30 + 65 * "ABCDE".index(slot)
            text(x, ys, f"{slot}.{person}")
            text(x + 2, ys + 12, f"  {function}")
            text(x + 2, ys + 20, f"  {license_text}")
        for i in range(5):  # etykiety powtarzane w KAŻDYM miejscu, także pustym
            x = 30 + 65 * i
            text(x + 4, ys + 33, "Nazwisko, imię - funkcja,")
            text(x + 14, ys + 44, "numer licencji")
        text(44, ys + 33, "Osoba odpowiedzialna za drużynę -")

    top, bottom = 122, 388
    if swap:
        team(top, "B", AWAY, away_players, away_staff)
        team(bottom, "A", HOME, home_players, home_staff)
    else:
        team(top, "A", HOME, home_players, home_staff)
        team(bottom, "B", AWAY, away_players, away_staff)
    text(30, 660, "Szczegółowe uwagi sędziów:")
    text(30, 671, "Liczba widzów:                    Pojemność hali:  750")
    y = 719
    for role, name in officials:
        text(48, y, role)
        text(102, y, name + ("          Omiejscowość" if role == "m. czas" else ""))
        text(186, y, "miejscowość") if role != "m. czas" else None
        text(313, y, "podpis")
        y += 14
    return doc.tobytes()


def build_plain_pdf(body: str = "Zwykły dokument bez tabel składów. " * 30) -> bytes:
    doc = fitz.open()
    page = doc.new_page()
    page.insert_textbox(fitz.Rect(40, 40, 550, 800), body, fontname="helv", fontsize=9)
    return doc.tobytes()


def build_blank_pdf() -> bytes:
    """Skan: strona z samym obrazkiem, bez warstwy tekstu."""
    doc = fitz.open()
    page = doc.new_page()
    page.insert_image(fitz.Rect(40, 40, 500, 700), stream=green_png())
    return doc.tobytes()


def jpeg_bytes(size=(400, 300)) -> bytes:
    from PIL import Image

    out = io.BytesIO()
    Image.new("RGB", size, (120, 160, 200)).save(out, format="JPEG")
    return out.getvalue()


def png_bytes(size=(400, 300)) -> bytes:
    return _png(size)


def _png(size) -> bytes:
    from PIL import Image

    out = io.BytesIO()
    Image.new("RGB", size, (10, 10, 10)).save(out, format="PNG")
    return out.getvalue()
