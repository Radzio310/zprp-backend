"""Raport o JEDNEJ osobie z meczu ProEl - zwięzły, dwie strony A4.

Kary tej osoby (wpisane, poprawiane, usunięte - kto i kiedy), jej bramki
z chwilą zapisu, kontekst akcji, kto dotykał jej zapisów i droga protokołu
do zatwierdzenia. Szablon: `wydruk_osoby.py`, fakty: `dossier.py`.

Przykłady (z katalogu zprp-backend):
  python tools/raport_dowodowy/raport_osoby.py SK/24 --nazwisko NOSEK
  python tools/raport_dowodowy/raport_osoby.py --z-pliku ..\\output\\raporty_dowodowe\\SK-24_...\\zrzut.json.gz --nazwisko NOSEK

Bez `--z-pliku` robi świeży zrzut przez `railway ssh` (tylko odczyt), tak jak `raport.py`.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import re
import sys
from datetime import datetime
from pathlib import Path

TU = Path(__file__).resolve().parent
sys.path.insert(0, str(TU))
# Rdzeń raportu mieszka w pakiecie aplikacji (`app/raport_dowodowy`).
sys.path.insert(0, str(TU.parents[1]))

from app.raport_dowodowy.dossier import dossier  # noqa: E402
from raport import DOMYSLNE_WYJSCIE, DRUZYNY, drukuj_pdf, pobierz_zrzut, rozpakuj_wyjscie  # noqa: E402
from app.raport_dowodowy.wydruk_osoby import html_osoby  # noqa: E402


def main() -> None:
    for strumien in (sys.stdout, sys.stderr):
        try:
            strumien.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    ap = argparse.ArgumentParser(description="Raport o jednej osobie z historii zapisu meczu ProEl.")
    ap.add_argument("mecz", nargs="?", help="klucz meczu, np. SK/24")
    ap.add_argument("--nazwisko", help="nazwisko osoby")
    ap.add_argument("--zawodnik", help="numer na koszulce")
    ap.add_argument("--druzyna", help="gospodarze | goscie")
    ap.add_argument("--z-pliku", help="zrzut .json.gz, teczka z panelu albo tekst z terminala")
    ap.add_argument("--wyjscie", help=f"katalog wyników (domyślnie {DOMYSLNE_WYJSCIE})")
    ap.add_argument("--serwis", default="zprp-backend")
    ap.add_argument("--railway", help="ścieżka do railway.exe")
    ap.add_argument("--bez-pdf", action="store_true")
    arg = ap.parse_args()
    if not (arg.nazwisko or arg.zawodnik):
        ap.error("podaj --nazwisko albo --zawodnik")

    swiezy = not arg.z_pliku
    if arg.z_pliku:
        zrodlo = Path(arg.z_pliku)
        paczka = zrodlo.read_bytes()
        katalog = Path(arg.wyjscie) if arg.wyjscie else zrodlo.parent
        if paczka[:2] != b"\x1f\x8b":
            kod = "utf-16" if paczka[:2] in (b"\xff\xfe", b"\xfe\xff") else "utf-8-sig"
            paczka = rozpakuj_wyjscie(paczka.decode(kod, "replace"))
            swiezy = True
    else:
        if not arg.mecz:
            ap.error("podaj numer meczu albo --z-pliku")
        paczka = pobierz_zrzut(arg.mecz, arg.serwis, arg.railway)
        nazwa = re.sub(r"[^A-Za-z0-9]+", "-", arg.mecz).strip("-")
        katalog = (Path(arg.wyjscie) if arg.wyjscie else DOMYSLNE_WYJSCIE) / f"{nazwa}_{datetime.now():%Y-%m-%d_%H%M%S}"
    katalog.mkdir(parents=True, exist_ok=True)

    sha = hashlib.sha256(paczka).hexdigest()
    if swiezy:
        (katalog / "zrzut.json.gz").write_bytes(paczka)
        (katalog / "zrzut.sha256.txt").write_text(f"{sha}  zrzut.json.gz\n", encoding="utf-8")
        print(f"✓ Zrzut zapisany: {katalog / 'zrzut.json.gz'}")

    zrzut = json.loads(gzip.decompress(paczka).decode("utf-8"))
    druzyna = DRUZYNY.get((arg.druzyna or "").strip().lower()) if arg.druzyna else None
    try:
        d = dossier(zrzut, numer=arg.zawodnik, druzyna=druzyna, nazwisko=arg.nazwisko)
    except ValueError as e:
        raise SystemExit(f"✗ {e}")

    klucz = re.sub(r"[^A-Za-z0-9]", "", str(zrzut.get("klucz") or arg.mecz or "")).upper()
    kto = re.sub(r"[^A-Za-z0-9]", "", (d["osoba"]["nazwisko"] or "").split(" ")[0]).upper() or f"NR{d['osoba']['numer']}"
    plik = katalog / f"{klucz}_{kto}.html"
    plik.write_text(html_osoby(d), encoding="utf-8")
    print(f"✓ Raport HTML: {plik}")
    if not arg.bez_pdf:
        pdf = plik.with_suffix(".pdf")
        if drukuj_pdf(plik, pdf):
            print(f"✓ Raport PDF:  {pdf}")


if __name__ == "__main__":
    main()
