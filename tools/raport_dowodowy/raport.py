"""Raport z historii zapisu meczu ProEl - narzędzie administratora, uruchamiane lokalnie.

Przykłady (z katalogu zprp-backend):
  python tools/raport_dowodowy/raport.py SK/24 --nazwisko NOSEK --autor "Radosław Witkowicz"
  python tools/raport_dowodowy/raport.py SK/24 --zawodnik 39 --druzyna goscie
  python tools/raport_dowodowy/raport.py SK/24 --tylko-zrzut
  python tools/raport_dowodowy/raport.py --z-pliku ..\\output\\raporty_dowodowe\\SK-24_...\\zrzut.json.gz --nazwisko NOSEK

Kroki:
  1. zrzut pełnego zapisu meczu przez `railway ssh` (skrypt `zrzut.py`, sesja bazy READ ONLY),
  2. zapis zrzutu na dysk razem z sumą SHA-256 - to jest materiał źródłowy, raport to jego odczyt,
  3. analiza (`analiza.py`) i wydruk HTML (`wydruk.py`),
  4. PDF przez Edge albo Chrome bez okna (`--print-to-pdf`).

Zrzut zostaje na dysku na zawsze - z `--z-pliku` raport da się odtworzyć bez
dostępu do serwera i bez względu na to, czy wersje na serwerze już wygasły.
"""
from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

TU = Path(__file__).resolve().parent
sys.path.insert(0, str(TU))
# Rdzeń raportu mieszka w pakiecie aplikacji (`app/raport_dowodowy`).
sys.path.insert(0, str(TU.parents[1]))

from app.raport_dowodowy.analiza import analizuj  # noqa: E402
from wydruk import html_raportu  # noqa: E402

DOMYSLNE_WYJSCIE = TU.parents[2] / "output" / "raporty_dowodowe"
DRUZYNY = {"goscie": "guest", "goście": "guest", "guest": "guest", "g": "guest",
           "gospodarze": "host", "host": "host", "h": "host"}


def _railway(podany: str | None) -> str:
    """Prawdziwy railway.exe - przez railway.cmd długi argument nie przejdzie (limit cmd.exe)."""
    if podany:
        return podany
    kandydaci = []
    w = shutil.which("railway")
    if w:
        p = Path(w)
        if p.suffix.lower() == ".exe":
            kandydaci.append(p)
        kandydaci.append(p.parent / "node_modules" / "@railway" / "cli" / "bin" / "railway.exe")
    if os.environ.get("APPDATA"):
        kandydaci.append(Path(os.environ["APPDATA"]) / "npm" / "node_modules" / "@railway" / "cli" / "bin" / "railway.exe")
    for k in kandydaci:
        if k.is_file():
            return str(k)
    if w:
        return w
    raise SystemExit("Nie znaleziono Railway CLI. Zainstaluj (npm i -g @railway/cli) albo podaj --railway.")


def pobierz_zrzut(klucz: str, serwis: str, railway: str | None) -> bytes:
    skrypt = base64.b64encode((TU / "zrzut.py").read_bytes()).decode("ascii")
    polecenie = f"echo {skrypt} | base64 -d | python - {shlex.quote(klucz)}"
    print(f"→ Zrzut meczu {klucz} z usługi {serwis} (tylko odczyt)...")
    proc = subprocess.run(
        [_railway(railway), "ssh", "-s", serwis, polecenie],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600,
        cwd=str(TU.parents[1]),
    )
    wyjscie = proc.stdout or ""
    if "===ZRZUT-POCZATEK===" not in wyjscie:
        print(wyjscie[-3000:])
        print(proc.stderr[-2000:] if proc.stderr else "")
        raise SystemExit(
            "Zrzut się nie udał - powyżej odpowiedź serwera. Jeśli to problem z terminalem, "
            "zapisz wynik ręcznie (README.md) i podaj go przez --z-pliku."
        )
    return rozpakuj_wyjscie(wyjscie)


def rozpakuj_wyjscie(wyjscie: str) -> bytes:
    """Paczka spomiędzy znaczników `zrzut.py`, sprawdzona sumą z serwera."""
    m = re.search(r"===ZRZUT-POCZATEK===(.*?)===ZRZUT-KONIEC===", wyjscie, re.S)
    if not m:
        raise SystemExit("W podanym tekście nie ma zrzutu (brak znaczników ===ZRZUT-...===).")
    paczka = base64.b64decode(re.sub(r"\s+", "", m.group(1)))
    suma = re.search(r"===SHA256 ([0-9a-f]{64})===", wyjscie)
    if suma and hashlib.sha256(paczka).hexdigest() != suma.group(1):
        raise SystemExit("Suma kontrolna zrzutu nie zgadza się z wyliczoną na serwerze - powtórz.")
    liczniki = re.search(r"===LICZNIKI (.*?)===", wyjscie)
    if liczniki:
        print(f"  {liczniki.group(1)}")
    return paczka


def _drukarka() -> str | None:
    for p in (
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    ):
        if Path(p).is_file():
            return p
    for nazwa in ("msedge", "chrome", "google-chrome", "chromium", "chromium-browser"):
        if shutil.which(nazwa):
            return shutil.which(nazwa)
    return None


def drukuj_pdf(html_plik: Path, pdf_plik: Path) -> bool:
    exe = _drukarka()
    if not exe:
        print("  (nie znaleziono Edge ani Chrome - PDF pominięty, otwórz HTML i wydrukuj do PDF)")
        return False
    with tempfile.TemporaryDirectory() as profil:
        subprocess.run(
            [exe, "--headless=new", "--disable-gpu", "--no-pdf-header-footer",
             f"--user-data-dir={profil}", f"--print-to-pdf={pdf_plik}", html_plik.resolve().as_uri()],
            capture_output=True, timeout=180,
        )
    return pdf_plik.is_file() and pdf_plik.stat().st_size > 0


def main() -> None:
    # Konsola Windows bywa w cp1250 - strzałka czy ptaszek nie mogą wywrócić raportu.
    for strumien in (sys.stdout, sys.stderr):
        try:
            strumien.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    ap = argparse.ArgumentParser(description="Raport z historii zapisu meczu ProEl.")
    ap.add_argument("mecz", nargs="?", help="klucz meczu w ProElu, np. SK/24")
    ap.add_argument("--zawodnik", help="numer na koszulce osoby objętej raportem")
    ap.add_argument("--druzyna", help="gospodarze | goscie (gdy numer jest w obu drużynach)")
    ap.add_argument("--nazwisko", help="nazwisko osoby (zamiast numeru albo razem z nim)")
    ap.add_argument("--autor", help="kto sporządza raport (stopka z podpisem)")
    ap.add_argument("--z-pliku", help="zrzut zapisany wcześniej (zrzut.json.gz) - bez łączenia z serwerem")
    ap.add_argument("--tylko-zrzut", action="store_true", help="zapisz sam zrzut, bez raportu")
    ap.add_argument("--wyjscie", help=f"katalog wyników (domyślnie {DOMYSLNE_WYJSCIE})")
    ap.add_argument("--serwis", default="zprp-backend", help="usługa Railway z dostępem do bazy")
    ap.add_argument("--railway", help="ścieżka do railway.exe")
    ap.add_argument("--bez-pdf", action="store_true", help="tylko HTML")
    arg = ap.parse_args()

    swiezy = not arg.z_pliku
    if arg.z_pliku:
        zrodlo = Path(arg.z_pliku)
        paczka = zrodlo.read_bytes()
        katalog = Path(arg.wyjscie) if arg.wyjscie else zrodlo.parent
        if paczka[:2] != b"\x1f\x8b":
            # Tekst z terminala (`railway ssh ... > zrzut.txt`) zamiast pliku .gz -
            # wyciągamy paczkę spomiędzy znaczników i zapisujemy ją jak świeży zrzut.
            # PowerShell 5.1 zapisuje `>` w UTF-16 z BOM-em.
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
        print(f"  SHA-256: {sha}")
    if arg.tylko_zrzut:
        return

    zrzut = json.loads(gzip.decompress(paczka).decode("utf-8"))
    druzyna = DRUZYNY.get((arg.druzyna or "").strip().lower()) if arg.druzyna else None
    if arg.druzyna and not druzyna:
        ap.error("--druzyna: gospodarze albo goscie")
    try:
        wynik = analizuj(zrzut, numer=arg.zawodnik, druzyna=druzyna, nazwisko=arg.nazwisko)
    except ValueError as e:
        raise SystemExit(f"✗ {e}")

    klucz = str(zrzut.get("klucz") or arg.mecz or "")
    numer_raportu = f"RD-{re.sub(r'[^A-Za-z0-9]', '', klucz).upper()}-{sha[:8].upper()}"
    tresc = html_raportu(wynik, numer_raportu=numer_raportu, sha256=sha, autor=arg.autor)
    html_plik = katalog / f"{numer_raportu}.html"
    html_plik.write_text(tresc, encoding="utf-8")
    print(f"✓ Raport HTML: {html_plik}")
    if not arg.bez_pdf:
        pdf_plik = katalog / f"{numer_raportu}.pdf"
        if drukuj_pdf(html_plik, pdf_plik):
            print(f"✓ Raport PDF:  {pdf_plik}")

    print("\nUstalenia:")
    for i, u in enumerate(wynik["ustalenia"], 1):
        print(f" {i}. {'[!] ' if u['waga'] == 'uwaga' else ''}{u['tekst']}")


if __name__ == "__main__":
    main()
