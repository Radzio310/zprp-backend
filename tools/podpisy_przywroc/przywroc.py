"""Przywrócenie podpisów protokołu ProEl - uruchamiane NA KOMPUTERZE administratora.

Wysyła `w_kontenerze.py` przez `railway ssh` do kontenera zprp-backend, tam
czyta bazę (i ewentualnie zapisuje), a wynik drukuje i zapisuje do pliku.

    python tools\\podpisy_przywroc\\przywroc.py SM/61              # sama diagnoza, nic nie zmienia
    python tools\\podpisy_przywroc\\przywroc.py SM/61 --zapisz     # przywrócenie (pyta o potwierdzenie)

Opcje przekazywane dalej: --podpis sciezka=adres, --tylko a,b, --nadpisz,
--mimo-zatwierdzenia. Szczegóły: README.md obok.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import gzip
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

TU = Path(__file__).resolve().parent


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


def uruchom(railway: str, serwis: str, argumenty: list[str]) -> str:
    paczka = base64.b64encode(gzip.compress((TU / "w_kontenerze.py").read_bytes(), 9)).decode("ascii")
    polecenie = (
        f"echo {paczka} | base64 -d | gunzip | PYTHONIOENCODING=utf-8 python - "
        + " ".join(shlex.quote(x) for x in argumenty)
    )
    proc = subprocess.run(
        [railway, "ssh", "-s", serwis, polecenie],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    tekst = (proc.stdout or "") + (("\n" + proc.stderr) if proc.stderr.strip() else "")
    if proc.returncode != 0:
        print(tekst)
        raise SystemExit(f"railway ssh zakończył się kodem {proc.returncode}.")
    return tekst


def main() -> None:
    ap = argparse.ArgumentParser(description="Diagnoza i przywrócenie podpisów meczu ProEl.")
    ap.add_argument("mecz", help="klucz meczu, np. SM/61")
    ap.add_argument("--zapisz", action="store_true", help="przywróć (bez tego: tylko diagnoza)")
    ap.add_argument("--podpis", action="append", default=[], help="sciezka=adres, np. official.secretary.signature=/static/x.png")
    ap.add_argument("--tylko", default="", help="tylko te ścieżki, po przecinku")
    ap.add_argument("--nadpisz", action="store_true", help="nadpisz rubryki, które mają już podpis")
    ap.add_argument("--mimo-zatwierdzenia", action="store_true")
    ap.add_argument("--serwis", default="zprp-backend")
    ap.add_argument("--railway", help="ścieżka do railway.exe")
    ap.add_argument("--tak", action="store_true", help="bez pytania o potwierdzenie zapisu")
    a = ap.parse_args()

    railway = _railway(a.railway)
    dalej = [a.mecz]
    for p in a.podpis:
        dalej += ["--podpis", p]
    if a.tylko:
        dalej += ["--tylko", a.tylko]
    if a.nadpisz:
        dalej.append("--nadpisz")
    if a.mimo_zatwierdzenia:
        dalej.append("--mimo-zatwierdzenia")

    # Zawsze najpierw diagnoza: zapis idzie dopiero po obejrzeniu planu.
    diagnoza = uruchom(railway, a.serwis, dalej)
    print(diagnoza)
    stempel = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    wyjscie = TU.parents[2] / "output" / "podpisy"
    wyjscie.mkdir(parents=True, exist_ok=True)
    nazwa = a.mecz.replace("/", "-")
    (wyjscie / f"{nazwa}_{stempel}_diagnoza.txt").write_text(diagnoza, encoding="utf-8")

    if not a.zapisz:
        print(f"\nRaport zapisany: {wyjscie / f'{nazwa}_{stempel}_diagnoza.txt'}")
        return
    if "PRZYWRÓCĘ" not in diagnoza:
        print("\nPlan nie zawiera niczego do przywrócenia - nic nie zapisuję.")
        return
    if not a.tak:
        odp = input("\nZapisać plan przywrócenia powyżej na PRODUKCJI? Wpisz TAK: ").strip()
        if odp != "TAK":
            print("Przerwano - nic nie zapisano.")
            return
    wynik = uruchom(railway, a.serwis, dalej + ["--zapisz"])
    print(wynik)
    (wyjscie / f"{nazwa}_{stempel}_zapis.txt").write_text(wynik, encoding="utf-8")
    if "ZAPISANO" in wynik:
        print(
            "\nDalej w aplikacji: otwórz podsumowanie meczu (podpisy wskoczą same),\n"
            "wygeneruj protokół PDF jeszcze raz i podmień załącznik w ZPRP."
        )


if __name__ == "__main__":
    sys.exit(main())
