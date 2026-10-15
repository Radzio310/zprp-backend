"""Buduje kompaktowy skorowidz miejscowości Polski dla tabeli odległości ZPRP.

Źródło: GeoNames, plik PL.txt (https://download.geonames.org/export/dump/PL.zip).
Dane GeoNames są na licencji Creative Commons Attribution 4.0
(https://creativecommons.org/licenses/by/4.0/) - przypis autorstwa
(„GeoNames, www.geonames.org") siedzi w nagłówku wygenerowanego pliku
i w `app/national_place_rules.py`.

Użycie (jednorazowo, wynik commitujemy do repozytorium):

    python scripts/build_pl_places.py ŚCIEŻKA/PL.txt app/data/pl_places.tsv.gz

Format wyjścia (UTF-8, gzip, rozdzielany tabulatorem):
    geonameid  nazwa  szer  dł  województwo  ludność  dodatkowe_klucze(|)

Bierzemy tylko miejscowości (klasa P) bez historycznych, opuszczonych
i zniszczonych (PPLH, PPLQ, PPLW) oraz bez części miast (PPLX) - dzielnica
o nazwie wsi dawała fałszywe dopasowania kilometrów.
"""

from __future__ import annotations

import gzip
import re
import sys
import unicodedata

#: Kody admin1 GeoNames -> województwo (te same nazwy co w `national_place_rules`).
ADMIN1 = {
    "72": "dolnoslaskie",
    "73": "kujawsko-pomorskie",
    "74": "lodzkie",
    "75": "lubelskie",
    "76": "lubuskie",
    "77": "malopolskie",
    "78": "mazowieckie",
    "79": "opolskie",
    "80": "podkarpackie",
    "81": "podlaskie",
    "82": "pomorskie",
    "83": "slaskie",
    "84": "swietokrzyskie",
    "85": "warminsko-mazurskie",
    "86": "wielkopolskie",
    "87": "zachodniopomorskie",
}
SKIP_CODES = {"PPLH", "PPLQ", "PPLW", "PPLX"}
BIG_CODES = {"PPLC", "PPLA", "PPLA2"}


def norm(value: str) -> str:
    text = unicodedata.normalize("NFKD", str(value or ""))
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    text = text.replace("Ł", "L").replace("ł", "l").lower()
    return re.sub(r"[^a-z0-9]+", " ", text).strip()


def main(src: str, dst: str) -> None:
    rows = []
    for line in open(src, encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) < 15 or f[6] != "P" or f[7] in SKIP_CODES:
            continue
        province = ADMIN1.get(f[10])
        if not province:
            continue
        name = f[1].strip()
        own = {norm(name), norm(f[2])}
        own.discard("")
        population = int(f[14] or 0)
        extra: set[str] = set()
        # Duże miasta GeoNames trzyma pod egzonimem („Warsaw"). Polską nazwę
        # bierzemy z nazw alternatywnych - tylko dla dużych, żeby nie zalać
        # skorowidza obcojęzycznymi wariantami wsi.
        if population >= 5000 or f[7] in BIG_CODES:
            for alt in f[3].split(","):
                key = norm(alt)
                if len(key) >= 3 and re.fullmatch(r"[a-z ]+", key) and key not in own:
                    extra.add(key)
        if norm(f[2]) != norm(name):
            extra.add(norm(f[2]))
        rows.append(
            (
                f[0],
                name,
                f"{float(f[4]):.5f}",
                f"{float(f[5]):.5f}",
                province,
                str(population),
                "|".join(sorted(extra)),
            )
        )
    rows.sort(key=lambda r: int(r[0]))
    with gzip.open(dst, "wt", encoding="utf-8", compresslevel=9) as out:
        out.write("# GeoNames (www.geonames.org), CC BY 4.0 - miejscowości PL, klasa P\n")
        for row in rows:
            out.write("\t".join(row) + "\n")
    print(f"{len(rows)} miejscowości -> {dst}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
