"""Porównaj referencyjny PDF stolików z archiwum ProvinceDataset.

PDF z Google Sheets zapisuje każdą kolumnę osobnym blokiem tekstu. Na każdej
stronie kolejność dat i kodów jest jednak identyczna, więc stabilnym kluczem
jest (dzień, kod meczu). Skrypt niczego nie zgaduje po nazwisku ani hali.
"""
from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from datetime import datetime
from pathlib import Path

MONTH = {"sty": 1, "lut": 2, "mar": 3, "kwi": 4, "maj": 5, "cze": 6,
         "lip": 7, "sie": 8, "wrz": 9, "paź": 10, "lis": 11, "gru": 12}
DATE_RE = re.compile(r"(?m)^(\d{1,2}) ([a-ząćęłńóśźż]{3}) (\d{2})\s*$", re.I)
CODE_RE = re.compile(r"(?m)^([A-Z0-9ŁŚŻŹĆŃÓĘĄ]+(?:/[A-Z0-9ŁŚŻŹĆŃÓĘĄ]+)*/\d+)\s*$")


def pdf_keys(path: Path) -> list[tuple[str, str]]:
    try:
        import fitz
    except ImportError as exc:  # pragma: no cover - narzędzie deweloperskie
        raise SystemExit("Brak PyMuPDF (`fitz`).") from exc
    doc = fitz.open(path)
    out: list[tuple[str, str]] = []
    for page_no, page in enumerate(doc, start=1):
        text = page.get_text("text")
        dates = [
            datetime(2000 + int(year), MONTH[month.lower()], int(day)).date().isoformat()
            for day, month, year in DATE_RE.findall(text)
        ]
        codes = CODE_RE.findall(text)
        if len(dates) != len(codes):
            raise SystemExit(f"Strona {page_no}: {len(dates)} dat, ale {len(codes)} kodów")
        out.extend(zip(dates, codes))
    return out


def archive_rows(path: Path) -> dict[tuple[str, str], list[dict]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    out: dict[tuple[str, str], list[dict]] = {}
    for match in data.get("matches", []):
        stamp = match.get("ts") or match.get("tsProp")
        if not stamp or not match.get("code"):
            continue
        day = datetime.fromtimestamp(stamp / 1000).date().isoformat()
        out.setdefault((day, str(match["code"])), []).append(match)
    return out


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("pdf", type=Path)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--officials", type=Path)
    args = parser.parse_args()
    expected = pdf_keys(args.pdf)
    archive = archive_rows(args.archive)
    by_code: dict[str, list[dict]] = {}
    for rows in archive.values():
        for row in rows:
            by_code.setdefault(str(row.get("code") or ""), []).append(row)
    found, missing, ambiguous, shifted = [], [], [], []
    for key in expected:
        rows = archive.get(key, [])
        if not rows:
            code_rows = by_code.get(key[1], [])
            if len(code_rows) == 1:
                found.append(code_rows[0])
                actual_stamp = code_rows[0].get("ts") or code_rows[0].get("tsProp")
                actual_day = datetime.fromtimestamp(actual_stamp / 1000).date().isoformat()
                shifted.append((key, actual_day))
            else:
                missing.append((key, len(code_rows)))
        elif len(rows) > 1:
            ambiguous.append((key, len(rows)))
            found.append(rows[0])
        else:
            found.append(rows[0])

    print(f"PDF: {len(expected)} | znalezione: {len(found)} | przesuniete: {len(shifted)} | brak: {len(missing)} | wieloznaczne: {len(ambiguous)}")
    print("Rozgrywki PDF:", dict(Counter(code.rsplit("/", 1)[0] for _, code in expected)))
    print("Województwo gospodarza:", dict(Counter(str(m.get("homeWoj") or "BRAK") for m in found)))
    print("Pochodzenie:", dict(Counter(str(m.get("origin") or "BRAK") for m in found)))
    if missing:
        print("Brakujące:")
        for (day, code), candidates in missing:
            print(f"  {day} {code} (kandydaci po kodzie: {candidates})")
    if shifted:
        print("Inna data w archiwum:")
        for (day, code), actual_day in shifted:
            print(f"  {day} -> {actual_day} {code}")
    if ambiguous:
        print("Wieloznaczne:")
        for key, count in ambiguous:
            print(f"  {key[0]} {key[1]}: {count}")

    distinct_homes = sorted({
        (str(m.get("homeId") or ""), str(m.get("home") or ""), str(m.get("homeWoj") or ""))
        for m in found
    }, key=lambda item: (item[1].casefold(), item[0]))
    print(f"Gospodarze ({len(distinct_homes)}):")
    for home_id, name, woj in distinct_homes:
        print(f"  {home_id}\t{woj or 'BRAK'}\t{name}")

    if args.officials:
        archive_doc = json.loads(args.archive.read_text(encoding="utf-8"))
        officials_doc = json.loads(args.officials.read_text(encoding="utf-8"))
        official_ids = set((officials_doc.get("officials") or officials_doc).keys())
        wanted_comps = {code.rsplit("/", 1)[0] for _, code in expected}
        first_day = min(day for day, _ in expected)
        last_day = max(day for day, _ in expected)
        predicted = set()
        for match in archive_doc.get("matches", []):
            stamp = match.get("ts") or match.get("tsProp")
            if not stamp:
                continue
            day = datetime.fromtimestamp(stamp / 1000).date().isoformat()
            code = str(match.get("code") or "")
            refs = match.get("refs") or {}
            local = str(refs.get("secretary") or "") in official_ids or str(refs.get("timer") or "") in official_ids
            if first_day <= day <= last_day and code.rsplit("/", 1)[0] in wanted_comps and local:
                predicted.add((day, code))
        expected_set = set(expected)
        print("Test filtra identyfikatorow stolikowych:")
        print(f"  wynik: {len(predicted)} | wspolne: {len(predicted & expected_set)} | tylko aktualne archiwum: {len(predicted - expected_set)} | tylko PDF: {len(expected_set - predicted)}")


if __name__ == "__main__":
    main()
