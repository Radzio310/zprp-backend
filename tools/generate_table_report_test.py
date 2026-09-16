"""Generate a table-official report from a ProvinceDataset archive.

This is a reproducible comparison tool for the historical Slask reference
report. It deliberately uses current archive data and the current province
official roster; it never fills missing rows from the reference PDF.
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path

COMPETITIONS = {"IMD", "IIK4", "IIM4", "IKB", "LCK", "OSK", "PPK", "PPM"}
ROLE_KEYS = {
    "secretary": ("secretary", "sekretarz"),
    "timer": ("timer", "timekeeper", "mierzacy", "mierzacy_czas"),
}


def role_id(match: dict, role: str) -> str:
    refs = match.get("refs") or {}
    for key in ROLE_KEYS[role]:
        value = refs.get(key)
        if value:
            return str(value)
    return ""


def role_name(match: dict, role: str, officials: dict) -> str:
    ref_id = role_id(match, role)
    item = officials.get(ref_id) or {}
    if item.get("name"):
        return str(item["name"])
    names = match.get("refNames") or {}
    for key in ROLE_KEYS[role]:
        if names.get(key):
            return str(names[key])
    return "-"


def render_local_pdf(output: Path, rows: list[dict], start: str, end: str) -> None:
    import fitz

    page_size = fitz.paper_size("a4-l")
    doc = fitz.open()
    font_file = Path(r"C:\Windows\Fonts\arial.ttf")
    bold_file = Path(r"C:\Windows\Fonts\arialbd.ttf")
    per_page = 27
    columns = [
        ("lp", 26), ("date", 58), ("time", 42), ("code", 57),
        ("home", 108), ("away", 108), ("hall", 176),
        ("secretary", 91), ("timer", 91),
    ]
    labels = ["LP", "DATA", "GODZ.", "ZAWODY", "GOSPODARZ", "GOSC", "HALA", "SEKRETARZ", "MIERZACY CZAS"]
    total_pages = max(1, (len(rows) + per_page - 1) // per_page)
    for page_no in range(total_pages):
        page = doc.new_page(width=page_size[0], height=page_size[1])
        page.insert_font(fontname="Body", fontfile=str(font_file))
        page.insert_font(fontname="Bold", fontfile=str(bold_file))
        width, height = page.rect.width, page.rect.height
        page.draw_rect(page.rect, color=None, fill=(0.975, 0.965, 0.95))
        page.draw_rect(fitz.Rect(0, 0, width, 79), color=None, fill=(0.055, 0.06, 0.075))
        page.draw_rect(fitz.Rect(0, 76, width, 79), color=None, fill=(0.82, 0.51, 0.31))
        page.insert_text((28, 27), "SLASKI ZWIAZEK PILKI RECZNEJ", fontname="Bold", fontsize=7.5, color=(0.93, 0.66, 0.47))
        page.insert_text((28, 52), "OBSADY STOLIKOWE", fontname="Bold", fontsize=20, color=(1, 1, 1))
        page.insert_text((28, 69), f"Sezon 2025/2026  |  {start} - {end}", fontname="Body", fontsize=8.5, color=(0.72, 0.73, 0.77))
        page.insert_text((width - 162, 37), str(len(rows)), fontname="Bold", fontsize=22, color=(0.93, 0.66, 0.47))
        page.insert_text((width - 118, 31), "MECZOW", fontname="Bold", fontsize=7, color=(0.72, 0.73, 0.77))
        page.insert_text((width - 118, 45), "W AKTUALNYM ARCHIWUM", fontname="Body", fontsize=6.5, color=(0.72, 0.73, 0.77))
        page.insert_text((width - 66, 67), f"{page_no + 1} / {total_pages}", fontname="Bold", fontsize=8, color=(0.82, 0.83, 0.86))

        left, top = 22, 94
        table_width = sum(size for _, size in columns)
        page.draw_rect(fitz.Rect(left, top, left + table_width, top + 23), color=None, fill=(0.12, 0.13, 0.16))
        x = left
        for label, (_, size) in zip(labels, columns):
            page.insert_textbox(fitz.Rect(x + 4, top + 7, x + size - 3, top + 20), label, fontname="Bold", fontsize=6.3, color=(0.93, 0.66, 0.47), align=0)
            x += size

        chunk = rows[page_no * per_page:(page_no + 1) * per_page]
        row_h = 16.7
        for row_no, row in enumerate(chunk):
            y = top + 23 + row_no * row_h
            fill = (1, 1, 1) if row_no % 2 == 0 else (0.945, 0.938, 0.925)
            page.draw_rect(fitz.Rect(left, y, left + table_width, y + row_h), color=None, fill=fill)
            page.draw_line(fitz.Point(left, y + row_h), fitz.Point(left + table_width, y + row_h), color=(0.84, 0.82, 0.79), width=0.35)
            x = left
            for key, size in columns:
                value = str(row.get(key) or "-")
                font = "Bold" if key in {"code", "home"} else "Body"
                color = (0.10, 0.105, 0.12) if key not in {"secretary", "timer"} else (0.36, 0.22, 0.14)
                page.insert_textbox(fitz.Rect(x + 4, y + 4.2, x + size - 3, y + row_h - 2), value, fontname=font, fontsize=6.45, color=color, align=0)
                x += size

        footer_y = height - 23
        page.insert_text((22, footer_y), "Dane: aktualne archiwum ZPRP  |  Raport testowy generowany lokalnie", fontname="Body", fontsize=6.5, color=(0.42, 0.42, 0.45))
        page.insert_text((width - 220, footer_y), "Aktywne filtry: IMD, IIK4, IIM4, IKB, LCK, OSK, PPK, PPM", fontname="Body", fontsize=6.5, color=(0.42, 0.42, 0.45))
    doc.save(output, deflate=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    parser.add_argument("officials", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--from-date", default="2025-09-06")
    parser.add_argument("--to-date", default="2026-04-10")
    args = parser.parse_args()

    archive = json.loads(args.archive.read_text(encoding="utf-8"))
    official_doc = json.loads(args.officials.read_text(encoding="utf-8"))
    officials = official_doc.get("officials", official_doc)
    official_ids = {str(value) for value in officials}
    start = datetime.fromisoformat(args.from_date).date()
    end = datetime.fromisoformat(args.to_date).date()

    selected = []
    for match in archive.get("matches", []):
        stamp = match.get("ts") or match.get("tsProp")
        if not stamp:
            continue
        day = datetime.fromtimestamp(stamp / 1000).date()
        competition = str(match.get("code") or "").rsplit("/", 1)[0]
        local_table = role_id(match, "secretary") in official_ids or role_id(match, "timer") in official_ids
        if start <= day <= end and competition in COMPETITIONS and local_table:
            selected.append((day, match))

    selected.sort(key=lambda item: (item[0], str(item[1].get("code") or "")), reverse=True)
    rows = []
    for index, (day, match) in enumerate(selected, start=1):
        stamp = match.get("ts") or match.get("tsProp")
        moment = datetime.fromtimestamp(stamp / 1000)
        rows.append({
            "lp": index,
            "date": day.strftime("%d.%m.%Y"),
            "time": moment.strftime("%H:%M"),
            "code": match.get("code") or "",
            "home": match.get("home") or "",
            "away": match.get("away") or "",
            "hall": " - ".join(part for part in (match.get("city"), match.get("hall")) if part),
            "secretary": role_name(match, "secretary", officials),
            "timer": role_name(match, "timer", officials),
        })

    payload = {
        "meta": {
            "province": "SLASKIE",
            "season": "2025/2026",
            "title": "Zestawienie obsad stolikowych",
            "subtitle": f"Zakres {args.from_date} - {args.to_date}",
            "filters": [
                "rozgrywki: " + ", ".join(sorted(COMPETITIONS)),
                "obsada stolikowa z listy sedziow okregu SLASKIE",
                "stan danych: aktualne archiwum ZPRP",
            ],
            "footnotes": [
                f"Liczba pozycji: {len(rows)}.",
                "Raport testowy nie uzupelnia rekordow, ktorych nie ma juz w aktualnym archiwum.",
            ],
        },
        "sections": [{
            "title": "Stoliki - mecze klubow wojewodztwa",
            "subtitle": "Sekretarz i mierzacy czas",
            "tiles": [
                {"label": "Mecze", "value": str(len(rows))},
                {"label": "Od", "value": args.from_date},
                {"label": "Do", "value": args.to_date},
            ],
            "columns": [
                {"key": "lp", "label": "L.p.", "format": "int"},
                {"key": "date", "label": "Data"},
                {"key": "time", "label": "Godzina"},
                {"key": "code", "label": "Zawody"},
                {"key": "home", "label": "Gospodarz"},
                {"key": "away", "label": "Gosc"},
                {"key": "hall", "label": "Hala"},
                {"key": "secretary", "label": "Sekretarz"},
                {"key": "timer", "label": "Mierzacy czas"},
            ],
            "rows": rows,
        }],
        "filename": f"stoliki_test_{args.from_date}_{args.to_date}",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    render_local_pdf(args.output, rows, args.from_date, args.to_date)
    print(f"Zapisano {args.output} ({len(rows)} pozycji, {args.output.stat().st_size} bajtow)")


if __name__ == "__main__":
    main()
