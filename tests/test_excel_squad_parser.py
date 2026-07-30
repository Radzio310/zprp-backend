from __future__ import annotations

from io import BytesIO

from openpyxl import Workbook

from app.beach.excel_squad import _read_excel_cells


def _xlsx_bytes(cells: dict[str, object]) -> bytes:
    workbook = Workbook()
    worksheet = workbook.active
    for address, value in cells.items():
        worksheet[address] = value
    output = BytesIO()
    workbook.save(output)
    return output.getvalue()


def test_official_layout_keeps_blank_letter_companions_out_of_players():
    file_bytes = _xlsx_bytes(
        {
            "B9": "A / Drużyna gospodarzy",
            "B10": "KPR Gminy Kobierzyce",
            # Some filled files put the city itself in this metadata row.
            "B11": "Kobierzyce",
            "B14": "Drużyna A - zawodnicy",
            "A15": 22,
            "B15": "Maria BASIUK",
            "A16": 21,
            "B16": "Zuzanna BEJMOWICZ",
            "A17": 19,
            "B17": "Matylda BRZEZIŃSKA",
            # The common official file leaves the companion letters blank.
            "B30": "Maciej Batura",
            "B31": "Beata Skalska",
            "B32": "Magdalena Słota",
            "A34": "Podpis oficjela A",
            "B36": "Drużyna B - zawodnicy",
        }
    )

    result = _read_excel_cells(file_bytes, "K_Kobierzyce.xlsx")

    assert result["team_name_raw"] == "KPR Gminy Kobierzyce"
    assert [row["raw_name"] for row in result["players_raw"]] == [
        "Maria BASIUK",
        "Zuzanna BEJMOWICZ",
        "Matylda BRZEZIŃSKA",
    ]
    assert result["companions_raw"] == [
        {"row": 30, "raw_name": "Maciej Batura", "raw_letter": "A"},
        {"row": 31, "raw_name": "Beata Skalska", "raw_letter": "B"},
        {"row": 32, "raw_name": "Magdalena Słota", "raw_letter": "C"},
    ]
    assert all(
        row["raw_name"] != "Kobierzyce"
        for row in [*result["players_raw"], *result["companions_raw"]]
    )


def test_recovery_parser_handles_shifted_layout_without_companion_letters():
    file_bytes = _xlsx_bytes(
        {
            # The complete host section is shifted down by one row.
            "B10": "A / Drużyna gospodarzy",
            "B11": "KPR Przesunięty",
            "B12": "Miejsce zawodów",
            "B15": "Drużyna A - zawodnicy",
            "A16": 4,
            "B16": "Anna NOWAK",
            "A17": 8,
            "B17": "Ewa KOWALSKA",
            # Fifteen player slots after row 15 means companions start at 31.
            "B31": "Jan Trener",
            "B32": "Iga Fizjo",
            "A35": "Podpis oficjela A",
            "B37": "Drużyna B - zawodnicy",
        }
    )

    result = _read_excel_cells(file_bytes, "shifted.xlsx")

    assert result["team_name_raw"] == "KPR Przesunięty"
    assert [row["raw_name"] for row in result["players_raw"]] == [
        "Anna NOWAK",
        "Ewa KOWALSKA",
    ]
    assert result["companions_raw"] == [
        {"row": 31, "raw_name": "Jan Trener", "raw_letter": "A"},
        {"row": 32, "raw_name": "Iga Fizjo", "raw_letter": "B"},
    ]


def test_recovery_parser_does_not_turn_city_into_player():
    file_bytes = _xlsx_bytes(
        {
            "B10": "KPR Uszkodzony",
            "B11": "Miejsce zawodów",
            "B12": "Kobierzyce",
            # Damaged sheet: player heading is gone, but numbered rows survived.
            "A15": 7,
            "B15": "Anna NOWAK",
            "B16": "Ewa KOWALSKA",
            "A17": "A",
            "B17": "Jan Trener",
            "B18": "Sędziowie",
        }
    )

    result = _read_excel_cells(file_bytes, "damaged.xlsx")

    assert [row["raw_name"] for row in result["players_raw"]] == [
        "Anna NOWAK",
        "Ewa KOWALSKA",
    ]
    assert result["companions_raw"] == [
        {"row": 17, "raw_name": "Jan Trener", "raw_letter": "A"},
    ]
    all_names = [
        *(row["raw_name"] for row in result["players_raw"]),
        *(row["raw_name"] for row in result["companions_raw"]),
    ]
    assert "Kobierzyce" not in all_names
