"""
Wczytywanie faktur PDF jako wpłat klubów: odczyt regułami i dopasowanie klubu.

Wzorzec: faktura SaldeoSMART wystawiona przez ŚlZPR dla KS Zgoda Ruda Śląska.
PDF-a nie trzymamy w repo - test składa go PyMuPDF-em z tym samym tekstem.
"""

from __future__ import annotations

import os

import pytest

from app.invoice_match_rules import budget_members, name_tokens, propose, rank_clubs
from app.invoice_parse_rules import (
    describe,
    invoice_key,
    merge_ai,
    needs_ai,
    nip_is_valid,
    normalize_nip,
    parse_amount,
    parse_date,
    parse_invoice_text,
    sanitize_ai,
    short_items,
)

SALDEO_LINES = [
    "Faktura Nr 77/SL/2026",
    "15-06-2026",
    "data wystawienia",
    "15-06-2026",
    "data dostawy/wykonania usługi",
    "Sprzedawca:",
    "ŚLĄSKI ZWIĄZEK PIŁKI RĘCZNEJ W KATOWICACH",
    "Adres: Jesionowa 15, 40-159 Katowice, Polska",
    "NIP: 9540008151",
    "Nabywca:",
    'KLUB SPORTOWY "ZGODA" RUDA ŚLĄSKA-BIELSZ',
    "Adres: Sportowców 10, 41-711 Ruda Śląska, Polska",
    "NIP: 6410008955",
    "Sposób zapłaty: Przelew",
    "Termin płatności: 22-06-2026",
    "Lp. Nazwa towaru/usługi Ilość J.m. Cena netto Stawka VAT Wartość netto Kwota VAT Wartość brutto",
    "1 Obsługa sędziowska zawodów 1.0 szt. 3 000,00 zw. 3 000,00 0,00 3 000,00",
    "Razem: 3 000,00 0,00 3 000,00",
    "Razem do zapłaty: 3 000,00 PLN",
    "Zapłacono: 0,00 PLN",
    "Pozostało do zapłaty: 3 000,00 PLN",
    "Słownie: trzy/zero/zero/zero PLN 00/100",
    "Wydrukowano z programu SaldeoSMART.pl firmy BrainSHARE",
]
SALDEO_TEXT = "\n".join(SALDEO_LINES)

CLUBS = [
    {"club_id": "1126", "name": "KS Zgoda Ruda Śląska", "names": ["KS Zgoda Ruda Śląska", "Zgoda Ruda Śląska II"]},
    {"club_id": "2001", "name": "UKS Grunwald Ruda Śląska", "names": ["UKS Grunwald Ruda Śląska"]},
    {"club_id": "2002", "name": "MKS Slavia Ruda Śląska", "names": ["MKS Slavia Ruda Śląska"]},
    {"club_id": "2003", "name": "KS Zagłębie Sosnowiec", "names": ["KS Zagłębie Sosnowiec"]},
    {"club_id": "2004", "name": "SPR Pogoń 1945 Zabrze", "names": ["SPR Pogoń 1945 Zabrze"]},
    {"club_id": "2005", "name": "MKS Sośnica Gliwice", "names": ["MKS Sośnica Gliwice", "Sośnica Gliwice II"]},
]


# ---------------------------------------------------------------------------
# drobne reguły
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw, value",
    [
        ("3 000,00", 3000.0),
        ("3 000,00", 3000.0),
        ("3 000,00", 3000.0),
        ("3.000,00", 3000.0),
        ("3000.00", 3000.0),
        ("1 234 567,89 PLN", 1234567.89),
        ("0,00", 0.0),
        ("450", 450.0),
        ("abc", None),
    ],
)
def test_amounts_with_spaces_and_nbsp(raw, value):
    assert parse_amount(raw) == value


def test_dates_in_both_orders():
    assert parse_date("15-06-2026").isoformat() == "2026-06-15"
    assert parse_date("15.06.2026").isoformat() == "2026-06-15"
    assert parse_date("2026-06-15").isoformat() == "2026-06-15"
    assert parse_date("31-02-2026") is None


def test_nip_normalized_and_checksum():
    assert normalize_nip("PL 954-000-81-51") == "9540008151"
    assert nip_is_valid("9540008151")
    assert nip_is_valid("6410008955")
    assert not nip_is_valid("1234567890")
    assert normalize_nip("123") == ""


def test_invoice_key_is_number_plus_seller():
    assert invoice_key("77/SL/2026", "954-000-81-51") == "9540008151|77/SL/2026"
    assert invoice_key(" 77/sl/2026 ", "9540008151") == invoice_key("77/SL/2026", "9540008151")
    assert invoice_key("", "9540008151") == ""


# ---------------------------------------------------------------------------
# faktura SaldeoSMART
# ---------------------------------------------------------------------------


def _assert_saldeo(parsed: dict) -> None:
    assert parsed["invoice_no"] == "77/SL/2026"
    assert parsed["issue_date"] == "2026-06-15"
    assert parsed["sale_date"] == "2026-06-15"
    assert parsed["due_date"] == "2026-06-22"
    assert parsed["seller_nip"] == "9540008151"
    assert parsed["seller_name"] == "ŚLĄSKI ZWIĄZEK PIŁKI RĘCZNEJ W KATOWICACH"
    assert parsed["buyer_nip"] == "6410008955"
    assert parsed["buyer_name"] == 'KLUB SPORTOWY "ZGODA" RUDA ŚLĄSKA-BIELSZ'
    assert parsed["gross"] == 3000.0
    assert parsed["paid"] == 0.0
    assert parsed["remaining"] == 3000.0
    assert parsed["currency"] == "PLN"
    assert [item["name"] for item in parsed["items"]] == ["Obsługa sędziowska zawodów"]
    assert parsed["items"][0]["gross"] == 3000.0
    assert parsed["missing"] == []


def test_saldeo_invoice_from_lines():
    _assert_saldeo(parse_invoice_text(SALDEO_TEXT))


def test_saldeo_invoice_as_one_line():
    # Tak tekst wygląda po skopiowaniu z przeglądarki PDF.
    _assert_saldeo(parse_invoice_text(" ".join(SALDEO_LINES)))


def test_description_is_number_and_short_items():
    parsed = parse_invoice_text(SALDEO_TEXT)
    assert describe(parsed) == "Faktura 77/SL/2026 · Obsługa sędziowska zawodów"
    assert short_items([{"name": "A"}, {"name": "B"}, {"name": "A"}]) == "A, B"
    many = [{"name": f"Pozycja numer {n}"} for n in range(10)]
    assert short_items(many).endswith(")")


def test_label_after_date_style():
    text = (
        "Faktura VAT nr FV/12/09/2026\nData sprzedaży: 10.09.2026\nData wystawienia: 12.09.2026\n"
        "Sprzedawca: Związek NIP: 954-000-81-51\nNabywca: UKS Grunwald Ruda Śląska ul. Leśna 1 NIP: PL6410008955\n"
        "Termin płatności: 26.09.2026\nDo zapłaty: 1.250,50 zł"
    )
    parsed = parse_invoice_text(text)
    assert parsed["invoice_no"] == "FV/12/09/2026"
    assert parsed["issue_date"] == "2026-09-12"
    assert parsed["sale_date"] == "2026-09-10"
    assert parsed["due_date"] == "2026-09-26"
    assert parsed["buyer_name"] == "UKS Grunwald Ruda Śląska"
    assert parsed["buyer_nip"] == "6410008955"
    assert parsed["gross"] == 1250.5


def test_interleaved_columns_take_nips_in_order():
    # Dwie kolumny sklejone w linii: nazwy nie da się rozdzielić, NIP-y po kolei.
    text = (
        "Faktura Nr 5/SL/2026\nSprzedawca: Nabywca:\nNIP: 9540008151 NIP: 6410008955\n"
        "Razem do zapłaty: 200,00 PLN"
    )
    parsed = parse_invoice_text(text)
    assert parsed["seller_nip"] == "9540008151"
    assert parsed["buyer_nip"] == "6410008955"
    assert parsed["gross"] == 200.0
    # NIP nabywcy wystarczy, żeby nie wołać AI (klub znajdzie się po NIP-ie albo ręcznie).
    assert not needs_ai(parsed, has_text=True)


def test_missing_amount_or_buyer_calls_for_ai():
    parsed = parse_invoice_text("Faktura Nr 1/2026 Nabywca: KS Zgoda")
    assert "gross" in parsed["missing"]
    assert needs_ai(parsed, has_text=True)
    assert needs_ai(parse_invoice_text(SALDEO_TEXT), has_text=False)  # skan
    assert not needs_ai(parse_invoice_text(SALDEO_TEXT), has_text=True)


def test_ai_fills_only_gaps_and_is_sanitized():
    rules = parse_invoice_text("Faktura Nr 1/SL/2026 Nabywca: KS Zgoda Adres: X")
    ai = sanitize_ai(
        {
            "invoice_no": "999/INNY",
            "issue_date": "2026-06-15T00:00:00",
            "buyer_nip": "641-000-89-55",
            "gross": "3 000,00",
            "items": [{"name": " Obsługa  sędziowska ", "gross": 3000}, "śmieć"],
            "extra": "ignorowane",
        }
    )
    assert ai["gross"] == 3000.0
    assert ai["buyer_nip"] == "6410008955"
    assert ai["issue_date"] == "2026-06-15"
    assert ai["items"] == [{"name": "Obsługa sędziowska", "quantity": None, "unit": "", "gross": 3000.0}]
    merged = merge_ai(rules, ai)
    assert merged["invoice_no"] == "1/SL/2026"  # reguły wygrywają
    assert merged["gross"] == 3000.0
    assert merged["missing"] == []


# ---------------------------------------------------------------------------
# PDF składany w teście
# ---------------------------------------------------------------------------


def _pdf(lines: list[str]) -> bytes:
    fitz = pytest.importorskip("fitz")
    font = os.path.join(os.path.dirname(__file__), "..", "app", "fonts", "NotoSans-Regular.ttf")
    doc = fitz.open()
    page = doc.new_page()
    page.insert_font(fontname="noto", fontfile=font)
    y = 50
    for line in lines:
        page.insert_text((40, y), line, fontname="noto", fontsize=9)
        y += 14
    data = doc.tobytes()
    doc.close()
    return data


def test_generated_pdf_reads_with_rules():
    from app.invoice_pdf import analyze_pdf, is_pdf

    data = _pdf(SALDEO_LINES)
    assert is_pdf(data)
    read = analyze_pdf(data)
    assert read["has_text"] is True
    assert read["pages"] == 1
    _assert_saldeo(read["parsed"])


def test_two_column_pdf_keeps_buyer_block():
    """Sprzedawca i Nabywca obok siebie - tak składa je większość programów."""
    fitz = pytest.importorskip("fitz")
    from app.invoice_pdf import analyze_pdf

    font = os.path.join(os.path.dirname(__file__), "..", "app", "fonts", "NotoSans-Regular.ttf")
    doc = fitz.open()
    page = doc.new_page()
    page.insert_font(fontname="noto", fontfile=font)
    page.insert_text((40, 40), "Faktura Nr 78/SL/2026", fontname="noto", fontsize=10)
    page.insert_text((40, 58), "16-06-2026 data wystawienia", fontname="noto", fontsize=9)
    left = ["Sprzedawca:", "ŚLĄSKI ZWIĄZEK PIŁKI RĘCZNEJ W KATOWICACH", "Adres: Jesionowa 15", "NIP: 9540008151"]
    right = ["Nabywca:", 'KLUB SPORTOWY "ZGODA" RUDA ŚLĄSKA-BIELSZ', "Adres: Sportowców 10", "NIP: 6410008955"]
    page.insert_textbox(fitz.Rect(40, 80, 290, 160), "\n".join(left), fontname="noto", fontsize=8)
    page.insert_textbox(fitz.Rect(310, 80, 560, 160), "\n".join(right), fontname="noto", fontsize=8)
    page.insert_text((40, 190), "Razem do zapłaty: 1 500,00 PLN", fontname="noto", fontsize=9)
    data = doc.tobytes()
    doc.close()

    parsed = analyze_pdf(data)["parsed"]
    assert parsed["seller_nip"] == "9540008151"
    assert parsed["buyer_nip"] == "6410008955"
    assert parsed["gross"] == 1500.0
    assert parsed["issue_date"] == "2026-06-16"
    assert "ZGODA" in parsed["buyer_name"]


def test_not_a_pdf_is_recognized():
    from app.invoice_pdf import is_pdf

    assert not is_pdf(b"\x89PNG\r\n\x1a\n....")
    assert not is_pdf(b"")


# ---------------------------------------------------------------------------
# dopasowanie klubu
# ---------------------------------------------------------------------------


def test_tokens_drop_legal_forms_quotes_and_diacritics():
    assert name_tokens('KLUB SPORTOWY "ZGODA" RUDA ŚLĄSKA-BIELSZ') == ["zgoda", "ruda", "slaska", "bielsz"]
    assert name_tokens("KS Zgoda Ruda Śląska") == ["zgoda", "ruda", "slaska"]
    assert name_tokens("Uczniowski Klub Sportowy Grunwald (SL)") == ["grunwald"]


def test_krs_name_matches_panel_club_confidently():
    buyer = 'KLUB SPORTOWY "ZGODA" RUDA ŚLĄSKA-BIELSZ'
    ranked = rank_clubs(buyer, CLUBS)
    assert ranked[0]["club_id"] == "1126"
    result = propose(buyer_name=buyer, buyer_nip="6410008955", candidates=CLUBS, known_nips={})
    assert result["club_id"] == "1126"
    assert result["via"] == "name"
    assert result["confident"] is True
    assert result["confidence"] >= 0.75


def test_same_city_alone_is_not_confident():
    result = propose(buyer_name="Klub Sportowy Ruda Śląska", buyer_nip="", candidates=CLUBS, known_nips={})
    assert result["confident"] is False


def test_known_nip_wins_over_name():
    result = propose(
        buyer_name="Zupełnie inna nazwa",
        buyer_nip="641-000-89-55",
        candidates=CLUBS,
        known_nips={"6410008955": "1126"},
    )
    assert result == {**result, "club_id": "1126", "via": "nip", "confident": True, "confidence": 1.0}


def test_unknown_buyer_has_no_proposal():
    result = propose(buyer_name="Fundacja Wspierania Czegoś", buyer_nip="", candidates=CLUBS, known_nips={})
    assert result["club_id"] == ""
    assert result["confident"] is False


def test_shared_budget_sends_payment_to_main_club():
    members = budget_members([{"budget_id": 1, "primary_club_id": "2001", "member_ids": ["2001", "1126"]}])
    assert members == {"1126": "2001"}
    result = propose(
        buyer_name='KLUB SPORTOWY "ZGODA" RUDA ŚLĄSKA-BIELSZ',
        buyer_nip="",
        candidates=CLUBS,
        known_nips={},
        budget_main=members,
    )
    assert result["club_id"] == "2001"
    assert result["budget_of"] == "1126"


def test_budget_contract_shapes():
    assert budget_members({"10": {"club_id": "10", "member_ids": ["10", "11"]}}) == {"11": "10"}
    assert budget_members({"10": ["10", "12"]}) == {"12": "10"}
    assert budget_members({"10": {"member_ids": '["10", "13"]'}}) == {"13": "10"}
    assert budget_members(None) == {}
