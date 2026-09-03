"""Podpisy złożone POD dodatkowym raportem.

Raport pisany dzień po meczu nie ma podpisów z protokołu - wtedy sędziowie
(albo delegat) podpisują się w samym raporcie. Te podpisy mieszkają na wierszu
raportu i NIGDY nie wracają do bloba meczu - działa tylko w tę stronę.

Dwie pułapki, których pilnuje ten plik:

  • autozapis treści leci co chwilę i BEZ pola `signatures` - gdyby brak pola
    znaczył „pusta lista", każda dopisana litera kasowałaby podpis złożony
    przed chwilą;
  • wiersze sprzed tej rubryki nie mają kolumny wcale - odczyt musi oddać
    pustą listę, a nie wybuchnąć.
"""
from app.extra_reports import (
    ExtraReportBody,
    _clean_signatures,
    _row_to_item,
)


def test_body_bez_pola_znaczy_nie_ruszaj():
    """Autozapis treści nie niesie podpisów - i nie może ich skasować."""
    body = ExtraReportBody(entries=[{"description": "opis"}])
    assert body.signatures is None


def test_body_z_pusta_lista_znaczy_wyczysc():
    """Pusta lista to świadome żądanie - odróżnialne od braku pola."""
    body = ExtraReportBody(entries=[], signatures=[])
    assert body.signatures == []


def test_clean_przycina_i_zamienia_none_na_pusty():
    assert _clean_signatures(["/signatures/a.png ", None, "  "]) == [
        "/signatures/a.png",
        "",
        "",
    ]


def test_clean_odrzuca_nie_liste():
    assert _clean_signatures(None) == []
    assert _clean_signatures("x") == []
    assert _clean_signatures({"0": "a"}) == []


def test_stary_wiersz_bez_kolumny_daje_pusta_liste():
    row = {
        "kind": "referees",
        "entries": [],
        "updated_by": None,
        "updated_by_name": None,
        "updated_at": None,
        "generated_by": None,
        "generated_by_name": None,
        "generated_at": None,
    }
    assert _row_to_item(row).signatures == []


def test_wiersz_z_podpisami_oddaje_je_w_kolejnosci():
    row = {
        "kind": "referees",
        "entries": [],
        "signatures": ["/signatures/ref1.png", "", "/signatures/ref2.png"],
        "updated_at": None,
    }
    # Kolejność jest znacząca: pierwszy podpis należy do pierwszego sędziego.
    assert _row_to_item(row).signatures == [
        "/signatures/ref1.png",
        "",
        "/signatures/ref2.png",
    ]
