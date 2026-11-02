"""Stawki międzypaństwowe: kopia w kodzie zgodna z zasileniem, dopisanie nie rusza istniejących kwot."""
import io
import json
import pathlib

from app.central_rates_intl import INTL_FIELD_RATES, with_intl_categories

ROOT = pathlib.Path(__file__).resolve().parents[1]
SEED = json.loads(io.open(ROOT / "app" / "data" / "central_rates_seed.json", encoding="utf-8").read())
NEW = next(v for v in SEED["versions"] if v.get("valid_from") == "2026-09-01")["content"]
OLD = next(v for v in SEED["versions"] if not v.get("valid_from"))["content"]


def test_seed_ma_te_same_kwoty_co_kod():
    for day, rates in INTL_FIELD_RATES.items():
        for key, band in rates.items():
            assert NEW[day]["boiskowy"][key] == band
            assert NEW[day]["stolikowy"][key] == 110


def test_stara_tabela_nie_dostaje_nowych_kategorii():
    assert "Międzypaństwowe seniorzy" not in OLD["weekend"]["boiskowy"]


def test_dopisanie_nie_nadpisuje_recznej_kwoty_i_jest_idempotentne():
    content = {"weekend": {"boiskowy": {"Międzypaństwowe seniorzy": {"below100": 1, "100to300": 2, "above300": 3}, "LC": {"below100": 339}}}}
    once = with_intl_categories(content)
    assert once["weekend"]["boiskowy"]["Międzypaństwowe seniorzy"]["below100"] == 1
    assert once["weekend"]["boiskowy"]["LC"] == {"below100": 339}
    assert once["weekend"]["boiskowy"]["Międzynarodowe młodzież"] == {"below100": 195, "100to300": 245, "above300": 245}
    assert once["weekday"]["stolikowy"]["Międzynarodowe seniorzy"] == 110
    assert with_intl_categories(once) == once
    assert "weekday" not in content


def test_zasilenie_tylko_wersji_od_dokladnie_01_09_2026_i_bez_wpisu_kategorii():
    from datetime import date

    from app.central_rates_intl import has_intl_entry, needs_intl_seed

    assert needs_intl_seed(date(2026, 9, 1), OLD) is True  # stan sprzed zasilenia: brak kategorii
    assert needs_intl_seed(date(2026, 9, 1), NEW) is False  # zasilona wersja zostaje
    assert needs_intl_seed(date(2027, 1, 1), OLD) is False  # późniejsza wersja nie dostaje kwot nie ze swojego okresu
    assert needs_intl_seed(date(2026, 8, 31), OLD) is False and needs_intl_seed(None, OLD) is False
    assert needs_intl_seed("2026-09-01", OLD) is True and needs_intl_seed("nie data", OLD) is False


def test_swiadomie_usuniety_klucz_nie_wraca():
    from datetime import date

    from app.central_rates_intl import needs_intl_seed

    trimmed = json.loads(json.dumps(NEW))
    del trimmed["weekend"]["boiskowy"]["Międzypaństwowe seniorzy"]
    del trimmed["weekday"]["stolikowy"]["Międzynarodowe młodzież"]
    assert needs_intl_seed(date(2026, 9, 1), trimmed) is False  # wersja ma już wpisy: nic nie dopisujemy
    assert needs_intl_seed(date(2026, 9, 1), {}) is False  # pusta treść to nie tabela


def test_zapis_zasilenia_jest_warunkowy_na_wersji_wiersza():
    source = (ROOT / "app" / "central_rates.py").read_text(encoding="utf-8")
    body = source[source.index("async def ensure_intl_categories"):source.index("async def seed_central_rates")]
    assert "needs_intl_seed(" in body and "central_rates.c.updated_at ==" in body and "INTL_FROM" not in body
