"""Reguła uprawnień okręgowych - sam rdzeń, bez bazy i bez HTTP.

Stawką jest zapis po cudzym okręgu, więc testy pilnują obu kierunków pomyłki:
Master, którego nie wpuszczono, i obcy, którego wpuszczono.
"""

from __future__ import annotations

from app.province_access import (
    is_app_admin,
    judge_ids,
    master_ids_for_province,
    may_write_offtimes,
    may_write_province,
    normalize_province,
)

DOLNY = "DOLNOŚLĄSKIE"


def test_wojewodztwo_bez_ogonkow_to_to_samo_wojewodztwo():
    # Nazwa przy ogłoszeniu przychodzi z telefonu, lista Masterów z panelu -
    # jedna strona potrafi napisać bez ogonków.
    assert normalize_province("Dolnośląskie") == normalize_province("DOLNOSLASKIE")
    assert normalize_province("  śląskie ") == "SLASKIE"
    assert normalize_province(None) == ""


def test_numery_sedziow_z_kazdego_ksztaltu_kolumny():
    # JSONB pod asyncpg bez kodeka wraca surowym napisem - na tym przewrócił
    # się kiedyś obsadowy w giełdzie.
    assert judge_ids('["12", "34"]') == ["12", "34"]
    assert judge_ids([12, "34", "", None]) == ["12", "34"]
    assert judge_ids({"12": True, "34": False}) == ["12"]
    assert judge_ids(None) == []
    assert judge_ids("to nie jest json") == []


def test_lista_masterow_szuka_wojewodztwa_odpornie_na_zapis():
    rows = [
        {"province": "ŚLĄSKIE", "judges": ["1"]},
        {"province": "DOLNOSLASKIE", "judges": ["7", "9"]},
    ]
    assert master_ids_for_province(rows, DOLNY) == ["7", "9"]
    assert master_ids_for_province(rows, "MAZOWIECKIE") == []
    assert master_ids_for_province([], DOLNY) == []


def test_master_okregu_moze_pisac_a_obcy_nie():
    assert may_write_province(judge_id="7", master_judge_ids=["7", "9"]) is True
    assert may_write_province(judge_id="8", master_judge_ids=["7", "9"]) is False


def test_administrator_przechodzi_wszedzie():
    assert (
        may_write_province(judge_id="999", master_judge_ids=[], admin_ids=["999"])
        is True
    )
    assert is_app_admin("999", ["999"]) is True
    assert is_app_admin("999", []) is False


def test_bez_numeru_sedziego_nie_ma_zapisu():
    # Konto bez NrSedzia (organizacja) nie może być na żadnej liście Masterów.
    assert may_write_province(judge_id="", master_judge_ids=["7"]) is False
    assert may_write_province(judge_id=None, admin_ids=["999"]) is False


def test_po_swoich_niedyspozycjach_pisze_kazdy():
    assert (
        may_write_offtimes(judge_id="55", target_judge_id="55", master_judge_ids=[])
        is True
    )


def test_po_cudzych_niedyspozycjach_tylko_master_albo_admin():
    assert (
        may_write_offtimes(judge_id="55", target_judge_id="66", master_judge_ids=[])
        is False
    )
    assert (
        may_write_offtimes(
            judge_id="55", target_judge_id="66", master_judge_ids=["55"]
        )
        is True
    )
    assert (
        may_write_offtimes(
            judge_id="999", target_judge_id="66", admin_ids=["999"]
        )
        is True
    )


def test_numer_porownujemy_jako_napis():
    # Token niesie numer napisem, baza bywa z liczbami.
    assert may_write_province(judge_id="7", master_judge_ids=[7]) is True
    assert may_write_offtimes(judge_id="7", target_judge_id=7) is True
