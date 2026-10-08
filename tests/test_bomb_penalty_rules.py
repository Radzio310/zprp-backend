"""Kara za nieobecność naliczana w sezonie - decyzje Radka z 07.10.2026.

Każda decyzja z rozmowy ma tu swój test:
  - 60 / 90 / 120 / 150 i dalej co 30 zł, bez górnej granicy,
  - liczą się tylko CZYNNE bomby, po kolei wg daty meczu; cofnięcie albo
    unieważnienie przelicza resztę na żywo,
  - ręczna kara zmienia tylko swoją bombę, a ta dalej liczy się jako kolejna,
  - skala ustawiana per okręg,
  - kolejność liczona dla SĘDZIEGO w sezonie (bez względu na okręg wpisu).
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app import bomb_penalty_rules as BP
from app.bomb_penalty_rules import effective_from_pool


def at(day: int, hour: int = 12, month: int = 10, year: int = 2026) -> datetime:
    return datetime(year, month, day, hour, 0, tzinfo=timezone.utc)


def bomb(bomb_id: int, **over) -> dict:
    row = {
        "id": bomb_id,
        "province": "SLASKIE",
        "season": 2026,
        "status": "active",
        "subject_judge_id": "5494",
        "subject_name": "DRAB Krzysztof",
        "match_at": at(3, 9 + bomb_id),
        "created_at": at(4, 16),
        "penalty": None,
        "penalty_mode": "auto",
    }
    row.update(over)
    return row


def test_skala_domyslna_60_90_120_150_i_dalej_co_30():
    assert [BP.amount_for(n) for n in (1, 2, 3, 4, 5, 10)] == [60, 90, 120, 150, 180, 330]


def test_kolejnosc_po_dacie_meczu_a_nie_po_chwili_wpisu():
    rows = [
        bomb(1, match_at=at(3, 14), created_at=at(4, 9)),
        bomb(2, match_at=at(3, 11), created_at=at(4, 10)),
        bomb(3, match_at=at(3, 12), created_at=at(4, 11)),
    ]
    assert BP.ordinals(rows) == {2: 1, 3: 2, 1: 3}


def test_uniewaznienie_przelicza_reszte_na_zywo():
    rows = [bomb(1), bomb(2), bomb(3)]
    pens = effective_from_pool(rows, rows, {})
    assert [pens[i].amount for i in (1, 2, 3)] == [60, 90, 120]

    rows[1]["status"] = "voided"
    pens = effective_from_pool(rows, rows, {})
    assert pens[1].amount == 60
    assert pens[2].amount is None and pens[2].ordinal is None
    assert pens[3].amount == 90 and pens[3].ordinal == 2


def test_cofniete_tez_nie_licza_sie():
    rows = [bomb(1, status="withdrawn"), bomb(2)]
    pens = effective_from_pool(rows, rows, {})
    assert pens[2].amount == 60


def test_reczna_kara_zmienia_tylko_swoja_bombe_a_kolejne_licza_ja_dalej():
    rows = [bomb(1), bomb(2, penalty_mode="manual", penalty=None), bomb(3)]
    pens = effective_from_pool(rows, rows, {})
    assert pens[2].amount is None and pens[2].auto is False and pens[2].ordinal == 2
    assert pens[3].amount == 120 and pens[3].auto is True


def test_reczna_kwota_wygrywa_ze_skala():
    rows = [bomb(1, penalty_mode="manual", penalty=45.5)]
    pen = effective_from_pool(rows, rows, {})[1]
    assert pen.amount == 45.5 and pen.auto is False and pen.ordinal == 1


def test_pusty_tryb_sprzed_naliczania_liczy_sie_jak_automat():
    rows = [bomb(1, penalty_mode=None, penalty=60)]
    pen = effective_from_pool(rows, rows, {})[1]
    assert pen.amount == 60 and pen.auto is True


def test_kazdy_sedzia_i_kazdy_sezon_ma_wlasna_kolejke():
    rows = [
        bomb(1),
        bomb(2),
        bomb(3, subject_judge_id="5506", subject_name="WOŹNIAKOWSKA Natalia"),
        bomb(4, season=2025, match_at=at(3, 12, month=5)),
    ]
    pens = effective_from_pool(rows, rows, {})
    assert pens[2].amount == 90
    assert pens[3].amount == 60
    assert pens[4].amount == 60


def test_bez_numeru_ten_sam_czlowiek_przy_innej_kolejnosci_nazwiska():
    rows = [
        bomb(1, subject_judge_id="", subject_name="DRAB Krzysztof"),
        bomb(2, subject_judge_id="", subject_name="Krzysztof DRAB"),
    ]
    assert BP.ordinals(rows) == {1: 1, 2: 2}


def test_kolejka_sedziego_nie_zalezy_od_okregu_wpisu_ale_kwota_z_jego_skali():
    rows = [bomb(1), bomb(2, province="MALOPOLSKIE")]
    scales = {"MALOPOLSKIE": BP.Scale(start=100, step=50, custom=True)}
    pens = effective_from_pool(rows, rows, scales)
    assert pens[1].amount == 60
    # druga bomba tego sędziego, ale w rejestrze Małopolski: 100 + 50
    assert pens[2].amount == 150 and pens[2].ordinal == 2


def test_skala_okregu():
    scale = BP.normalize_scale(50, 25)
    assert [BP.amount_for(n, scale) for n in (1, 2, 3)] == [50, 75, 100]
    assert BP.normalize_scale("80", "0").step == 0


@pytest.mark.parametrize("start, step", [(-1, 30), (60, -5), ("abc", 30), (20000, 30)])
def test_skala_z_bledem_odmawia_zdaniem(start, step):
    with pytest.raises(ValueError) as err:
        BP.normalize_scale(start, step)
    assert "zł" in str(err.value) or "ujemna" in str(err.value)


def test_wiersz_skali_z_bazy_i_jego_brak():
    assert BP.scale_from_row(None) == BP.DEFAULT_SCALE
    assert BP.scale_from_row({"start": 70, "step": 35}).as_dict() == {
        "start": 70,
        "step": 35,
        "custom": True,
    }


def test_podglad_kolejki_dla_nowego_wpisu():
    rows = [bomb(1, match_at=at(3, 11)), bomb(2, match_at=at(3, 14))]
    key = BP.subject_key({"subject_judge_id": "5494"})
    # mecz po obu: trzecia
    assert BP.preview_ordinal(rows, key=key, season=2026, match_at=at(5)) == 3
    # mecz między nimi: druga (po zapisie wpis dostanie 90, a późniejsza 120)
    assert BP.preview_ordinal(rows, key=key, season=2026, match_at=at(3, 12)) == 2
    # inny sezon: pierwsza
    assert BP.preview_ordinal(rows, key=key, season=2027, match_at=at(5, 12, year=2027)) == 1
