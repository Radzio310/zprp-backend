"""
II liga powierzona okręgowi: boiskowych płaci okręg (decyzja z 06.10.2026).

Zgłoszenie: na koncie MKS Wiry Mysłowice mecze IIM4 miały tylko stolikowych -
boiskowi „naszej" II ligi szli jako obsada ZPRP. Od sezonu 2026/2027 okręg ich
płaci i obciąża gospodarza; delegaci zostają przy ZPRP.
"""

from datetime import date, datetime, timezone

from app import settlement_engine as E
from app import settlement_rates as R

MANAGED = ["IIM4", "IIK4"]


def test_province_pays_field_only_in_entrusted_second_league():
    day = date(2026, 10, 1)
    assert R.province_pays_field("IIM4/10", MANAGED, day)
    assert R.province_pays_field("IIK4/2", MANAGED, datetime(2026, 9, 27, 15, tzinfo=timezone.utc))
    assert not R.province_pays_field("IIM3/10", MANAGED, day)     # cudza grupa
    assert not R.province_pays_field("IM/10", MANAGED, day)       # I liga - zawsze ZPRP
    assert not R.province_pays_field("S/JMM/1", MANAGED, day)     # nie II liga
    assert not R.province_pays_field("IIM4/10", [], day)          # okręg bez lig
    assert not R.province_pays_field("IIM4/10", MANAGED, date(2026, 8, 31))  # sezon zamknięty
    assert not R.province_pays_field("IIM4/10", MANAGED, None)


def test_reason_keeps_delegate_and_table_rules():
    assert R.zprp_settlement_reason("IIM4/10", R.ROLE_FIELD) == R.ZPRP_FIELD
    assert R.zprp_settlement_reason("IIM4/10", R.ROLE_FIELD, province_field=True) is None
    assert R.zprp_settlement_reason("IIM4/10", R.ROLE_DELEGATE, province_field=True) == R.ZPRP_DELEGATE
    assert R.zprp_settlement_reason("IIM4/10", R.ROLE_TABLE, province_field=True) is None


def test_engine_counts_province_paid_field_referee():
    common = dict(
        province="SLASKIE",
        central_versions=[],
        province_versions=[],
        now=datetime(2026, 10, 6, tzinfo=timezone.utc),
    )
    when = datetime(2026, 10, 1, 17, tzinfo=timezone.utc)
    zprp = E.Assignment(match_key="d:1", judge_id="9", match_at=when, match_code="IIM4/10",
                        role=R.ROLE_FIELD, distance_km=30)
    ours = E.Assignment(match_key="d:1", judge_id="9", match_at=when, match_code="IIM4/10",
                        role=R.ROLE_FIELD, distance_km=30, province_field=True)
    assert E.settle_judges([zprp], **common) == []
    entries = E.settle_judges([ours], **common)
    assert len(entries) == 1 and entries[0].matches[0].zprp_reason is None
    assert E.zprp_matches([ours], now=common["now"]) == []
