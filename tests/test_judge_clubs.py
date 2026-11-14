"""
„Kto płaci" przy meczu sędziego - tylko kluby Z JEGO meczów.

Zgłoszenie z 14.11.2026 (Śląskie): Michał Kopiec miał jeden mecz klubowy,
LCK/50 MTS Trendy Top Żory - SMS ZPRP I Płock w Żorach. Panel pokazywał go
dobrze, a aplikacja pisała „wypłaca MKS Siemion SP4 Siemianowice Śląski…".
`/me` brał wycinek z miesiąca CAŁEGO okręgu (pamięć panelu), a `_judge_payload`
przepisywał `outside_district.clubs` bez zawężenia - czyli wszystkie kluby
okręgu płacące same. Aplikacja skleja ich nazwy w jedną linię i ucina ją po
pierwszym klubie.

⚠ `app/province_settlements.py` ciągnie `app/db.py`, który łączy się z bazą już
przy imporcie - funkcję wyciągamy ze ŹRÓDŁA (ast) i wykonujemy naprawdę.
"""
from __future__ import annotations

import ast
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "app" / "province_settlements.py").read_text(encoding="utf-8")


def _load(name: str):
    tree = ast.parse(SOURCE)
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name)
    scope: dict = {}
    exec(compile(ast.Module(body=[node], type_ignores=[]), "province_settlements.py", "exec"), scope)  # noqa: S102 - funkcja z naszego źródła
    return scope[name]


judge_clubs = _load("_judge_clubs")

SIEMION = {"club_id": "100", "club_name": "MKS Siemion SP4 Siemianowice Śląskie", "matches": 9, "amount": 900.0}
TRENDY = {"club_id": "manual:club:abc", "club_name": "MTS Trendy Top Żory", "matches": 3, "amount": 540.0}
OTHER = {"club_id": "200", "club_name": "KS Inny", "matches": 1, "amount": 100.0}

# Miesiąc CAŁEGO okręgu: trzy kluby płacące same, mecze wielu sędziów.
WHOLE_DISTRICT = {
    "clubs": [SIEMION, TRENDY, OTHER],
    "club_of": {"d:1": "100", "d:2": "100", "o:50": "manual:club:abc", "d:9": "200"},
}


def test_zostaja_tylko_kluby_z_meczow_sedziego():
    rows = [{"match_key": "o:50"}]
    clubs = judge_clubs(WHOLE_DISTRICT, rows)
    assert [c["club_name"] for c in clubs] == ["MTS Trendy Top Żory"]
    assert clubs[0]["matches"] == 1


def test_wiersz_niesie_swojego_platnika():
    rows = [{"match_key": "d:1"}, {"match_key": "o:50"}]
    judge_clubs(WHOLE_DISTRICT, rows)
    assert rows[0]["club_id"] == "100"
    assert rows[0]["club_name"] == "MKS Siemion SP4 Siemianowice Śląskie"
    assert rows[1]["club_name"] == "MTS Trendy Top Żory"


def test_kolejnosc_i_liczniki_jak_w_okregu():
    rows = [{"match_key": "o:50"}, {"match_key": "d:1"}, {"match_key": "d:2"}]
    clubs = judge_clubs(WHOLE_DISTRICT, rows)
    assert [(c["club_id"], c["matches"]) for c in clubs] == [("100", 2), ("manual:club:abc", 1)]


def test_nie_psuje_wspolnej_pamieci():
    """Miesiąc okręgu jest wspólny dla wszystkich pytających - tylko do odczytu."""
    judge_clubs(WHOLE_DISTRICT, [{"match_key": "o:50"}])
    assert WHOLE_DISTRICT["clubs"][1]["matches"] == 3
    assert len(WHOLE_DISTRICT["clubs"]) == 3


def test_bez_meczow_klubowych_pusta_lista():
    assert judge_clubs(WHOLE_DISTRICT, []) == []


def test_wynik_sprzed_zmiany_zostawia_liste():
    """Pamięć policzona przed wdrożeniem nie ma `club_of` - lepsza pełna lista niż pusta."""
    old = {"clubs": [SIEMION, TRENDY]}
    rows = [{"match_key": "o:50"}]
    assert judge_clubs(old, rows) == [SIEMION, TRENDY]
    assert "club_name" not in rows[0]


def test_trasy_uzywaja_zawezenia():
    body = SOURCE[SOURCE.index("async def _judge_payload"):]
    body = body[: body.index("\n@router")]
    assert "_judge_clubs(data[\"outside_district\"]" in body
    assert '"clubs": outside_clubs' in body
    assert '"clubs": data["outside_district"]["clubs"]' not in body
    load = SOURCE[SOURCE.index("async def load_settlement"):SOURCE.index("def _tournament_mates")]
    assert '"club_of": {' in load
