"""Ukryci zgłoszeni na giełdzie (decyzja 12.11.2026).

Moduły giełdy importują `app.db` (JSONB), więc bez Postgresa nie da się ich
zaimportować. Funkcje widoków wyciągamy z kodu źródłowego przez `ast` i
wykonujemy z prostymi atrapami - sprawdzamy realną logikę, nie napisy.
"""

import ast
import asyncio
import inspect
import pathlib

from app.match_market_access import names_hidden_split
from app.match_market_crew_rules import text_filled
from app.match_market_journal import CONFIG_FIELD_LABELS, config_diff_message
from app.match_market_notify import (
    claim_digest_hidden,
    claim_lost_hidden,
    claim_withdrawn_hidden,
    crew_changed_hidden,
    giver_released_hidden,
    taker_won_hidden,
)

APP = pathlib.Path(__file__).resolve().parents[1] / "app"


def _extract(module: str, name: str, env: dict):
    tree = ast.parse((APP / module).read_text(encoding="utf-8"))
    fn = next(
        n for n in tree.body
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name
    )
    fn.returns = None
    for a in fn.args.args + fn.args.kwonlyargs:
        a.annotation = None
    ns = dict(env)
    exec(compile(ast.Module(body=[fn], type_ignores=[]), module, "exec"), ns)
    return ns[name]


def _s(v):
    return "" if v is None else str(v).strip()


def _market():
    env = {
        "_s": _s,
        "_iso": lambda v: _s(v) or None,
        "_person": lambda jid, card: {"id": jid, "fullName": _s((card or {}).get("full_name"))},
        "_match_view": lambda *a: {},
        "slot_label": lambda s: _s(s),
        "state_dict": lambda v: v or {},
        "nearest_km": lambda *a: None,
        "km_value": lambda v: None,
        "bench_fields": lambda v: {},
        "CLAIMERS_PREVIEW_LIMIT": 5,
    }
    return _extract("match_market.py", "_offer_payload", env)


OFFER = {"id": 1, "from_judge_id": "G", "status": "done", "slot": "sedzia1", "province": "slaskie"}
CARDS = {j: {"full_name": f"Sędzia {j}"} for j in ("G", "A", "B", "T")}
CLAIMS = [
    {"id": 1, "judge_id": "A", "status": "pending", "created_at": "1"},
    {"id": 2, "judge_id": "B", "status": "pending", "created_at": "2"},
    {"id": 3, "judge_id": "T", "status": "chosen", "created_at": "3"},
]


def _payload(viewer, hide):
    return asyncio.run(_market()(OFFER, CARDS, CLAIMS, viewer_id=viewer, hide_names=hide))


def test_jawnie_jak_dotad_gdy_ukrycie_wylaczone():
    giver = _payload("G", False)
    assert len(giver["claimers"]) == 3 and len(giver["claims"]) == 3
    assert giver["takerName"] == "Sędzia T"
    other = _payload("A", False)
    assert other["claims"] == [] and len(other["claimers"]) == 3


def test_zwykly_sedzia_przy_ukryciu_nie_dostaje_nazwisk():
    p = _payload("A", True)
    assert p["claimers"] == [] and p["claims"] == []
    assert p["takerName"] is None and p["taker"] is None
    assert p["claimCount"] == 2
    assert p["myClaim"]["status"] == "pending"  # „ja się zgłosiłem"
    assert "Sędzia B" not in repr(p) and "Sędzia T" not in repr(p)


def test_oddajacy_przy_ukryciu_widzi_tylko_liczbe():
    p = _payload("G", True)
    assert p["claims"] == [] and p["claimers"] == []
    assert p["claimCount"] == 2
    assert p["takerName"] is None and p["taker"] is None
    for name in ("Sędzia A", "Sędzia B", "Sędzia T"):
        assert name not in repr(p)


def test_przejmujacy_widzi_siebie_przy_ukryciu():
    p = _payload("T", True)
    assert p["takerName"] == "Sędzia T"
    assert "Sędzia A" not in repr(p)


def test_approver_dostaje_komplet_bo_serwer_nie_ukrywa_przed_nim():
    p = _payload("M", False)
    assert len(p["claimers"]) == 3 and p["takerName"] == "Sędzia T"


def test_trasy_licza_ukrycie_tylko_dla_nie_approverow():
    src = (APP / "match_market.py").read_text(encoding="utf-8")
    assert 'hide_names=bool(cfg["hide_claimers"]) and not approver' in src
    assert 'hide_names = bool(cfg["hide_claimers"]) and not approver' in src
    assert "if approver or (mine and not hide_names):" in src
    assert '"hideClaimers": bool(cfg and cfg["hide_claimers"])' in src


def _slot_views():
    class R:
        SLOT_LABELS = {"s1": "Sędzia 1", "s2": "Sędzia 2"}
        role_of_slot = staticmethod(lambda s: "field")

    env = {
        "_s": _s,
        "R": R,
        "_assigned": lambda claims: {c["slot"]: c for c in claims if c.get("slot")},
        "_person": lambda jid, cards: {"id": jid, "name": cards.get(jid, {}).get("full_name", "")},
    }
    return _extract("match_market_crew.py", "_slot_views", env)


def test_giełda_obsadowego_ukrywa_obsadzonych_przed_zwyklym():
    views = _slot_views()
    offer = {"slots": ["s1", "s2"]}
    claims = [{"id": 1, "judge_id": "A", "slot": "s1"}, {"id": 2, "judge_id": "B", "slot": "s2"}]
    cards = {"A": {"full_name": "Anna A"}, "B": {"full_name": "Beata B"}}
    shown = views(offer, claims, cards, hide_names=False, viewer_id="X")
    assert shown[0]["assignedTo"]["name"] == "Anna A"
    hidden = views(offer, claims, cards, hide_names=True, viewer_id="A")
    assert hidden[0]["assignedTo"]["name"] == "Anna A" and hidden[0]["takenByMe"]
    assert hidden[1]["assignedTo"] is None and hidden[1]["taken"] and not hidden[1]["takenByMe"]
    assert hidden[1]["claimId"] is None
    assert "Beata" not in repr(hidden)


def test_podzial_adresatow_pushy():
    assert names_hidden_split(["a", "b", "m"], ["m"], False) == (["a", "b", "m"], [])
    assert names_hidden_split(["a", "b", "m"], ["m"], True) == (["m"], ["a", "b"])


OFFER_TXT = {
    "slot": "sedzia1", "match_code": "IIM4/1", "match_at": None,
    "match_snapshot": {"home": "Pogoń", "away": "Śląsk"},
}


def test_teksty_pushy_bez_nazwisk():
    assert taker_won_hidden(OFFER_TXT)[0].endswith("Masz mecz")
    assert claim_lost_hidden(OFFER_TXT)[0] == "Tym razem nie"
    assert text_filled(OFFER_TXT, True)[0] == "Tym razem nie"
    assert text_filled(OFFER_TXT, False)[0] == "Mecz obsadzony"
    assert giver_released_hidden(OFFER_TXT)[0].endswith("Mecz oddany")
    digest = claim_digest_hidden(OFFER_TXT, 4)
    assert "4" in digest[0] and "Wybiera obsadowy" in digest[1]
    assert "Brak" in claim_digest_hidden(OFFER_TXT, 0)[0]
    for fn in (claim_digest_hidden, claim_withdrawn_hidden, taker_won_hidden,
               claim_lost_hidden, giver_released_hidden, crew_changed_hidden):
        assert "name" not in "".join(inspect.signature(fn).parameters)
    for t in (claim_withdrawn_hidden(OFFER_TXT), crew_changed_hidden(OFFER_TXT)):
        assert t[0] and t[1]


def test_ustawienie_w_dzienniku():
    assert "hide_claimers" in CONFIG_FIELD_LABELS
    msg = config_diff_message({"hide_claimers": False}, {"hide_claimers": True})
    assert "ukrycie zgłoszonych: wyłączone → włączone" in msg


def test_zapis_odczyt_i_migracja_ustawienia():
    src = (APP / "match_market.py").read_text(encoding="utf-8")
    assert 'values["hide_claimers"] = bool(req.hide_claimers)' in src
    assert '"hideClaimers": cfg["hide_claimers"]' in src
    db = (APP / "db.py").read_text(encoding="utf-8")
    assert "ADD COLUMN IF NOT EXISTS hide_claimers boolean NOT NULL DEFAULT false" in db
