"""Podpisy z pełnej treści protokołu trafiają do overlaya (SM/61, 28.11.2026)."""

from app.proel_fields import (
    SIGNATURE_SRC_BLOB,
    adopt_blob_signatures,
    blob_signature,
    project,
)

BY = {"judge_id": "5803", "name": "SOŁODKO Leszek", "install": "tel-delegata", "verified": False}


def _blob(**officials):
    return {
        "matchConfig": {
            "extras": {
                "officials": {
                    role: {"fullName": role.upper(), "signature": sig}
                    for role, sig in officials.items()
                }
            }
        }
    }


def test_podpis_tylko_w_tresci_trafia_do_overlaya():
    blob = _blob(secretary="/static/szpurek.png", delegate="/static/solodko.png")
    out, paths = adopt_blob_signatures({}, [blob], rev=7, at="t", by=BY)
    assert sorted(paths) == ["official.delegate.signature", "official.secretary.signature"]
    entry = out["official.secretary.signature"]
    assert entry["v"] == "/static/szpurek.png"
    assert entry["rev"] == 7
    assert entry["src"] == SIGNATURE_SRC_BLOB
    assert entry["by"]["install"] == "tel-delegata"


def test_pelny_zapis_bez_podpisow_ich_nie_kasuje():
    """Przebieg SM/61: treść z podpisami na serwerze, potem pełny zapis z telefonu,
    który ich nie zna. Podpisy wciągnięte z ZAPISANEJ treści wracają reprojekcją."""
    zapisana = _blob(secretary="/static/szpurek.png", timekeeper="/static/kornek.png")
    przychodzaca = _blob(secretary="", timekeeper="")
    overlay, paths = adopt_blob_signatures({}, [przychodzaca, zapisana], rev=2, at="t", by=BY)
    assert set(paths) == {"official.secretary.signature", "official.timekeeper.signature"}
    wynik = project(overlay, przychodzaca)
    officials = wynik["matchConfig"]["extras"]["officials"]
    assert officials["secretary"]["signature"] == "/static/szpurek.png"
    assert officials["timekeeper"]["signature"] == "/static/kornek.png"


def test_wpis_w_overlayu_wygrywa_takze_pusty():
    """Pusty wpis to świadome skasowanie - nie wskrzeszamy podpisu z treści."""
    overlay = {
        "official.secretary.signature": {"v": "", "rev": 3},
        "official.delegate.signature": {"v": "/static/nowy.png", "rev": 4},
    }
    blob = _blob(secretary="/static/stary.png", delegate="/static/stary2.png")
    out, paths = adopt_blob_signatures(overlay, [blob], rev=5, at="t", by=BY)
    assert paths == []
    assert out["official.secretary.signature"]["v"] == ""
    assert out["official.delegate.signature"]["v"] == "/static/nowy.png"


def test_tresc_przychodzaca_ma_pierwszenstwo_przed_zapisana():
    out, _ = adopt_blob_signatures(
        {},
        [_blob(delegate="/static/nowszy.png"), _blob(delegate="/static/starszy.png")],
        rev=1,
        at="t",
        by=BY,
    )
    assert out["official.delegate.signature"]["v"] == "/static/nowszy.png"


def test_sciezki_z_telefonu_i_slady_migawek_odpadaja():
    blob = _blob(
        secretary="file:///data/user/0/podpis.png",
        timekeeper="content://media/1",
        delegate="[zdjęto: podpis, 40 KB, abc]",
    )
    out, paths = adopt_blob_signatures({}, [blob], rev=1, at="t", by=BY)
    assert paths == [] and out == {}


def test_druzyny_i_medyk():
    blob = {
        "matchConfig": {
            "extras": {
                "hostTeamSignature": "/static/a.png",
                "guestTeamSignature": " ",
                "medic": {"signature": "/static/m.png"},
            }
        }
    }
    assert blob_signature(blob, "sig.team.host") == "/static/a.png"
    assert blob_signature(blob, "sig.team.guest") == ""
    _, paths = adopt_blob_signatures({}, [blob], rev=1, at="t", by=BY)
    assert set(paths) == {"sig.team.host", "medic.signature"}


def test_nie_zmienia_przekazanego_overlaya():
    overlay = {}
    adopt_blob_signatures(overlay, [_blob(delegate="/static/x.png")], rev=1, at="t", by=BY)
    assert overlay == {}


def test_dziwny_ksztalt_tresci_nie_wywraca():
    out, paths = adopt_blob_signatures({}, [None, "tekst", {"matchConfig": []}], rev=1, at="t", by=BY)
    assert out == {} and paths == []
