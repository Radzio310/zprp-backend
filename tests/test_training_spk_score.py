"""Ocena podejścia szkoleniowego na meczu SPK/1.

To jest jedyne miejsce, które mówi sędziemu „poszło ci tak a tak", więc każda
reguła ma tu swój test - łącznie z tymi, które wyglądają na oczywiste.
"""
from __future__ import annotations

from app.training_spk_score import (
    GOAL_TOLERANCE_MS,
    MATCH_WINDOW_MS,
    STRICT_TOLERANCE_MS,
    grade,
    normalize_events,
    score_run,
    tolerance_for,
)


def ev(t, kind="goal", team="host", player=7, half=1, **extra):
    out = {"time": t, "type": kind, "team": team, "player": player, "half": half}
    out.update(extra)
    return out


# ───────────────────────── normalizacja ─────────────────────────

def test_nieznany_rodzaj_wypada_po_obu_stronach():
    """Nieznany rodzaj po jednej stronie byłby karą za coś, czego nie rozumiemy."""
    assert normalize_events([ev(0, kind="cosNowego")]) == []


def test_zdarzenie_bez_druzyny_wypada():
    assert normalize_events([{"type": "goal", "time": 0}]) == []


def test_numer_zawodnika_porownujemy_jako_tekst():
    """„7" i 7 to ten sam zawodnik - protokół bywa zapisany raz tak, raz tak."""
    a = normalize_events([ev(0, player=7)])[0]
    b = normalize_events([ev(0, player="7")])[0]
    assert a["player"] == b["player"] == "7"


def test_pusty_numer_zostaje_pusty():
    # Czas dla drużyny numeru nie ma i brak numeru nie jest pomyłką.
    assert normalize_events([ev(0, kind="teamTime", player=None)])[0]["player"] == ""


# ───────────────────────── dopasowanie ─────────────────────────

def test_identyczny_przebieg_to_komplet():
    events = [ev(1000), ev(60000, kind="penalty2", player=9, team="guest")]
    out = score_run(events, events)
    assert out["score"] == 100.0
    assert out["counts"]["missed"] == 0
    assert out["counts"]["extra"] == 0


def test_pominiete_zdarzenie_liczy_sie_raz():
    out = score_run([ev(1000), ev(2000, player=9)], [ev(1000)])
    assert out["counts"]["missed"] == 1
    assert out["counts"]["extra"] == 0


def test_zly_numer_to_jedna_pomylka_a_nie_dwie():
    """Bramka pod złym numerem NIE jest jednocześnie pominięta i nadmiarowa.

    Gdyby numer wchodził do dopasowania, sędzia dostawałby za jedną pomyłkę
    dwie kary - i wynik spadałby dwa razy szybciej, niż na to zasłużył.
    """
    out = score_run([ev(1000, player=7)], [ev(1000, player=8)])
    assert out["counts"]["matched"] == 1
    assert out["counts"]["missed"] == 0
    assert out["counts"]["extra"] == 0
    assert out["counts"]["wrongPlayer"] == 1


def test_zdarzenie_poza_oknem_to_pominiete_i_nadmiarowe():
    """Poza oknem dopasowania to już nie jest to samo zdarzenie."""
    out = score_run([ev(1000)], [ev(1000 + MATCH_WINDOW_MS + 1)])
    assert out["counts"]["missed"] == 1
    assert out["counts"]["extra"] == 1


def test_zdarzenie_druzyny_przeciwnej_nie_dopasowuje_sie():
    out = score_run([ev(1000, team="host")], [ev(1000, team="guest")])
    assert out["counts"]["missed"] == 1
    assert out["counts"]["extra"] == 1


# ───────────────────────── tolerancja czasu ─────────────────────────

def test_bramka_ma_dziesiec_sekund_luzu():
    assert tolerance_for("goal") == GOAL_TOLERANCE_MS
    out = score_run([ev(30000)], [ev(30000 + GOAL_TOLERANCE_MS)])
    assert out["counts"]["lateOrEarly"] == 0


def test_bramka_poza_tolerancja_jest_liczona_jako_zla_w_czasie():
    out = score_run([ev(30000)], [ev(30000 + GOAL_TOLERANCE_MS + 1)])
    assert out["counts"]["matched"] == 1
    assert out["counts"]["lateOrEarly"] == 1


def test_kara_wymaga_dokladnego_czasu():
    """Kara ma w protokole czas, od którego liczy się jej koniec."""
    assert tolerance_for("penalty2") == STRICT_TOLERANCE_MS
    out = score_run(
        [ev(30000, kind="penalty2")], [ev(30000 + 5000, kind="penalty2")]
    )
    assert out["counts"]["lateOrEarly"] == 1


# ───────────────────────── tryb prezentacji ─────────────────────────

def test_prezentacja_nie_ocenia_czasu():
    """Slajdy przewija sędzia własnym tempem - zegar mówi o klikaniu, nie o meczu."""
    out = score_run([ev(30000)], [ev(600000)], mode="slides")
    assert "timing" not in out["parts"]
    assert out["score"] == 100.0


def test_prezentacja_dalej_ocenia_zdarzenia_i_numery():
    out = score_run([ev(1000, player=7)], [ev(1000, player=8)], mode="slides")
    assert out["parts"]["players"] == 0.0
    assert out["parts"]["events"] == 100.0


# ───────────────────────── zdarzenia nadmiarowe ─────────────────────────

def test_dopisane_zdarzenie_obniza_ocene():
    """Protokół z bramką, której nie było, jest tak samo nieprawdziwy."""
    ref = [ev(1000), ev(2000, player=9)]
    out = score_run(ref, ref + [ev(50000, player=11)])
    assert out["counts"]["extra"] == 1
    assert out["parts"]["events"] < 100.0


def test_kara_za_nadmiar_jest_proporcjonalna_do_meczu():
    """Trzy zmyślone kary w meczu o siedemdziesięciu zdarzeniach to co innego
    niż trzy w meczu o dziesięciu."""
    small = [ev(i * 1000) for i in range(10)]
    big = [ev(i * 1000) for i in range(70)]
    junk = [ev(500000 + i * 1000, player=99) for i in range(3)]
    out_small = score_run(small, small + junk)
    out_big = score_run(big, big + junk)
    assert out_small["parts"]["events"] < out_big["parts"]["events"]


# ───────────────────────── seria rzutów karnych ─────────────────────────

def test_seria_karnych_nie_wchodzi_do_oceny_czasu():
    """Seria nie ma własnego zegara - jej zdarzenia mają czas końca meczu."""
    ref = [ev(3600000, kind="penalty2", shootout=True)]
    mine = [ev(3600000, kind="penalty2", shootout=True)]
    out = score_run(ref, mine)
    assert out["counts"]["lateOrEarly"] == 0
    assert out["counts"]["matched"] == 1


def test_zdarzenie_z_serii_nie_dopasuje_sie_do_zdarzenia_z_gry():
    out = score_run(
        [ev(3600000, kind="penalty2", shootout=True)],
        [ev(3600000, kind="penalty2")],
    )
    assert out["counts"]["missed"] == 1
    assert out["counts"]["extra"] == 1


# ───────────────────────── wynik meczu ─────────────────────────

def test_wynik_meczu_oceniany_osobno_od_zdarzen():
    """Sędzia może zgubić dwie kary i oddać poprawny wynik - i odwrotnie."""
    out = score_run(
        [],
        [],
        reference_meta={"finalHost": 30, "finalGuest": 24, "halfHost": 15, "halfGuest": 12},
        attempt_meta={"finalHost": 30, "finalGuest": 24, "halfHost": 14, "halfGuest": 12},
    )
    assert out["result"]["final"]["ok"] is True
    assert out["result"]["half"]["ok"] is False


# ───────────────────────── ocena słowna ─────────────────────────

def test_progi_oceny_slownej():
    assert grade(100) == "wzorowo"
    assert grade(95) == "wzorowo"
    assert grade(94.9) == "bardzo dobrze"
    assert grade(70) == "dobrze"
    assert grade(69.9) == "są braki"
    assert grade(49.9) == "do powtórzenia"


def test_pusty_wzorzec_nie_wywraca_oceny():
    """Zanim ktoś wczyta wzorzec, ocena ma wyjść, a nie polec."""
    out = score_run([], [ev(1000)])
    assert out["counts"]["extra"] == 1
    assert isinstance(out["score"], float)
