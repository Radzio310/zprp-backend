"""Pakiet pełnych danych na serwerze - same reguły (liść, bez sieci i bazy).

Sedno: serwer ma ponawiać, pomijać i zatrzymywać DOKŁADNIE tak, jak telefon
(`utils/zprpPlayerStats.ts` -> `runOne`, `utils/zprpSessionRetry.ts`). Sędzia
nie może dostać innego wyniku tylko dlatego, że jego serwer zna już pakiet.
"""

from __future__ import annotations

import pytest

from app.proel_zprp_batch_rules import (
    FAILED,
    PENDING,
    SENT,
    SESSION_MAX_ATTEMPTS,
    SESSION_SOFT_RETRIES,
    SKIPPED,
    STOPPED,
    BatchItem,
    BatchJob,
    MAX_ITEMS,
    build_items,
    is_expired,
    is_transient,
    next_step,
    oldest_first,
    progress,
    retry_delay_s,
    session_retry_plan,
    snapshot,
    step_after_failed_renew,
)


# ─────────────────────────── ponowienia ───────────────────────────


def test_przerwy_takie_jak_w_telefonie():
    # sessionRetryDelayMs = 160 + 120 * attempt
    assert [round(retry_delay_s(a) * 1000) for a in (1, 2, 3, 4)] == [280, 400, 520, 640]


def test_limity_prob_jak_w_telefonie():
    assert SESSION_SOFT_RETRIES == 3
    assert SESSION_MAX_ATTEMPTS == 5


def test_plan_po_sesja_wygasla():
    assert [session_retry_plan(a, False) for a in (1, 2, 3)] == ["retry"] * 3
    assert session_retry_plan(4, False) == "renew"
    assert session_retry_plan(4, True) == "retry"
    assert session_retry_plan(5, True) == "give-up"


@pytest.mark.parametrize(
    "status,code,expected",
    [
        (504, "UPSTREAM_TIMEOUT", True),
        (502, "UPSTREAM_ERROR", True),
        # Telefon liczy KAŻDE 5xx jako przejściowe - także PROEL_CONFIG.
        (502, "PROEL_CONFIG", True),
        (503, "PROEL_CONFIG", True),
        (429, "RATE_LIMITED", True),
        (0, None, True),
        (401, "SESSION_EXPIRED", False),
        (400, "BAD_REQUEST", False),
        (404, "PLAYER_NOT_IN_SQUAD", False),
    ],
)
def test_przejsciowe(status, code, expected):
    assert is_transient(status, code) is expected


def test_zamkniety_protokol_zatrzymuje_wszystko():
    for kind in ("number", "player", "official"):
        assert next_step(kind, status=409, code="PROTOCOL_LOCKED", attempt=1, renewed=False) == "stop"


def test_wylaczony_proel_zatrzymuje_wszystko():
    assert next_step("player", status=403, code="PROEL_INACTIVE", attempt=1, renewed=False) == "stop"


def test_brak_w_kadrze_pomija_tylko_wlasny_rodzaj():
    assert next_step("player", status=404, code="PLAYER_NOT_IN_SQUAD", attempt=1, renewed=False) == "skip"
    assert next_step("number", status=404, code="PLAYER_NOT_IN_SQUAD", attempt=1, renewed=False) == "skip"
    assert next_step("official", status=404, code="OFFICIAL_NOT_IN_SQUAD", attempt=1, renewed=False) == "skip"
    # Cudzy kod nie jest pominięciem - telefon też go nie rozpoznawał.
    assert next_step("official", status=404, code="PLAYER_NOT_IN_SQUAD", attempt=1, renewed=False) == "fail"
    assert next_step("player", status=404, code="OFFICIAL_NOT_IN_SQUAD", attempt=1, renewed=False) == "fail"


def test_inne_404_to_porazka_nie_pominiecie():
    assert next_step("player", status=404, code=None, attempt=1, renewed=False) == "fail"


def test_sesja_wygasla_najpierw_ten_sam_klucz_potem_odnowienie():
    steps = [
        next_step("player", status=401, code="SESSION_EXPIRED", attempt=a, renewed=False)
        for a in (1, 2, 3, 4)
    ]
    assert steps == ["retry", "retry", "retry", "renew"]
    # Ostatnia próba po odnowieniu - i koniec.
    assert next_step("player", status=401, code="SESSION_EXPIRED", attempt=5, renewed=True) == "fail"


def test_awaria_przejsciowa_trzy_ponowienia():
    steps = [
        next_step("player", status=502, code="UPSTREAM_ERROR", attempt=a, renewed=False)
        for a in (1, 2, 3, 4)
    ]
    assert steps == ["retry", "retry", "retry", "fail"]


def test_zle_zadanie_bez_ponowien():
    assert next_step("player", status=400, code="BAD_FIELDS", attempt=1, renewed=False) == "fail"


def test_nieudane_odnowienie_konczy_pozycje():
    # Odnowienie przychodzi dopiero przy 4. próbie - furtka „przejściowe" jest
    # już zamknięta, jak w telefonie.
    assert step_after_failed_renew(status=401, code="SESSION_EXPIRED", attempt=4) == "fail"
    assert step_after_failed_renew(status=502, code="UPSTREAM_ERROR", attempt=2) == "retry"


# ─────────────────────────── plan pakietu ───────────────────────────


def test_kolejnosc_numery_zawodnicy_osoby():
    items = build_items(
        [{"key": "n0", "payload": {"id_zawodnik": 1}}],
        [{"key": "p0", "payload": {"id_zawodnik": 2}}, {"key": "p1", "payload": {"id_zawodnik": 3}}],
        [{"key": "o0", "payload": {"id_osoba": 4}}],
    )
    assert [(i.key, i.kind) for i in items] == [
        ("n0", "number"),
        ("p0", "player"),
        ("p1", "player"),
        ("o0", "official"),
    ]
    assert all(i.phase == PENDING for i in items)


def test_hash_sesji_z_pozycji_nie_przechodzi():
    """Klucz sesji dokłada pętla - bywa odnawiany w trakcie pakietu."""
    items = build_items([], [{"key": "p0", "payload": {"hash_sesji": "stary", "id_zawodnik": 1}}], [])
    assert "hash_sesji" not in items[0].payload


def test_obiekty_z_atrybutami_tez_przechodza():
    class Row:
        def __init__(self, key, payload):
            self.key = key
            self.payload = payload

    items = build_items([], [Row("p0", {"a": 1})], [])
    assert items[0].key == "p0"


@pytest.mark.parametrize(
    "rows",
    [
        [{"key": "", "payload": {}}],
        [{"key": "p0", "payload": {}}, {"key": "p0", "payload": {}}],
        [{"key": "p0", "payload": None}],
    ],
)
def test_zly_plan_odrzucony(rows):
    with pytest.raises(ValueError):
        build_items([], rows, [])


def test_za_duzy_plan_odrzucony():
    rows = [{"key": f"p{i}", "payload": {}} for i in range(MAX_ITEMS + 1)]
    with pytest.raises(ValueError):
        build_items([], rows, [])


# ─────────────────────────── postęp ───────────────────────────


def _job(phases):
    items = [BatchItem(key=f"p{i}", kind="player", payload={}, phase=p) for i, p in enumerate(phases)]
    return BatchJob(job_id="j", id_zawody=1, hash_sesji="h", items=items)


def test_postep_liczy_rozstrzygniete_takze_zatrzymana():
    job = _job([SENT, SKIPPED, FAILED, STOPPED, PENDING, PENDING])
    counts = progress(job.items)
    assert counts["done"] == 4
    assert counts["total"] == 6
    assert (counts[SENT], counts[SKIPPED], counts[FAILED]) == (1, 1, 1)


def test_migawka_ma_komplet_pol():
    job = _job([SENT, PENDING])
    job.hash_sesji = "nowy"
    job.renewed = 1
    out = snapshot(job)
    assert out["state"] == "running"
    assert out["stop_code"] is None
    assert (out["done"], out["total"]) == (1, 2)
    assert out["hash_sesji"] == "nowy"
    assert out["renewed"] is True
    assert set(out["items"][0]) >= {"key", "kind", "phase", "status", "code", "message", "upstream", "attempts"}


def test_termin_liczony_od_ostatniego_ruchu():
    job = _job([PENDING])
    job.touched_at = 100.0
    assert not is_expired(job, now=100.0 + 60, ttl_s=900)
    assert is_expired(job, now=100.0 + 901, ttl_s=900)
    job.finished_at = 2000.0
    assert not is_expired(job, now=2000.0 + 899, ttl_s=900)


def test_przy_przepelnieniu_najpierw_skonczone():
    a = _job([SENT])
    a.job_id, a.state, a.finished_at = "a", "done", 50.0
    b = _job([PENDING])
    b.job_id, b.touched_at = "b", 10.0
    c = _job([SENT])
    c.job_id, c.state, c.finished_at = "c", "done", 20.0
    assert [j.job_id for j in oldest_first([a, b, c])] == ["c", "a", "b"]
