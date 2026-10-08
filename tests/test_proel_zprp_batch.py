"""Pakiet pełnych danych: pętla serwera na podmienionym ZPRP.

Sieć zastąpiona monkeypatchem `_post_upstream` (jedyny punkt sieciowy
`app.proel_zprp`), dziennik - podmianą `_journal_send`, przerwy - zerem.
Pakiet idzie przez te same rdzenie co pojedyncze trasy, więc te testy
sprawdzają przy okazji, że niczego po drodze nie przepisał po swojemu.
"""

from __future__ import annotations

import asyncio

import pytest
from fastapi import HTTPException

import app.proel_zprp as z
import app.proel_zprp_batch as b
from app.proel_zprp_batch_rules import BatchJob, build_items

pytestmark = pytest.mark.anyio


@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("PROEL_APP_KEY", "test-app-key")

    async def no_sleep(_s):
        return None

    monkeypatch.setattr(b, "_sleep", no_sleep)
    journal: list = []

    async def fake_journal(event, **kwargs):
        journal.append((event, kwargs))

    monkeypatch.setattr(z, "_journal_send", fake_journal)
    b._jobs.clear()
    yield journal
    b._jobs.clear()


def _player(i: int) -> dict:
    return {
        "key": f"p{i}",
        "payload": {"id_zawody": 208136, "id_zespol": 1, "id_zawodnik": 100 + i, "fields": {"bramki": "1"}},
    }


def _number(i: int) -> dict:
    return {
        "key": f"n{i}",
        "payload": {"id_zawody": 208136, "id_zespol": 1, "id_zawodnik": 500 + i, "fields": {"NrKoszulki2": "7"}},
    }


def _official(i: int) -> dict:
    return {
        "key": f"o{i}",
        "payload": {
            "id_zawody": 208136,
            "id_zespol": 1,
            "id_osoba": 900 + i,
            "fields": {"upomnienie_U": "0", "wykluczenie_2min": "0", "dyskwalifikacja_D": "0"},
        },
    }


def _job(numbers=(), players=(), officials=(), auth=None) -> BatchJob:
    return BatchJob(
        job_id="test",
        id_zawody=208136,
        hash_sesji="h1",
        items=build_items(list(numbers), list(players), list(officials)),
        auth=auth,
    )


def _script(responses):
    """Upstream odpowiadający z listy (status, data); ostatnia odpowiedź się powtarza."""
    calls: list = []

    async def fake(endpoint, payload):
        calls.append((endpoint, dict(payload)))
        idx = min(len(calls) - 1, len(responses) - 1)
        resp = responses[idx]
        if callable(resp):
            return resp(endpoint, payload)
        return resp

    fake.calls = calls
    return fake


OK = (200, {"status": "success"})


async def _drain():
    # Wpisy dziennika idą w tle - dajemy im dokończyć się przed asercjami.
    for _ in range(5):
        await asyncio.sleep(0)


async def test_pelny_pakiet_w_kolejnosci_numery_zawodnicy_osoby(monkeypatch, _env):
    fake = _script([OK])
    monkeypatch.setattr(z, "_post_upstream", fake)
    job = _job([_number(0)], [_player(0), _player(1)], [_official(0)])

    await b.run_job(job)
    await _drain()

    assert job.state == "done"
    assert [i.phase for i in job.items] == ["sent"] * 4
    assert [c[0] for c in fake.calls] == [
        "player_stats.php",
        "player_stats.php",
        "player_stats.php",
        "officials_stats.php",
    ]
    # Klucz sesji dokłada pętla.
    assert all(c[1]["hash_sesji"] == "h1" for c in fake.calls)
    # Jeden wpis na rodzaj, z kluczem godzinowym jak pojedyncze trasy.
    events = [e for e, _ in _env]
    assert events == ["zprp.players_sent", "zprp.officials_sent"]
    assert _env[0][1]["event_key"].startswith("zprp:208136:zprp.players_sent:")


async def test_brak_w_kadrze_pomija_i_idzie_dalej(monkeypatch, _env):
    def respond(endpoint, payload):
        if payload["id_zawodnik"] == 101:
            return 404, {"status": "error", "message": "Nie znaleziono zawodnika"}
        return OK

    fake = _script([respond])
    monkeypatch.setattr(z, "_post_upstream", fake)
    job = _job(players=[_player(0), _player(1), _player(2)])

    await b.run_job(job)

    assert [i.phase for i in job.items] == ["sent", "skipped", "sent"]
    skipped = job.items[1]
    assert skipped.code == "PLAYER_NOT_IN_SQUAD"
    assert skipped.upstream == "Nie znaleziono zawodnika"
    assert skipped.sent and skipped.sent["id_zawodnik"] == 101


async def test_zamkniety_protokol_zatrzymuje_pakiet(monkeypatch, _env):
    def respond(endpoint, payload):
        if payload["id_zawodnik"] == 101:
            return 403, {"code": "PROTOCOL_LOCKED", "message": "Protokół zatwierdzony"}
        return OK

    fake = _script([respond])
    monkeypatch.setattr(z, "_post_upstream", fake)
    job = _job(players=[_player(0), _player(1), _player(2)], officials=[_official(0)])

    await b.run_job(job)

    assert job.state == "stopped"
    assert job.stop_code == "PROTOCOL_LOCKED"
    assert job.stop_message == "Protokół zatwierdzony"
    assert [i.phase for i in job.items] == ["sent", "stopped", "pending", "pending"]
    assert len(fake.calls) == 2


async def test_wylaczony_proel_zatrzymuje_pakiet(monkeypatch, _env):
    fake = _script([(403, {"code": "PROEL_INACTIVE"})])
    monkeypatch.setattr(z, "_post_upstream", fake)
    job = _job(players=[_player(0), _player(1)])

    await b.run_job(job)

    assert job.stop_code == "PROEL_INACTIVE"
    assert job.items[0].phase == "stopped"
    assert job.items[0].message == z.PROEL_INACTIVE_MESSAGE
    assert len(fake.calls) == 1


async def test_falszywe_wygasla_przechodzi_tym_samym_kluczem(monkeypatch, _env):
    expired = (401, {"code": "SESSION_EXPIRED"})
    fake = _script([expired, expired, expired, OK])
    monkeypatch.setattr(z, "_post_upstream", fake)
    renew_calls = []

    async def fake_authorize(payload, ip):
        renew_calls.append(payload)
        return {"hash_sesji": "h2"}

    monkeypatch.setattr(z, "authorize", fake_authorize)
    job = _job(players=[_player(0)], auth={"id_zawody": 208136, "nr_sedzia": "5635"})

    await b.run_job(job)

    assert job.items[0].phase == "sent"
    assert job.items[0].attempts == 4
    assert renew_calls == []
    assert [c[1]["hash_sesji"] for c in fake.calls] == ["h1"] * 4


async def test_martwa_sesja_odnawiana_raz_i_dalej_nowym_kluczem(monkeypatch, _env):
    def respond(endpoint, payload):
        if payload["hash_sesji"] == "h1":
            return 401, {"code": "SESSION_EXPIRED"}
        return OK

    fake = _script([respond])
    monkeypatch.setattr(z, "_post_upstream", fake)
    seen_ip = []

    async def fake_authorize(payload, ip):
        seen_ip.append(ip)
        assert payload.nr_sedzia == "5635"
        return {"hash_sesji": "h2"}

    monkeypatch.setattr(z, "authorize", fake_authorize)
    job = _job(players=[_player(0), _player(1)], auth={"id_zawody": 208136, "nr_sedzia": "5635"})
    job.client_ip = "10.1.2.3"

    await b.run_job(job)

    assert [i.phase for i in job.items] == ["sent", "sent"]
    assert job.hash_sesji == "h2"
    assert job.renewed == 1
    assert seen_ip == ["10.1.2.3"]
    # Cztery próby starym kluczem (3 miękkie + ta, po której odnowienie),
    # potem nowy - także dla następnego zawodnika.
    assert [c[1]["hash_sesji"] for c in fake.calls] == ["h1"] * 4 + ["h2", "h2"]


async def test_odnowienie_odbite_przez_wylaczony_proel_zatrzymuje(monkeypatch, _env):
    fake = _script([(401, {"code": "SESSION_EXPIRED"})])
    monkeypatch.setattr(z, "_post_upstream", fake)

    async def fake_authorize(payload, ip):
        raise HTTPException(status_code=403, detail={"code": "PROEL_INACTIVE", "message": "wylaczony"})

    monkeypatch.setattr(z, "authorize", fake_authorize)
    job = _job(players=[_player(0), _player(1)], auth={"token": "ABCDE"})

    await b.run_job(job)

    assert job.stop_code == "PROEL_INACTIVE"
    assert job.stop_message == "wylaczony"
    assert [i.phase for i in job.items] == ["stopped", "pending"]


async def test_trwala_odmowa_odnowienia_nie_puka_drugi_raz(monkeypatch, _env):
    fake = _script([(401, {"code": "SESSION_EXPIRED"})])
    monkeypatch.setattr(z, "_post_upstream", fake)
    renew_calls = []

    async def fake_authorize(payload, ip):
        renew_calls.append(1)
        raise HTTPException(status_code=401, detail={"code": "INVALID_CREDENTIALS", "message": "nie"})

    monkeypatch.setattr(z, "authorize", fake_authorize)
    job = _job(players=[_player(0), _player(1)], auth={"token": "ABCDE"})

    await b.run_job(job)

    assert [i.phase for i in job.items] == ["failed", "failed"]
    assert job.items[0].code == "SESSION_EXPIRED"
    assert len(renew_calls) == 1
    # Każda pozycja: 4 próby przed odnowieniem; po nieudanym - koniec.
    assert len(fake.calls) == 8


async def test_bez_materialu_do_odnowienia_pozycja_nieudana(monkeypatch, _env):
    fake = _script([(401, {"code": "SESSION_EXPIRED"})])
    monkeypatch.setattr(z, "_post_upstream", fake)
    job = _job(players=[_player(0)], auth=None)

    await b.run_job(job)

    assert job.items[0].phase == "failed"
    assert job.items[0].message == "Sesja ZPRP wygasła."
    assert len(fake.calls) == 4


async def test_awaria_przejsciowa_trzy_ponowienia_potem_porazka(monkeypatch, _env):
    import httpx

    calls = []

    async def boom(endpoint, payload):
        calls.append(1)
        raise httpx.ConnectError("nie ma sieci")

    monkeypatch.setattr(z, "_post_upstream", boom)
    job = _job(players=[_player(0), _player(1)])

    await b.run_job(job)

    assert [i.phase for i in job.items] == ["failed", "failed"]
    assert job.items[0].code == "UPSTREAM_ERROR"
    assert job.items[0].status == 502
    assert len(calls) == 8


async def test_zla_pozycja_nie_wywraca_pakietu(monkeypatch, _env):
    fake = _script([OK])
    monkeypatch.setattr(z, "_post_upstream", fake)
    bad = {"key": "p9", "payload": {"id_zawody": 208136, "fields": {"bramki": "1"}}}
    job = _job(players=[bad, _player(1)])

    await b.run_job(job)

    assert [i.phase for i in job.items] == ["failed", "sent"]
    assert job.items[0].code == "BAD_REQUEST"


async def test_zamek_meczu_jeden_zapis_naraz(monkeypatch, _env):
    """Pakiet i wynik skrócony tego samego meczu - ZPRP widzi jedno żądanie naraz."""
    in_flight = {"now": 0, "max": 0}

    async def slow(endpoint, payload):
        in_flight["now"] += 1
        in_flight["max"] = max(in_flight["max"], in_flight["now"])
        await asyncio.sleep(0.01)
        in_flight["now"] -= 1
        return OK

    monkeypatch.setattr(z, "_post_upstream", slow)
    job = _job(players=[_player(0), _player(1), _player(2)])

    summary = z.ZprpSummaryRequest(hash_sesji="h1", fields={"widzowie": "120"}, id_zawody=208136)
    await asyncio.gather(b.run_job(job), z.submit_summary(summary), z.submit_summary(summary))

    assert in_flight["max"] == 1
    assert job.state == "done"
    # Zamki sprzątają się same.
    assert z._match_locks == {}


async def test_zamek_rozne_mecze_ida_rownolegle(monkeypatch, _env):
    in_flight = {"now": 0, "max": 0}

    async def slow(endpoint, payload):
        in_flight["now"] += 1
        in_flight["max"] = max(in_flight["max"], in_flight["now"])
        await asyncio.sleep(0.01)
        in_flight["now"] -= 1
        return OK

    monkeypatch.setattr(z, "_post_upstream", slow)
    a = z.ZprpSummaryRequest(hash_sesji="h1", fields={"widzowie": "1"}, id_zawody=1)
    c = z.ZprpSummaryRequest(hash_sesji="h2", fields={"widzowie": "1"}, id_zawody=2)
    await asyncio.gather(z.submit_summary(a), z.submit_summary(c))
    assert in_flight["max"] == 2


def test_klucz_zamka():
    assert z._match_lock_key(208136, "h") == "z:208136"
    assert z._match_lock_key("208136", "h") == "z:208136"
    # Starsza aplikacja bez numeru meczu - zamek na sesji.
    assert z._match_lock_key(None, "abc") == "h:abc"
    assert z._match_lock_key(0, "") == ""


# ─────────────────────────── trasy ───────────────────────────


async def test_trasa_startuje_pakiet_i_oddaje_postep(monkeypatch, _env):
    fake = _script([OK])
    monkeypatch.setattr(z, "_post_upstream", fake)
    payload = b.FullBatchRequest(
        id_zawody="208136",
        hash_sesji="h1",
        auth={"id_zawody": 208136, "nr_sedzia": "5635"},
        numbers=[_number(0)],
        players=[_player(0)],
        officials=[_official(0)],
    )

    out = await b.zprp_full_batch_start(
        payload=payload,
        request=None,
        x_forwarded_for="1.2.3.4, 10.0.0.1",
        x_judge_id="5635",
        x_installation_id="ins",
        x_actor_name="KOWALSKI Jan",
        authorization=None,
        x_elevation=None,
    )
    assert out["total"] == 3
    job_id = out["job_id"]
    assert len(job_id) >= 16

    for _ in range(50):
        snap = await b.zprp_full_batch_status(job_id)
        if snap["state"] != "running":
            break
        await asyncio.sleep(0)
    assert snap["state"] == "done"
    assert (snap["done"], snap["total"]) == (3, 3)
    assert [i["key"] for i in snap["items"]] == ["n0", "p0", "o0"]
    assert [i["kind"] for i in snap["items"]] == ["number", "player", "official"]
    assert b.get_job(job_id).client_ip == "1.2.3.4"
    await _drain()
    # Podpis z nagłówków trafia do dziennika.
    assert _env[0][1]["judge_id"] == "5635"


async def test_nieznany_pakiet_to_404():
    with pytest.raises(HTTPException) as err:
        await b.zprp_full_batch_status("nie-ma-takiego")
    assert err.value.status_code == 404
    assert err.value.detail["code"] == "JOB_NOT_FOUND"


async def test_trasa_odrzuca_brak_sesji_i_meczu():
    with pytest.raises(HTTPException) as err:
        await b.zprp_full_batch_start(
            payload=b.FullBatchRequest(id_zawody=1, hash_sesji=" ", players=[_player(0)]),
            request=None,
        )
    assert err.value.status_code == 400
    with pytest.raises(HTTPException) as err:
        await b.zprp_full_batch_start(
            payload=b.FullBatchRequest(id_zawody="abc", hash_sesji="h", players=[_player(0)]),
            request=None,
        )
    assert err.value.status_code == 400


async def test_trasa_odrzuca_powtorzony_klucz():
    with pytest.raises(HTTPException) as err:
        await b.zprp_full_batch_start(
            payload=b.FullBatchRequest(id_zawody=1, hash_sesji="h", players=[_player(0), _player(0)]),
            request=None,
        )
    assert err.value.status_code == 400
    assert err.value.detail["code"] == "BAD_REQUEST"


async def test_brak_klucza_aplikacji_od_razu_503(monkeypatch):
    monkeypatch.delenv("PROEL_APP_KEY", raising=False)
    with pytest.raises(HTTPException) as err:
        await b.zprp_full_batch_start(
            payload=b.FullBatchRequest(id_zawody=1, hash_sesji="h", players=[_player(0)]),
            request=None,
        )
    assert err.value.status_code == 503
    assert b._jobs == {}
