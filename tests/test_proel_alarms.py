"""Alarmy meczu i karta osoby (`app/raport_dowodowy/alarmy.py`, `sklad.py`,
`app/proel_alarm_scan.py`, `app/proel_match_history.py`) - bez bazy.

Najważniejsza reguła: nie każde usunięcie kary jest podejrzane. Push dostaje
administrator tylko przy karze wykluczającej albo karze zdjętej przed bramką
tej osoby - i tylko wtedy, gdy kara stała w protokole dłużej niż chwilę.
"""
import copy
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_raport_dowodowy import P1, P2b, P3, G39, G_HOST1, G_HOST2, ev, ms, snap, zrzut_syntetyczny  # noqa: E402

from app.raport_dowodowy.alarmy import PROG_S, alarmy_meczu  # noqa: E402
from app.raport_dowodowy.sklad import sklad_meczu  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def test_usunieta_iii_kara_przed_bramka_jest_podejrzana():
    a = alarmy_meczu(zrzut_syntetyczny())
    assert a["poziom"] == "podejrzane" and a["liczba"] == 1
    o = a["osoby"][0]
    assert (o["druzyna"], o["numer"], o["nazwa"]) == ("guest", "39", "nr 39 TESTOWA Anna")
    f = o["znaleziska"][0]
    assert f["rodzaj"] == "usunieta_wykluczajaca" and f["trwanie_s"] == 635
    assert f["bramki_po"][0]["decydujaca"] is True
    assert "Usunięta III kara 2 min: nr 39 TESTOWA Anna (51:05)" in a["naglowek"]
    assert "w tym decydująca" in a["naglowek"]
    assert a["odcisk"]


def _z_szybka_poprawka(rodzaj="penalty1"):
    """I kara usunięta 20 s po wpisaniu, bez innych zdarzeń - zwykła pomyłka stolika."""
    z = zrzut_syntetyczny()
    kara = ev(rodzaj, "guest", 7, ms(20, 0), 1)
    z["migawki"] = [
        snap(1, "16:00:00", [P1]),
        snap(2, "16:00:30", [P1, kara]),
        snap(3, "16:00:50", [P1]),
    ]
    z["mecz"]["data_json"]["protocol"] = [P1]
    return z


def test_szybka_poprawka_kary_to_tylko_uwaga():
    a = alarmy_meczu(_z_szybka_poprawka())
    assert a["poziom"] == "uwaga"
    f = a["osoby"][0]["znaleziska"][0]
    assert f["trwanie_s"] < PROG_S and f["poziom"] == "uwaga"
    assert a["odcisk"] == ""  # nic do pushu


def test_szybko_usunieta_iii_kara_bez_bramki_to_uwaga():
    a = alarmy_meczu(_z_szybka_poprawka("penalty3"))
    assert a["poziom"] == "uwaga"


def test_cofnij_powtorz_nie_jest_alarmem():
    z = zrzut_syntetyczny()
    z["migawki"] = [
        snap(1, "16:00:00", [P1]),
        snap(2, "16:05:00", [P1, P3]),
        snap(3, "16:06:00", [P1]),
        snap(4, "16:06:10", [P1, P3]),
    ]
    z["mecz"]["data_json"]["protocol"] = [P1, P3]
    assert alarmy_meczu(z)["poziom"] is None


def test_przeniesienie_kary_na_inna_osobe():
    z = zrzut_syntetyczny()
    inna = ev("penalty1", "guest", 7, ms(14, 9), 1)
    z["migawki"] = [snap(1, "16:00:00", [P1]), snap(2, "16:00:20", [inna])]
    z["mecz"]["data_json"]["protocol"] = [inna]
    a = alarmy_meczu(z)
    f = a["osoby"][0]["znaleziska"][0]
    assert f["rodzaj"] == "przeniesiona" and "nr 7 PRÓBNA Ewa" in f["przeniesiono_na"]
    assert a["poziom"] == "uwaga"


def test_sklad_ma_plakietki_i_kary():
    z = zrzut_syntetyczny()
    s = sklad_meczu(z, alarmy_meczu(z))
    goscie = next(d for d in s["druzyny"] if d["strona"] == "guest")
    nosek = next(o for o in goscie["osoby"] if o["numer"] == "39")
    assert nosek["poziom"] == "podejrzane" and nosek["kary"] == ["I", "II"] and nosek["bramki"] == 1
    assert nosek["zmiany"] == 3  # dwie poprawki czasu i usunięcie
    assert next(o for o in goscie["osoby"] if o["numer"] == "7")["poziom"] is None


def test_push_tylko_przy_nowym_i_swiezym_podejrzanym():
    from app.proel_alarm_scan import should_push

    a = alarmy_meczu(zrzut_syntetyczny())
    teraz = datetime(2026, 10, 7, 18, 0, tzinfo=timezone.utc)
    assert should_push(a, None, teraz)
    assert not should_push(a, a["odcisk"], teraz)  # o tym już powiadomiono
    assert not should_push(a, None, teraz + timedelta(days=3))  # stare - bez pushu po wdrożeniu
    assert not should_push(alarmy_meczu(_z_szybka_poprawka()), None, teraz)


def test_karta_osoby_jest_jsonem():
    import json

    from app.proel_match_history import karta_osoby
    from app.raport_dowodowy.dossier import dossier

    k = karta_osoby(dossier(zrzut_syntetyczny(), nazwisko="TESTOWA"))
    json.dumps(k, default=str)
    glowna = next(z for z in k["zyciorysy"] if z["glowne"])
    assert glowna["rodzaj"] == "penalty3" and glowna["usuniecie"]
    assert [z["czas_meczu"] for z in k["zyciorysy"] if z["po_usunieciu"]] == ["59:00"]


def test_okablowanie():
    main = (ROOT / "main.py").read_text(encoding="utf-8")
    assert main.index("app.include_router(proel_match_history_router)") < main.index("app.include_router(proel_router)")
    assert "asyncio.create_task(run_alarm_scan())" in main
    journal = (ROOT / "app/proel_journal.py").read_text(encoding="utf-8")
    assert '"alarm": (' in journal and "alarm: bool = Query(False" in journal
    from app.admin_alert_rules import ADMIN_ALERT_KINDS, ALWAYS_ON_KINDS

    assert "proel_suspicious" in ADMIN_ALERT_KINDS and "proel_suspicious" in ALWAYS_ON_KINDS
    hist = (ROOT / "app/proel_match_history.py").read_text(encoding="utf-8")
    assert "dependencies=[Depends(proel_admin_guard)]" in hist
    assert hist.count("await _require_admin(actor)") == 3


def test_push_tylko_dla_meczu_z_terminarza_zprp():
    """Decyzja 24.10.2026: mecz testowy, cwiczenie i recznie wpisany numer - bez pushu."""
    from app.proel_alarm_scan import oficjalny_mecz

    assert oficjalny_mecz("IMB/49", {"matchId": "123456"}, None, False)
    assert oficjalny_mecz("IMB/49", {}, "123456", False)
    assert oficjalny_mecz("IMB/49", {}, None, True)  # numer stoi w terminarzu okregu
    assert not oficjalny_mecz("GG", {"origin": "manual"}, None, False)  # recznie wpisany
    assert not oficjalny_mecz("IMB/49", {"matchId": "123456", "isTest": True}, "123456", True)
    assert not oficjalny_mecz("T-N37FNRQ3/LCM/1", {"matchId": "1"}, "1", True)
    assert not oficjalny_mecz("IMB/49", {"training": {"eventId": "x"}}, None, True)
    assert not oficjalny_mecz("", {}, "1", True)


def test_opis_meczu_do_powiadomienia():
    from app.proel_alarm_scan import opis_meczu

    o = opis_meczu({"numer": "IMB/49", "gospodarze": "SGH", "goscie": "DBAM", "data": "14.11.2026, 19:00"}, "IMB/49")
    assert o == {"numer": "IMB/49", "druzyny": "SGH – DBAM", "linia": "SGH – DBAM · 14.11.2026, 19:00"}
    assert opis_meczu({}, "T-ABCDEF12/SPM/1")["numer"] == "SPM/1"
    assert opis_meczu({}, "GG")["linia"] == ""


def test_trwanie_w_godzinach_i_dniach():
    from app.raport_dowodowy.alarmy import _trwanie

    assert _trwanie(45) == "45 s"
    assert _trwanie(635) == "10 min 35 s"
    assert _trwanie(3600) == "1 h"
    assert _trwanie(7500) == "2 h 5 min"
    assert _trwanie(86400) == "1 dzień"
    assert _trwanie(14349 * 60 + 8) == "9 dni 23 h"
