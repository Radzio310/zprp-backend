"""Raport z historii zapisu meczu (`tools/raport_dowodowy`) - analiza i wydruk bez bazy.

Scenariusz odwzorowuje to, co naprawdę wydarzyło się w zapisie SK/24
(07.10.2026): III kara dopisana i po kilku minutach usunięta, w międzyczasie
inne zdarzenia, po usunięciu bramka tej samej osoby, dwie poprawki czasu
II kary. Nazwiska i drużyny są wymyślone.
"""
import sys
from collections import Counter
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools" / "raport_dowodowy"))

from app.raport_dowodowy import analiza  # noqa: E402
from app.raport_dowodowy.analiza import analizuj, czas_pl, klasyfikuj, znajdz_osobe  # noqa: E402
from wydruk import html_raportu  # noqa: E402


def ms(m, s):
    return (m * 60 + s) * 1000


def ev(typ, team, player, t, half, score=None):
    e = {"type": typ, "team": team, "player": player, "time": t, "half": half}
    if score:
        e["score"] = score
    return e


CFG = {
    "matchNumber": "XK/9",
    "hostTeamName": "Drużyna A",
    "guestTeamName": "Drużyna B",
    "referee1": "SĘDZIA Jan",
    "referee2": "SĘDZIA Piotr",
    "delegate": "DELEGAT Adam",
    "extras": {"matchDate": "2026-10-07", "matchTime": "19:45"},
    "hostPlayerCards": [{"number": 39, "fullName": "GOSPODYNI Ola"}, {"number": 5, "fullName": "INNA Iza"}],
    "guestPlayerCards": [{"number": 39, "fullName": "TESTOWA Anna"}, {"number": 7, "fullName": "PRÓBNA Ewa"}],
}


def blob(protocol, row39=None, score=(0, 0)):
    return {
        "matchConfig": CFG,
        "protocol": protocol,
        "scoreHost": score[0],
        "scoreGuest": score[1],
        "guestPlayerStats": [{"number": 39, "goals": 1, **(row39 or {})}, {"number": 7, "goals": 0}],
        "hostPlayerStats": [{"number": 39, "goals": 0}],
    }


P1 = ev("penalty1", "guest", 39, ms(14, 9), 1)
P2a = ev("penalty2", "guest", 39, ms(44, 47), 2)
P2b = ev("penalty2", "guest", 39, ms(44, 48), 2)
P2c = ev("penalty2", "guest", 39, ms(44, 51), 2)
P3 = ev("penalty3", "guest", 39, ms(51, 5), 2)
G_HOST1 = ev("goal", "host", 5, ms(51, 10), 2, "21:22")
G_HOST2 = ev("goal", "host", 5, ms(53, 20), 2, "22:22")
G39 = ev("goal", "guest", 39, ms(59, 0), 2, "22:23")


def snap(i, hhmmss, protocol, row39=None, clock=0, score=(0, 0), milestone=None):
    return {
        "id": 100 + i,
        "created_at": f"2026-10-07T{hhmmss}+00:00",
        "received_at": f"2026-10-07T{hhmmss}+00:00",
        "doc_rev": i,
        "source": "server",
        "milestone": milestone,
        "status": "in_progress",
        "writer_name": "STOLIKOWY Grzegorz",
        "writer_install": "abcdef123456",
        "main_time_ms": clock,
        "score_host": score[0],
        "score_guest": score[1],
        "expires_at": "2026-10-14T16:00:00+00:00",
        "payload": blob(protocol, row39, score),
    }


@pytest.fixture
def zrzut():
    r1 = {"penalty1": "14:09"}
    r2 = {**r1, "penalty2": "44:47"}
    r2b = {**r1, "penalty2": "44:48"}
    r3 = {**r2b, "penalty3": "51:05", "hasRedCard": True}
    r2c = {**r1, "penalty2": "44:51"}
    migawki = [
        snap(1, "15:52:39", [], milestone="start"),
        snap(2, "16:22:52", [P1], r1, ms(14, 9), (5, 8)),
        snap(3, "17:16:15", [P1, P2a], r2, ms(44, 47), (17, 19)),
        snap(4, "17:16:36", [P1, P2b], r2b, ms(44, 48), (17, 19)),
        snap(5, "17:23:59", [P1, P2b, P3, G_HOST1], r3, ms(51, 10), (21, 22)),
        snap(6, "17:30:00", [P1, P2b, P3, G_HOST1, G_HOST2], r3, ms(53, 20), (22, 22)),
        snap(7, "17:34:34", [P1, P2b, G_HOST1, G_HOST2], r2b, ms(58, 47), (22, 22)),
        snap(8, "17:34:48", [P1, P2b, G_HOST1, G_HOST2, G39], r2b, ms(59, 0), (22, 23)),
        snap(9, "17:47:56", [P1, P2c, G_HOST1, G_HOST2, G39], r2c, ms(60, 0), (22, 23)),
    ]
    koniec = blob([P1, P2c, G_HOST1, G_HOST2, G39], r2c, (22, 23))
    return {
        "klucz": "XK/9",
        "wykonano": "2026-10-09T12:00:00+00:00",
        "mecz": {"match_number": "XK/9", "status": "approved", "doc_rev": 9, "data_json": koniec},
        "migawki": migawki,
        "dziennik": [
            {"event": "match.created", "created_at": "2026-10-07T15:52:39+00:00", "actor_name": "STOLIKOWY Grzegorz"},
            {"event": "field.changed", "created_at": "2026-10-07T15:50:57+00:00", "actor_name": "STOLIKOWY Grzegorz",
             "details_json": {"paths": ["medic.fullName"], "rev": 8}},
            {"event": "field.changed", "created_at": "2026-10-07T15:50:58+00:00", "actor_name": "STOLIKOWY Grzegorz",
             "details_json": {"paths": ["medic.fullName"], "rev": 9}},
            {"event": "match.approved", "created_at": "2026-10-07T18:53:59+00:00", "actor_name": "DELEGAT Adam",
             "details_json": {"from": "finished", "to": "approved"}},
        ],
        "historia_sporow": [],
        "usuniete": [],
        "protokoly_pdf": [{"code": "BZ-TEST-0001", "created_at": "2026-10-07T18:53:34+00:00",
                           "actor_name": "DELEGAT Adam", "pdf_sha256": "ab" * 32, "signature": "x.y",
                           "state_gzip": koniec, "pdf_text_gzip": "39 TESTOWA Anna 14:09 44:51\n"}],
    }


def _ustalenia(wynik):
    return [u["tekst"] for u in wynik["ustalenia"]]


def test_czas_polski_z_przejsciem_na_czas_zimowy():
    assert czas_pl("2026-10-07T16:22:52+00:00").strftime("%H:%M:%S") == "18:22:52"
    assert czas_pl("2026-01-15T12:00:00Z").strftime("%H:%M") == "13:00"
    # 25.10.2026 - ostatnia niedziela października, zmiana o 01:00 UTC.
    assert czas_pl("2026-10-25T00:59:00+00:00").strftime("%H:%M") == "02:59"
    assert czas_pl("2026-10-25T01:00:00+00:00").strftime("%H:%M") == "02:00"
    # 29.03.2026 - ostatnia niedziela marca.
    assert czas_pl("2026-03-29T00:59:00+00:00").strftime("%H:%M") == "01:59"
    assert czas_pl("2026-03-29T01:00:00+00:00").strftime("%H:%M") == "03:00"


def test_klasyfikacja_rozroznia_czas_osobe_i_rodzaj():
    k = analiza.klucz_zdarzenia
    poprawka = klasyfikuj(Counter([k(P2a)]), Counter([k(P2b)]))
    assert [z["rodzaj"] for z in poprawka] == ["czas"]
    inna = ev("penalty3", "guest", 7, ms(51, 5), 2)
    przeniesienie = klasyfikuj(Counter([k(P3)]), Counter([k(inna)]))
    assert [z["rodzaj"] for z in przeniesienie] == ["osoba"]
    rodzaj = klasyfikuj(Counter([k(P3)]), Counter([k(ev("disqualification", "guest", 39, ms(51, 5), 2))]))
    assert [z["rodzaj"] for z in rodzaj] == ["rodzaj"]
    usuniecie = klasyfikuj(Counter([k(P3)]), Counter([k(G39)]))
    assert sorted(z["rodzaj"] for z in usuniecie) == ["dodane", "usuniete"]


def test_osoba_niejednoznaczna_mowi_kto_pasuje():
    b = blob([])
    with pytest.raises(ValueError, match="TESTOWA Anna"):
        znajdz_osobe(b, "39", None, None)
    assert znajdz_osobe(b, "39", "guest", None)["nazwisko"] == "TESTOWA Anna"
    assert znajdz_osobe(b, None, None, "testowa")["numer"] == "39"


def test_usunieta_iii_kara_ma_pelne_ustalenie(zrzut):
    w = analizuj(zrzut, nazwisko="TESTOWA")
    teksty = _ustalenia(w)
    usuniecie = next(t for t in teksty if t.startswith("III kara 2 min z 51:05"))
    assert "wpisano o 19:23:59" in usuniecie
    assert "usunięto o 19:34:34" in usuniecie
    assert "zegar 58:47" in usuniecie
    assert "przez 10 min 35 s" in usuniecie
    assert "zniknęła dyskwalifikacja" in usuniecie
    assert "nie wpisano tej kary nikomu innemu" in usuniecie
    # G_HOST2 doszła między wpisaniem a usunięciem i została - to nie było „cofnij".
    assert "doszło 1 inne zdarzenie, które zostało w protokole" in usuniecie
    po = next(t for t in teksty if t.startswith("Po usunięciu tej kary"))
    assert "bramka 59:00 (zapisano o 19:34:48)" in po
    # II kara z poprawionym czasem to stara kara, nie wpis „po usunięciu".
    assert "II kara" not in po


def test_poprawiona_kara_dziedziczy_chwile_wpisu(zrzut):
    w = analizuj(zrzut, nazwisko="TESTOWA")
    druga = next(z for z in w["osoba"]["zdarzenia_koniec"] if z["opis"] == "II kara 2 min")
    assert druga["czas"] == "44:51"
    assert analiza.godz(druga["zapisano"]) == "19:16:15"


def test_odmiana_liczby_zdarzen():
    assert analiza._ile_zdarzen(3) == "doszły 3 inne zdarzenia, które zostały"
    assert analiza._ile_zdarzen(12) == "doszło 12 innych zdarzeń, które zostały"
    assert analiza._ile_zdarzen(22) == "doszły 22 inne zdarzenia, które zostały"


def test_poprawki_czasu_i_stan_koncowy(zrzut):
    w = analizuj(zrzut, numer="39", druzyna="guest")
    teksty = _ustalenia(w)
    assert any("44:47 → 44:48" in t and "44:48 → 44:51" in t for t in teksty)
    assert teksty[0].startswith("W końcowym zapisie protokołu nr 39 TESTOWA Anna ma: I kara 2 min - 14:09")
    assert "Brak dyskwalifikacji" in teksty[0]
    assert w["osoba"]["rola"] == "Zawodniczka"
    # Historia: I kara, II kara, dwie poprawki czasu, III kara, jej usunięcie.
    rodzaje = [h["rodzaje"] for h in w["osoba"]["historia"]]
    assert ["usuniete"] in rodzaje
    assert sum(1 for r in rodzaje if r == ["czas"]) == 2


def test_pdf_zgodny_z_koncowym_zapisem(zrzut):
    w = analizuj(zrzut, nazwisko="TESTOWA")
    assert w["pdf"][0]["zgodny"] is True
    assert w["pdf"][0]["wydruk"] == ["39 TESTOWA Anna 14:09 44:51"]


def test_korekty_w_calym_meczu_wyrozniaja_osobe(zrzut):
    w = analizuj(zrzut, nazwisko="TESTOWA")
    oznaczone = [z for k in w["korekty"] for z in k["zmiany"] if z["osoby"]]
    assert {z["rodzaj"] for z in oznaczone} == {"czas", "usuniete"}


def test_dziennik_zwija_serie(zrzut):
    w = analizuj(zrzut)
    seria = next(d for d in w["dziennik"] if d["co"] == "Zmiana pól")
    assert seria["ile"] == 2


def test_wydruk_escapuje_i_ma_numer(zrzut):
    zrzut["mecz"]["data_json"]["matchConfig"] = {**CFG, "hostTeamName": "<script>x</script>"}
    w = analizuj(zrzut, nazwisko="TESTOWA")
    tekst = html_raportu(w, numer_raportu="RD-XK9-ABCDEF12", sha256="0" * 64, autor="Admin")
    assert "<script>x</script>" not in tekst
    assert "&lt;script&gt;" in tekst
    assert "RD-XK9-ABCDEF12" in tekst
    assert "—" not in tekst and "–" not in tekst


# ─────────────────────────── raport o jednej osobie ───────────────────────────


def test_teczka_osoby_sklada_sedno_sprawy(zrzut):
    from app.raport_dowodowy.dossier import dossier
    from app.raport_dowodowy.wydruk_osoby import html_osoby

    d = dossier(zrzut, nazwisko="TESTOWA")
    g = d["glowne"]
    assert g["rodzaj"] == "penalty3" and g["czas_meczu"] == "51:05"
    assert analiza.godz(g["usuniecie"]["czas"]) == "19:34:34"
    assert round(g["trwanie_s"]) == 635
    assert g["zdarzen_w_miedzyczasie"] == 1
    # Bramka po usunięciu i to ta na wynik końcowy, różnicą jednej bramki.
    assert [z["czas_meczu"] for z in d["po_usunieciu"]] == ["59:00"]
    assert d["po_usunieciu"][0]["decydujaca"] is True
    # II kara: wpis z pierwotnym czasem, dwie poprawki z ich godzinami.
    druga = next(z for z in d["zyciorysy"] if z["rodzaj"] == "penalty2")
    assert analiza.mmss(druga["klucz_wpisu"][3]) == "44:47"
    assert [analiza.godz(p["czas"]) for p in druga["poprawki"]] == ["19:16:36", "19:47:56"]
    assert d["usuniec_w_meczu"] == 1
    czynnosci = [t for e in d["edytorzy"] for _g, t in e["czynnosci"]]
    assert "usunięcie III kary 2 min (51:05)" in czynnosci
    assert "poprawka czasu II kary 2 min: 44:47 → 44:48" in czynnosci

    tekst = html_osoby(d)
    # Sama treść: bez podpisów i sum kontrolnych.
    assert "Podpis" not in tekst and "SHA-256" not in tekst
    assert "Usunięto III karę 2 min z 51:05 i dyskwalifikację" in tekst
    assert "decydującą o wyniku meczu" in tekst
    assert "—" not in tekst and "–" not in tekst


def test_droga_protokolu_bez_dubli(zrzut):
    from app.raport_dowodowy.dossier import dossier

    zrzut["dziennik"] += [
        {"event": "match.finished", "created_at": "2026-10-07T17:52:16+00:00", "actor_name": "STOLIKOWY Grzegorz"},
        {"event": "match.reopened", "created_at": "2026-10-07T17:52:25+00:00", "actor_name": "STOLIKOWY Grzegorz"},
        {"event": "match.finished", "created_at": "2026-10-07T17:52:25+00:00", "actor_name": "STOLIKOWY Grzegorz"},
        {"event": "zprp.attachment_sent", "created_at": "2026-10-07T18:53:51+00:00", "actor_name": "DELEGAT Adam"},
        {"event": "zprp.attachment_sent", "created_at": "2026-10-07T18:53:51+00:00", "actor_name": "DELEGAT Adam"},
    ]
    zrzut["dziennik"].sort(key=lambda w: w["created_at"])
    d = dossier(zrzut, nazwisko="TESTOWA")
    co = [x["co"] for x in d["droga"]]
    assert co.count("Zakończenie meczu") == 1 and "Wznowienie meczu" not in co
    assert co.count("Protokół PDF w ZPRP") == 1
    assert d["zatwierdzenie"]["kto"] == "DELEGAT Adam" and d["zatwierdzenie"]["rola"] == "delegat"
