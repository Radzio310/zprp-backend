"""Pobieranie klipów Mentora - reguły czyste: przeliczenie czasu, brakujące gwizdki, kolejność źródeł, nazwy, paczka."""

import pytest

from app import mentor_clip_download_rules as D

SYNC_YT = {"match_start_s": 100, "second_half_s": 2000}
SYNC_FILE = {"match_start_s": 40, "second_half_s": 1900}


def test_przeliczenie_czasu_per_polowa():
    # I połowa: przesunięcie z pierwszego gwizdka (40 - 100 = -60), II połowa: z drugiego (1900 - 2000 = -100).
    assert D.map_time(SYNC_YT, SYNC_FILE, 1500) == 1440
    assert D.map_time(SYNC_YT, SYNC_FILE, 2500) == 2400
    # Granica: dokładnie początek II połowy źródła liczy się już do II połowy.
    assert D.map_time(SYNC_YT, SYNC_FILE, 2000) == 1900
    assert D.convert_range(SYNC_YT, SYNC_FILE, 1500, 1520) == (1440, 1460)
    assert D.convert_range(SYNC_YT, SYNC_FILE, 2500, 2530) == (2400, 2430)


def test_przeliczenie_nie_schodzi_ponizej_zera_a_znikajacy_zakres_jest_bledem():
    assert D.map_time({"match_start_s": 500, "second_half_s": 3000}, {"match_start_s": 10, "second_half_s": 2500}, 100) == 0
    with pytest.raises(ValueError):
        D.convert_range({"match_start_s": 500, "second_half_s": 3000}, {"match_start_s": 10, "second_half_s": 2500}, 100, 120)


def test_brakujacy_gwizdek():
    assert D.sync_gaps({"match_start_s": 5}) == ["second_half"]
    assert D.sync_gaps({"second_half_s": 5}) == ["start"]
    assert D.sync_gaps(None) == ["start", "second_half"]
    assert D.sync_gaps(SYNC_YT) == []


def link(sync=None):
    return {"id": "yt", "kind": "link", "label": "YouTube", "sync": sync or {}, "ready": True}


def file_opt(sync=None, ready=True, vid="f1"):
    return {"id": vid, "kind": "file", "label": "Mecz.mp4", "sync": sync or {}, "ready": ready}


def bastion(sync=None):
    return {"id": "b1", "kind": "bastion", "label": "Handball Bastion", "sync": sync or {}, "ready": True}


def test_klip_na_wlasnym_pliku_lub_bastionie_nie_wymaga_synchronizacji():
    got = D.choose_source(file_opt(), [bastion()])
    assert got["mode"] == "direct" and got["reason"] is None and got["option"]["kind"] == "file"
    assert D.choose_source(file_opt(ready=False), [])["reason"] == "NOT_READY"


def test_sam_link_bez_drugiego_zrodla_to_no_source():
    got = D.choose_source(link(SYNC_YT), [])
    assert got["mode"] == "none" and got["reason"] == "NO_SOURCE" and got["option"] is None


def test_kolejnosc_zrodel_plik_przed_bastionem():
    got = D.choose_source(link(SYNC_YT), [bastion(SYNC_FILE), file_opt(SYNC_FILE)])
    assert got["mode"] == "convert" and got["reason"] is None and got["option"]["kind"] == "file"


def test_niezsynchronizowany_plik_ustepuje_zsynchronizowanemu_bastionowi():
    got = D.choose_source(link(SYNC_YT), [file_opt({}), bastion(SYNC_FILE)])
    assert got["option"]["kind"] == "bastion" and got["reason"] is None


def test_plik_w_przetwarzaniu_jest_not_ready_a_gotowy_bastion_wygrywa():
    got = D.choose_source(link(SYNC_YT), [file_opt(SYNC_FILE, ready=False)])
    assert got["reason"] == "NOT_READY" and got["option"]["id"] == "f1"
    got = D.choose_source(link(SYNC_YT), [file_opt(SYNC_FILE, ready=False), bastion(SYNC_FILE)])
    assert got["reason"] is None and got["option"]["kind"] == "bastion"


def test_need_sync_wskazuje_czego_brakuje_na_obu_nagraniach():
    got = D.choose_source(link({"match_start_s": 100}), [file_opt({"second_half_s": 1900})])
    assert got["reason"] == "NEED_SYNC"
    assert got["missing"] == [
        {"video_id": "yt", "label": "YouTube", "whistle": "second_half"},
        {"video_id": "f1", "label": "Mecz.mp4", "whistle": "start"},
    ]
    text = D.hint_for("NEED_SYNC", got["missing"])
    assert "początek II połowy w nagraniu „YouTube”" in text and "pierwszy gwizdek w nagraniu „Mecz.mp4”" in text


def test_need_sync_wybiera_zrodlo_ktoremu_brakuje_najmniej():
    got = D.choose_source(link(SYNC_YT), [file_opt({}), bastion({"match_start_s": 3})])
    assert got["option"]["kind"] == "bastion"
    assert [m["whistle"] for m in got["missing"]] == ["second_half"]


def test_nazwa_pliku_z_minuta_i_tytulem_bez_znakow_zakazanych():
    assert D.download_filename("Kara 2 min - czerwona", 26 * 60 + 23) == "26m23 Kara 2 min - czerwona.mp4"
    assert D.download_filename('Faul: "ręka" / atak?*', 5) == "0m05 Faul ręka atak.mp4"
    assert D.download_filename("Długi — myślnik", 61) == "1m01 Długi - myślnik.mp4"
    assert D.download_filename(None, 0) == "0m00 klip.mp4"
    assert D.download_filename("CON", 0) == "0m00 _CON.mp4"
    assert len(D.download_filename("x" * 300, 0)) < 80


def test_foldery_mecz_i_kategoria():
    match = {"date": "2026-10-10T18:00:00+02:00", "home": "AGH Kraków", "away": "Gwardia", "code": "LCM-32"}
    assert D.folder_names(match, "Do dyskusji") == {"match": "2026-10-10 AGH Kraków - Gwardia (LCM-32)", "category": "Do dyskusji"}
    odd = D.folder_names({"date": "2026-10-10", "home": "A/B", "away": "C:D", "code": None}, "Kat/ego*ria. ")
    assert odd == {"match": "2026-10-10 A B - C D", "category": "Kat ego ria"}
    assert D.folder_names({}, "")["category"] == "Bez kategorii" and D.folder_names({}, "")["match"] == "Mecz"


def test_minuta_meczu_z_protokolu_synchronizacji_albo_z_nagrania():
    assert D.match_time_s(1_583_000, 999, SYNC_YT) == 1583
    assert D.match_time_s(None, 1500, SYNC_YT) == 1400
    assert D.match_time_s(None, 2300, {**SYNC_YT, "half_minutes": 30}) == 300 + 1800
    assert D.match_time_s(None, 50, {}) == 50


def test_paczka_limit_kolejki_bastionu_nie_dotyczy_plikow_i_gotowych():
    def plan(source, status="none", can=True):
        return {"can_download": can, "source": source, "mp4_status": status}

    plans = [plan("bastion"), plan("file"), plan("bastion", "ready"), plan("bastion"), plan(None, can=False), plan("bastion")]
    assert D.allocate_batch(plans, active_bastion=10, cap=12) == [True, True, True, True, False, False]
    assert D.allocate_batch([plan("bastion")], active_bastion=12, cap=12) == [False]


def test_sygnatura_planszy_zmienia_sie_z_trescia():
    assert D.card_signature(["a", "b"]) == D.card_signature(["a", "b"])
    assert D.card_signature(["a", "b"]) != D.card_signature(["a", "c"])
    assert D.estimate_s("bastion", True) > D.estimate_s("bastion", False) > D.estimate_s("file", False)


def test_pelna_nazwa_niesie_mecz_i_kategorie():
    card = {"date": "2026-10-10", "home": "AGH Kraków", "away": "Gwardia", "code": "LCM-32"}
    assert D.full_filename(card, "Do dyskusji", "23m20 Kara 2 min - czerwona.mp4") == "LCM-32 Do dyskusji 23m20 Kara 2 min - czerwona.mp4"
    # Bez numeru: data i drużyny; znaki zakazane znikają.
    assert D.full_filename({**card, "code": ""}, "Istotne", "5m01 Gol.mp4") == "2026-10-10 AGH Kraków - Gwardia Istotne 5m01 Gol.mp4"
    assert D.full_filename({}, "", "5m01 Gol.mp4") == "5m01 Gol.mp4"
    assert "/" not in D.full_filename(card, "A/B?", "1m00 x.mp4")


def test_pelna_nazwa_ma_limit_a_minuta_i_tytul_zostaja():
    card = {"code": "M" * 30, "date": "", "home": "", "away": ""}
    out = D.full_filename(card, "K" * 50, "26m23 " + "t" * 60 + ".mp4", limit=100)
    assert len(out) <= 100 and out.endswith(".mp4")
    assert "26m23 " + "t" * 60 in out
