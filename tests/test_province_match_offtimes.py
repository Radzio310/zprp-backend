from datetime import datetime, timedelta, timezone

from app.province_match_offtimes import (
    MATCH_ID_PREFIX,
    MATCH_SOURCE,
    client_match_id,
    entries_by_judge,
    is_match_entry,
    match_entry,
    match_venue,
    match_window_start,
    parse_match_moment,
    without_client_duplicates,
)


STATE = {
    "Id": "123456",
    "RozgrywkiCode": "1LMP",
    "data_fakt": "2026-10-04 17:30:00",
    "ID_zespoly_gosp_ZespolNazwa": "GOSPODARZ",
    "ID_zespoly_gosc_ZespolNazwa": "GOSC",
    "Hala_miasto": "Katowice",
    "Hala_ulica": "Sportowa",
    "Hala_numer": "12",
}


def test_termin_bez_strefy_znaczy_godzine_polska():
    # 4 pazdziernika Polska ma UTC+2, wiec 17:30 lokalnie to 15:30 UTC.
    assert parse_match_moment("2026-10-04 17:30:00") == datetime(
        2026, 10, 4, 15, 30, tzinfo=timezone.utc
    )
    # Kolumna bazy jest juz w UTC - przepuszczamy ja bez przeliczania drugi raz.
    stored = datetime(2026, 10, 4, 15, 30, tzinfo=timezone.utc)
    assert parse_match_moment(stored) == stored
    assert parse_match_moment("") is None


def test_mecz_zajmuje_dwie_godziny_od_startu():
    entry = match_entry("123456", STATE)
    assert entry is not None
    assert entry["from"] == "2026-10-04T15:30:00+00:00"
    assert entry["to"] == "2026-10-04T17:30:00+00:00"
    start = datetime.fromisoformat(entry["from"])
    finish = datetime.fromisoformat(entry["to"])
    assert finish - start == timedelta(hours=2)


def test_ksztalt_wpisu_jest_wspolny_z_pozostalymi_zrodlami():
    entry = match_entry("123456", STATE)
    assert entry["entry_type"] == "UNAVAIL"
    assert entry["id"] == f"{MATCH_ID_PREFIX}123456"
    assert entry["source"] == MATCH_SOURCE
    assert entry["source_match_id"] == "123456"
    assert entry["info"] == "GOSPODARZ - GOSC"
    assert entry["location"] == "Katowice, Sportowa 12"
    assert entry["category_name"] == "1LMP"
    assert entry["isMatch"] is True
    assert entry["is_global"] is True
    assert entry["is_manual"] is False
    assert is_match_entry(entry)


def test_mecz_bez_terminu_nie_trafia_do_kalendarza():
    assert match_entry("123456", {"RozgrywkiCode": "1LMP"}) is None
    assert match_entry("", STATE) is None


def test_termin_z_kolumny_ratuje_mecz_bez_data_fakt():
    stored = datetime(2026, 10, 4, 15, 30, tzinfo=timezone.utc)
    entry = match_entry("123456", {"RozgrywkiCode": "1LMP"}, match_at=stored)
    assert entry is not None
    assert entry["from"] == "2026-10-04T15:30:00+00:00"
    # Bez nazw druzyn zostaje czytelna etykieta, nie pusty pasek.
    assert entry["info"] == "MECZ"


def test_adres_hali_bez_wiszacych_przecinkow():
    assert match_venue({"Hala_miasto": "Katowice"}) == "Katowice"
    assert match_venue({"Hala_ulica": "Sportowa"}) == "Sportowa"
    assert match_venue({}) == ""


def test_wpis_meczowy_z_telefonu_poznajemy_po_numerze_zawodow():
    phone = {"id": "0123456", "isMatch": True, "info": "GOSPODARZ - GOSC"}
    assert client_match_id(phone) == "123456"
    # Zwykla niedyspozycja to nie mecz.
    assert client_match_id({"id": "abc", "isMatch": False}) == ""
    # Wlasny wpis serwerowy nie jest kandydatem do odsiania.
    assert client_match_id(match_entry("123456", STATE)) == ""


def test_serwer_wypiera_ten_sam_mecz_z_telefonu():
    server = [match_entry("123456", STATE)]
    district = [
        {"id": "0123456", "isMatch": True, "info": "stara nazwa"},
        {"id": "999", "isMatch": True, "info": "mecz, o ktorym serwer nie wie"},
        {"id": "ndz-1", "info": "Urlop"},
    ]
    kept = without_client_duplicates(district, server)
    assert [item["id"] for item in kept] == ["999", "ndz-1"]


def test_okno_siega_trzydziesci_dni_wstecz():
    now = datetime(2026, 10, 4, 12, 0, tzinfo=timezone.utc)
    assert match_window_start(now) == now - timedelta(days=30)


def test_mapa_po_sedziach_scala_role_i_normalizuje_numer():
    rows = [
        {"judge_id": "03390", "match_id": "123456", "match_at": None, "state": STATE},
        # Ten sam mecz, ten sam sedzia w drugiej roli - jeden wpis, nie dwa.
        {"judge_id": "3390", "match_id": "123456", "match_at": None, "state": STATE},
        {
            "judge_id": "3390",
            "match_id": "111",
            "match_at": None,
            "state": {**STATE, "data_fakt": "2026-10-01 09:00:00"},
        },
    ]
    out = entries_by_judge(rows)
    assert list(out) == ["3390"]
    # Posortowane po terminie: wczesniejszy mecz pierwszy.
    assert [item["source_match_id"] for item in out["3390"]] == ["111", "123456"]


def test_mapa_pomija_sedziow_spoza_kalendarza_okregu():
    rows = [
        {"judge_id": "3390", "match_id": "123456", "match_at": None, "state": STATE},
        {"judge_id": "9999", "match_id": "111", "match_at": None, "state": STATE},
    ]
    out = entries_by_judge(rows, judge_keys={"03390"})
    assert list(out) == ["3390"]
