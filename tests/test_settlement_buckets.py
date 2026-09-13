"""
Kubelki statystyk okregowych.

Zgloszenie uzytkownika z 13.09.2026: ekran „Moje statystyki" pokazywal DWA
mecze jako „Rozgrywki okregowe", choc jeden byl stolikiem na meczu I ligi,
a drugi boiskowym na meczu ligowym - ani jeden, ani drugi nie jest okregowy.
Te testy pilnuja granicy, ktora to rozstrzyga.
"""

from app import settlement_buckets as B
from app import settlement_rates as R


def test_rozgrywki_okregowe_sa_meczem_okregu_w_kazdej_roli():
    for role in (R.ROLE_FIELD, R.ROLE_TABLE, R.ROLE_DELEGATE):
        assert B.bucket_of("S/MlK1213/7", role) == B.DISTRICT


def test_stolik_na_meczu_ligowym_to_wlasny_kubelek():
    # Dokladnie mecz ze zgloszenia: LCK/6, sedzia stolikowy.
    assert B.bucket_of("LCK/6", R.ROLE_TABLE) == B.LEAGUE_TABLE


def test_boiskowy_na_meczu_ligowym_wypada_poza_domyslne():
    # Drugi mecz ze zgloszenia: IMD/3, sedzia boiskowy. Okreg go nie rozlicza.
    assert B.bucket_of("IMD/3", R.ROLE_FIELD) == B.LEAGUE_OTHER
    assert B.LEAGUE_OTHER not in B.DEFAULT_BUCKETS


def test_delegat_na_meczu_ligowym_tez_wypada():
    assert B.bucket_of("IMD/3", R.ROLE_DELEGATE) == B.LEAGUE_OTHER


def test_puchar_wojewodzki_zostaje_meczem_okregu_mimo_stawek_ii_ligi():
    # „S/PPK/2" ma szczebel „central" (placi jak II liga), ale to mecz OKREGU
    # i okreg rozlicza go w kazdej roli - bez osobnego warunku znikalby
    # z domyslnych statystyk.
    assert R.match_level("S/PPK/2") == "central"
    assert B.bucket_of("S/PPK/2", R.ROLE_FIELD) == B.DISTRICT


def test_puchar_centralny_liczy_sie_jak_mecz_okregu():
    # Ta sama granica co w `settlement_origin._district_level` - dwie rozne
    # odpowiedzi na to samo pytanie rozjechalyby zestawienie z rozliczeniem.
    assert B.is_own_match("PPM/23")
    assert B.bucket_of("PPM/23", R.ROLE_TABLE) == B.DISTRICT


def test_nieznany_numer_nie_wchodzi_do_domyslnych_statystyk():
    # Cisza nie moze udawac meczu okregowego.
    assert B.bucket_of("", R.ROLE_FIELD) == B.LEAGUE_OTHER
    assert B.bucket_of(None, R.ROLE_TABLE) == B.LEAGUE_TABLE


def test_rola_z_polskimi_znakami_rozstrzyga_stolik():
    # Porownanie po ASCII cicho wpadaloby w galaz „pozostale ligowe".
    assert R.ROLE_TABLE == "Sędzia stolikowy"
    assert B.bucket_of("LCK/6", " Sędzia stolikowy ") == B.LEAGUE_TABLE


def test_counts_liczy_kazdy_kubelek_i_nie_gubi_pustych():
    items = [
        {"bucket": B.DISTRICT},
        {"bucket": B.DISTRICT},
        {"bucket": B.LEAGUE_TABLE},
        {"bucket": "cokolwiek"},
        {},
    ]
    assert B.counts(items) == {
        B.DISTRICT: 2,
        B.LEAGUE_TABLE: 1,
        B.LEAGUE_OTHER: 0,
    }
    assert B.counts(None) == {B.DISTRICT: 0, B.LEAGUE_TABLE: 0, B.LEAGUE_OTHER: 0}
