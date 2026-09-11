from app.province_clubs_scope import (
    home_province,
    is_district_code,
    season_club_ids,
    team_in_scope,
)


def team(club_id, province, *codes):
    return {"club_id": club_id, "province": province, "codes": list(codes)}


SEASON = [
    team("1", "SL", "S/JmM"),
    team("2", "SL", "S/JmM"),
    team("3", "SL", "IIM4"),
    team("40", "MA", "IIM4"),          # rywal z II ligi z Krakowa
    team("41", "SK", "IIM4"),          # rywal z II ligi z Kielc
    team("50", "OP", "S/JmM"),         # Opole gra w naszej lidze juniorow
]


def test_district_codes():
    assert is_district_code("S/JmM")
    assert is_district_code("S/PPK/2")        # puchar wojewodzki
    assert not is_district_code("IIM4")       # II liga jest centralna
    assert not is_district_code("PPM/23")


def test_home_province_comes_from_district_competitions():
    assert home_province(SEASON) == "SL"
    # Bez rozgrywek okregowych - najczestszy kod w ogole.
    assert home_province([team("1", "SL", "IIM4"), team("2", "SL", "IIM4"), team("3", "MA", "IIM4")]) == "SL"
    assert home_province([]) == ""


def test_rival_from_another_province_in_central_group_is_out():
    assert not team_in_scope(team("40", "MA", "IIM4"), "SL")
    assert team_in_scope(team("3", "SL", "IIM4"), "SL")


def test_neighbour_playing_in_our_league_is_in():
    assert team_in_scope(team("50", "OP", "S/JmM"), "SL")


def test_unknown_province_stays():
    assert team_in_scope(team("7", "", "IIM4"), "SL")


def test_club_known_only_from_another_season_is_gone():
    # Klub 99 ma tylko wiersz ustawien z innego sezonu - nie ma go w druzynach
    # ani w meczach, wiec nie wraca jako „0 druzyn".
    assert season_club_ids(SEASON, []) == {"1", "2", "3", "50"}


def test_money_or_matches_keep_any_club():
    assert season_club_ids(SEASON, ["40", "99", "", None]) == {"1", "2", "3", "50", "40", "99"}
