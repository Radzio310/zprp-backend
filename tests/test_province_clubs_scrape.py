"""
Rozbior stron „Rozgrywki" i „Druzyny" - na prawdziwych stronach z ZPRP.

Strony leza w `tests/fixtures`, zeby zmiana szablonu po stronie zwiazku
wywalila test, a nie panel klubow u uzytkownika.
"""

from pathlib import Path

from app.province_clubs_scrape import (
    club_display_name,
    parse_competitions,
    parse_eligible_teams,
    parse_seasons,
    parse_selected_province,
    parse_team_club_id,
    parse_teams,
    team_key,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _read(name: str) -> str:
    raw = (FIXTURES / name).read_bytes()
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        # Strony ZPRP chodza w iso-8859-2 - `fetch_with_correct_encoding`
        # rozstrzyga to samo przy pobieraniu.
        return raw.decode("iso-8859-2")


ROZGRYWKI = _read("rozgrywki.html")
DRUZYNY = _read("druzyny.html")


def test_sezony_z_listy():
    seasons = parse_seasons(ROZGRYWKI)
    assert len(seasons) == 14
    current = [item for item in seasons if item.selected]
    assert [item.id for item in current] == ["195"]
    assert "2026/2027" in current[0].label
    assert seasons[-1].label.startswith("2013/2014")


def test_wojewodztwo_bierzemy_ze_strony():
    assert parse_selected_province(ROZGRYWKI) == "12"


def test_rozgrywki_z_kodami_i_kategoriami():
    competitions = parse_competitions(ROZGRYWKI)
    assert len(competitions) == 7

    by_id = {item.id: item for item in competitions}
    liga = by_id["12024"]
    assert liga.name == "II Liga Kobiet gr. 4"
    assert liga.gender == "K"
    assert liga.category == "Senior"
    assert liga.province == "SL"
    assert liga.code == "IIK4"
    assert liga.kind == "II"
    assert liga.season_label == "2026/2027"
    assert liga.state == "nieaktywny"
    assert (liga.teams_required, liga.teams_registered) == (6, 6)
    assert "b=zespoly" in liga.teams_path and "IdRozgr=12024" in liga.teams_path

    mlodzicy = by_id["12094"]
    assert mlodzicy.category == "Młodzik"
    assert mlodzicy.code == "S/MłMR"
    assert mlodzicy.teams_registered == 0


def test_druzyny_tylko_uczestniczace():
    teams = parse_teams(DRUZYNY)
    assert len(teams) == 6

    first = teams[0]
    assert first.team_id == "5192"
    assert first.name == "MKS Start Michałkowice"
    assert first.province == "SL"
    assert first.club_id == "2851"

    by_id = {item.team_id: item for item in teams}
    assert by_id["18447"].province == "OP"      # gosc z innego wojewodztwa
    assert by_id["18447"].club_id == "4268"
    # `parse_teams` zachowuje semantyke lewej tabeli. Prawa ma osobny parser,
    # zeby zespół uprawniony nie udawał uczestnika aktualnych rozgrywek.
    assert "15153" not in by_id


def test_druzyny_uprawnione_z_prawej_tabeli():
    teams = parse_eligible_teams(DRUZYNY)
    assert len(teams) == 7
    by_id = {item.team_id: item for item in teams}
    sosnica = by_id["15153"]
    assert sosnica.name == "Sośnica Gliwice"
    assert sosnica.province == "SL"
    assert sosnica.club_id == ""  # prawa tabela nie podaje numeru klubu
    assert sosnica.other_competitions == [("12009", "LOTTO Superliga kobiet")]
    assert "Filtr_zespol=15153" in sosnica.team_path


def test_numer_klubu_ze_strony_skladu():
    html = '<a href="?a=klub&amp;b=edycja&amp;NrKlubu=4321">Szczegóły klubu</a>'
    assert parse_team_club_id(html) == "4321"


def test_klucz_nazwy_rozroznia_drugie_zespoly():
    assert team_key("SPR Sośnica II Gliwice  (SL) ") == "spr sosnica ii gliwice"
    assert team_key("SPR Sośnica II Gliwice") != team_key("Sośnica Gliwice")
    # Ta sama druzyna zapisana raz z ogonkami, raz bez - jeden klucz.
    assert team_key("MUKS Skałka Śląsk Świętochłowice") == team_key(
        "MUKS Skalka Slask Swietochlowice"
    )


def test_nazwa_klubu_z_nazw_druzyn():
    assert club_display_name(["SPR Sośnica II Gliwice", "Sośnica Gliwice"]) == "Sośnica Gliwice"
    assert club_display_name([]) == ""
