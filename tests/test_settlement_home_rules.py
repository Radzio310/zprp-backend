"""Historia miejsca zamieszkania i odczyt listy przejazdów (06.11.2026)."""
from datetime import date, datetime, timezone

import pytest

from app import settlement_home_rules as H

LIST_TEXT = """Śląski Związek Piłki Ręcznej
L I S TA P R Z E J A Z D Ó W
SLP/2026_27/2
05.10.2026 - 01.11.2026
Lista kosztów przejazdów
Lp
Nazwisko i imię
1
ANDERS Magdalena
17.10.2026
Ruda Śląska-Chorzów-Ruda Śląska
10,0 km
Razem ANDERS Magdalena
2
WOJTYCZKA Karol
16.10.2026
Mikołów-Bielsko-Biała-Mikołów
37,0 km
28.10.2026
Mikołów-Wilkowice-Mikołów
37,0 km
3
ŁUSZCZYKIEWICZ
Maksymilian
10.10.2026
Siemianowice Śląskie-Piekary Śląskie-Siemianowice
Śląskie
25,0 km *
4
NOWAK Jan
12.10.2026
Bytom-Zabrze-Bytom
5
OBCY Ktoś
12.10.2026
Zabrze-Bytom-Zabrze
str. 1 z 30
"""

JUDGES = [
    {"judge_id": "10", "name": "Magdalena Anders", "home_city": "Ruda Śląska"},
    {"judge_id": "11", "name": "Karol Wojtyczka", "home_city": "Orzesze"},
    {"judge_id": "12", "name": "Maksymilian Łuszczykiewicz", "home_city": ""},
    {"judge_id": "13", "name": "Jan Nowak", "home_city": "Gliwice"},
]


def test_home_for_picks_first_entry_covering_the_day():
    entries = [(date(2026, 11, 1), "Mikołów"), (date(2026, 6, 30), "Tychy")]
    assert H.home_for(entries, date(2026, 5, 1)) == "Tychy"
    assert H.home_for(entries, date(2026, 6, 30)) == "Tychy"
    assert H.home_for(entries, date(2026, 7, 1)) == "Mikołów"
    assert H.home_for(entries, date(2026, 11, 1)) == "Mikołów"
    assert H.home_for(entries, date(2026, 11, 2)) is None
    assert H.home_for(entries, None) is None


def test_local_day_uses_polish_time():
    assert H.local_day(datetime(2026, 11, 1, 23, 30, tzinfo=timezone.utc)) == date(2026, 11, 2)


def test_timeline_and_validation():
    assert H.timeline([(date(2026, 11, 1), "Mikołów")], "Orzesze") == [
        {"city": "Mikołów", "from": None, "to": "2026-11-01"},
        {"city": "Orzesze", "from": "2026-11-02", "to": None},
    ]
    assert H.clean_entry(" Mikołów ", "2026-11-01") == ("Mikołów", date(2026, 11, 1))
    with pytest.raises(ValueError):
        H.clean_entry("", "2026-11-01")
    with pytest.raises(ValueError):
        H.clean_entry("Mikołów", "jutro")


def test_split_route_handles_hyphenated_towns():
    assert H.split_route("Ruda Śląska-Chorzów-Ruda Śląska") == ("Ruda Śląska", "Chorzów")
    assert H.split_route("Bielsko-Biała-Chorzów-Bielsko-Biała") == ("Bielsko-Biała", "Chorzów")
    assert H.split_route("Mikołów-Bielsko-Biała-Mikołów") == ("Mikołów", "Bielsko-Biała")
    assert H.split_route("Chorzów") is None


def test_parse_travel_list_reads_header_judges_and_wrapped_cells():
    parsed = H.parse_travel_list(LIST_TEXT)
    assert parsed["number"] == "SLP/2026_27/2"
    assert (parsed["from"], parsed["to"]) == (date(2026, 10, 5), date(2026, 11, 1))
    assert set(parsed["judges"]) == {
        "ANDERS Magdalena", "WOJTYCZKA Karol", "ŁUSZCZYKIEWICZ Maksymilian", "NOWAK Jan", "OBCY Ktoś",
    }
    assert parsed["judges"]["WOJTYCZKA Karol"]["trips"] == 2
    assert dict(parsed["judges"]["ŁUSZCZYKIEWICZ Maksymilian"]["homes"]) == {"Siemianowice Śląskie": 1}


def test_compare_list_finds_who_moved():
    result = H.compare_list(H.parse_travel_list(LIST_TEXT), JUDGES, {"13": [(date(2026, 11, 1), "Bytom")]})
    by_name = {row["name"]: row for row in result["rows"]}
    karol = by_name["Karol Wojtyczka"]
    assert (karol["status"], karol["list_city"], karol["current"], karol["until"]) == (
        "changed", "Mikołów", "Orzesze", "2026-11-01")
    assert by_name["Magdalena Anders"]["status"] == "same"
    assert by_name["Maksymilian Łuszczykiewicz"]["status"] == "no_city"
    assert by_name["Jan Nowak"]["status"] == "declared"
    assert by_name["OBCY Ktoś"]["status"] == "unknown"
    assert result["rows"][0]["status"] == "changed"
    assert result["counts"]["changed"] == 1
