# Zdjęcie przy kilku sędziach naraz jest cudze (app.judge_photos).
#
# Z produkcji (2026-10-15): w „Mentorzy i pary" przy Dawidzie CELOCHU stało
# zdjęcie innego sędziego - telefon po przełączeniu konta wysłał zdjęcie
# poprzedniego konta pod nowy numer.

from app.judge_photos import photo_number, shared_photo_fixes

URL = "https://baza.zprp.pl/foto_sedzia/5124.jpg?v=3"


def test_photo_number():
    assert photo_number(URL) == "5124"
    assert photo_number("https://baza.zprp.pl/foto_sedzia/00288.JPG") == "288"
    assert photo_number("https://example.com/a.jpg") == ""
    assert photo_number(None) == ""


def test_unique_photos_are_left_alone():
    rows = [{"judge_id": "1", "photo_url": "a"}, {"judge_id": "2", "photo_url": "b"}, {"judge_id": "3", "photo_url": ""}]
    assert shared_photo_fixes(rows) == {}


def test_shared_photo_stays_with_the_owner_named_in_the_file():
    rows = [{"judge_id": "5124", "photo_url": URL}, {"judge_id": "777", "photo_url": URL}]
    assert shared_photo_fixes(rows) == {"777": ""}


def test_shared_photo_without_a_known_owner_goes_from_everyone():
    rows = [{"judge_id": "1", "photo_url": "https://x/p.jpg"}, {"judge_id": "2", "photo_url": "https://x/p.jpg"}]
    assert shared_photo_fixes(rows) == {"1": "", "2": ""}
