from datetime import datetime, timezone

from app import obsada_view_rules as R


def test_token_alphabet_and_length():
    tokens = {R.new_token() for _ in range(200)}
    assert len(tokens) == 200
    for t in tokens:
        assert len(t) == 16 and R.valid_token(t)
        assert not set("O0I1l") & set(t)
    assert not R.valid_token("short") and not R.valid_token("O" * 16)


def test_modes():
    assert R.normalize_mode(" LINK ") == "link"
    assert R.normalize_mode("x") is None


def test_judge_key_order_independent():
    a = R.judge_key("KOWALCZYK Bartłomiej O")
    assert a == R.judge_key("Bartłomiej O. Kowalczyk")
    assert a != R.judge_key("KOWALCZYK Bartłomiej")
    assert R.safe_key(a)


def _state(first="", second="", sec=""):
    return {"NrSedzia_pierwszy_nazwisko": first, "NrSedzia_drugi_nazwisko": second,
            "NrSedzia_sekretarz_nazwisko": sec}


def test_diff_changes():
    t1 = datetime(2026, 11, 20, 18, tzinfo=timezone.utc)
    t2 = datetime(2026, 11, 21, 18, tzinfo=timezone.utc)
    assert R.diff_changes(_state(), _state("NOWAK Jan"), t1, t1)[0]["kind"] == "new_crew"
    assert R.diff_changes(_state("NOWAK Jan"), _state("Jan Nowak"), t1, t1) == []
    assert R.diff_changes(_state("NOWAK Jan"), _state("ZAJĄC Karol"), t1, t1)[0]["kind"] == "crew_change"
    assert [d["kind"] for d in R.diff_changes(_state(), _state(), t1, t2)] == ["moved"]
    assert R.diff_changes(_state("--- ---"), _state(), t1, t1) == []
    assert R.diff_changes({}, {"status": "Odwołany"}, t1, t1)[0]["kind"] == "cancelled"


def test_needs_and_crew_view():
    crew = {"pierwszy": {"number": "1", "name": "NOWAK Jan"}, "drugi": None, "sekretarz": None,
            "czas": None, "delegat": None, "delegat2": None}
    view = R.crew_view(crew)
    assert view["first"]["name"] == "NOWAK Jan" and "number" not in view["first"]
    assert view["second"] is None
    needs = R.needs_view(crew, {"field": 2, "table": 2})
    assert needs == {"first": False, "second": True, "secretary": True, "time": True,
                     "delegate": False, "delegate2": False}


def test_rev_and_etag():
    rev = R.compute_rev([{"a": 1}], "x")
    assert rev == R.compute_rev([{"a": 1}], "x") != R.compute_rev([{"a": 2}], "x")
    assert R.etag_matches(f'W/"{rev}"', rev) and R.etag_matches(rev, rev)
    assert not R.etag_matches('"zzz"', rev) and not R.etag_matches(None, rev)


def test_ics():
    key = R.judge_key("KOWALCZYK Bartłomiej O")
    matches = [
        {"match_id": "7", "match_at": "2026-11-21T16:00:00+00:00", "host": "A", "guest": "B",
         "hall": "Hala; 1", "city": "Gliwice", "code": "S/JmM/1",
         "crew": {"first": {"name": "KOWALCZYK Bartłomiej O", "key": key}, "second": None}},
        {"match_id": "8", "match_at": None, "host": "C", "guest": "D",
         "crew": {"first": {"name": "x", "key": key}}},
        {"match_id": "9", "match_at": "2026-11-22T16:00:00+00:00", "host": "E", "guest": "F",
         "crew": {"first": {"name": "y", "key": "inny"}}},
    ]
    ics = R.build_ics(matches, key, now=datetime(2026, 11, 12, tzinfo=timezone.utc))
    assert ics.count("BEGIN:VEVENT") == 1 and "UID:obsada-7-" in ics
    assert "DTSTART:20261121T160000Z" in ics and "DTEND:20261121T180000Z" in ics
    assert r"Hala\; 1" in ics and ics.endswith("END:VCALENDAR\r\n")
    assert all(len(line.encode()) <= 75 for line in ics.split("\r\n"))


def test_signed_ics():
    sig = R.sign_ics("s", "SLASKIE", "u12", "k", "TOKEN")
    assert R.verify_ics("s", "SLASKIE", "u12", "k", "TOKEN", sig)
    assert not R.verify_ics("s", "SLASKIE", "u12", "k", "NOWY", sig)
    assert not R.verify_ics("s", "SLASKIE", "u13", "k", "TOKEN", sig)


def test_app_mode_row_always_has_token():
    """Tryb `app` (bez linku) tez podpisuje .ics tokenem wiersza: token jest NOT NULL i
    powstaje przy tworzeniu wiersza (_row), wiec ics-link dziala bez wczesniejszego 'link'."""
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent / "app"
    tables = (root / "obsada_view_tables.py").read_text(encoding="utf-8")
    assert 'Column("token", String(16), nullable=False, unique=True)' in tables
    view = (root / "obsada_view.py").read_text(encoding="utf-8")
    assert "mode=R.DEFAULT_MODE, token=R.new_token()" in view
    token = R.new_token()
    assert R.valid_token(token)
    sig = R.sign_ics("s", "SLASKIE", "u1", "k", token)
    assert R.verify_ics("s", "SLASKIE", "u1", "k", token, sig)


def _roster():
    return R.Roster([
        {"judge_id": "101", "full_name": "NALEŻNY Adam", "photo_url": "https://x/a.jpg"},
        {"judge_id": "102", "full_name": "WRONA Marcin", "photo_url": ""},
        {"judge_id": "103", "full_name": "KOWAL Jan", "photo_url": "https://x/k1.jpg"},
        {"judge_id": "104", "full_name": "Jan Kowal", "photo_url": "https://x/k2.jpg"},
        {"judge_id": "105", "full_name": "HTTP Piotr", "photo_url": "http://x/p.jpg"},
    ])


def test_keep_match_foreign_without_our_referee_is_dropped():
    r = _roster()
    foreign = {"pierwszy": {"number": "900", "name": "OBCY Ktos"}, "drugi": None}
    assert not R.keep_match("foreign", foreign, r)
    assert R.keep_match("own", foreign, r)
    assert R.keep_match("foreign", {"pierwszy": {"number": "", "name": "Adam Należny"}}, r)
    assert R.keep_match("foreign", {"drugi": {"number": "102", "name": "inaczej"}}, r)
    assert not R.keep_match("foreign", {}, r)


def test_crew_view_photo():
    r = _roster()
    crew = {"pierwszy": {"number": "101", "name": "NALEŻNY Adam"},
            "drugi": {"number": "", "name": "Marcin Wrona"},
            "sekretarz": {"number": "", "name": "KOWAL Jan"},
            "czas": {"number": "900", "name": "OBCY Ktos"},
            "delegat": {"number": "105", "name": "HTTP Piotr"}}
    v = R.crew_view(crew, r)
    assert v["first"]["photo"] == "https://x/a.jpg"
    assert v["second"]["photo"] is None      # brak zdjecia
    assert v["secretary"]["photo"] is None   # namesaki
    assert v["time"]["photo"] is None        # nie nasz
    assert v["delegate"]["photo"] is None    # nie https
    assert v["delegate2"] is None
    assert R.crew_view(crew)["first"]["photo"] is None


def test_rev_changes_with_photo():
    crew = {"pierwszy": {"number": "101", "name": "NALEŻNY Adam"}}
    a = R.compute_rev([{"crew": R.crew_view(crew, _roster())}])
    r2 = R.Roster([{"judge_id": "101", "full_name": "NALEŻNY Adam", "photo_url": "https://x/b.jpg"}])
    assert a != R.compute_rev([{"crew": R.crew_view(crew, r2)}])


def test_roster_accepts_records_without_get():
    """Rekord z `databases` to Mapping bez .get() - Roster nie moze na tym paść (produkcja 13.11)."""
    class Record:
        """Jak rekord `databases`: keys() i [] dzialaja, .get() nie."""
        def __init__(self, d):
            self._d = d
        def keys(self):
            return self._d.keys()
        def __getitem__(self, k):
            return self._d[k]

    from app import obsada_view_rules as R
    roster = R.Roster([Record({"judge_id": "123", "full_name": "Jan Kowalski", "photo_url": "https://x/y.jpg"})])
    assert roster.by_id["123"] == "https://x/y.jpg"
