"""Czytanie kalendarza iCal: co z pliku staje się niedyspozycją.

Testy chodzą po kształtach, które przychodzą naprawdę: plan zajęć z USOS
(strefa Europe/Warsaw, zawinięte linie), zajęcia co tydzień z odwołaniem
pojedynczego terminu, wpisy całodniowe z WYŁĄCZNYM końcem i pliki, w których
coś jest połamane. Reguła nadrzędna: uszkodzony wpis pomijamy, ale nigdy nie
wywracamy całego importu - kalendarz sędziego nie może zniknąć przez jedno
dziwne wydarzenie.
"""

from __future__ import annotations

from datetime import date, datetime, timezone

from app.ical_feed import (
    SOURCE,
    feed_entries,
    is_feed_entry,
    occurrences,
    parse_events,
    unescape,
    unfold_lines,
)

WINDOW_START = date(2026, 3, 1)
WINDOW_END = date(2026, 7, 1)


def wrap(*events: str) -> str:
    return "BEGIN:VCALENDAR\r\nVERSION:2.0\r\n" + "".join(events) + "END:VCALENDAR\r\n"


USOS_LECTURE = (
    "BEGIN:VEVENT\r\n"
    "UID:usos-2026-1234\r\n"
    "DTSTART;TZID=Europe/Warsaw:20260302T093000\r\n"
    "DTEND;TZID=Europe/Warsaw:20260302T111500\r\n"
    "SUMMARY:Statystyka matematyczna\\, wyk\\u0142ad\r\n"
    "LOCATION:Katowice\\, bud. A sala 112\r\n"
    "END:VEVENT\r\n"
)


def entries(ics: str, **kwargs):
    return feed_entries(
        ics,
        feed_id="f1",
        feed_name="Plan studiów",
        color="#7C4DFF",
        window_start=kwargs.get("window_start", WINDOW_START),
        window_end=kwargs.get("window_end", WINDOW_END),
        synced_at=datetime(2026, 3, 1, 6, 0, tzinfo=timezone.utc),
    )


# ── format pliku ─────────────────────────────────────────────────


def test_zawiniete_linie_sklejaja_sie():
    lines = unfold_lines("SUMMARY:Bardzo dlugi\r\n  tytul zajec\r\nUID:x\r\n")
    assert lines[0] == "SUMMARY:Bardzo dlugi tytul zajec"
    assert lines[1] == "UID:x"


def test_znaki_specjalne_w_tresci():
    assert unescape("Statystyka\\, wyklad") == "Statystyka, wyklad"
    assert unescape("Sala 12\\nBudynek A") == "Sala 12\nBudynek A"


# ── pojedyncze zajęcia ───────────────────────────────────────────


def test_zajecia_z_usos_staja_sie_wpisem():
    out = entries(wrap(USOS_LECTURE))
    assert len(out) == 1
    item = out[0]
    # 9:30 czasu polskiego w marcu to 8:30 UTC.
    assert item["from"].startswith("2026-03-02T08:30")
    assert item["to"].startswith("2026-03-02T10:15")
    assert item["info"].startswith("Statystyka matematyczna")
    assert item["location"].startswith("Katowice")
    assert item["source"] == SOURCE
    assert item["source_feed"] == "f1"
    assert item["category_name"] == "Plan studiów"
    assert item["color"] == "#7C4DFF"
    assert item["is_manual"] is False
    assert is_feed_entry(item)


def test_identyfikator_jest_staly_miedzy_synchronizacjami():
    first = entries(wrap(USOS_LECTURE))[0]["id"]
    second = entries(wrap(USOS_LECTURE))[0]["id"]
    assert first == second


def test_czas_w_UTC_i_bez_strefy_czytamy_jako_polski():
    utc = wrap(
        "BEGIN:VEVENT\r\nUID:a\r\nDTSTART:20260302T080000Z\r\n"
        "DTEND:20260302T090000Z\r\nSUMMARY:Z UTC\r\nEND:VEVENT\r\n"
    )
    floating = wrap(
        "BEGIN:VEVENT\r\nUID:b\r\nDTSTART:20260302T090000\r\n"
        "DTEND:20260302T100000\r\nSUMMARY:Bez strefy\r\nEND:VEVENT\r\n"
    )
    assert entries(utc)[0]["from"].startswith("2026-03-02T08:00")
    # 9:00 „bez strefy" ma znaczyć 9:00 w Polsce, czyli 8:00 UTC.
    assert entries(floating)[0]["from"].startswith("2026-03-02T08:00")


def test_brak_konca_i_czas_trwania():
    bez_konca = wrap(
        "BEGIN:VEVENT\r\nUID:c\r\nDTSTART;TZID=Europe/Warsaw:20260302T090000\r\n"
        "SUMMARY:Godzina\r\nEND:VEVENT\r\n"
    )
    z_duration = wrap(
        "BEGIN:VEVENT\r\nUID:d\r\nDTSTART;TZID=Europe/Warsaw:20260302T090000\r\n"
        "DURATION:PT1H30M\r\nSUMMARY:Poltorej\r\nEND:VEVENT\r\n"
    )
    assert entries(bez_konca)[0]["to"].startswith("2026-03-02T09:00")
    assert entries(z_duration)[0]["to"].startswith("2026-03-02T09:30")


# ── serie ────────────────────────────────────────────────────────


WEEKLY = (
    "BEGIN:VEVENT\r\n"
    "UID:weekly-1\r\n"
    "DTSTART;TZID=Europe/Warsaw:20260302T093000\r\n"
    "DTEND;TZID=Europe/Warsaw:20260302T111500\r\n"
    "RRULE:FREQ=WEEKLY;UNTIL=20260331T215959Z\r\n"
    "SUMMARY:Cwiczenia\r\n"
    "END:VEVENT\r\n"
)


def test_zajecia_co_tydzien_rozwijaja_sie_do_konca_serii():
    out = entries(wrap(WEEKLY))
    days = [item["from"][:10] for item in out]
    assert days == ["2026-03-02", "2026-03-09", "2026-03-16", "2026-03-23", "2026-03-30"]


def test_odwolany_termin_wypada_z_serii():
    with_ex = WEEKLY.replace(
        "SUMMARY:Cwiczenia",
        "EXDATE;TZID=Europe/Warsaw:20260316T093000\r\nSUMMARY:Cwiczenia",
    )
    days = [item["from"][:10] for item in entries(wrap(with_ex))]
    assert "2026-03-16" not in days
    assert len(days) == 4


def test_dwa_dni_w_tygodniu_i_licznik_powtorzen():
    ics = wrap(
        "BEGIN:VEVENT\r\nUID:byday\r\n"
        "DTSTART;TZID=Europe/Warsaw:20260302T080000\r\n"
        "DTEND;TZID=Europe/Warsaw:20260302T093000\r\n"
        "RRULE:FREQ=WEEKLY;BYDAY=MO,WE;COUNT=4\r\n"
        "SUMMARY:Laboratorium\r\nEND:VEVENT\r\n"
    )
    days = [item["from"][:10] for item in entries(ics)]
    assert days == ["2026-03-02", "2026-03-04", "2026-03-09", "2026-03-11"]


def test_co_dwa_tygodnie():
    ics = wrap(
        "BEGIN:VEVENT\r\nUID:interval\r\n"
        "DTSTART;TZID=Europe/Warsaw:20260302T080000\r\n"
        "DTEND;TZID=Europe/Warsaw:20260302T093000\r\n"
        "RRULE:FREQ=WEEKLY;INTERVAL=2;COUNT=3\r\n"
        "SUMMARY:Seminarium\r\nEND:VEVENT\r\n"
    )
    days = [item["from"][:10] for item in entries(ics)]
    assert days == ["2026-03-02", "2026-03-16", "2026-03-30"]


def test_seria_bez_konca_nie_rozwija_sie_poza_okno():
    ics = wrap(
        "BEGIN:VEVENT\r\nUID:forever\r\n"
        "DTSTART;TZID=Europe/Warsaw:20260302T080000\r\n"
        "DTEND;TZID=Europe/Warsaw:20260302T090000\r\n"
        "RRULE:FREQ=DAILY\r\nSUMMARY:Codziennie\r\nEND:VEVENT\r\n"
    )
    out = entries(ics, window_end=date(2026, 3, 31))
    assert len(out) == 30
    assert out[-1]["from"][:10] == "2026-03-31"


def test_nieznana_regula_daje_pierwsze_wystapienie_zamiast_pustki():
    ics = wrap(
        "BEGIN:VEVENT\r\nUID:weird\r\n"
        "DTSTART;TZID=Europe/Warsaw:20260302T080000\r\n"
        "DTEND;TZID=Europe/Warsaw:20260302T090000\r\n"
        "RRULE:FREQ=HOURLY;INTERVAL=3\r\nSUMMARY:Dziwne\r\nEND:VEVENT\r\n"
    )
    out = entries(ics)
    assert len(out) == 1
    assert out[0]["from"][:10] == "2026-03-02"


# ── całodniowe i okno ────────────────────────────────────────────


def test_calodniowe_z_wylacznym_koncem():
    ics = wrap(
        "BEGIN:VEVENT\r\nUID:allday\r\n"
        "DTSTART;VALUE=DATE:20260309\r\nDTEND;VALUE=DATE:20260312\r\n"
        "SUMMARY:Sesja\r\nEND:VEVENT\r\n"
    )
    item = entries(ics)[0]
    # Trzy dni: 9, 10 i 11 marca. Dwunasty to już koniec wyłączny.
    assert item["from"].startswith("2026-03-08T23:00")  # 9 marca 00:00 czasu polskiego
    assert item["to"].startswith("2026-03-11T22:59")
    assert len(entries(ics)) == 1


def test_wydarzenia_spoza_okna_nie_wchodza():
    ics = wrap(
        "BEGIN:VEVENT\r\nUID:old\r\n"
        "DTSTART;TZID=Europe/Warsaw:20250302T080000\r\n"
        "DTEND;TZID=Europe/Warsaw:20250302T090000\r\n"
        "SUMMARY:Rok temu\r\nEND:VEVENT\r\n"
    )
    assert entries(ics) == []


# ── pliki połamane ───────────────────────────────────────────────


def test_odwolane_zajecia_nie_sa_niedyspozycja():
    ics = wrap(
        "BEGIN:VEVENT\r\nUID:cancelled\r\n"
        "DTSTART;TZID=Europe/Warsaw:20260302T080000\r\n"
        "DTEND;TZID=Europe/Warsaw:20260302T090000\r\n"
        "STATUS:CANCELLED\r\nSUMMARY:Odwolane\r\nEND:VEVENT\r\n"
    )
    assert entries(ics) == []


def test_polamany_wpis_nie_psuje_reszty():
    ics = wrap(
        "BEGIN:VEVENT\r\nUID:broken\r\nDTSTART;TZID=Europe/Warsaw:cos-nie-tak\r\n"
        "SUMMARY:Zepsute\r\nEND:VEVENT\r\n",
        USOS_LECTURE,
    )
    out = entries(ics)
    assert len(out) == 1
    assert out[0]["info"].startswith("Statystyka")


def test_pusty_i_nie_ten_plik_oddaja_pustke():
    assert entries("") == []
    assert entries("zwykly tekst, nie kalendarz") == []
    assert parse_events("") == []


def test_nieznana_strefa_czytana_jako_polska():
    ics = wrap(
        "BEGIN:VEVENT\r\nUID:tz\r\n"
        "DTSTART;TZID=Mars/Olympus:20260302T090000\r\n"
        "DTEND;TZID=Mars/Olympus:20260302T100000\r\n"
        "SUMMARY:Nieznana strefa\r\nEND:VEVENT\r\n"
    )
    assert entries(ics)[0]["from"].startswith("2026-03-02T08:00")


def test_ten_sam_termin_dwa_razy_liczy_sie_raz():
    out = entries(wrap(USOS_LECTURE, USOS_LECTURE))
    assert len(out) == 1


def test_occurrences_zwraca_czasy_ze_strefa():
    event = parse_events(wrap(USOS_LECTURE))[0]
    spans = occurrences(event, WINDOW_START, WINDOW_END)
    assert len(spans) == 1
    begin, finish = spans[0]
    assert begin.tzinfo is not None and finish.tzinfo is not None
    assert finish > begin
