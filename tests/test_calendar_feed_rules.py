"""Reguły kalendarzy sędziego: co przyjmujemy jako adres i co pokazujemy.

Sedno: link do planu zajęć NIESIE KLUCZ, więc nie może wracać do aplikacji w
całości, a serwer nie może dać sobą odpytać sieci wewnętrznej.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.calendar_feed_rules import (
    DEFAULT_INTERVAL_SECONDS,
    FeedUrlError,
    feed_due,
    mask_feed_url,
    normalize_feed_url,
    sync_window,
)

USOS = (
    "https://usosapps.ue.katowice.pl/services/tt/upcoming_ical"
    "?lang=pl&user_id=5025&key=HETqHcrJsQMgKwFAHUKC"
)


# ── adres ────────────────────────────────────────────────────────


def test_prawdziwy_link_z_usos_przechodzi():
    assert normalize_feed_url(USOS) == USOS
    assert normalize_feed_url(f"  {USOS}  ") == USOS


def test_webcal_zamienia_sie_na_https():
    assert normalize_feed_url("webcal://example.com/plan.ics") == (
        "https://example.com/plan.ics"
    )


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "   ",
        "plan.ics",
        "ftp://example.com/plan.ics",
        "file:///etc/passwd",
        "https://",
    ],
)
def test_adres_bez_sensu_odrzucamy_z_powodem(bad):
    with pytest.raises(FeedUrlError) as err:
        normalize_feed_url(bad)
    assert str(err.value)
    assert "—" not in str(err.value) and "–" not in str(err.value)


@pytest.mark.parametrize(
    "local",
    [
        "http://localhost/plan.ics",
        "http://127.0.0.1/plan.ics",
        "https://10.0.0.5/plan.ics",
        "https://192.168.1.10/plan.ics",
        "https://169.254.169.254/latest/meta-data/",
        "https://[::1]/plan.ics",
        "https://serwer.local/plan.ics",
    ],
)
def test_adresy_z_sieci_wewnetrznej_nie_przechodza(local):
    # Inaczej cudzym linkiem dałoby się kazać backendowi odpytać samego siebie.
    with pytest.raises(FeedUrlError):
        normalize_feed_url(local)


def test_bardzo_dlugi_adres_odrzucony():
    with pytest.raises(FeedUrlError):
        normalize_feed_url("https://example.com/" + "a" * 3000)


# ── maskowanie ───────────────────────────────────────────────────


def test_maska_nie_wydaje_klucza():
    masked = mask_feed_url(USOS)
    assert "HETqHcrJsQMgKwFAHUKC" not in masked
    assert "key=" not in masked
    assert "usosapps.ue.katowice.pl" in masked
    assert "upcoming_ical" in masked
    # Końcówka zostaje, żeby właściciel rozpoznał swój link.
    assert masked.endswith("HUKC")


def test_maska_adresu_bez_zapytania():
    assert mask_feed_url("https://example.com/plan.ics") == "example.com/plan.ics"
    assert mask_feed_url("") == ""


# ── terminy ──────────────────────────────────────────────────────


def test_nowy_kalendarz_jest_od_razu_do_pobrania():
    assert feed_due(None) is True


def test_swiezy_kalendarz_czeka_na_swoja_kolej():
    now = datetime(2026, 9, 13, 12, 0, tzinfo=timezone.utc)
    assert feed_due(now - timedelta(hours=1), now=now) is False
    assert feed_due(now - timedelta(hours=7), now=now) is True


def test_czas_bez_strefy_czytamy_jako_UTC():
    now = datetime(2026, 9, 13, 12, 0, tzinfo=timezone.utc)
    naive = datetime(2026, 9, 13, 1, 0)
    assert feed_due(naive, now=now) is True


def test_domyslny_odstep_to_szesc_godzin():
    assert DEFAULT_INTERVAL_SECONDS == 6 * 3600


def test_okno_obejmuje_semestr_i_kilka_dni_wstecz():
    from datetime import date

    start, end = sync_window(date(2026, 9, 13))
    assert start < date(2026, 9, 13) < end
    assert (end - start).days > 180
