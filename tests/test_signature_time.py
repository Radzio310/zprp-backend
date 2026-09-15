"""Czas złożenia podpisu - co wolno uznać za prawdziwe.

Stempel podaje telefon, więc jest wart tyle, co jego zegar. Te testy pilnują
jednej rzeczy: że wartość niewiarygodna ZNIKA, zamiast trafić do bazy jako
fakt. Nic tu nie dotyka bazy - reguła jest czystą arytmetyką na datach.
"""

from datetime import datetime, timedelta, timezone

from app.signature_time import FUTURE_TOLERANCE, MAX_AGE, parse_signed_at

TERAZ = datetime(2026, 9, 15, 18, 30, 0, tzinfo=timezone.utc)


def test_zwykly_stempel_ze_strefa_przechodzi():
    podpis = TERAZ - timedelta(minutes=40)
    assert parse_signed_at(podpis.isoformat(), now=TERAZ) == podpis


def test_zapis_z_Z_na_koncu_jest_ta_sama_chwila():
    """Aplikacja wysyła `toISOString()`, czyli zawsze z „Z"."""
    assert parse_signed_at("2026-09-15T17:50:00.000Z", now=TERAZ) == datetime(
        2026, 9, 15, 17, 50, tzinfo=timezone.utc
    )


def test_inna_strefa_jest_przeliczana_a_nie_obcinana():
    assert parse_signed_at("2026-09-15T20:00:00+02:00", now=TERAZ) == datetime(
        2026, 9, 15, 18, 0, tzinfo=timezone.utc
    )


def test_milisekundy_tez_sa_czasem():
    """`Date.now()` w aplikacji to liczba, nie napis."""
    podpis = TERAZ - timedelta(hours=2)
    ms = podpis.timestamp() * 1000
    assert parse_signed_at(ms, now=TERAZ) == podpis


def test_brak_pola_nie_jest_bledem():
    """Starsze wydania aplikacji nie wysyłają stempla i mają działać dalej."""
    assert parse_signed_at(None, now=TERAZ) is None
    assert parse_signed_at("", now=TERAZ) is None
    assert parse_signed_at("   ", now=TERAZ) is None


def test_smiec_nie_staje_sie_data():
    assert parse_signed_at("wczoraj", now=TERAZ) is None
    assert parse_signed_at("2026-13-45T99:99:99Z", now=TERAZ) is None
    assert parse_signed_at(True, now=TERAZ) is None
    assert parse_signed_at({"kiedy": "teraz"}, now=TERAZ) is None


def test_drobny_dryf_zegara_w_przod_przechodzi():
    """Kilka minut w przód to normalny rozjazd, nie podpis złożony jutro."""
    assert parse_signed_at(
        (TERAZ + FUTURE_TOLERANCE - timedelta(seconds=30)).isoformat(), now=TERAZ
    ) is not None


def test_daleka_przyszlosc_odpada():
    """Zły zegar nie ma prawa wpisać do protokołu przyszłości."""
    assert parse_signed_at((TERAZ + timedelta(hours=3)).isoformat(), now=TERAZ) is None


def test_glab_przeszlosci_odpada():
    assert (
        parse_signed_at((TERAZ - MAX_AGE - timedelta(days=1)).isoformat(), now=TERAZ)
        is None
    )


def test_naiwna_data_jest_czytana_jako_utc():
    """Bez strefy nie zgadujemy strefy serwera - to przesunęłoby podpis."""
    assert parse_signed_at("2026-09-15T18:00:00", now=TERAZ) == datetime(
        2026, 9, 15, 18, 0, tzinfo=timezone.utc
    )


def test_odrzucenie_stempla_nie_jest_odmowa_podpisu():
    """Dokumentuje kontrakt: `None` to brak stempla, a nie błąd wysyłki.

    Ten test istnieje po to, żeby nikt nie zamienił `None` na wyjątek.
    Obrazek podpisu jest wart więcej niż stempel, a moment dotarcia i tak
    zapisuje `created_at`.
    """
    for smiec in ("wczoraj", (TERAZ + timedelta(days=2)).isoformat(), None):
        assert parse_signed_at(smiec, now=TERAZ) is None
