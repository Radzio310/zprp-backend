"""Okoliczności wysyłki w dzienniku meczu: czym i czyim kontem.

Do 10.09.2026 wiersz o udanej wysyłce brzmiał zawsze tak samo: „Pełne dane
meczu trafiły do bazy ZPRP". Nie dało się z niego odczytać ani tego, czy poszły
oficjalnym API czy formularzem drogi awaryjnej, ani tego, czyim numerem
podpisano zapis po stronie związku - a przy sesji podniesionej to bywa numer
CUDZY, bo administrator spoza obsady inaczej by tam nie wszedł.
"""

from app.proel_journal import (
    event_summary,
    send_attempt_sentence,
    send_context_sentence,
)


def test_bez_okolicznosci_wiersz_wyglada_jak_dotad():
    """Dziennik jest księgą - wpisów sprzed zmiany się nie przepisuje."""
    assert send_context_sentence(None) == ""
    assert send_context_sentence({}) == ""
    assert (
        event_summary("zprp.full_data_sent", {"paths": ["post.fullDataSent"]})
        == "Pełne dane meczu trafiły do bazy ZPRP"
    )


def test_droga_oficjalna_i_awaryjna_brzmia_inaczej():
    # To jest cała różnica, której administrator szuka przy reklamacji:
    # formularz wypełnia komplet rubryk cudzymi rękami, API pisze pojedyncze pola.
    official = event_summary(
        "zprp.full_data_sent", {"paths": ["post.fullDataSent"], "via": "official"}
    )
    legacy = event_summary(
        "zprp.full_data_sent", {"paths": ["post.fullDataSent"], "via": "legacy"}
    )
    assert "oficjalnym API" in official
    assert "formularz" in legacy
    assert official != legacy


def test_administrator_pracuje_cudzym_numerem():
    """Najważniejszy wiersz w całej tej sprawie.

    Czynność wykonał administrator - i jego nazwisko stoi w nagłówku wiersza.
    Ale sesję zapisu otworzył numerem sędziego prowadzącego, bo oficjalne API
    ZPRP przyjmuje wyłącznie numery z obsady meczu. Po tamtej stronie zapis
    jest podpisany TAMTYM numerem i wpis musi to powiedzieć wprost.
    """
    out = event_summary(
        "zprp.summary_sent",
        {
            "paths": ["post.shortResultSent"],
            "via": "official",
            "zprp_judge": "12345",
            "on_behalf": "KOWALSKI Jan",
            "admin": True,
        },
    )
    assert "wynik skrócony" in out.lower()
    assert "12345" in out
    assert "KOWALSKI Jan" in out
    assert "administrator" in out.lower()


def test_konto_formularza_stoi_przy_drodze_awaryjnej():
    out = send_context_sentence({"via": "legacy", "zprp_account": "jkowalski"})
    assert "kontem jkowalski" in out


def test_liczba_podejsc_tylko_gdy_bylo_ich_wiecej():
    # „Zapisane" i „zapisane za szóstym razem" to dwie różne informacje o łączu
    # z bazą związku; jedno podejście nie jest żadną informacją.
    assert "podejściach" not in send_context_sentence({"via": "official", "attempts": 1})
    assert "po 6 podejściach" in send_context_sentence(
        {"via": "official", "attempts": 6}
    )


def test_nieudana_proba_tez_mowi_czyim_kontem():
    """Przy PORAŻCE to bywa cała odpowiedź na pytanie, czemu nie przeszło.

    Numer spoza obsady odbija się od oficjalnego API zawsze, ile razy by nie
    powtarzać - i wtedy jedyną naprawą jest wysyłka innym numerem, a nie
    kolejne podejście.
    """
    out = send_attempt_sentence(
        "zprp.send_failed",
        {
            "what": "full",
            "attempt": 2,
            "of": 3,
            "via": "official",
            "zprp_judge": "777",
            "upstream": "Nie znaleziono takiego zawodnika w kadrze tego meczu.",
        },
    )
    assert "próba 2 z 3" in out
    assert "numerem sędziego 777" in out
    # Cytat ze związku zostaje OSTATNI - to on rozstrzyga, co dalej robić.
    assert out.rstrip().endswith('meczu.".')


def test_wlasny_numer_nie_jest_powtarzany_w_kazdym_wierszu():
    # Aplikacja podaje `zprp_judge` wyłącznie wtedy, gdy jest inny niż numer
    # osoby wykonującej - serwer nie ma czego dopowiadać.
    assert send_context_sentence({"via": "official"}) == "oficjalnym API"
