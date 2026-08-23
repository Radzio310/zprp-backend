"""Różnica między wygenerowanym protokołem a plikiem wgranym do sprawdzenia.

Prawdziwy przypadek: sędzia dostał plik przepuszczony przez edytor PDF, w którym
liczbę widzów, pojemność hali i numer przepisu podmieniono o jeden znak. Edytor
NARYSOWAŁ nowe wartości na starych, więc stare napisy zostały w strumieniu
tekstu i różnica pokazywała tylko „dopisane 351", „dopisane 1051",
„dopisane 8:5b." - bez cienia informacji, czego dotyczą i gdzie leżą.
"""
from __future__ import annotations

from app.results import _diff_pdf_text, _guess_replaced_fragment, _page_of_line

#: Fragment prawdziwej strony 1 - z tabelą przebiegu, żeby liczb było dużo.
STRONA_1 = "\n".join(
    [
        "PROTOKÓŁ ZAWODÓW",
        "Numer meczu: TEST/2",
        "1 2 1 : 0",
        "31",
        "33",
        "11 : 12",
        "Liczba widzów:",
        "350",
        "Pojemność hali:",
        "1050",
        "MARECKI Jan",
        "0987/987P",
    ]
)

STRONA_3 = "\n".join(
    [
        "Strona 3/3",
        "20.08.2026, Siemianowice Śląskie",
        "podstawie przepisu 8:5a.",
        "WITKOWICZ Radosław",
    ]
)

ORYGINAL = STRONA_1 + "\n" + STRONA_3

#: Tak wygląda plik po nakładce: stare napisy zostają, nowe dochodzą na koniec.
PODROBIONY_STRONA_1 = STRONA_1 + "\n351\n1051"
PODROBIONY_STRONA_3 = STRONA_3 + "\n8:5b."
PODROBIONY = PODROBIONY_STRONA_1 + "\n" + PODROBIONY_STRONA_3

STAN = {
    "matchConfig": {
        "extras": {"spectatorsCount": 350, "venueCapacity": 1050},
        "matchNumber": "TEST/2",
    }
}


def _by_after(diff, value):
    return next(c for c in diff["changes"] if c.get("after") == value)


# ───────────────────────── zamiast czego ─────────────────────────


def test_dopisana_wartosc_dostaje_ta_ktora_przykryla():
    diff = _diff_pdf_text(ORYGINAL, PODROBIONY, STAN)

    widzowie = _by_after(diff, "351")
    assert widzowie["before"] == "350"
    assert widzowie["kind"] == "changed"
    assert widzowie["guessed"] is True

    pojemnosc = _by_after(diff, "1051")
    assert pojemnosc["before"] == "1050"

    przepis = _by_after(diff, "8:5b.")
    assert przepis["before"] == "8:5a."


def test_podmieniona_wartosc_dostaje_nazwe_pola_ze_stanu():
    diff = _diff_pdf_text(ORYGINAL, PODROBIONY, STAN)
    assert _by_after(diff, "351")["label"] == "Liczba widzów"
    assert _by_after(diff, "1051")["label"] == "Pojemność obiektu"
    # Numer przepisu leży w treści uwag, nie w osobnym polu - nazwy nie ma
    # i nie wymyślamy jej.
    assert _by_after(diff, "8:5b.")["label"] == ""


def test_nie_zgadujemy_gdy_kandydatow_jest_wielu():
    stary = "\n".join(["100", "200", "300"])
    # „400" jest tak samo blisko każdego z nich - jedna zmiana znaku.
    assert _guess_replaced_fragment("400", ["100", "200", "300"], set())[0] == ""
    diff = _diff_pdf_text(stary, stary + "\n400")
    assert diff["changes"][0]["kind"] == "added"
    assert not diff["changes"][0].get("before")


def test_nie_zgadujemy_przy_innej_dlugosci():
    # „1050" kontra „350" to inna liczba, nie podmiana jednego znaku.
    assert _guess_replaced_fragment("350", ["1050"], set())[0] == ""


def test_nie_wycinamy_kawalka_ze_srodka_liczby():
    """Fragment „050" siedzi w „1050", ale nie jest osobną wartością.

    Porównujemy całe słowa właśnie po to: wycinek ze środka dałby odpowiedź
    wyglądającą wiarygodnie i nieprawdziwą.
    """
    assert _guess_replaced_fragment("351", ["1050"], set())[0] == ""


def test_fragment_zdania_wskazuje_tez_swoj_wiersz():
    frag, line, whole = _guess_replaced_fragment(
        "8:5b.", ["podstawie przepisu 8:5a."], set()
    )
    assert frag == "8:5a."
    assert line == "podstawie przepisu 8:5a."
    assert whole is False


def test_zbyt_duza_roznica_to_nie_podmiana():
    assert _guess_replaced_fragment("999", ["350"], set())[0] == ""


def test_ta_sama_wartosc_nie_jest_uzywana_dwa_razy():
    # Dwa dopisania i jeden kandydat: pierwsze bierze, drugie zostaje bez pary.
    stary = "350"
    nowy = "350\n351\n359"
    diff = _diff_pdf_text(stary, nowy)
    guessed = [c for c in diff["changes"] if c.get("guessed")]
    assert len(guessed) == 1


# ───────────────────────── i w którym miejscu ─────────────────────────


def test_zmiana_dostaje_numer_strony_z_wgranego_pliku():
    diff = _diff_pdf_text(
        ORYGINAL,
        PODROBIONY,
        STAN,
        [PODROBIONY_STRONA_1, PODROBIONY_STRONA_3],
    )
    assert _by_after(diff, "351")["page"] == 1
    assert _by_after(diff, "1051")["page"] == 1
    assert _by_after(diff, "8:5b.")["page"] == 2
    assert diff["pages"] == 2


def test_bez_stron_nie_dokladamy_zmyslonego_numeru():
    diff = _diff_pdf_text(ORYGINAL, PODROBIONY, STAN)
    assert all("page" not in c for c in diff["changes"])
    assert diff["pages"] is None


def test_numer_strony_szuka_takze_po_starej_wartosci():
    strony = [["350", "inne"], ["cos"]]
    assert _page_of_line(strony, "350") == 1
    assert _page_of_line(strony, "brak") == 0


# ───────────────────────── nietknięty plik ─────────────────────────


def test_plik_nietkniety_nie_ma_zmian():
    diff = _diff_pdf_text(ORYGINAL, ORYGINAL, STAN, [STRONA_1, STRONA_3])
    assert diff["changes"] == []
