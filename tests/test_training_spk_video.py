"""Kotwice czasu wideo dla skrótu SPK/1.

Zegar meczu przy skrócie idzie za czasem wideo i przeskakuje między akcjami.
Kotwice muszą być rosnące w obu osiach i nie mogą nieść treści zdarzeń.

Nagranie jest zbudowane jako `klip -> plansza -> klip -> plansza…`, a kotwica
stoi na starcie planszy. Opisy w `CLIPS` są tylko dla czytelności - telefon
dostaje same pary liczb.
"""
from __future__ import annotations

from app.training_spk_video import (
    CLIPS,
    HALF_END_MS,
    HALF_START_MS,
    clock_anchors,
    video_clock,
)


def _ms(mm, ss=0):
    return (mm * 60 + ss) * 1000


class TestArkusz:
    def test_jedna_pozycja_na_plansze(self):
        # W nagraniu wykryto dokładnie 36 plansz i tyle samo ma być sytuacji.
        assert len(CLIPS) == 36

    def test_wynik_biegnacy_nigdy_sie_nie_cofa_i_konczy_na_26_26(self):
        """Wynik z arkusza pilnuje, że nie zgubiliśmy ani nie dodaliśmy bramki.

        Pierwsza połowa skończyła się 10:14, mecz 26:26. Gdyby przy
        przepisywaniu wypadła jedna sytuacja albo wynik przeskoczył o dwie
        bramki naraz, ten opis to złapie.
        """
        poprzedni = (10, 14)
        for _v, _m, label, score in CLIPS:
            a, b = (int(x) for x in score.split(":"))
            assert a >= poprzedni[0] and b >= poprzedni[1], label
            assert (a - poprzedni[0]) + (b - poprzedni[1]) <= 1, label
            poprzedni = (a, b)
        assert poprzedni == (26, 26)

    def test_caly_skrot_lezy_w_drugiej_polowie(self):
        for _v, match_ms, label, _score in CLIPS:
            assert HALF_START_MS <= match_ms <= HALF_END_MS, label

    def test_upomnienie_lawki_gospodarzy_stoi_na_51_51(self):
        """Arkusz plansz miał tu 51:15 - to była literówka.

        51:15 to czas dla drużyny A z poprzedniej planszy; upomnienie ławki
        padło w 51:51 i tak stoi w oficjalnym protokole. Gdyby wróciła stara
        wartość, dwie sąsiednie kotwice miałyby ten sam czas meczu.
        """
        # Indeks, nie słownik po opisie: „Czas dla drużyny A" pada dwa razy
        # i słownik zostawiłby tylko ostatni, przez co ten opis nie
        # sprawdzałby niczego.
        assert CLIPS[25][1] == _ms(51, 51)
        assert CLIPS[25][2].startswith("Upomnienie ławki A")
        assert CLIPS[24][1] == _ms(51, 15)

    def test_zadne_dwie_sytuacje_nie_stoja_w_tej_samej_sekundzie(self):
        """Równy czas meczu obok siebie znaczy, że jedna z nich jest zła.

        Właśnie tak wyglądał arkusz przed poprawką: czas dla drużyny A i
        upomnienie ławki miały wpisane 51:15.
        """
        czasy = [m for _v, m, _l, _s in CLIPS]
        assert len(set(czasy)) == len(czasy)


class TestKotwice:
    def test_rosna_w_obu_osiach(self):
        anchors = clock_anchors()
        assert anchors, "brak kotwic"
        videos = [a[0] for a in anchors]
        matches = [a[1] for a in anchors]
        assert videos == sorted(videos) and len(set(videos)) == len(videos)
        assert matches == sorted(matches)
        assert matches[0] >= HALF_START_MS

    def test_zadna_sytuacja_nie_wypada(self):
        # Odrzucenie kotwicy znaczy, że arkusz cofa zegar - to byłby błąd
        # danych, a nie normalny stan.
        assert len(clock_anchors()) == len(CLIPS)

    def test_czasy_sa_co_do_sekundy(self):
        anchors = dict((a[0], a[1]) for a in clock_anchors())
        assert anchors[50_940] == _ms(30, 41)
        assert anchors[203_810] == _ms(34, 52)
        assert anchors[824_190] == _ms(51, 51)
        assert anchors[1_171_560] == _ms(59, 56)

    def test_kotwica_stoi_na_starcie_planszy(self):
        """Pierwsza plansza zaczyna się 50,94 s po starcie nagrania.

        Zmierzone w nagraniu; klip 2 potwierdza regułę - przy wideo 72 s
        wtopiony zegar pokazuje 31:27, a bramka pada w 31:31, czyli plansza
        wchodzi około dwóch sekund po akcji.
        """
        assert clock_anchors()[0][0] == 50_940

    def test_telefon_dostaje_same_pary(self):
        clock = video_clock()
        assert clock["halfStartMs"] == HALF_START_MS
        assert all(len(a) == 2 for a in clock["anchors"])
        # Ani treści zdarzeń, ani opisów - to byłby klucz odpowiedzi.
        assert set(clock) == {"halfStartMs", "anchors"}
        assert all(isinstance(x, int) for a in clock["anchors"] for x in a)
