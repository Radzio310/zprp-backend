"""Skrót nagrania SPK/1: kotwice czasu wideo dla zegara meczu.

PO CO. Skrót drugiej połowy trwa dwadzieścia kilka minut, a połowa
trzydzieści. Sędzia ćwiczący przy skrócie nie może prowadzić zegara ręcznie,
bo między akcjami czas gry ucieka o minuty. Telefon liczy więc czas WIDEO od
chwili naciśnięcia „START CZAS" (razem z play na laptopie) i tuż przed każdą
kotwicą przeskakuje zegar meczu na minutę, w której ta akcja naprawdę padła.
Regułę przeskoków trzyma aplikacja (`utils/videoClock.ts`); tu powstają same
pary „czas wideo -> czas meczu".

NAGRANIE Z PLANSZAMI. Skrót jest zbudowany jako `klip -> plansza -> klip ->
plansza…`: po każdej sytuacji wchodzi plansza z opisem tego, co się wydarzyło,
i stoi 15 sekund. Klipów jest 36 i tyle samo jest kotwic - jedna na sytuację.

DLACZEGO KOTWICA STOI NA POCZĄTKU PLANSZY. Wewnątrz klipu czas wideo i czas
meczu idą 1:1 (to zwykłe nagranie meczu z wtopionym zegarem), a plansza wchodzi
około dwóch sekund po akcji. Kotwica na starcie planszy znaczy więc, że zegar
dochodzi do minuty zdarzenia jeszcze PRZED nim - aplikacja przestawia go
`VIDEO_JUMP_LEAD_MS` przed kotwicą - i trzyma ją przez całą planszę, bo reguła
zegara nie pozwala mu wyprzedzić następnej kotwicy. Sędzia ma więc 15 sekund na
wpis przy właściwym czasie gry.

SKĄD DANE. Czasy meczu: arkusz plansz przepisany raz, na stałe, z dokładnością
do sekundy. Czasy wideo: zmierzone w nagraniu przez wykrycie plansz (są
nieruchome, więc kolejne klatki się nie różnią) i połowienie przedziału do
około 0,1 s.

⚠ CZASU BRAMEK JUŻ NIE ZGADUJEMY. Poprzedni arkusz podawał minutę bramki
całkowitą („31" znaczyło gdzieś między 30:00 a 31:00), więc stała tu maszyneria,
która brała środek minuty, a potem próbowała dociągnąć sekundy ze wzorca
protokołu, dopasowując bramki po drużynie i numerze. Nowy arkusz ma sekundy
wprost i cała ta droga zniknęła razem z nim.

CO WYCHODZI NA TELEFON. Wyłącznie pary czasów. Ani bramki, ani kary, ani kto je
dostał: skrót jest oceniany, a treść zdarzeń to klucz odpowiedzi, który nie ma
prawa leżeć w telefonie przed podejściem. Opisy niżej służą tylko czytelności
tego pliku i testom.

KARNE BEZ KOTWIC. Po ostatniej planszy zostaje jeszcze kilka minut nagrania -
seria rzutów karnych. Zegar meczu jej nie dotyczy, więc kotwic tam nie ma.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

#: Początek drugiej połowy w czasie gry.
HALF_START_MS = 30 * 60_000
HALF_END_MS = 60 * 60_000


def _ms(mm: int, ss: int = 0) -> int:
    """Czas meczu z minut i sekund."""
    return (mm * 60 + ss) * 1000


def _v(seconds: float) -> int:
    """Czas wideo ze zmierzonych sekund nagrania."""
    return int(round(seconds * 1000))


#: Jedna sytuacja skrótu: (czas wideo = start planszy, czas meczu, opis, wynik).
#:
#: Opis NIE jedzie na telefon - jest tu po to, żeby dało się ten plik czytać i
#: żeby test miał czego pilnować. Drużyna „A" to gospodarz protokołu (host),
#: „B" - gość (guest). Wynik jest wynikiem BIEGNĄCYM po tej sytuacji - trzyma
#: arkusz w ryzach, bo musi dojść do 26:26.
CLIPS: Tuple[Tuple[int, int, str, str], ...] = (
    (_v(50.94), _ms(30, 41), "Bramka A 3", "11:14"),
    (_v(77.94), _ms(31, 31), "Bramka B 28", "11:15"),
    (_v(103.44), _ms(33, 11), "Bramka B 28", "11:16"),
    (_v(126.44), _ms(33, 19), "Bramka A 34", "12:16"),
    (_v(150.19), _ms(33, 28), "Bramka B 36", "12:17"),
    (_v(203.81), _ms(34, 52), "Kara B 36 + rzut karny A 34", "12:17"),
    (_v(227.69), _ms(35, 50), "Bramka A 10", "13:17"),
    (_v(253.81), _ms(36, 56), "Bramka A 34", "14:17"),
    (_v(286.44), _ms(37, 28), "Kara A 17", "14:17"),
    (_v(324.81), _ms(38, 42), "Kara A 14", "14:17"),
    (_v(349.44), _ms(39, 28), "Bramka A 13", "15:17"),
    (_v(374.94), _ms(39, 57), "Bramka A 17", "16:17"),
    (_v(406.69), _ms(40, 14), "Bramka B 28", "16:18"),
    (_v(434.06), _ms(41, 12), "Bramka B 22", "16:19"),
    (_v(484.56), _ms(42, 18), "Rzut karny A 3", "17:19"),
    (_v(510.06), _ms(42, 50), "Bramka B 2", "17:20"),
    (_v(537.19), _ms(43, 1), "Bramka A 34", "18:20"),
    (_v(564.19), _ms(43, 33), "Bramka B 28", "18:21"),
    (_v(588.94), _ms(43, 41), "Bramka A 17", "19:21"),
    (_v(613.06), _ms(46, 31), "Bramka A 13", "20:21"),
    (_v(637.94), _ms(46, 38), "Czas dla drużyny B", "20:21"),
    (_v(665.31), _ms(47, 46), "Bramka B 42", "20:22"),
    (_v(726.69), _ms(49, 4), "Kara A 7 + rzut karny B 28", "20:23"),
    (_v(755.31), _ms(50, 13), "Bramka B 28", "20:24"),
    (_v(784.06), _ms(51, 15), "Czas dla drużyny A", "20:24"),
    # Arkusz plansz miał tu 51:15, czyli tę samą sekundę co czas dla drużyny A
    # wyżej. To była literówka: upomnienie ławki gospodarzy padło w 51:51 i tak
    # stoi w oficjalnym protokole.
    (_v(824.19), _ms(51, 51), "Upomnienie ławki A (osoba B)", "20:24"),
    (_v(866.56), _ms(52, 12), "Kara B 28 + upomnienie ławki B (osoba B)", "20:24"),
    (_v(923.94), _ms(52, 42), "Rzut karny A 10", "21:24"),
    (_v(978.81), _ms(53, 26), "Rzut karny B 66", "21:25"),
    (_v(1002.56), _ms(53, 59), "Bramka A 13", "22:25"),
    (_v(1025.81), _ms(55, 1), "Bramka A 20", "23:25"),
    (_v(1048.06), _ms(55, 53), "Bramka A 20", "24:25"),
    (_v(1070.69), _ms(56, 38), "Bramka B 36", "24:26"),
    (_v(1095.81), _ms(58, 51), "Czas dla drużyny A", "24:26"),
    (_v(1148.19), _ms(59, 6), "Bramka A 3", "25:26"),
    (_v(1171.56), _ms(59, 56), "Bramka A 13", "26:26"),
)


def clock_anchors() -> List[List[int]]:
    """Kotwice skrótu: pary czasów, rosnące w obu osiach.

    Kotwica, która cofałaby zegar względem poprzedniej, jest odrzucana: zegar
    meczu przy skrócie idzie tylko do przodu, a pojedyncza pomyłka w arkuszu
    nie ma prawa go zatrzymać ani cofnąć. Przy dwóch sytuacjach w tej samej
    sekundzie wideo zostaje późniejsza minuta meczu - do niej i tak zaraz
    przeskoczymy.
    """
    out: List[List[int]] = []
    last_match = HALF_START_MS
    last_video = -1
    for video_ms, match_ms, _label, _score in CLIPS:
        match_ms = min(match_ms, HALF_END_MS)
        if match_ms < last_match:
            continue
        if video_ms == last_video:
            out[-1][1] = match_ms
        else:
            out.append([video_ms, match_ms])
        last_match = match_ms
        last_video = video_ms
    return out


def video_clock() -> Dict[str, Any]:
    """To, co dostaje telefon: same pary czasów i początek połowy."""
    return {"halfStartMs": HALF_START_MS, "anchors": clock_anchors()}
