"""
Miesiac sedziego: odsiew, wyjazd zbiorczy, przelacznik przyszlych meczow
i podatek liczony od SUMY.
"""

import io
import json
from datetime import date, datetime, timezone
from pathlib import Path

from app import settlement_engine as E
from app import settlement_rates as R

ROOT = Path(__file__).resolve().parent.parent
SEED = json.loads(io.open(ROOT / "app" / "data" / "central_rates_seed.json", encoding="utf-8").read())
CENTRAL_VERSIONS = [
    {"id": 1, "valid_from": None, "valid_to": "2026-08-31", "enabled": True, "content": SEED["versions"][0]["content"]},
    {"id": 2, "valid_from": "2026-09-01", "valid_to": None, "enabled": True, "content": SEED["versions"][1]["content"]},
]

PROV_RAW = json.loads(
    io.open(ROOT.parent / "BAZA" / "assets" / "data" / "okregowe" / "slaskieCalcRates.json", encoding="utf-8").read()
)
# Slask od 01.09.2026: stala stawka za mecz + kilometrowka 0,70 zl/km (kopia serwera).
PROV_VERSIONS = [
    {"id": 10, "valid_from": "2026-09-01", "valid_to": None, "enabled": True, "content": PROV_RAW},
]

# Wersja sprzed 01.09.2026: bez kategorii „Dzieci" i bez kilometrowki - dokladnie
# to, po czym liczyly sie stare sezony slaskie.
OLD_PROV_RAW = json.loads(
    io.open(
        ROOT.parent
        / "BAZA"
        / "assets"
        / "data"
        / "okregowe"
        / "STAWKI - wersjonowanie"
        / "slaskie wersje"
        / "slaskie_do_31_08_2026.json",
        encoding="utf-8",
    ).read()
)
OLD_PROV_VERSIONS = [
    {"id": 9, "valid_from": None, "valid_to": "2026-08-31", "enabled": True, "content": OLD_PROV_RAW},
]

NOW = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)


def at(iso: str) -> datetime:
    return datetime.fromisoformat(iso).replace(tzinfo=timezone.utc)


def make(match_key, code, role, when, *, km=20.0, city="Zabrze", judge="5124", origin="district", runda=None):
    return E.Assignment(
        match_key=match_key, judge_id=judge, judge_name="KOWALSKI Jan",
        match_at=when, match_code=code, role=role, origin=origin,
        city=city, home_city="Bystra", distance_km=km, distance_source="table",
        round_text=runda,
    )


def settle(assignments, **kwargs):
    return E.settle_judges(
        assignments,
        province="ŚLĄSKIE",
        central_versions=CENTRAL_VERSIONS,
        province_versions=PROV_VERSIONS,
        now=NOW,
        names={"5124": "KOWALSKI Jan"},
        **kwargs,
    )


# ------------------------------------------------------------------ podstawy

def test_pojedynczy_mecz_okregowy():
    [entry] = settle([make("m1", "S/JMM/7", R.ROLE_FIELD, at("2026-10-04T10:00"))])
    [match] = entry.matches
    assert match.gross == 117          # Junior ml., stala stawka od 01.09.2026
    assert match.km_rate == 0.7        # stawka wojewodzka
    assert match.travel == round(20 * 0.7 * 2)   # 28 zl, w obie strony
    assert entry.gross == 117
    assert entry.costs == 0            # ponizej progu 200 zl
    assert entry.tax == 14
    assert entry.total == entry.net + entry.travel


def test_stolik_ligowy_spoza_okregu_placi_kilometrowka_centralna():
    [entry] = settle([make("m2", "IIM4/12", R.ROLE_TABLE, at("2026-10-04T18:00"), km=50, origin="outside")])
    [match] = entry.matches
    assert match.gross == 110          # tabela od 01.09.2026
    assert match.km_rate == 0.8        # II liga -> stawka centralna
    assert match.travel == 80


def test_podatek_liczy_sie_od_SUMY_miesiaca():
    """Trzy mecze po 117 zl: mecz po meczu koszty nie przyslugiwalyby wcale."""
    entries = settle([
        make("a", "S/JMM/7", R.ROLE_FIELD, at("2026-10-04T10:00"), city="Zabrze"),
        make("b", "S/JMM/7", R.ROLE_FIELD, at("2026-10-11T10:00"), city="Bytom"),
        make("c", "S/JMM/7", R.ROLE_FIELD, at("2026-10-14T10:00"), city="Gliwice"),
    ])
    entry = entries[0]
    assert entry.gross == 351
    assert entry.costs == 70           # 20% od sumy, bo 351 > 200
    assert entry.tax == 34
    assert entry.net == 317
    # Kilometrowka dochodzi PO podatku.
    assert entry.total == entry.net + entry.travel


# ------------------------------------------------------- przyszle mecze

def test_przyszly_mecz_domyslnie_nie_wchodzi():
    entries = settle([
        make("byl", "S/JMM/7", R.ROLE_FIELD, at("2026-10-04T10:00")),
        make("bedzie", "S/JMM/7", R.ROLE_FIELD, at("2026-11-08T10:00")),
    ])
    assert entries[0].match_count == 1
    assert entries[0].gross == 117


def test_przelacznik_dolacza_przyszle_i_je_oznacza():
    entries = settle(
        [
            make("byl", "S/JMM/7", R.ROLE_FIELD, at("2026-10-04T10:00")),
            make("bedzie", "S/JMM/7", R.ROLE_FIELD, at("2026-11-08T10:00")),
        ],
        include_future=True,
    )
    entry = entries[0]
    assert entry.match_count == 2
    assert entry.future_count == 1
    assert entry.gross == 234
    assert [m.future for m in entry.matches] == [False, True]


def test_mecz_bez_daty_nie_jest_przyszly():
    # Wpis niekompletny, nie zaplanowany - nie moze znikac przez brak terminu.
    [entry] = settle([make("brak", "S/JMM/7", R.ROLE_FIELD, None)])
    assert entry.match_count == 1
    assert entry.matches[0].future is False


# ------------------------------------------------------- wyjazd zbiorczy

def test_dzieci_w_jednej_hali_placa_dojazd_raz():
    entries = settle([
        make("d1", "S/DZM/1", R.ROLE_FIELD, at("2026-10-04T09:00"), city="Zabrze"),
        make("d2", "S/DZM/2", R.ROLE_FIELD, at("2026-10-04T10:30"), city="Zabrze"),
        make("d3", "S/DZM/3", R.ROLE_FIELD, at("2026-10-04T12:00"), city="Zabrze"),
    ])
    entry = entries[0]
    placily = [m for m in entry.matches if m.travel]
    assert len(placily) == 1
    assert sum(1 for m in entry.matches if m.travel_shared) == 2
    # Ryczałt za mecz zostaje pelny przy kazdym - znika sam dojazd. Od
    # 01.09.2026 turniej dzieci ma wlasna stawke: 40 zl za mecz.
    assert all(m.gross == 40 for m in entry.matches)
    assert entry.gross == 120


def test_juniorzy_w_jednej_hali_placa_dojazd_za_kazdy_mecz():
    entries = settle([
        make("j1", "S/JMM/1", R.ROLE_FIELD, at("2026-10-04T09:00"), city="Zabrze"),
        make("j2", "S/JMM/2", R.ROLE_FIELD, at("2026-10-04T10:30"), city="Zabrze"),
    ])
    entry = entries[0]
    assert all(m.travel > 0 for m in entry.matches)
    assert entry.travel == 2 * round(20 * 0.7 * 2)


def test_turniej_dzieci_to_caly_dzien_a_nie_trzy_godziny():
    """Mecze o 9:00 i 15:00 to jeden turniej, mimo szesciu godzin przerwy.

    Dotad sklejal je lancuch trzech godzin i taki dzien rozpadal sie na dwa
    wyjazdy - a sedzia przyjechal raz i przesiedzial w hali caly dzien.
    """
    entries = settle([
        make("d1", "S/DZM/1", R.ROLE_FIELD, at("2026-10-04T09:00"), city="Zabrze"),
        make("d2", "S/DZM/2", R.ROLE_FIELD, at("2026-10-04T15:00"), city="Zabrze"),
    ])
    entry = entries[0]
    assert sum(1 for m in entry.matches if m.travel) == 1
    assert {m.tournament_key for m in entry.matches} == {entry.matches[0].tournament_key}
    assert all(m.tournament_size == 2 for m in entry.matches)


def test_dzm_i_dzk_w_jednej_hali_to_JEDEN_turniej():
    """Sedzia jedzie raz i siedzi raz - plec rozgrywek tego nie dzieli."""
    entries = settle([
        make("m1", "S/DZM/1", R.ROLE_FIELD, at("2026-10-04T09:00"), city="Zabrze"),
        make("k1", "S/DZK/1", R.ROLE_FIELD, at("2026-10-04T11:00"), city="Zabrze"),
    ])
    entry = entries[0]
    assert len({m.tournament_key for m in entry.matches}) == 1
    assert sum(1 for m in entry.matches if m.travel) == 1


def test_turniej_po_starych_stawkach_placi_JEDNA_stawke():
    """Wersja sprzed 01.09.2026 nie zna kategorii „Dzieci".

    Dotad kazdy mecz liczyl sie tam jak pelny mecz okregowy i trzy mecze
    dzieci wychodzily 351 zl za jeden dzien w hali.
    """
    entries = E.settle_judges(
        [
            make("d1", "S/DZM/1", R.ROLE_FIELD, at("2026-06-13T11:00"), city="Chorzow"),
            make("d2", "S/DZM/2", R.ROLE_FIELD, at("2026-06-13T12:30"), city="Chorzow"),
            make("d3", "S/DZM/3", R.ROLE_FIELD, at("2026-06-13T14:00"), city="Chorzow"),
        ],
        province="ŚLĄSKIE",
        central_versions=CENTRAL_VERSIONS,
        province_versions=OLD_PROV_VERSIONS,
        now=NOW,
        names={"5124": "KOWALSKI Jan"},
    )
    entry = entries[0]
    # Kwota stawki mieszka na serwerze i bywa zmieniana - test pilnuje REGULY:
    # caly turniej placi tyle, co JEDEN mecz okregowy, a nie tyle razy ile
    # meczow. (Dla soboty 13.06.2026 to 152 zl zamiast 456 zl.)
    one_rate = entry.matches[0].gross
    assert one_rate > 0
    assert entry.gross == one_rate
    assert [m.gross for m in entry.matches] == [one_rate, 0, 0]
    assert [m.rate_shared for m in entry.matches] == [False, True, True]
    # Dojazd tez raz - i po tej wersji stawek wychodzi zero, bo stary Slask
    # nie placil kilometrowki wcale.
    assert sum(1 for m in entry.matches if m.travel_shared) == 2


def test_nowe_stawki_dalej_placa_za_KAZDY_mecz():
    """Gdy wersja zna „Dzieci", grupowanie dotyczy wylacznie dojazdu."""
    entries = settle([
        make("d1", "S/DZM/1", R.ROLE_FIELD, at("2026-10-04T09:00"), city="Zabrze"),
        make("d2", "S/DZM/2", R.ROLE_FIELD, at("2026-10-04T10:30"), city="Zabrze"),
    ])
    entry = entries[0]
    assert [m.gross for m in entry.matches] == [40, 40]
    assert not any(m.rate_shared for m in entry.matches)


def test_turniej_w_innym_dniu_to_inny_turniej():
    entries = E.settle_judges(
        [
            make("d1", "S/DZM/1", R.ROLE_FIELD, at("2026-06-13T11:00"), city="Chorzow"),
            make("d2", "S/DZM/2", R.ROLE_FIELD, at("2026-06-14T11:00"), city="Chorzow"),
        ],
        province="ŚLĄSKIE",
        central_versions=CENTRAL_VERSIONS,
        province_versions=OLD_PROV_VERSIONS,
        now=NOW,
        names={"5124": "KOWALSKI Jan"},
    )
    entry = entries[0]
    assert all(m.gross > 0 for m in entry.matches)
    assert not any(m.rate_shared for m in entry.matches)
    assert len({m.tournament_key for m in entry.matches}) == 2


def test_pojedynczy_mecz_dzieci_nie_jest_turniejem():
    entries = E.settle_judges(
        [make("d1", "S/DZM/1", R.ROLE_FIELD, at("2026-06-13T11:00"), city="Chorzow")],
        province="ŚLĄSKIE",
        central_versions=CENTRAL_VERSIONS,
        province_versions=OLD_PROV_VERSIONS,
        now=NOW,
        names={"5124": "KOWALSKI Jan"},
    )
    [match] = entries[0].matches
    assert match.gross > 0
    assert match.tournament_size == 1
    assert match.rate_shared is False


def test_dzieci_w_innej_hali_to_inny_wyjazd():
    entries = settle([
        make("d1", "S/DZM/1", R.ROLE_FIELD, at("2026-10-04T09:00"), city="Zabrze"),
        make("d2", "S/DZM/2", R.ROLE_FIELD, at("2026-10-04T10:30"), city="Bytom"),
    ])
    assert all(m.travel > 0 for m in entries[0].matches)


def test_sklejanie_idzie_PO_odsiewie_przyszlych():
    """Dojazd ma zaplacic najwczesniejszy mecz Z TYCH, ktore weszly."""
    entries = settle(
        [
            make("przyszly", "S/DZM/1", R.ROLE_FIELD, at("2026-11-08T09:00"), city="Ruda"),
            make("przyszly2", "S/DZM/2", R.ROLE_FIELD, at("2026-11-08T10:30"), city="Ruda"),
        ],
        include_future=False,
    )
    assert entries == []


# ------------------------------------------------------------------ zakres

def test_zakres_dat_odsiewa_mecze_spoza_miesiaca():
    entries = settle(
        [
            make("wrzesien", "S/JMM/7", R.ROLE_FIELD, at("2026-09-20T10:00")),
            make("pazdziernik", "S/JMM/7", R.ROLE_FIELD, at("2026-10-04T10:00")),
        ],
        date_from=date(2026, 10, 1),
        date_to=date(2026, 10, 31),
    )
    assert entries[0].match_count == 1
    assert entries[0].matches[0].match_key == "pazdziernik"


# ------------------------------------------------------------------ statusy

def test_brak_odleglosci_nie_wywala_rachunku():
    [entry] = settle([E.Assignment(
        match_key="x", judge_id="5124", match_at=at("2026-10-04T10:00"),
        match_code="S/JMM/7", role=R.ROLE_FIELD, city="Zabrze", distance_km=None,
    )])
    assert entry.matches[0].status == "missing-distance"
    assert entry.matches[0].gross == 0
    assert entry.missing_distance == 1


def test_mecz_bez_stawki_ma_wlasny_status():
    # Obsady ZPRP doliczamy jawnie - domyslnie nie wchodza do rozliczenia okregu.
    [entry] = settle([make("e", "EHF/1", R.ROLE_FIELD, at("2026-10-04T10:00"))], include_zprp=True)
    assert entry.matches[0].status == "missing-rate"


def test_puchar_bez_rundy_jest_oznaczony_jako_zgadywany():
    [entry] = settle(
        [make("p", "PPM/23", R.ROLE_FIELD, at("2026-10-04T10:00"), km=50)], include_zprp=True
    )
    match = entry.matches[0]
    assert match.stage == "1/16 i 1/8PP"
    assert match.stage_guessed is True


# ------------------------------------------------------------- przejazdy

def test_lista_przejazdow_pomija_sklejone_i_zerowe():
    entries = settle([
        make("d1", "S/DZM/1", R.ROLE_FIELD, at("2026-10-04T09:00"), city="Zabrze"),
        make("d2", "S/DZM/2", R.ROLE_FIELD, at("2026-10-04T10:30"), city="Zabrze"),
        make("l1", "IIM4/12", R.ROLE_TABLE, at("2026-10-10T18:00"), km=50, city="Katowice"),
    ])
    rows = E.travel_rows(entries)
    assert len(rows) == 2
    trasy = sorted(r.route for r in rows)
    assert trasy == ["Bystra-Katowice-Bystra", "Bystra-Zabrze-Bystra"]
    liga = next(r for r in rows if "Katowice" in r.route)
    assert liga.one_way_km == 50
    assert liga.total_km == 100
    assert liga.rate == 0.8
    assert liga.amount == 80


def test_sumy_okregu():
    entries = settle([
        make("a", "S/JMM/7", R.ROLE_FIELD, at("2026-10-04T10:00")),
        make("b", "IIM4/12", R.ROLE_TABLE, at("2026-10-10T18:00"), km=50, judge="5124"),
    ])
    totals = E.totals_of(entries)
    assert totals["judges"] == 1
    assert totals["matches"] == 2
    assert totals["gross"] == 117 + 110
    assert totals["total"] == entries[0].total
