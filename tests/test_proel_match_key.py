"""Guard przed nadpisaniem cudzego protokołu i projekcja listy meczów.

Dlaczego to ma testy, skoro to trzy krótkie funkcje: bo od nich zależy, czy
zapis meczu wejdzie w wiersz SWOJEGO meczu, czy w wiersz meczu sprzed roku
o tym samym numerze. Numer meczu ("OSK/12") jest kluczem głównym tabeli
i jest unikalny w rozgrywkach, ale NIE między sezonami - a błąd w tę stronę
kasuje protokół, którego nikt już nie odtworzy z telefonu.

Druga funkcja pilnuje granicy, na której lista meczów przestaje wozić na
telefon nazwiska, licencje i przebieg wszystkich meczów w systemie.
"""
from __future__ import annotations

from app.proel_match_key import (
    live_head,
    match_head,
    match_id_conflict,
    zprp_id_of,
)


# ───────────────────────── zprp_id_of ─────────────────────────


def test_bierze_numeryczny_identyfikator_z_konfiguracji():
    assert zprp_id_of({"matchConfig": {"matchId": "208135"}}) == "208135"


def test_liczba_zamiast_tekstu_tez_przechodzi():
    assert zprp_id_of({"matchConfig": {"matchId": 208135}}) == "208135"


def test_syntetyczny_identyfikator_meczu_recznego_jest_pomijany():
    # Mecze zakładane ręcznie mają `Date.now()-…`; uznanie tego za identyfikator
    # ZPRP zablokowałoby prowadzenie zwykłego meczu bez rozgrywek.
    assert zprp_id_of({"matchConfig": {"matchId": "1755870000000-ab12"}}) == ""


def test_brak_konfiguracji_nie_wywraca_odczytu():
    assert zprp_id_of(None) == ""
    assert zprp_id_of({}) == ""
    assert zprp_id_of({"matchConfig": {}}) == ""
    assert zprp_id_of("nie-obiekt") == ""


# ───────────────────────── match_id_conflict ─────────────────────────


def test_inny_mecz_pod_tym_samym_numerem_to_konflikt():
    assert match_id_conflict("208135", "209001") is True


def test_ten_sam_mecz_przechodzi():
    assert match_id_conflict("208135", "208135") is False


def test_nieznany_identyfikator_po_ktorejkolwiek_stronie_nie_blokuje():
    # Mecz ręczny i zapis sprzed tej kolumny MUSZĄ przechodzić - inaczej guard
    # zabiłby prowadzenie meczu, który nigdy nie miał odpowiednika w ZPRP.
    assert match_id_conflict("", "209001") is False
    assert match_id_conflict("208135", "") is False
    assert match_id_conflict("", "") is False


# ───────────────────────── match_head ─────────────────────────


FULL_BLOB = {
    "date": "2026-08-14T18:30:00.000Z",
    "scoreHost": 29,
    "scoreGuest": 27,
    "protocol": [{"type": "goal", "player": 7}],
    "hostPlayerStats": [{"number": 7, "name": "KOWALSKI Jan"}],
    "matchConfig": {
        "matchNumber": "OSK/12",
        "matchId": "208135",
        "hostTeamName": "Gospodarze SA",
        "guestTeamName": "Goście SA",
        "isTest": False,
        "hostPlayers": ["7", "9", "11"],
        "hostPlayerCards": [{"number": 7, "license": "12345"}],
        "referee1": "NOWAK Adam",
    },
}


def test_naglowek_niesie_to_co_rysuje_wiersz_listy():
    head = match_head(FULL_BLOB)
    assert head["matchConfig"]["matchNumber"] == "OSK/12"
    assert head["matchConfig"]["hostTeamName"] == "Gospodarze SA"
    assert head["matchConfig"]["matchId"] == "208135"
    assert head["scoreHost"] == 29
    assert head["date"].startswith("2026-08-14")


def test_naglowek_nie_niesie_danych_osobowych_ani_przebiegu():
    head = match_head(FULL_BLOB)
    assert "hostPlayers" not in head["matchConfig"]
    assert "hostPlayerCards" not in head["matchConfig"]
    assert "referee1" not in head["matchConfig"]
    assert "protocol" not in head
    assert "hostPlayerStats" not in head


def test_naglowek_znosi_smieci_zamiast_bloba():
    assert match_head(None) == {"matchConfig": {}}
    assert match_head("nie-obiekt") == {"matchConfig": {}}
    assert match_head({}) == {"matchConfig": {}}


# ── Nagłówek meczu W TOKU ───────────────────────────────────────────────────


def test_naglowek_na_zywo_niesie_zegar_a_nie_sklady():
    # Kafelek „na żywo" odświeża się przy każdej zmianie rewizji, czyli co
    # minutę przez cały mecz. Gdyby ciągnął pełny blob, kosztowałby składy,
    # licencje i przebieg za każdym razem.
    blob = {
        "matchConfig": {
            "matchNumber": "SPM/1",
            "hostTeamName": "KS Test 1",
            "guestTeamName": "KS Test 2",
            "hostJerseyColor": "#3a86ff",
            "halfTime": 30,
            "hostPlayerCards": [{"fullName": "KOWALSKI Jan", "license": "A"}],
        },
        "scoreHost": 8,
        "scoreGuest": 8,
        "mainTime": 910000,
        "isFirstHalf": True,
        "isGameRunning": True,
        "savedAtMs": 1_700_000_000_000,
        "halfScore": {"host": 4, "guest": 5},
        "protocol": [{"type": "goal"}] * 40,
        "undoStack": [1, 2, 3],
    }
    head = live_head(blob)

    assert head["scoreHost"] == 8
    assert head["mainTime"] == 910000
    assert head["savedAtMs"] == 1_700_000_000_000
    assert head["halfScore"] == {"host": 4, "guest": 5}
    assert head["matchConfig"]["hostJerseyColor"] == "#3a86ff"

    # Nic, co opisuje LUDZI, nie ma prawa tędy wyjść.
    assert "hostPlayerCards" not in head["matchConfig"]
    assert "protocol" not in head
    assert "undoStack" not in head


def test_bez_znacznika_czasu_zegar_nie_ma_od_czego_liczyc():
    # `savedAtMs` jest tym, co odróżnia żywy zegar od zamrożonej liczby.
    # Zapis sprzed tego pola po prostu go nie ma - i to musi przejść bez błędu.
    head = live_head({"matchConfig": {"matchNumber": "SPM/1"}, "mainTime": 1000})
    assert "savedAtMs" not in head
    assert head["mainTime"] == 1000


def test_smieci_zamiast_bloba_nie_wywracaja_naglowka():
    for junk in (None, [], "tekst", 7):
        assert live_head(junk) == {"matchConfig": {}}


# ─────────────────────── TOŻSAMOŚĆ MECZU (odcisk lokalny) ───────────────────

from app.proel_match_key import (  # noqa: E402
    IDENTITY_ADOPT,
    IDENTITY_CONFLICT,
    IDENTITY_OK,
    IDENTITY_UPGRADE,
    identity_verdict,
    local_key_from_blob,
    local_key_from_guard,
    local_key_of,
    match_identity,
)


def test_odcisk_nie_rozroznia_zapisu_tej_samej_druzyny():
    # Dwie osoby przy jednym stoliku wpisują ten sam mecz ręcznie i różnią się
    # ogonkiem albo kropką. To MUSI zostać jednym meczem, inaczej guard
    # rozdzieliłby współpracę, która działa dziś.
    a = local_key_of("SL/123", "Łączpol Gdańsk", "MKS Kraków")
    b = local_key_of("sl/123", "LACZPOL GDANSK", "M.K.S. Krakow")
    assert a == b != ""


def test_odcisk_rozroznia_dwa_mecze_pod_jednym_numerem():
    oficjalny = local_key_of("SL/123", "Gdańsk", "Łódź")
    reczny = local_key_of("SL/123", "Poznań", "Kraków")
    assert oficjalny != reczny


def test_bez_obu_druzyn_odcisku_nie_ma():
    # Pusty odcisk znaczy „nie wiem, który to mecz" i nigdy nikogo nie blokuje.
    # Sam numer nie identyfikuje niczego - o to rozbiła się pierwsza wersja.
    assert local_key_of("SL/123", "Gdańsk", "") == ""
    assert local_key_of("SL/123", "", "Łódź") == ""
    assert local_key_of("", "Gdańsk", "Łódź") == ""


def test_odcisk_z_bloba_i_z_ensure_to_ta_sama_wartosc():
    # Gdyby te dwie drogi liczyły inaczej, mecz blokowałby sam siebie: raz
    # przedstawiłby się przy zakładaniu wiersza, a raz przy zapisie bloba.
    blob = {
        "matchConfig": {
            "matchNumber": "SL/123",
            "hostTeamName": "Gdańsk",
            "guestTeamName": "Łódź",
        }
    }
    guard = {"hostTeamName": "Gdańsk", "guestTeamName": "Łódź"}
    assert local_key_from_blob(blob) == local_key_from_guard("SL/123", guard) != ""


def test_smieci_zamiast_bloba_nie_wywracaja_odcisku():
    for junk in (None, [], "tekst", 7):
        assert local_key_from_blob(junk) == ""
        assert local_key_from_guard("SL/1", junk) == ""


def test_identyfikator_zprp_wygrywa_z_odciskiem():
    assert match_identity("8891", "SL123|A|B") == "zprp:8891"
    assert match_identity("", "SL123|A|B") == "local:SL123|A|B"
    assert match_identity("", "") == ""


def test_niewiedza_ktorejkolwiek_strony_nikogo_nie_blokuje():
    # Stara wersja aplikacji nie przedstawia się wcale. Ma dalej działać.
    assert identity_verdict("zprp:1", "") == IDENTITY_OK
    assert identity_verdict("", "zprp:1") == IDENTITY_ADOPT
    assert identity_verdict("zprp:1", "zprp:1") == IDENTITY_OK


def test_dwa_rozne_mecze_pod_jednym_numerem_to_konflikt():
    assert identity_verdict("zprp:1", "zprp:2") == IDENTITY_CONFLICT
    assert identity_verdict("local:A", "local:B") == IDENTITY_CONFLICT


def test_mecz_z_rozgrywek_odbiera_wiersz_recznemu():
    # Kolejność wejścia jest przypadkowa: ręczna kopia założona kwadrans przed
    # meczem nie może odebrać numeru meczowi, który ten numer naprawdę nosi.
    assert identity_verdict("local:SL123|A|B", "zprp:8891") == IDENTITY_UPGRADE
    # W drugą stronę NIGDY - ręczny nie wypycha meczu z rozgrywek.
    assert identity_verdict("zprp:8891", "local:SL123|A|B") == IDENTITY_CONFLICT
