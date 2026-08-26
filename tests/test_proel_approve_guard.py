"""Kto może zatwierdzić mecz i cofnąć zatwierdzenie.

CO SIĘ ZEPSUŁO. Reguła „delegat, a gdy go nie ma - sędziowie prowadzący"
istniała wyłącznie w aplikacji, w ekranie finalizacji, i sterowała samą
widocznością przycisku. Opierała się przy tym na nazwisku wpisanym przez
użytkownika w ustawieniach. `PUT /proel/{numer}` przyjmował zmianę statusu od
każdego, kto znał numer meczu - bez tożsamości, bez roli. Zatwierdzony protokół
potrafiła więc odtwierdzić osoba spoza meczu, a po odmowie nie zostawał żaden
ślad, bo odmowy nie było.

Testy są czyste: reguła to funkcja obsady i aktora. Samo wpięcie jej w trasę
sprawdzamy odczytem źródła - `app.proel` importuje `app.db`, który żąda żywego
Postgresa (ten sam powód co w `test_proel_actor_attrs`).
"""
from __future__ import annotations

import ast
import pathlib
from typing import Any

from app.proel_auth import (
    Actor,
    approve_roles,
    can_approve,
    clean_judge_number,
    clean_person_name,
    merged_officials,
    officials_from_blob,
    officials_from_config,
    officials_with_overlay,
)

PROEL_PY = pathlib.Path(__file__).resolve().parents[1] / "app" / "proel.py"

CREW_WITH_DELEGATE = {
    "referee1": {"name": "KOWALSKI Jan", "judgeId": "111"},
    "referee2": {"name": "NOWAK Piotr", "judgeId": "222"},
    "secretary": {"name": "WIŚNIEWSKA Anna", "judgeId": "333"},
    "delegate": {"name": "LEWANDOWSKI Marek", "judgeId": "444"},
}
CREW_NO_DELEGATE = {
    key: value for key, value in CREW_WITH_DELEGATE.items() if key != "delegate"
}
CREW_WITH_TWO_DELEGATES = dict(
    CREW_WITH_DELEGATE,
    delegate2={"name": "ZIELIŃSKA Ewa", "judgeId": "555"},
)


def judge(number: str, name: str = "") -> Actor:
    return Actor(judge_id=number, installation_id="telefon", name=name)


def proel_account(name: str, uid: int = 7) -> Actor:
    return Actor(judge_id=f"proel:{uid}", installation_id="telefon", name=name)


# ─────────────────────────── sama reguła ───────────────────────────

def test_z_delegatem_decyduje_delegat():
    assert approve_roles(CREW_WITH_DELEGATE) == {"delegate"}


def test_bez_delegata_decyduja_sedziowie():
    assert approve_roles(CREW_NO_DELEGATE) == {"referee1", "referee2"}


def test_pusty_wpis_delegata_to_brak_delegata():
    crew = dict(CREW_NO_DELEGATE, delegate={"name": "", "judgeId": ""})
    assert approve_roles(crew) == {"referee1", "referee2"}


# ─────────────────────────── kto wchodzi ───────────────────────────

def test_delegat_zatwierdza():
    assert can_approve(judge("444"), CREW_WITH_DELEGATE)


def test_obaj_delegaci_moga_zatwierdzic_ten_sam_mecz():
    assert approve_roles(CREW_WITH_TWO_DELEGATES) == {"delegate"}
    assert can_approve(judge("444"), CREW_WITH_TWO_DELEGATES)
    assert can_approve(judge("555"), CREW_WITH_TWO_DELEGATES)


def test_sedzia_prowadzacy_NIE_zatwierdza_gdy_jest_delegat():
    """Ta sama asymetria co w aplikacji - decyzja należy do delegata."""
    assert not can_approve(judge("111"), CREW_WITH_DELEGATE)


def test_obaj_sedziowie_zatwierdzaja_gdy_delegata_nie_ma():
    assert can_approve(judge("111"), CREW_NO_DELEGATE)
    assert can_approve(judge("222"), CREW_NO_DELEGATE)


def test_sekretarz_nie_zatwierdza():
    """Protokół zamyka ten, kto go podpisuje."""
    assert not can_approve(judge("333"), CREW_NO_DELEGATE)


def test_osoba_spoza_meczu_nie_zatwierdza():
    assert not can_approve(judge("99999", "OBCY Jan"), CREW_WITH_DELEGATE)
    assert not can_approve(judge("99999", "OBCY Jan"), CREW_NO_DELEGATE)


def test_obsada_nieznana_przepuszcza_kazdego():
    """Mecz stolikowy założony ręcznie nie ma obsady z ZPRP i mieć nie będzie.

    Gdyby pusta obsada odmawiała wszystkim, jedyny człowiek prowadzący taki
    protokół nie mógłby go zamknąć.
    """
    assert can_approve(judge("99999", "KTOKOLWIEK Jan"), {})


def test_None_to_nie_to_samo_co_pusta_obsada():
    """`None` znaczy „nie ma nawet gdzie szukać" - `roles_for` odróżnia to od
    pustej obsady i my tego rozróżnienia nie zacieramy. Trasa i tak nigdy nie
    poda `None`, bo `merged_officials` zawsze oddaje słownik."""
    assert not can_approve(judge("99999", "KTOKOLWIEK Jan"), None)
    assert merged_officials(None, None) == {}


# ────────────────── pusty slot to NIE jest obsadzona rola ──────────────────

#: Tak wygląda mecz BEZ delegata w danych z ZPRP: nazwisko to placeholder,
#: a numer roli to zero. Aplikacja czyści nazwisko przy pobieraniu, numeru nie
#: czyścił nikt - i to wystarczyło, żeby serwer zobaczył delegata.
CREW_PLACEHOLDER_DELEGATE = dict(
    CREW_NO_DELEGATE, delegate={"name": "--- ---", "judgeId": "0"}
)


def test_placeholder_w_nazwisku_to_pusty_slot():
    for junk in ("--- ---", "---", "-", "—", "- -", ".", "  ", "", None, "·"):
        assert clean_person_name(junk) == "", junk
    assert clean_person_name("  KOWALSKI Jan ") == "KOWALSKI Jan"


def test_zero_w_numerze_to_pusty_slot():
    for junk in ("0", "00", "--- ---", "-", "", None):
        assert clean_judge_number(junk) == "", junk
    assert clean_judge_number("444") == "444"
    assert clean_judge_number("0444") == "0444"


def test_placeholder_delegata_oddaje_decyzje_sedziom():
    """DOKŁADNIE ten przypadek zapalał przycisk i odmawiał po dotknięciu.

    Serwer widział „delegat jest" (numer „0"), więc żądał zgody delegata,
    a aplikacja - patrząc na wyczyszczone nazwisko - pokazywała przycisk
    sędziemu prowadzącemu.
    """
    assert approve_roles(CREW_PLACEHOLDER_DELEGATE) == {"referee1", "referee2"}
    assert can_approve(judge("111"), CREW_PLACEHOLDER_DELEGATE)


def test_placeholder_nie_daje_roli_nikomu():
    """Aktor o numerze „0" nie jest delegatem tylko dlatego, że slot ma zero."""
    assert not can_approve(judge("0", "--- ---"), CREW_PLACEHOLDER_DELEGATE)


def test_placeholder_z_protokolu_tez_znika():
    blob = {"matchConfig": {"referee1": "KOWALSKI Jan", "delegate": "--- ---"}}
    out = officials_from_blob(blob)
    assert out["referee1"]["name"] == "KOWALSKI Jan"
    assert "delegate" not in out


# ────────────────── konto ProEl w swoim własnym meczu ──────────────────

def test_konto_proel_zatwierdza_swoj_mecz_po_nazwisku():
    """Konto ProEl nie ma numeru sędziego - jedynym sygnałem jest nazwisko.

    Bez tego sędzia prowadzący protokół kontem ProEl nie miałby w SWOIM meczu
    żadnej roli i nie zamknąłby własnego protokołu.
    """
    assert can_approve(proel_account("KOWALSKI Jan"), CREW_NO_DELEGATE)


def test_konto_proel_z_cudzym_nazwiskiem_odpada():
    assert not can_approve(proel_account("OBCY Jan"), CREW_NO_DELEGATE)


def test_numer_dalej_rozstrzyga_miedzy_sedziami():
    """Dwóch Kowalskich na mecz: gdy OBIE strony mają numer, liczy się numer."""
    assert not can_approve(judge("99999", "KOWALSKI Jan"), CREW_NO_DELEGATE)


# ─────────────────────── obsada z zapisanego protokołu ───────────────────────

def test_obsada_z_extras_officials():
    blob = {
        "matchConfig": {
            "extras": {
                "officials": {
                    "referee1": {"fullName": "KOWALSKI Jan", "judgeId": "111"},
                    "delegate": {"fullName": "LEWANDOWSKI Marek"},
                }
            }
        }
    }
    out = officials_from_blob(blob)
    assert out["referee1"] == {"name": "KOWALSKI Jan", "judgeId": "111"}
    assert out["delegate"]["name"] == "LEWANDOWSKI Marek"
    assert "secretary" not in out


def test_obsada_ze_starszego_zapisu_z_samymi_nazwiskami():
    blob = {"matchConfig": {"referee1": "KOWALSKI Jan", "referee2": "NOWAK Piotr"}}
    out = officials_from_blob(blob)
    assert out["referee1"]["name"] == "KOWALSKI Jan"
    assert out["referee2"]["name"] == "NOWAK Piotr"


def test_obsada_z_tekstu_json():
    """Starsze wiersze bywają zapisane jako tekst - klient też to toleruje."""
    out = officials_from_blob('{"matchConfig": {"referee1": "KOWALSKI Jan"}}')
    assert out["referee1"]["name"] == "KOWALSKI Jan"


def test_smiec_zamiast_protokolu_nie_wywraca():
    for junk in (None, "", "nie json", 7, [], {"matchConfig": None}):
        assert officials_from_blob(junk) == {}


def test_stan_wygrywa_z_protokolem_ale_tylko_wypelniony():
    blob = {
        "matchConfig": {
            "extras": {
                "officials": {
                    "referee1": {"fullName": "STARY Zapis"},
                    "delegate": {"fullName": "LEWANDOWSKI Marek"},
                }
            }
        }
    }
    state = {
        "referee1": {"name": "KOWALSKI Jan", "judgeId": "111"},
        "delegate": {"name": "", "judgeId": ""},
    }
    out = merged_officials(state, officials_from_blob(blob))
    # Wiersz stanu ma numer prosto z ZPRP - jest lepszym źródłem.
    assert out["referee1"] == {"name": "KOWALSKI Jan", "judgeId": "111"}
    # Ale pusty wpis w stanie nie wymazuje tego, co wie protokół.
    assert out["delegate"]["name"] == "LEWANDOWSKI Marek"


def test_bez_stanu_liczy_sie_sam_protokol():
    blob = {"matchConfig": {"referee1": "KOWALSKI Jan"}}
    out = merged_officials(None, officials_from_blob(blob))
    assert out["referee1"]["name"] == "KOWALSKI Jan"


def test_sama_konfiguracja_wystarczy():
    """Trasa stanu czyta z bazy SAMĄ `matchConfig`, nie cały protokół."""
    cfg = {"extras": {"officials": {"referee1": {"fullName": "KOWALSKI Jan"}}}}
    assert officials_from_config(cfg)["referee1"]["name"] == "KOWALSKI Jan"


# ─────────────── overlay: dopisany i SKASOWANY delegat ───────────────

def overlay(name: Any, **kw) -> dict:
    """Wpis overlaya w kształcie, jaki zapisuje `/proel/patch`."""
    return {"official.delegate.fullName": {"v": name, "at": "2026-08-26T07:10:00", **kw}}


def test_skasowane_nazwisko_zdejmuje_role():
    """Sędzia kasuje delegata w ekranie finalizacji i musi móc zatwierdzić.

    Guard z `/ensure` celowo nie daje się wyczyścić pustą wartością, więc sam
    twierdziłby, że delegat dalej jest - a pole na ekranie byłoby puste.
    """
    crew = officials_with_overlay(CREW_WITH_DELEGATE, overlay(""))
    assert "delegate" not in crew
    assert approve_roles(crew) == {"referee1", "referee2"}
    assert can_approve(judge("111"), crew)


def test_placeholder_w_overlayu_tez_zdejmuje_role():
    crew = officials_with_overlay(CREW_WITH_DELEGATE, overlay("--- ---"))
    assert "delegate" not in crew


def test_dopisany_delegat_przejmuje_decyzje():
    crew = officials_with_overlay(CREW_NO_DELEGATE, overlay("LEWANDOWSKI Marek"))
    assert approve_roles(crew) == {"delegate"}
    assert can_approve(judge("0", "LEWANDOWSKI Marek"), crew)
    assert not can_approve(judge("111"), crew)


def test_dopisane_nazwisko_nie_dziedziczy_numeru_po_poprzedniku():
    """Numer został po człowieku, którego w tym meczu nie ma."""
    crew = officials_with_overlay(CREW_WITH_DELEGATE, overlay("KOWALCZYK Ewa"))
    assert crew["delegate"]["name"] == "KOWALCZYK Ewa"
    assert not crew["delegate"].get("judgeId")


def test_poprawka_literowki_numeru_nie_gubi():
    """To wciąż ten sam człowiek - numer jest przy nim najmocniejszym sygnałem."""
    crew = officials_with_overlay(CREW_WITH_DELEGATE, overlay("LEWANDOWSKI"))
    assert crew["delegate"]["judgeId"] == "444"


def test_wpis_uniewazniony_jest_pomijany():
    crew = officials_with_overlay(
        CREW_WITH_DELEGATE, overlay("", superseded_at="2026-08-26T07:00:00")
    )
    assert crew["delegate"]["name"] == "LEWANDOWSKI Marek"


def test_obce_sciezki_overlaya_nie_ruszaja_obsady():
    crew = officials_with_overlay(
        CREW_WITH_DELEGATE,
        {"post.spectatorsCount": {"v": 120}, "official.delegate.signature": {"v": "data:..."}},
    )
    assert crew == CREW_WITH_DELEGATE


def test_overlay_nakladany_jest_ZAWSZE():
    """Nie tylko wtedy, gdy wiersz stanu nie zna obsady - inaczej skasowanie
    delegata działałoby wyłącznie na meczach bez guardu."""
    code = _function_source("_approval_officials")
    assert "officials_with_overlay" in code
    assert code.rstrip().endswith("return officials_with_overlay(officials, _overlay_of(state))")


# ─────────────────────── lekki odczyt z bazy ───────────────────────

def test_czytamy_sama_konfiguracje_a_nie_caly_protokol():
    """`data_json` bywa megabajtem, a trasa stanu chodzi długim pollingiem.

    Wyrażenie musi się skompilować do operatora JSON (`->`), inaczej odczyt
    wywróciłby się dopiero na produkcji - tak jak `contains` na kolumnie
    tablicowej (patrz `test_proel_device_cleanup`).
    """
    from sqlalchemy import JSON, Column, MetaData, String, Table, select
    from sqlalchemy.dialects import postgresql

    fake = Table(
        "fake_proel_matches",
        MetaData(),
        Column("match_number", String, primary_key=True),
        Column("data_json", JSON),
    )
    stmt = select(fake.c.data_json["matchConfig"].label("cfg")).where(
        fake.c.match_number == "OSK/12"
    )
    # Dialekt jawnie: ogólny renderuje indeks jako `data_json[:param]`, a
    # operator `->` daje dopiero Postgres - czyli to, co stoi na produkcji.
    sql = str(stmt.compile(dialect=postgresql.dialect()))
    assert "->" in sql
    assert "data_json" in sql


def test_protokol_czytamy_TYLKO_gdy_stan_nie_zna_obsady():
    code = _function_source("_approval_officials")
    assert "crew_is_known" in code
    assert code.index("crew_is_known") < code.index("_fetch_doc_config")


# ─────────────────────── wpięcie w trasę ───────────────────────

def _function_source(name: str) -> str:
    tree = ast.parse(PROEL_PY.read_text(encoding="utf-8"))
    fn = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)) and node.name == name
    )
    return ast.unparse(fn)


def test_zapis_meczu_pyta_o_prawo_do_zatwierdzenia():
    code = _function_source("update_proel_match")
    assert "_require_approver" in code


def test_guard_stoi_przed_zapisem_do_bazy():
    """Odmowa po zapisie byłaby odmową po fakcie."""
    code = _function_source("update_proel_match")
    assert code.index("_require_approver") < code.index("database.execute(stmt)")


def test_guard_wymaga_TWARDEJ_tozsamosci():
    """`soft_actor` nigdy nie odmawia - tutaj odmowa jest sednem."""
    code = _function_source("_require_approver")
    assert "proel_actor(" in code
    assert "soft_actor" not in code


def test_guard_przepuszcza_admina():
    assert "is_admin" in _function_source("_may_approve")


def test_przycisk_i_zapis_pytaja_TEGO_SAMEGO():
    """Sedno całej sprawy.

    Ekran zapala przycisk na podstawie `can_approve` z trasy stanu, a zapis
    sprawdza to samo prawo jeszcze raz. Gdy każde z tych miejsc liczy je po
    swojemu, sędzia dostaje przycisk, który po dotknięciu mówi „ta decyzja
    należy do kogo innego". Obie drogi mają wołać jedną funkcję.
    """
    assert "_may_approve" in _function_source("_require_approver")
    assert "_may_approve" in _function_source("_build_state_response")


def test_obsada_do_decyzji_ma_jedno_zrodlo():
    assert "_approval_officials" in _function_source("_may_approve")


def test_starsza_aplikacja_zostaje_przepuszczona():
    """Ten sam kompromis co przy blokadzie prowadzenia - patrz docstring."""
    code = _function_source("_require_approver")
    assert "legacy" in code
