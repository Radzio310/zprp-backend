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

from app.proel_auth import (
    Actor,
    approve_roles,
    can_approve,
    merged_officials,
    officials_from_blob,
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
    out = merged_officials(state, blob)
    # Wiersz stanu ma numer prosto z ZPRP - jest lepszym źródłem.
    assert out["referee1"] == {"name": "KOWALSKI Jan", "judgeId": "111"}
    # Ale pusty wpis w stanie nie wymazuje tego, co wie protokół.
    assert out["delegate"]["name"] == "LEWANDOWSKI Marek"


def test_bez_stanu_liczy_sie_sam_protokol():
    blob = {"matchConfig": {"referee1": "KOWALSKI Jan"}}
    assert merged_officials(None, blob)["referee1"]["name"] == "KOWALSKI Jan"


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
    assert "is_admin" in _function_source("_require_approver")


def test_starsza_aplikacja_zostaje_przepuszczona():
    """Ten sam kompromis co przy blokadzie prowadzenia - patrz docstring."""
    code = _function_source("_require_approver")
    assert "legacy" in code
