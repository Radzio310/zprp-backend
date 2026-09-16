from app.delegate_evaluation_utils import (
    GRADE_POINTS,
    absorb_evaluation,
    allowed_season,
    canonical_hash,
    finalize_bucket,
    grade_distribution,
    grade_values,
    new_bucket,
    pair_names,
    safe_source_fingerprint,
)


def test_only_supported_seasons_are_collected():
    assert allowed_season("2025/2026")
    assert allowed_season("2026_2027")
    assert not allowed_season("2024/2025")
    assert not allowed_season("")


def test_hash_is_canonical_and_source_url_is_not_exposed():
    assert canonical_hash({"b": 2, "a": 1}) == canonical_hash({"a": 1, "b": 2})
    url = "https://example.test/form?secret=abc"
    fingerprint = safe_source_fingerprint(url)
    assert url not in fingerprint
    assert "secret" not in fingerprint
    assert len(fingerprint) == 64


def test_grade_values_include_main_and_parameter_grades():
    result = grade_values({"sections": [
        {"key": "I", "mainGrade": "A", "items": [{"grade": "B"}, {"grade": "x"}]},
        {"title": "Komunikacja", "mainGrade": "C", "items": []},
    ]})
    assert result == {"I": [1, 2], "Komunikacja": [3]}


def test_wieksza_liczba_punktow_znaczy_lepsza_ocena():
    """A to „niedopuszczalnie", G to „wybitnie" - patrz legenda arkusza.

    Do 15.09.2026 mapa punktów była odwrócona i para z samymi „A" wychodziła
    na średnią 7,00, czyli wybitną. Ten test istnieje po to, żeby nikt nie
    odwrócił jej z powrotem „dla porządku alfabetycznego".
    """
    assert GRADE_POINTS["A"] < GRADE_POINTS["D"] < GRADE_POINTS["G"]
    assert GRADE_POINTS["G"] == max(GRADE_POINTS.values())


def test_najlepsza_i_najgorsza_ocena_nie_sa_zamienione():
    bucket = new_bucket(key="para")
    absorb_evaluation(
        bucket,
        {"sections": [{"key": "I", "mainGrade": "G", "items": [{"title": "Krok", "grade": "A"}]}]},
        grade_values({"sections": [{"key": "I", "mainGrade": "G", "items": [{"grade": "A"}]}]}),
    )
    done = finalize_bucket(bucket)
    assert done["best"] == GRADE_POINTS["G"]
    assert done["worst"] == GRADE_POINTS["A"]


def test_para_dostaje_rozpisanie_na_kryteria_tak_jak_osoba():
    """Delegat ocenia PARĘ - ekran pary nie może sięgać po dane jednego sędziego."""
    evaluation = {"sections": [
        {"key": "I", "title": "Zarządzanie", "mainGrade": "E",
         "items": [{"title": "Kontakt", "grade": "F"}, {"title": "Kontakt", "grade": "D"}]},
    ]}
    bucket = new_bucket(key="1|2", judge_ids=["1", "2"], names=["Kowalski", "Nowak"])
    absorb_evaluation(bucket, evaluation, grade_values(evaluation))
    done = finalize_bucket(bucket)
    assert done["evaluations"] == 1
    assert done["sections"]["I"]["samples"] == 3
    parametry = done["section_details"]["I"]["parameters"]
    assert [p["title"] for p in parametry] == ["Kontakt"]
    assert parametry[0]["samples"] == 2
    assert parametry[0]["best"] == GRADE_POINTS["F"]


def test_dwa_arkusze_tej_samej_pary_sumuja_sie():
    evaluation = {"sections": [{"key": "I", "mainGrade": "D", "items": []}]}
    bucket = new_bucket(key="1|2")
    for _ in range(2):
        absorb_evaluation(bucket, evaluation, grade_values(evaluation))
    done = finalize_bucket(bucket)
    assert done["evaluations"] == 2
    assert done["sections"]["I"]["samples"] == 2
    assert done["average"] == GRADE_POINTS["D"]


def test_nazwiska_pary_stoja_rownorzednie():
    """Kolejność z arkusza stawiałaby jednego sędziego zawsze pierwszego."""
    assert pair_names(["7", "3"], ["Zalewski", "Adamczyk"]) == ["Adamczyk", "Zalewski"]
    assert pair_names(["7", "3"], ["Adamczyk", "Zalewski"]) == ["Adamczyk", "Zalewski"]


def test_brak_nazwiska_zastepuje_numer_a_nie_pustka():
    assert pair_names(["7", "3"], ["Adamczyk"]) == ["3", "Adamczyk"]


def test_rozklad_liter_liczy_to_samo_co_srednia():
    """Skala ocen pokazuje, ile razy padła każda litera.

    Rozkład powstaje z TYCH SAMYCH punktów co średnia (ocena sekcji plus
    każde kryterium) - inaczej kafelek „SKALA OCEN" mówiłby o innym zbiorze
    niż liczba nad nim.
    """
    evaluation = {"sections": [
        {"key": "I", "mainGrade": "D", "items": [{"title": "Krok", "grade": "D"}, {"title": "Gest", "grade": "F"}]},
    ]}
    bucket = new_bucket(key="para")
    absorb_evaluation(bucket, evaluation, grade_values(evaluation))
    done = finalize_bucket(bucket)

    assert done["grades"]["D"] == 2
    assert done["grades"]["F"] == 1
    assert sum(done["grades"].values()) == 3


def test_rozklad_ma_wszystkie_litery_takze_te_bez_trafien():
    """Pusta kolumna w skali to informacja - brak klucza kazałby ekranowi zgadywać."""
    rozklad = grade_distribution([GRADE_POINTS["C"], GRADE_POINTS["C"]])
    assert set(rozklad) == set(GRADE_POINTS)
    assert rozklad["C"] == 2
    assert rozklad["A"] == 0


def test_pusty_worek_nie_wymysla_ocen():
    done = finalize_bucket(new_bucket(key="para"))
    assert done["average"] is None
    assert sum(done["grades"].values()) == 0


def test_lacznie_wazy_ocenionymi_elementami_a_nie_parami():
    """„Łącznie" to jeden worek na wszystkie arkusze, nie średnia ze średnich par.

    Para z jednym kryterium nie może ciążyć na wyniku okręgu tyle samo, co para
    z dziesięcioma - ekran liczy wszystkie pozostałe średnie po ocenionych
    elementach i ta jedna nie może liczyć inaczej.
    """
    duza = {"sections": [{"key": "I", "mainGrade": "B", "items": [
        {"title": f"Kryterium {index}", "grade": "B"} for index in range(9)
    ]}]}
    mala = {"sections": [{"key": "I", "mainGrade": "F", "items": []}]}

    lacznie = new_bucket()
    for arkusz in (duza, mala):
        absorb_evaluation(lacznie, arkusz, grade_values(arkusz))
    wynik = finalize_bucket(lacznie)["average"]

    # 10 x B (2 pkt) i 1 x F (6 pkt) = 26 / 11
    assert wynik == round(26 / 11, 2)
    # srednia ze srednich par dalaby (2 + 6) / 2 = 4,00 - czyli co innego
    assert wynik != 4.0


# ---------------------------------------------------------------------------
# Dostęp (decyzja z 16.09.2026): w BAZA_web tylko admin i VIP z uprawnieniem
# ---------------------------------------------------------------------------

from app.delegate_evaluation_utils import (  # noqa: E402
    NO_ACCESS_GRANT,
    NO_ACCESS_VIP_PERMISSION,
    NO_ACCESS_VIP_PROVINCE,
    NO_ACCESS_WEB_JUDGE,
    resolve_access,
)


def test_vip_z_samym_wojewodztwem_nie_widzi_ocen():
    access = resolve_access(surface="web", is_org=True, same_province=True, permissions={"district_unavailability": True})
    assert not access["stats"] and not access["full"]
    assert access["reason"] == NO_ACCESS_VIP_PERMISSION


def test_vip_z_uprawnieniem_widzi_oceny_swojego_okregu():
    access = resolve_access(surface="web", is_org=True, same_province=True, permissions={"delegate_evaluations": True})
    assert access["stats"] and access["full"] and access["reason"] == ""
    other = resolve_access(surface="web", is_org=True, same_province=False, permissions={"delegate_evaluations": True})
    assert not other["stats"] and other["reason"] == NO_ACCESS_VIP_PROVINCE


def test_vip_admin_z_uprawnieniami_zapisanymi_napisem():
    access = resolve_access(surface="web", is_org=True, same_province=True, permissions='{"admin": true}')
    assert access["stats"] and access["full"]


def test_admin_widzi_wszedzie():
    for surface in ("web", ""):
        access = resolve_access(surface=surface, is_org=False, is_admin=True)
        assert access["stats"] and access["full"] and access["admin"]


def test_dostep_nadany_sedziemu_dziala_tylko_w_aplikacji():
    grant = {"can_view_stats": True, "can_view_full": False}
    web = resolve_access(surface="web", is_org=False, grant=grant)
    assert not web["stats"] and web["reason"] == NO_ACCESS_WEB_JUDGE
    app = resolve_access(surface="", is_org=False, grant=grant)
    assert app["stats"] and not app["full"]
    none = resolve_access(surface="", is_org=False, grant=None)
    assert not none["stats"] and none["reason"] == NO_ACCESS_GRANT
