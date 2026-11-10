"""Formularze okręgowe - schemat listy i formularza (port testów Communio `tests/test_forms.py`).

Scena formularza: zapisy na turniej - imię, czy jedzie (jeśli nie - koniec), co zabiera,
PESEL do ubezpieczenia, ocena, zdjęcie legitymacji.
"""
import json

import pytest

from app import district_form_schema as SC
from app.district_forms_rules import FormError

PESEL_OK = "44051401359"


def sections_raw():
    return [
        {
            "id": "s1",
            "title": "Ty",
            "questions": [
                {"id": "imie", "type": "short_text", "title": "Imię", "required": True},
                {
                    "id": "jedzie",
                    "type": "single",
                    "title": "Jedziesz?",
                    "required": True,
                    "options": [{"id": "tak", "label": "Tak"}, {"id": "nie", "label": "Nie"}],
                    "logic": {"nie": "end"},
                },
            ],
        },
        {
            "id": "s2",
            "title": "Wyjazd",
            "questions": [
                {
                    "id": "nocleg",
                    "type": "multi",
                    "title": "Co zabierasz?",
                    "options": [{"id": "spiwor", "label": "Śpiwór"}, {"id": "karimata", "label": "Karimata"}],
                    "other": True,
                    "max_choices": 2,
                },
                {"id": "pesel", "type": "pesel", "title": "PESEL"},
                {"id": "ocena", "type": "rating", "title": "Jak się cieszysz?", "stars": 5},
                {"id": "skan", "type": "file", "title": "Legitymacja", "accept": "image", "max_files": 1},
            ],
        },
    ]


def sections(raw=None):
    return [SC.FormSection.model_validate(s) for s in (raw or sections_raw())]


# ---------------------------------------------------------------------------
# Lista (§4)
# ---------------------------------------------------------------------------


def test_lista_domyslne_opcje_statusu_i_ustawienia_kolumn():
    schema = SC.clean_list_schema(
        {"columns": [{"id": "status", "type": "status", "title": "Będę?"}, {"id": "pay", "type": "confirm", "title": "Wpłata"}]}
    )
    status, pay = schema["columns"]
    assert [o["id"] for o in status["options"]] == ["yes", "no"]
    assert status["editor"] == "self" and status["visibility"] == "all" and status["lock_after_deadline"] is True
    assert pay["editor"] == "self_confirm" and pay["lock_after_deadline"] is False and pay["amount"] is None


@pytest.mark.parametrize(
    "columns, fragment",
    [
        ([], "co najmniej jednej kolumny"),
        ([{"id": "a", "type": "status", "title": "A"}, {"id": "b", "type": "status", "title": "B"}], "jedną kolumnę statusu"),
        ([{"id": "a", "type": "text", "title": "A"}, {"id": "a", "type": "text", "title": "B"}], "ten sam identyfikator"),
        ([{"id": "A B", "type": "text", "title": "A"}], "Identyfikator kolumny"),
        ([{"id": "a", "type": "money", "title": "A"}], "Nieznany rodzaj"),
        ([{"id": "a", "type": "text", "title": ""}], "potrzebuje nazwy"),
        ([{"id": "a", "type": "text", "title": "x" * 61}], "najwyżej 60"),
        ([{"id": "a", "type": "text", "title": "A", "editor": "self_confirm"}], "tylko przy kolumnie potwierdzenia"),
        ([{"id": "a", "type": "choice", "title": "A", "options": [{"id": "x", "label": "X"}]}], "od 2 do 20"),
        ([{"id": "a", "type": "status", "title": "A", "options": [{"id": str(i), "label": str(i)} for i in range(6)]}], "od 2 do 5"),
        ([{"id": "a", "type": "number", "title": "A", "min": 5, "max": 1}], "większa od największej"),
        ([{"id": "a", "type": "text", "title": "A", "max_length": 501}], "od 1 do 500"),
        ([{"id": "a", "type": "confirm", "title": "A", "amount": -1}], "kwota"),
        ([{"id": f"c{i}", "type": "text", "title": "T"} for i in range(21)], "najwyżej 20"),
    ],
)
def test_lista_odrzuca_zly_schemat_ze_zdaniem(columns, fragment):
    with pytest.raises(FormError) as err:
        SC.clean_list_schema({"columns": columns})
    assert err.value.status == 400 and fragment in err.value.message


def test_clean_schema_wybiera_rodzaj():
    assert "columns" in SC.clean_schema("list", {"columns": [{"id": "t", "type": "text", "title": "Uwagi"}]})
    assert "sections" in SC.clean_schema("form", {"sections": sections_raw()})


# ---------------------------------------------------------------------------
# Formularz (§5) - port Communio
# ---------------------------------------------------------------------------


def test_pesel_suma_kontrolna_i_data():
    assert SC.pesel_valid(PESEL_OK)
    assert not SC.pesel_valid("44051401358")
    assert not SC.pesel_valid("4405140135")
    assert not SC.pesel_valid("44133101350")


def test_trasa_skacze_do_konca_i_przechodzi_dalej():
    secs = sections()
    assert SC.route(secs, {"jedzie": {"option": "nie"}}) == ["s1"]
    assert SC.route(secs, {"jedzie": {"option": "tak"}}) == ["s1", "s2"]
    assert SC.route(secs, {}) == ["s1", "s2"]


def test_dokument_odrzuca_skok_wstecz_dubel_i_odwolanie_wsteczne():
    bad = sections_raw()
    bad[1]["questions"].append(
        {"id": "wstecz", "type": "dropdown", "title": "Wróć?", "options": [{"id": "a", "label": "A"}], "logic": {"a": "s1"}}
    )
    with pytest.raises(FormError, match="dalej w formularzu"):
        SC.clean_form_schema({"sections": bad})
    double = sections_raw()
    double[1]["questions"][0]["id"] = "imie"
    with pytest.raises(FormError, match="ten sam identyfikator"):
        SC.clean_form_schema({"sections": double})
    backref = sections_raw()
    backref[0]["questions"][0]["pattern"] = r"(a)\1"
    with pytest.raises(FormError, match="wcześniejszych grup"):
        SC.clean_form_schema({"sections": backref})
    with pytest.raises(FormError, match="zły kształt"):
        SC.clean_form_schema({"sections": [{"id": "s 1", "questions": []}]})
    with pytest.raises(FormError, match="co najmniej jednej sekcji"):
        SC.clean_form_schema({"sections": []})


def test_wzorzec_katastrofalny_odpada_przy_zapisie_a_prosty_dziala():
    bad = sections_raw()
    bad[0]["questions"][0]["pattern"] = r"(a+)+$"
    with pytest.raises(FormError, match="zbyt złożony"):
        SC.clean_form_schema({"sections": bad})
    good = sections_raw()
    good[0]["questions"][0]["pattern"] = r"[A-ZŁŚŻŹĆ][a-ząćęłńóśźż]+"
    good[0]["questions"][0]["pattern_message"] = "Imię wielką literą"
    schema = SC.clean_form_schema({"sections": good})
    _, errors = SC.check_answers(SC.sections_of(schema), {"imie": "ania", "jedzie": {"option": "nie"}})
    assert errors == {"imie": "Imię wielką literą"}


def test_odpowiedzi_spoza_trasy_sa_odcinane_a_obowiazkowe_pilnowane():
    secs = sections()
    clean, errors = SC.check_answers(
        secs, {"imie": " Ania ", "jedzie": {"option": "nie"}, "pesel": "123", "nocleg": {"options": ["spiwor"]}}
    )
    assert errors == {}
    assert clean == {"imie": "Ania", "jedzie": {"option": "nie"}}
    _, errors = SC.check_answers(secs, {"jedzie": {"option": "tak"}, "pesel": "123"})
    assert set(errors) == {"imie", "pesel"}


def test_rodzaje_odpowiedzi_sa_sprawdzane_i_normalizowane():
    secs = sections(
        [
            {
                "id": "s",
                "questions": [
                    {"id": "mail", "type": "email", "title": "E-mail"},
                    {"id": "tel", "type": "phone", "title": "Telefon"},
                    {"id": "kod", "type": "postal", "title": "Kod"},
                    {"id": "ile", "type": "number", "title": "Ile", "number_min": 1, "number_max": 10, "integer": True},
                    {"id": "skala", "type": "scale", "title": "Skala", "scale_min": 1, "scale_max": 10},
                    {"id": "data", "type": "date", "title": "Data"},
                    {
                        "id": "siatka",
                        "type": "grid",
                        "title": "Siatka",
                        "required": True,
                        "rows": [{"id": "r1", "label": "Sobota"}, {"id": "r2", "label": "Niedziela"}],
                        "columns": [{"id": "c1", "label": "Rano"}, {"id": "c2", "label": "Wieczorem"}],
                    },
                    {
                        "id": "wiele",
                        "type": "multi",
                        "title": "Wiele",
                        "min_choices": 2,
                        "options": [{"id": "a", "label": "A"}, {"id": "b", "label": "B"}],
                    },
                ],
            }
        ]
    )
    clean, errors = SC.check_answers(
        secs,
        {
            "mail": "ania@oaza.pl", "tel": "+48 600-100-200", "kod": "00950", "ile": "7", "skala": 10,
            "data": "2026-10-10", "siatka": {"r1": "c1", "r2": "c2"}, "wiele": {"options": ["b", "a"]},
        },
    )
    assert errors == {}
    assert clean["kod"] == "00-950" and clean["ile"] == 7
    assert clean["wiele"] == {"options": ["a", "b"], "other": None}
    _, errors = SC.check_answers(
        secs,
        {
            "mail": "ania", "tel": "12", "kod": "1-1", "ile": 7.5, "skala": 11, "data": "2026-02-30",
            "siatka": {"r1": "c1"}, "wiele": {"options": ["a"]},
        },
    )
    assert set(errors) == {"mail", "tel", "kod", "ile", "skala", "data", "siatka", "wiele"}


def test_plik_w_odpowiedzi_musi_byc_wlasny_i_obrazem():
    secs = sections()
    base = {"imie": "Ania", "jedzie": {"option": "tak"}}
    _, errors = SC.check_answers(secs, {**base, "skan": ["0123456789abcdef"]})
    assert "skan" in errors
    _, errors = SC.check_answers(secs, {**base, "skan": ["0123456789abcdef"]}, files=SC.Files({"0123456789abcdef": False}))
    assert errors["skan"] == "Tu można dołączyć tylko zdjęcie."
    clean, errors = SC.check_answers(secs, {**base, "skan": ["0123456789abcdef"]}, files=SC.Files({"0123456789abcdef": True}))
    assert errors == {} and clean["skan"] == ["0123456789abcdef"]


def test_zbiorczo_pomija_rodzaje_z_danymi_osobowymi():
    secs = sections(
        [
            {
                "id": "s",
                "questions": [
                    {"id": "u", "type": "date", "title": "Data urodzenia"},
                    {"id": "m", "type": "email", "title": "E-mail"},
                    {"id": "k", "type": "postal", "title": "Kod"},
                    {"id": "g", "type": "time", "title": "Godzina"},
                    {"id": "t", "type": "long_text", "title": "Uwagi"},
                ],
            }
        ]
    )
    results, hidden = SC.aggregate(
        secs, [{"u": "2001-02-03", "m": "a@b.pl", "k": "00-001", "g": "18:00", "t": "Mieszkam przy Polnej 3"}]
    )
    assert set(hidden) == {"u", "m", "k"} and {"date", "email", "postal"} <= SC.PERSONAL
    assert "Polnej" not in json.dumps(results) and "2001" not in json.dumps(results)
    assert [r["question_id"] for r in results] == ["g", "t"]


def test_zbiorczo_wybor_skala_i_inne_to_tylko_liczby():
    secs = sections()
    results, _ = SC.aggregate(
        secs,
        [
            {"jedzie": {"option": "tak"}, "nocleg": {"options": ["spiwor"], "other": "namiot"}, "ocena": 5},
            {"jedzie": {"option": "nie"}},
            {"jedzie": {"option": "tak"}, "ocena": 3},
        ],
    )
    by_id = {r["question_id"]: r for r in results}
    assert [o["count"] for o in by_id["jedzie"]["options"]] == [2, 1]
    assert by_id["nocleg"]["other_count"] == 1 and "namiot" not in json.dumps(results)
    assert by_id["ocena"]["average"] == 4 and by_id["ocena"]["stars"] is True
    assert by_id["imie"] == {"question_id": "imie", "kind": "text", "answered": 0}


def test_odpowiedz_po_ludzku_do_eksportu():
    secs = sections()
    q = {q.id: q for q in SC.questions(secs)}
    assert SC.answer_text(q["jedzie"], {"option": "tak"}) == "Tak"
    assert SC.answer_text(q["nocleg"], {"options": ["karimata"], "other": "namiot"}) == "Karimata; Inne: namiot"
    assert SC.answer_text(q["ocena"], None) == ""
    assert SC.median([3, 1, 2]) == 2 and SC.median([1, 2]) == 1.5 and SC.median([]) is None


def test_obraz_pytania_zostaje_po_zapisie_i_dostaje_adres():
    raw = sections_raw()
    raw[0]["questions"][0]["image"] = "0123456789abcdef"
    raw[0]["questions"][0]["image_url"] = "https://cdn.example/x.png"
    schema = SC.clean_form_schema({"sections": raw})
    assert schema["sections"][0]["questions"][0]["image_url"] == "https://cdn.example/x.png"
    app_view = SC.with_image_urls(schema, "f" * 16)
    assert app_view["sections"][0]["questions"][0]["image_url"] == "/district-forms/ffffffffffffffff/files/0123456789abcdef"
    web_view = SC.with_image_urls(schema, "f" * 16, public_code="ab23cd45")
    assert web_view["sections"][0]["questions"][0]["image_url"] == "/public/forms/ab23cd45/files/0123456789abcdef"
    assert schema["sections"][0]["questions"][0]["image_url"] == "https://cdn.example/x.png"  # oryginał bez zmian
    bad = sections_raw()
    bad[0]["questions"][0]["image_url"] = "javascript:alert(1)"
    with pytest.raises(FormError):
        SC.clean_form_schema({"sections": bad})
