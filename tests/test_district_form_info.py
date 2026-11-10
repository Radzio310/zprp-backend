"""Formularze okręgowe - bloki informacyjne nad i pod formularzem (docs/formularze-okregowe.md §17)."""
from datetime import datetime, timezone

import pytest

from app import district_form_info as I
from app import district_form_schema as SC
from app import district_form_templates as T
from app.district_forms_rules import FormError

UTC = timezone.utc
NRB = "61109010140000071219812874"

SCHEMA = SC.clean_list_schema(
    {
        "columns": [
            {"id": "status", "type": "status", "title": "Obecność"},
            {"id": "pay", "type": "confirm", "title": "Wpłata", "amount": 80},
            {"id": "menu", "type": "choice", "title": "Menu", "options": [{"id": "a", "label": "A"}, {"id": "b", "label": "B"}]},
        ]
    }
)


def payment(**extra):
    return {"id": "pay", "type": "payment", "recipient": "Kolegium Sędziów", "account": NRB,
            "transfer_title": "Wigilia – {imie_nazwisko}", **extra}


def errors_of(raw, schema=SCHEMA, **kw):
    with pytest.raises(FormError) as err:
        I.clean_info(raw, schema, **kw)
    assert err.value.code == "bad_info" and err.value.status == 400
    return err.value.extra["errors"]


def test_nrb_suma_kontrolna_i_format():
    assert I.nrb_valid(NRB)
    assert I.nrb_valid("PL 61 1090 1014 0000 0712 1981 2874")
    assert not I.nrb_valid("62109010140000071219812874")
    assert not I.nrb_valid("6110901014000007121981287")
    assert not I.nrb_valid("")
    assert I.normalize_nrb("PL61 1090-1014 0000 0712 1981 2874") == NRB
    assert I.format_nrb(NRB) == "61 1090 1014 0000 0712 1981 2874"


def test_puste_info_i_nieznane_typy():
    assert I.clean_info(None) == {"above": [], "below": []}
    cleaned = I.clean_info({"above": [{"type": "video", "url": "x"}, {"type": "text", "body": "  Witajcie  "}], "below": None}, SCHEMA)
    assert cleaned == {"above": [{"id": "b1", "type": "text", "body": "Witajcie"}], "below": []}
    errors_of("zly")


def test_wszystkie_typy_przechodza_i_sa_czyszczone():
    raw = {
        "above": [
            {"id": "t", "type": "text", "title": " Program ", "body": "**Start** 18:00\n- kolacja"},
            {"id": "c", "type": "callout", "tone": "warning", "body": "Pamiętaj o stroju"},
            {"id": "d", "type": "countdown", "target": "date", "date": "2026-12-18T17:00:00Z", "show_date": False},
            payment(amount_column="pay", confirm_column="pay", bank_qr=False, account="PL61 1090 1014 0000 0712 1981 2874"),
        ],
        "below": [
            {"id": "k", "type": "copy", "items": [{"label": "Hasło Wi-Fi", "value": "sedzia2026", "mono": True}]},
            {"id": "p", "type": "place", "name": "Hala Sportowa", "address": "ul. Polna 1", "lat": "50.123456789", "lon": 19.5},
            {"id": "o", "type": "contact", "people": [{"name": "Jan Nowak", "role": "Komisja", "phone": "+48 600 100 200", "email": "jan@x.pl"}]},
            {"id": "l", "type": "links", "items": [{"label": "Regulamin", "url": "https://zprp.pl/regulamin"}]},
        ],
    }
    info = I.clean_info(raw, SCHEMA)
    above = {b["id"]: b for b in info["above"]}
    below = {b["id"]: b for b in info["below"]}
    assert above["t"]["title"] == "Program"
    assert above["d"]["show_date"] is False and above["d"]["date"] == "2026-12-18T17:00:00+00:00"
    assert above["pay"]["account"] == NRB and above["pay"]["bank_qr"] is False and above["pay"]["amount"] is None
    assert below["k"]["items"] == [{"id": "c1", "label": "Hasło Wi-Fi", "value": "sedzia2026", "mono": True}]
    assert below["p"]["lat"] == 50.123457 and below["p"]["lon"] == 19.5
    assert below["o"]["people"][0]["id"] == "p1"
    assert below["l"]["items"][0]["url"] == "https://zprp.pl/regulamin"
    # Domyślne: licznik do terminu z datą, QR banku włączony.
    simple = I.clean_info({"above": [{"type": "countdown"}, payment()]}, SCHEMA)["above"]
    assert simple[0]["target"] == "deadline" and simple[0]["show_date"] is True and simple[1]["bank_qr"] is True


def test_bledy_zbierane_per_blok():
    errors = errors_of(
        {
            "above": [
                {"id": "a", "type": "text", "body": ""},
                {"id": "b", "type": "countdown", "target": "event"},
                payment(id="c", account="62109010140000071219812874"),
                payment(id="d", amount_column="menu"),
                payment(id="e", confirm_column="nope"),
            ],
            "below": [
                {"id": "f", "type": "links", "items": [{"label": "X", "url": "http://zprp.pl"}]},
                {"id": "g", "type": "contact", "people": []},
                {"id": "h", "type": "callout", "tone": "pink", "body": "x"},
                {"id": "i", "type": "countdown", "target": "date"},
                {"id": "j", "type": "place", "name": "Hala", "lat": 50},
                {"id": "k", "type": "text", "body": "x" * 3001},
            ],
        }
    )
    assert set(errors) == set("abcdefghijk")
    assert "wydarzeniem" in errors["b"] and "konta" in errors["c"] and "https://" in errors["f"]
    assert "kolumną potwierdzenia" in errors["d"] and "nie ma" in errors["e"]
    # Z wydarzeniem licznik do wydarzenia jest w porządku.
    assert I.clean_info({"above": [{"type": "countdown", "target": "event"}]}, SCHEMA, has_event=True)["above"][0]["target"] == "event"
    # Formularz (bez kolumn) nie może wskazać kolumny wpłaty.
    assert "c" in errors_of({"above": [payment(id="c", amount_column="pay")]}, {"sections": []})
    with pytest.raises(FormError):
        I.clean_info({"above": [{"type": "text", "body": "x"}] * 13})


def test_identyfikatory_blokow_unikalne_w_obu_strefach():
    info = I.clean_info({"above": [{"id": "x", "type": "text", "body": "1"}], "below": [{"id": "x", "type": "text", "body": "2"}]})
    ids = [b["id"] for zone in ("above", "below") for b in info[zone]]
    assert len(set(ids)) == 2 and ids[0] == "x"


def test_resolved_at_i_resolved_amount():
    info = I.clean_info(
        {
            "above": [
                {"id": "a", "type": "countdown", "target": "deadline"},
                {"id": "b", "type": "countdown", "target": "event"},
                {"id": "c", "type": "countdown", "target": "date", "date": "2026-12-01T10:00:00+00:00"},
                payment(id="d", amount_column="pay"),
                payment(id="e", amount=55.5, amount_column="pay"),
                payment(id="f"),
            ]
        },
        SCHEMA,
        has_event=True,
    )
    closes = datetime(2026, 12, 18, 22, 59, tzinfo=UTC)
    start = datetime(2026, 12, 20, 17, tzinfo=UTC)
    resolved = {b["id"]: b for b in I.resolve_info(info, closes_at=closes, event_start=start, schema=SCHEMA)["above"]}
    assert resolved["a"]["resolved_at"] == closes.isoformat()
    assert resolved["b"]["resolved_at"] == start.isoformat()
    assert resolved["c"]["resolved_at"] == "2026-12-01T10:00:00+00:00"
    assert resolved["d"]["resolved_amount"] == 80
    assert resolved["e"]["resolved_amount"] == 55.5
    assert resolved["f"]["resolved_amount"] is None
    none = I.resolve_info(info, schema=SCHEMA)["above"]
    assert none[0]["resolved_at"] is None and none[1]["resolved_at"] is None
    assert "resolved_at" not in info["above"][0]  # oryginał bez zmian


def test_web_wylaczony_pokazuje_tylko_licznik_i_tekst():
    info = I.clean_info({"above": [{"type": "countdown"}, payment()], "below": [{"type": "text", "body": "x"}, {"type": "callout", "body": "y"}]}, SCHEMA)
    hidden = I.public_info(info, web_enabled=False)
    assert [b["type"] for b in hidden["above"]] == ["countdown"] and [b["type"] for b in hidden["below"]] == ["text"]
    assert I.public_info(info, web_enabled=True) == info
    assert I.first_countdown(info)["type"] == "countdown"
    assert I.first_countdown({"above": [], "below": []}) is None
    assert I.first_payment(info)["recipient"] == "Kolegium Sędziów"
    assert I.info_changed(info, info) is False and I.info_changed(info, I.clean_info(None)) is True


def test_szablony_maja_bloki_i_dzialaja_bez_kreatora():
    party = T.template("party_payment")
    assert [b["type"] for b in party["info"]["above"]] == ["countdown", "payment"]
    assert party["info"]["above"][1]["amount_column"] == "payment" == party["info"]["above"][1]["confirm_column"]
    assert [b["type"] for b in party["info"]["below"]] == ["contact"]
    schema = SC.clean_schema("list", party["schema"])
    # Wprost z szablonu: puste konto i kontakty odpadają, licznik zostaje.
    adapted = I.adapt_template_info(party["info"], has_event=False, template_title=party["title"], form_title="Wigilia 2026")
    assert [b["type"] for b in I.clean_info(adapted, schema)["above"]] == ["countdown"]
    # Kreator uzupełnia konto: tytuł przelewu bierze tytuł formularza.
    filled = {**party["info"], "above": [party["info"]["above"][0], {**party["info"]["above"][1], "recipient": "Kolegium", "account": NRB}]}
    adapted = I.adapt_template_info(filled, has_event=False, template_title=party["title"], form_title="Wigilia 2026")
    pay = I.clean_info(adapted, schema)["above"][1]
    assert pay["transfer_title"] == "Wigilia 2026 – {imie_nazwisko}"
    assert I.resolve_info({"above": [pay], "below": []}, schema=schema)["above"][0]["resolved_amount"] is None  # kwota do ustawienia
    meeting = T.template("meeting")
    adapted = I.adapt_template_info(meeting["info"], has_event=False, template_title=meeting["title"], form_title="Zebranie")
    blocks = I.clean_info(adapted, SC.clean_schema("list", meeting["schema"]))["above"]
    assert [(b["type"], b.get("target")) for b in blocks] == [("countdown", "deadline")]
    with_event = I.adapt_template_info(meeting["info"], has_event=True, template_title="", form_title="Zebranie")
    assert with_event["above"][0]["target"] == "event"


def test_kto_oglada_imie_i_nazwisko():
    assert I.split_full_name("NOWAK Jan") == ("Jan", "NOWAK")
    assert I.split_full_name("Anna Maria KOWALSKA-NOWAK") == ("Anna Maria", "KOWALSKA-NOWAK")
    assert I.split_full_name("Jan Nowak") == ("", "Jan Nowak")
    assert I.split_full_name("") == ("", "")
    assert I.viewer_info("12", "ZAJĄC Karol R.") == {"judge_id": "12", "name": "ZAJĄC Karol R.", "first_name": "Karol R.", "last_name": "ZAJĄC"}
    assert I.viewer_info("12", None) == {"judge_id": "12", "name": "12", "first_name": "", "last_name": "12"}
