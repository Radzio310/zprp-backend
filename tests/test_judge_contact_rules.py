"""
Adresy sędziów do maili okręgu: profil logowania, potem Kontakty po okręgu,
imieniu i nazwisku - a nie konta ProEla (decyzja użytkownika z 24.09.2026).
"""

from app import judge_contact_rules as JC


def test_adresy_z_pola_wielokrotnego():
    assert JC.emails_in("A@x.pl; b@y.pl ; a@x.pl; zly") == ["a@x.pl", "b@y.pl"]
    assert JC.emails_in(None) == []


def test_adres_z_profilu_logowania():
    assert JC.login_email({"config_json": {"email": "jan@x.pl"}}) == "jan@x.pl"
    assert JC.login_email({"config_json": '{"profile": {"email": "ewa@x.pl"}}'}) == "ewa@x.pl"
    assert JC.login_email({"email": "kol@x.pl", "config_json": {}}) == "kol@x.pl"
    assert JC.login_email({"config_json": {"devices": {}}}) == ""


def test_kontakty_po_nazwisku_w_dowolnej_kolejnosci_i_bez_ogonkow():
    contacts = [
        {"name": "Radosław", "surname": "Witkowicz", "email": "radek@x.pl", "isReferee": True},
        {"name": "Klub", "surname": "KS Sośnica", "email": "klub@x.pl", "isReferee": False, "isTeam": True},
    ]
    out = JC.resolve_emails(
        {"100": "WITKOWICZ Radoslaw", "200": "KS Sośnica Klub"},
        login_rows=[],
        contacts=contacts,
        province="ŚLĄSKIE",
    )
    assert out == {"100": ("radek@x.pl", JC.SOURCE_CONTACTS)}


def test_profil_wygrywa_z_kontaktami_i_okreg_musi_pasowac():
    contacts = [{"name": "Jan", "surname": "Nowak", "email": "kontakt@x.pl", "isReferee": True}]
    rows = [{"judge_id": "0100", "province": "SLASKIE", "config_json": {"email": "profil@x.pl"}}]
    same = lambda a, b: str(a).lstrip("0") == str(b).lstrip("0")
    out = JC.resolve_emails({"100": "Nowak Jan"}, login_rows=rows, contacts=contacts, province="ŚLĄSKIE", same_judge=same)
    assert out == {"100": ("profil@x.pl", JC.SOURCE_LOGIN)}
    # Profil z innego okręgu nie daje adresu - zostają kontakty.
    rows = [{"judge_id": "100", "province": "MAZOWIECKIE", "config_json": {"email": "obcy@x.pl"}}]
    out = JC.resolve_emails({"100": "Nowak Jan"}, login_rows=rows, contacts=contacts, province="SLASKIE")
    assert out == {"100": ("kontakt@x.pl", JC.SOURCE_CONTACTS)}


def test_dwa_rozne_adresy_pod_jednym_nazwiskiem_to_brak_adresu():
    contacts = [
        {"name": "Jan", "surname": "Nowak", "email": "jeden@x.pl", "isReferee": True},
        {"name": "Jan", "surname": "Nowak", "email": "drugi@x.pl", "isReferee": True},
    ]
    assert JC.resolve_emails({"1": "Nowak Jan"}, login_rows=[], contacts=contacts, province="SLASKIE") == {}


def test_kontakt_z_innego_okregu_odpada():
    contacts = [{"name": "Jan", "surname": "Nowak", "email": "jan@x.pl", "province": "Mazowieckie"}]
    assert JC.resolve_emails({"1": "Nowak Jan"}, login_rows=[], contacts=contacts, province="SLASKIE") == {}
