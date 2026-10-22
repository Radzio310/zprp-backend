from app.seed_province_emails import SEED, merge_district, merge_dw
from app.zprp_accounts import normalize_province


def test_dw_zastepuje_liste_okregu():
    cur = {"SLASKIE": ["stary@x.pl", "drugi@x.pl"], "INNE": ["a@b.pl"]}
    out = merge_dw(cur, SEED, normalize_province)
    assert out["SLASKIE"] == ["artur_jedrycha@interia.pl"]
    assert out["INNE"] == ["a@b.pl"]
    assert out["LODZKIE"] == ["wojciechkulinski82@gmail.com"]
    assert len(out) == 17


def test_okreg_tylko_do_pustych():
    cur = {"SLASKIE": ["jest@x.pl"], "LUBELSKIE": []}
    out = merge_district(cur, SEED, normalize_province)
    assert "SLASKIE" not in out
    assert out["LUBELSKIE"] == ["lublin@zprp.org.pl"]
    assert out["MALOPOLSKIE"] == ["biuro@mzpr.pl"]
    assert len(out) == 15


def test_adresy_male_litery_bez_spacji():
    assert all(a == a.strip().lower() for p in SEED.values() for a in p)
