from app import event_links as L
from app import province_event_rules as R


def test_kod_to_link_a_stary_zapis_nadal_dziala():
    link = R.qr_payload(12, "AbC_def-123456", "https://serwer.example/")
    assert link == "https://serwer.example/e/12/AbC_def-123456"
    assert R.parse_qr(link) == (12, "AbC_def-123456")
    assert R.parse_qr("refhandballapp://e/12/AbC_def-123456") == (12, "AbC_def-123456")
    assert R.parse_qr(link + "?web=1") == (12, "AbC_def-123456")
    assert R.parse_qr("BAZA-EVENT|7|tok") == (7, "tok")
    assert R.qr_payload(7, "tok") == "BAZA-EVENT|7|tok"
    assert R.parse_qr("https://serwer.example/e/12/<script>") is None
    assert R.parse_qr("https://communio.app/join/abc") is None


def test_pliki_weryfikacyjne_ios_i_android():
    aasa = L.apple_app_site_association("TEAM123")
    ids = [d["appIDs"][0] for d in aasa["applinks"]["details"]]
    assert ids == ["TEAM123.com.radzio.RefHandballApp", "TEAM123.com.radzio.RefHandballApp.dev"]
    assert all(d["components"][0]["/"] == "/e/*" for d in aasa["applinks"]["details"])
    keys = L.fingerprints("aa:" * 31 + "bb, zle, " + L.DEV_SHA256)
    assert keys == ["AA:" * 31 + "BB", L.DEV_SHA256]
    links = L.assetlinks([], [L.DEV_SHA256])
    assert [x["target"]["package_name"] for x in links] == ["com.radzio.RefHandballApp.dev"]


def test_zapasowe_przekierowanie_androida():
    intent = L.android_intent(12, "AbC_def-123456")
    assert intent.startswith("intent://e/12/AbC_def-123456#Intent;scheme=refhandballapp;")
    assert "package=" not in intent and intent.endswith(";end")
    assert "S.browser_fallback_url=https%3A%2F%2F" in intent
