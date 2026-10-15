from datetime import datetime, timedelta, timezone

import pytest

from app.pod_reka_login_rules import (
    AttemptLimiter,
    LoginError,
    check_scope,
    classify_login_response,
    client_key,
    decode_html,
    encode_login_form,
    looks_like_login_page,
    merge_cookies,
)

CLUB_SCOPE = {"account_type": "club", "active": True, "club_id": "0042", "team_ids": ["1"], "display_name": "Klub"}


def test_formularz_w_iso_8859_2_i_znak_spoza_strony_kodowej():
    assert "login=ad%B1" in encode_login_form("adą", "x")  # ą = 0xB1
    with pytest.raises(LoginError) as err:
        encode_login_form("ok", "hasło😀")
    assert err.value.code == "bad_credentials" and err.value.status == 401


def test_dekodowanie_html_wg_charsetu_i_nieznana_nazwa():
    raw = "Zalogowany: Łódź".encode("iso-8859-2")
    assert decode_html(raw, "text/html; charset=iso-8859-2") == "Zalogowany: Łódź"
    assert decode_html(raw, "text/html") == "Zalogowany: Łódź"
    assert decode_html(raw, "text/html; charset=nie-ma-takiego") == "Zalogowany: Łódź"
    assert decode_html("Łódź".encode("utf-8"), 'text/html; charset="utf-8"') == "Łódź"


def test_klasyfikacja_odpowiedzi_logowania():
    classify_login_response("/index.php", 200, "<html>panel</html>")  # sukces: bez wyjątku

    def code(path, status, html):
        with pytest.raises(LoginError) as err:
            classify_login_response(path, status, html)
        return err.value.code

    assert code("/login.php", 200, "Nieznany użytkownik") == "bad_credentials"
    assert code("/login.php", 200, "Spróbuj ponownie") == "bad_credentials"
    assert code("/zle.php", 200, '<input name="login"><input name="haslo">') == "bad_credentials"
    assert code("/inna.php", 200, "<html>coś zupełnie innego</html>") == "unexpected_response"
    assert code("/login.php", 502, "Bad gateway") == "upstream_unavailable"
    assert code("/index.php", 503, "") == "upstream_unavailable"


def test_strona_logowania_nie_myli_sie_z_formularzem_zmiany_hasla():
    assert looks_like_login_page('<input name="login"><input type=password name="haslo">')
    assert not looks_like_login_page("<form action='login.php'><input name='haslo'></form>")


def test_zakres_konta_klubowego():
    check_scope(CLUB_SCOPE)

    def code(scope, html=""):
        with pytest.raises(LoginError) as err:
            check_scope(scope, relogin_html=html)
        return err.value.code

    assert code({**CLUB_SCOPE, "account_type": "unknown"}) == "not_club_account"
    assert code({**CLUB_SCOPE, "account_type": "unknown"}, '<input name="login"><input name="haslo">') == "session_expired"
    assert code({**CLUB_SCOPE, "active": False}) == "inactive_account"
    assert code({**CLUB_SCOPE, "team_ids": []}) == "no_teams"
    assert code({**CLUB_SCOPE, "club_id": ""}) == "no_teams"


def test_ciasteczka_z_przekierowan_sa_scalane():
    assert merge_cookies({"PHPSESSID": "a"}, {"PHPSESSID": "b", "x": "1"}) == {"PHPSESSID": "b", "x": "1"}


def test_limit_prob_zlicza_tylko_nieudane_i_resetuje_sie_po_sukcesie():
    limiter = AttemptLimiter(limit=2, window=timedelta(minutes=10))
    t0 = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)
    limiter.fail("ip:1", "user:a", now=t0)
    assert not limiter.blocked("ip:1", "user:a", now=t0)
    limiter.fail("ip:1", "user:a", now=t0)
    assert limiter.blocked("ip:1", now=t0)
    assert limiter.blocked("ip:2", "user:a", now=t0)  # ten sam login z innego adresu
    assert not limiter.blocked("ip:1", now=t0 + timedelta(minutes=11))
    limiter.success("ip:1", "user:a")
    assert not limiter.blocked("ip:1", "user:a", now=t0)


def test_adres_klienta_z_naglowka_proxy():
    assert client_key("203.0.113.5, 10.0.0.1", "10.0.0.2") == "203.0.113.5"
    assert client_key("", "10.0.0.2") == "10.0.0.2"
    assert client_key("", "") == "unknown"


def test_blad_ma_tekst_i_kod():
    body = LoginError("rate_limited").body()
    assert body["code"] == "rate_limited" and "prób" in body["detail"]
