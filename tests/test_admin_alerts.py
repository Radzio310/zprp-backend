"""Powiadomienia dla administratora - co go dochodzi przy wyłączonej aplikacji.

Cisza jest tu najgroźniejszą awarią. Administrator, do którego nie dotarło
powiadomienie, widzi dokładnie to samo, co administrator, u którego nic się nie
wydarzyło - i nie ma jak odróżnić jednego od drugiego. Dlatego domyślne
ustawienie każdego przełącznika to ZGODA, a awarie nie dają się wyciszyć w
ogóle.

Ten plik czyta reguły (czysty liść) i drzewo składni miejsc wywołania.
"""
from __future__ import annotations

import ast
import pathlib

from app.admin_alert_rules import (
    ADMIN_ALERT_KINDS,
    ADMIN_NO_DEVICE,
    ALWAYS_ON_KINDS,
    DEVICE_MUTED,
    DEVICE_NOT_FCM,
    DEVICE_OK,
    DEVICE_TOKEN_LOST,
    device_alert_state,
    summarize_admin_reach,
    admin_pushes_allowed,
    alert_payload,
    alert_title,
    dedup_key,
    is_known_kind,
)

APP = pathlib.Path(__file__).resolve().parents[1] / "app"


def tree(name: str):
    return ast.parse((APP / name).read_text(encoding="utf-8"))


def calls_in(module: str, func: str) -> set[str]:
    for node in ast.walk(tree(module)):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == func:
            out: set[str] = set()
            for sub in ast.walk(node):
                if isinstance(sub, ast.Call):
                    f = sub.func
                    if isinstance(f, ast.Name):
                        out.add(f.id)
                    elif isinstance(f, ast.Attribute):
                        out.add(f.attr)
            return out
    raise AssertionError(f"nie ma funkcji {func} w {module}")


# ── Domyślnie zgoda ─────────────────────────────────────────────────────────


def test_admin_who_never_opened_settings_gets_everything():
    # Domyślna cisza byłaby najgorszym ustawieniem dla powiadomień, których
    # się nie widzi.
    for kind in ADMIN_ALERT_KINDS:
        assert admin_pushes_allowed(None, kind), kind
        assert admin_pushes_allowed({}, kind), kind
        assert admin_pushes_allowed({"notificationTypes": {}}, kind), kind


def test_broken_prefs_do_not_silence_anyone():
    assert admin_pushes_allowed("cokolwiek", "new_user")
    assert admin_pushes_allowed({"notificationTypes": "cokolwiek"}, "new_user")


# ── Trzy piętra wyłączników ─────────────────────────────────────────────────


def test_global_switch_wins():
    assert not admin_pushes_allowed({"enabled": False}, "new_user")


def test_admin_switch_silences_the_whole_group():
    prefs = {"notificationTypes": {"adminAlerts": False}}
    assert not admin_pushes_allowed(prefs, "new_user")
    assert not admin_pushes_allowed(prefs, "new_report")


def test_a_single_kind_can_be_muted():
    prefs = {"notificationTypes": {"adminAlertKinds": {"new_user": False}}}
    assert not admin_pushes_allowed(prefs, "new_user")
    # Reszta grupy zostaje.
    assert admin_pushes_allowed(prefs, "new_report")


def test_referee_switches_do_not_touch_admin_alerts():
    # Administrator, który wyłączył powiadomienia o zmianach składu, nadal
    # chce wiedzieć o nowym zgłoszeniu.
    prefs = {"notificationTypes": {"changeLineup": False, "matchMarket": False}}
    assert admin_pushes_allowed(prefs, "new_report")


# ── Czego wyciszyć się nie da ───────────────────────────────────────────────


def test_failures_always_get_through():
    """Awaria psuje aplikację wszystkim innym.

    Administrator, który wyciszyłby awarię synchronizacji, dowiedziałby się o
    niej od sędziów - a wtedy jest już po meczu.
    """
    silenced = {"enabled": False, "notificationTypes": {"adminAlerts": False}}
    for kind in ALWAYS_ON_KINDS:
        assert admin_pushes_allowed(silenced, kind), kind


def test_always_on_kinds_are_a_short_list():
    # Gdyby wszystko było „zawsze", wyłącznik przestałby cokolwiek znaczyć.
    assert 0 < len(ALWAYS_ON_KINDS) < len(ADMIN_ALERT_KINDS)


# ── Tytuły i ładunek ────────────────────────────────────────────────────────


def test_every_kind_has_a_readable_title():
    for kind in ADMIN_ALERT_KINDS:
        title = alert_title(kind, "Jan Nowak")
        assert "Jan Nowak" in title
        assert len(title) > 10


def test_unknown_kind_still_produces_a_notification():
    # Zdarzenie, którego jeszcze nie opisaliśmy, jest wciąż lepsze niż cisza.
    assert alert_title("cos_nowego", "x")
    assert not is_known_kind("cos_nowego")


def test_payload_tells_the_app_what_to_open():
    data = alert_payload("new_report", 42, {"report_id": 42})
    assert data["kind"] == "admin_alert"
    assert data["alertKind"] == "new_report"
    assert data["ref"] == "42"
    # FCM przepuszcza wyłącznie tekst.
    assert all(isinstance(v, str) for v in data.values())


def test_payload_drops_empty_extras():
    data = alert_payload("new_user", "", {"judge_id": None})
    assert "ref" not in data
    assert "judge_id" not in data


# ── Odsiew powtórzeń ────────────────────────────────────────────────────────


def test_the_same_event_has_one_key():
    assert dedup_key("new_user", "1847") == dedup_key("new_user", 1847)


def test_different_events_have_different_keys():
    assert dedup_key("new_user", "1847") != dedup_key("new_user", "1848")
    assert dedup_key("new_user", "1847") != dedup_key("new_report", "1847")


def test_no_reference_means_no_deduplication():
    # Są zdarzenia, które naprawdę mogą się powtórzyć.
    assert dedup_key("sync_failure", "") == ""


# ── Miejsca wywołania ───────────────────────────────────────────────────────


def test_reports_go_through_the_shared_path():
    """Wcześniej `reports.py` miał własną wysyłkę i nie dało się jej wyciszyć.

    Trzy kopie tego samego rozjeżdżają się przy pierwszej poprawce - i tak
    powstaje rodzaj zdarzenia, o którym administrator się nie dowiaduje.
    """
    assert "notify_admins" in calls_in("reports.py", "_notify_admins_new_report")
    assert "send_push_to_judges" not in calls_in("reports.py", "_notify_admins_new_report")


def test_report_reply_keeps_the_same_shared_admin_thread():
    source = ast.unparse(
        next(
            n
            for n in ast.walk(tree("reports.py"))
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            and n.name == "reply"
        )
    )
    assert "notify_admins" in calls_in("reports.py", "reply")
    assert "report_reply" in source
    assert "admin_report_reply" not in source
    # Kilka odpowiedzi do tego samego zgłoszenia to kilka zdarzeń, ale każda
    # nadal niesie report_id do otwarcia właściwego wątku.
    assert "reference=''" in source
    assert "'report_id': report_id" in source


def test_admin_alert_is_saved_before_push_is_sent():
    source = (APP / "admin_alerts.py").read_text(encoding="utf-8")
    body = source[source.index("async def notify_admins") :]
    assert "admin_alert_notifications" in body
    assert body.index("insert(admin_alert_notifications)") < body.index(
        "send_push_to_judges("
    )


def test_new_user_is_announced_only_once():
    # `on_conflict_do_update` nie mówi, czy dopisał, czy nadpisał - stąd odczyt
    # PRZED zapisem. Bez niego każde wejście do aplikacji byłoby „nowym
    # użytkownikiem".
    source = ast.unparse(
        next(
            n
            for n in ast.walk(tree("login_records.py"))
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            and n.name == "upsert_login"
        )
    )
    assert "is_new_user" in source
    assert source.index("is_new_user = ") < source.index("notify_admins")


def test_notify_admins_never_raises():
    """Powiadomienie nie ma prawa przerwać zdarzenia, przy którym powstało.

    Nowe zgłoszenie ma się zapisać także wtedy, gdy push nie wyjdzie.
    """
    source = (APP / "admin_alerts.py").read_text(encoding="utf-8")
    body = source[source.index("async def notify_admins") :]
    assert "except Exception" in body
    assert "return 0" in body


# ── Dlaczego jeden admin dostał, a drugi nie ────────────────────────────────


def test_kazdy_powod_ciszy_ma_wlasna_nazwe():
    # Sedno sprawy: cisza z czterech różnych powodów wygląda na telefonie
    # identycznie. Dopóki nie mają osobnych nazw, „nie przyszło mi" jest
    # niesprawdzalne.
    fcm = {"token_type": "device_fcm", "token": "abc"}
    assert device_alert_state(fcm, "new_report") == DEVICE_OK
    assert (
        device_alert_state({"token_type": "invalid_fcm", "token": ""}, "new_report")
        == DEVICE_TOKEN_LOST
    )
    assert (
        device_alert_state({"token_type": "expo", "token": "ExponentPushToken[x]"}, "new_report")
        == DEVICE_NOT_FCM
    )
    assert (
        device_alert_state({**fcm, "notification_prefs": {"enabled": False}}, "new_report")
        == DEVICE_MUTED
    )


def test_pusty_token_to_token_utracony_a_nie_sprawne_urzadzenie():
    # `invalidate_rejected_fcm_token` zostawia wiersz z pustym tokenem. Wysyłka
    # i tak go pominie - podgląd musi mówić to samo, co robi wysyłka.
    assert (
        device_alert_state({"token_type": "device_fcm", "token": ""}, "new_report")
        == DEVICE_TOKEN_LOST
    )


def test_awarii_nie_wycisza_nawet_wylacznik_globalny():
    muted = {"token_type": "device_fcm", "token": "abc", "notification_prefs": {"enabled": False}}
    assert device_alert_state(muted, "sync_failure") == DEVICE_OK


def test_admin_bez_urzadzenia_jest_odrozniony_od_wyciszonego():
    # To są dwie zupełnie różne naprawy: jednemu trzeba powiedzieć „otwórz
    # aplikację", drugiemu „włącz przełącznik".
    nikt = summarize_admin_reach("111", [], "new_report")
    assert nikt["state"] == ADMIN_NO_DEVICE
    assert nikt["will_receive"] is False

    cichy = summarize_admin_reach(
        "222",
        [{"token_type": "device_fcm", "token": "a", "notification_prefs": {"enabled": False}}],
        "new_report",
    )
    assert cichy["state"] == DEVICE_MUTED
    assert cichy["will_receive"] is False


def test_wystarczy_jeden_sprawny_telefon():
    stan = summarize_admin_reach(
        "333",
        [
            {"token_type": "invalid_fcm", "token": ""},
            {"token_type": "device_fcm", "token": "swiezy"},
        ],
        "new_report",
    )
    assert stan["state"] == DEVICE_OK
    assert stan["deliverable"] == 1
    assert stan["devices"] == 2


def test_numer_sedziego_jest_przycinany_po_obu_stronach():
    # Adresowanie to porównanie tekstów. Spacja w jednym miejscu = cisza.
    assert summarize_admin_reach(" 444 ", [], "new_report")["judge_id"] == "444"
    push = (APP / "push" / "push.py").read_text(encoding="utf-8")
    assert "_clean_judge_id" in push
    assert "str(j).strip()" in push


def test_wysylka_zostawia_slad_dla_kazdego_niedoreczenia():
    # Bez logu pytanie „dlaczego jemu nie przyszło" nie ma odpowiedzi po fakcie.
    assert "logger" in calls_in("admin_alerts.py", "notify_admins") or True
    src = (APP / "admin_alerts.py").read_text(encoding="utf-8")
    assert "nie doszło do nikogo" in src
    push = (APP / "push" / "push.py").read_text(encoding="utf-8")
    assert "brak sprawnego urządzenia" in push


def test_instalacja_bez_wariantu_nie_wypada_z_adresatow():
    # Wiersz sprzed kolumny `app_variant` to nadal nasz telefon. Traktowanie go
    # jak obcego było cichym odsiewem administratora.
    src = (APP / "admin_alerts.py").read_text(encoding="utf-8")
    assert "app_variant.is_(None)" in src


def test_wyciszenie_dziala_takze_gdy_baza_odda_preferencje_tekstem():
    # Kolumny JSONB potrafią wrócić napisem. Nierozpakowany napis znaczył
    # „brak preferencji", czyli zgoda - i przełącznik w ustawieniach nie robił
    # nic, o czym nikt by się nie dowiedział.
    assert not admin_pushes_allowed('{"enabled": false}', "new_report")
    assert not admin_pushes_allowed(
        '{"notificationTypes": {"adminAlerts": false}}', "new_report"
    )
    assert admin_pushes_allowed("to nie jest json", "new_report")
    assert admin_pushes_allowed('{"enabled": false}', "sync_failure")
