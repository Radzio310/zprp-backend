"""Tryb prezentacji - JAWNA lista tras zapisu i odczytów z nakładką.

Nie ma tu reguły „każdy POST": wiele POST-ów to odczyty (match-form, rights,
candidates, suggest, forecast, pdf szkicu...) i te MUSZĄ przejść do serwera
bez zmian. Trasa spoza listy idzie zawsze do prawdziwego handlera.

Każdy wpis zapisu: (metoda, wzorzec ścieżki, obszar, symulator, kod sukcesu,
skąd wiemy, kto pyta). Symulatory: `app/presentation_sim.py` (nazwy z `SIMS`).

`identity`:
  * "jwt"  - wystarczy token BAZA (Bearer);
  * "body" - także treść żądania: zaszyfrowane RSA `username`/`judge_id`
             (trasy /zprp/*, niedyspozycje ZPRP, ogłoszenia - multipart) albo
             jawne `judge_id`. Treść czytamy TYLKO, gdy tryb jest włączony
             i trasa jest na tej liście. Dotyczy też odczytów (match-form);
  * "synthetic" - token BAZA albo udawany numer w ścieżce (`{id}` >=
             `SYNTH_BASE`): takiego wiersza nie ma w bazie, więc żądanie bez
             tokenu (aplikacja usuwa ocenę gołym `fetch`) i tak dotyczy tylko
             nakładki. Prawdziwy numer bez tokenu idzie do handlera jak dotąd.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

ID = r"(?P<id>\d+)"
SEG = r"[^/]+"


@dataclass(frozen=True)
class WriteRoute:
    method: str
    pattern: "re.Pattern[str]"
    area: str
    sim: str
    status: int = 200
    identity: str = "jwt"
    label: str = ""


@dataclass(frozen=True)
class ReadRoute:
    method: str
    pattern: "re.Pattern[str]"
    area: str
    merge: str
    identity: str = "jwt"


def _w(method: str, path: str, area: str, sim: str, status: int = 200, identity: str = "jwt", label: str = "") -> WriteRoute:
    return WriteRoute(method, re.compile("^" + path + "/?$"), area, sim, status, identity, label or f"{method} {path}")


def _r(method: str, path: str, area: str, merge: str, identity: str = "jwt") -> ReadRoute:
    return ReadRoute(method, re.compile("^" + path + "/?$"), area, merge, identity)


MM = "/match-market"
CREW = "/match-market/crew-offers"
PA = "/province/assignment"
PS = "/province/settlements"
PE = "/province-events"
DF = "/district-forms"
ANN = "/silesia/announcements"
YR = "/young_referees/ratings"

WRITE_ROUTES: Tuple[WriteRoute, ...] = (
    # ── giełda ─────────────────────────────────────────────────────────────
    _w("POST", f"{MM}/offers", "market", "market_create_offer", 201, label="Wystawienie meczu na giełdę"),
    _w("DELETE", f"{MM}/offers/{ID}", "market", "market_withdraw_offer", label="Wycofanie oferty"),
    _w("POST", f"{MM}/offers/{ID}/listing-approval/approve", "market", "market_listing_approve", label="Zgoda na pilne wystawienie"),
    _w("POST", f"{MM}/offers/{ID}/listing-approval/reject", "market", "market_listing_reject", label="Odmowa pilnego wystawienia"),
    _w("POST", f"{MM}/offers/{ID}/claims", "market", "market_create_claim", 201, label="Zgłoszenie na mecz"),
    _w("DELETE", f"{MM}/offers/{ID}/claims/me", "market", "market_withdraw_claim", label="Wycofanie zgłoszenia"),
    _w("POST", f"{MM}/offers/{ID}/reject", "market", "market_reject", label="Odrzucenie wymiany"),
    _w("POST", f"{MM}/offers/{ID}/approve", "market", "market_approve", label="Zatwierdzenie wymiany (bez ZPRP)"),
    _w("PUT", f"{MM}/admin/notification-preferences", "market", "market_admin_prefs", label="Powiadomienia admina giełdy"),
    _w("POST", f"{MM}/admin/provinces/(?P<province>{SEG})/offers/{ID}/withdraw", "market", "market_admin_withdraw", label="Zdjęcie oferty przez admina"),
    _w("POST", f"{MM}/admin/provinces/(?P<province>{SEG})/notification-test/send", "market", "market_notification_test", label="Test powiadomienia giełdy"),
    _w("PUT", f"{MM}/admin/provinces/(?P<province>{SEG})", "market", "market_admin_province", label="Ustawienia giełdy okręgu"),
    # giełda obsadowego
    _w("POST", CREW, "market", "crew_create", 201, label="Oferta obsadowego"),
    _w("POST", f"{CREW}/{ID}/claims", "market", "crew_claim", 201, label="Zgłoszenie na ofertę obsadowego"),
    _w("DELETE", f"{CREW}/{ID}/claims/me", "market", "crew_withdraw_claim", label="Wycofanie zgłoszenia (obsadowy)"),
    _w("POST", f"{CREW}/{ID}/assign", "market", "crew_assign", label="Przydział z giełdy do kolejki Obsady"),
    _w("POST", f"{CREW}/{ID}/claims/(?P<cid>\\d+)/unassign", "market", "crew_unassign", label="Cofnięcie przydziału"),
    _w("DELETE", f"{CREW}/{ID}", "market", "crew_withdraw", label="Wycofanie oferty obsadowego"),
    _w("POST", f"{CREW}/{ID}/invite", "market", "crew_invite", 201, label="Zaproszenie sugerowanego sędziego"),
    # ── obsada i wysyłka do ZPRP ───────────────────────────────────────────
    _w("POST", "/zprp/obsada/save", "obsada", "obsada_save", identity="body", label="Zapis obsady w ZPRP"),
    _w("POST", "/zprp/obsada/save-hall", "obsada", "obsada_save_hall", identity="body", label="Zmiana hali w ZPRP"),
    _w("POST", "/zprp/obsada/save-date", "obsada", "obsada_save_date", identity="body", label="Zmiana terminu w ZPRP"),
    _w("POST", "/zprp/obsada/table-officials/save", "obsada", "obsada_table_save", identity="body", label="Stolikowy w ZPRP"),
    _w("POST", "/zprp/obsada/table-officials/clear", "obsada", "obsada_table_clear", identity="body", label="Usunięcie stolikowego w ZPRP"),
    _w("PUT", f"{PA}/draft", "obsada", "obsada_draft", label="Szkic kolejki Obsady"),
    _w("PUT", "/province/me/availability", "obsada", "obsada_me_availability", label="Moja dyspozycyjność"),
    _w("PUT", f"{PA}/mentor-pairs", "obsada", "ok_success", label="Para mentorska"),
    _w("PUT", f"{PA}/judges/(?P<judge_id>{SEG})", "obsada", "obsada_judge_settings", label="Parametry sędziego dla Automatu"),
    _w("POST", f"{PA}/judges/(?P<judge_id>{SEG})/blocks", "obsada", "ok_created_id", label="Wykluczenie pary"),
    _w("DELETE", f"{PA}/blocks/{ID}", "obsada", "ok_success", label="Zdjęcie wykluczenia pary"),
    _w("POST", f"{PA}/judges/(?P<judge_id>{SEG})/pauses", "obsada", "ok_created_id", label="Przerwa sędziego"),
    _w("DELETE", f"{PA}/pauses/{ID}", "obsada", "ok_success", label="Zdjęcie przerwy"),
    _w("POST", f"{PA}/judges/(?P<judge_id>{SEG})/pairs", "obsada", "ok_success", label="Para sędziowska"),
    _w("DELETE", f"{PA}/judges/(?P<judge_id>{SEG})/pairs", "obsada", "ok_success", label="Rozwiązanie pary"),
    _w("POST", f"{PA}/manual", "obsada", "ok_success", label="Mecz układany ręcznie"),
    _w("PUT", f"{PA}/clubs/bulk", "obsada", "ok_success", label="Ustawienia klubów (grupowo)"),
    _w("PUT", f"{PA}/clubs/(?P<club_id>{SEG})", "obsada", "ok_success", label="Ustawienia obsadowe klubu"),
    _w("POST", PA, "obsada", "obsada_auto_dry_run", label="Automat (przebieg bez zapisu)"),
    _w("POST", f"{PA}/runs/{ID}/applied", "obsada", "ok_success", label="Ślad publikacji przebiegu"),
    _w("POST", f"{PA}/runs/{ID}/undone", "obsada", "obsada_runs_undone", label="Ślad cofnięcia"),
    _w("POST", "/assignment-drafts", "obsada", "ok_created_id", label="Szkic obsady (stary)"),
    _w("PUT", f"/assignment-drafts/{ID}", "obsada", "ok_true", label="Szkic obsady (stary)"),
    _w("DELETE", f"/assignment-drafts/{ID}", "obsada", "ok_true", label="Szkic obsady (stary)"),
    # ── rozliczenia i potwierdzenia ────────────────────────────────────────
    _w("PUT", f"/province-travel/(?P<judge_id>{SEG})", "settlements", "ok_success_echo", label="Przejazdy sędziego"),
    _w("PATCH", f"/province-travel/(?P<judge_id>{SEG})/season", "settlements", "ok_success_echo", label="Przejazdy sędziego (sezon)"),
    _w("PUT", f"{PS}/modules/(?P<province>{SEG})/(?P<module>{SEG})", "settlements", "ok_success_echo", label="Moduł okręgu"),
    _w("PUT", f"{PS}/accounting/codes", "settlements", "ok_success_echo", label="Kody księgowe"),
    _w("PUT", f"{PS}/exclusions", "settlements", "ok_success_echo", label="Wykluczenia z rozliczeń"),
    _w("POST", f"{PS}/homes", "settlements", "ok_success_echo", label="Miejsce zamieszkania"),
    _w("POST", f"{PS}/homes/batch", "settlements", "ok_success_echo", label="Miejsca zamieszkania (kilka)"),
    _w("DELETE", f"{PS}/homes/{ID}", "settlements", "ok_success", label="Usunięcie miejsca zamieszkania"),
    _w("PUT", f"{PS}/periods", "settlements", "ok_success_echo", label="Okresy rozliczeń"),
    _w("DELETE", f"{PS}/register", "settlements", "ok_success", label="Usunięcie dokumentu z rejestru"),
    _w("PUT", f"{PS}/register/settings", "settlements", "ok_success_echo", label="Ustawienia rejestru"),
    _w("PUT", f"{PS}/register/doc-settings", "settlements", "ok_success_echo", label="Ustawienia dokumentu"),
    _w("PUT", f"{PS}/register/doc-extra", "settlements", "ok_success_echo", label="Dodatki dokumentu"),
    _w("PUT", f"{PS}/splits", "settlements", "ok_success_echo", label="Podział rozliczenia"),
    _w("DELETE", f"{PS}/splits", "settlements", "ok_success", label="Usunięcie podziału"),
    # Oficjalny wydruk zajmuje numer w rejestrze: w trybie idzie jako szkic.
    _w("POST", f"{PS}/pdf/zestawienie", "settlements", "pdf_as_draft", label="Zestawienie (szkic zamiast oficjalnego)"),
    _w("POST", f"{PS}/pdf/przejazdy", "settlements", "pdf_as_draft", label="Przejazdy (szkic zamiast oficjalnego)"),
    _w("POST", "/province/invoices/upload", "settlements", "ok_success", label="Wczytanie faktur"),
    _w("POST", f"/province/invoices/batches/{ID}/approve", "settlements", "ok_success_echo", label="Zatwierdzenie faktur"),
    _w("POST", f"/province/invoices/batches/{ID}/reopen", "settlements", "ok_success_echo", label="Przywrócenie pozycji faktur"),
    _w("POST", "/province/invoices/items/confirm", "settlements", "ok_success_echo", label="Potwierdzenie płatności"),
    _w("POST", "/province/invoices/items/unconfirm", "settlements", "ok_success_echo", label="Cofnięcie potwierdzenia"),
    _w("POST", "/province/invoices/items/trash", "settlements", "ok_success_echo", label="Faktury do kosza"),
    _w("POST", "/province/invoices/items/restore", "settlements", "ok_success_echo", label="Faktury z kosza"),
    _w("POST", "/province/invoices/items/purge", "settlements", "ok_success_echo", label="Trwałe usunięcie faktur"),
    _w("POST", "/match-bombs", "settlements", "ok_created_id", 201, label="Bomba"),
    _w("DELETE", f"/match-bombs/{ID}", "settlements", "ok_success", label="Usunięcie bomby"),
    _w("POST", f"/match-bombs/{ID}/void", "settlements", "ok_success_echo", label="Unieważnienie bomby"),
    _w("POST", "/match-bombs/manual", "settlements", "ok_created_id", 201, label="Bomba ręczna"),
    _w("PUT", f"/match-bombs/{ID}/penalty", "settlements", "ok_success_echo", label="Kara za nieobecność"),
    _w("PUT", f"{PS}/bombs/{ID}/penalty", "settlements", "ok_success_echo", label="Kara za nieobecność (panel)"),
    _w("PUT", f"{PS}/bombs/penalty-scale", "settlements", "ok_success_echo", label="Taryfikator kar"),
    # ── niedyspozycje ──────────────────────────────────────────────────────
    _w("POST", "/judge/offtimes/create", "offtimes", "offtime_zprp_create", identity="body", label="Niedyspozycja w ZPRP"),
    _w("POST", "/judge/offtimes/update", "offtimes", "offtime_zprp_update", identity="body", label="Zmiana niedyspozycji w ZPRP"),
    _w("POST", "/judge/offtimes/delete", "offtimes", "offtime_zprp_delete", identity="body", label="Usunięcie niedyspozycji w ZPRP"),
    _w("POST", "/silesia/offtimes/set", "offtimes", "offtime_silesia_set", identity="body", label="Niedyspozycje okręgu"),
    _w("DELETE", f"/silesia/offtimes/(?P<enc>{SEG})", "offtimes", "no_content", 204, identity="body", label="Usunięcie niedyspozycji okręgu"),
    _w("POST", "/silesia/offtimes/assigned", "offtimes", "offtime_assigned_create", label="Niedyspozycja wpisana sędziemu"),
    _w("PATCH", f"/silesia/offtimes/assigned/(?P<item>{SEG})", "offtimes", "offtime_assigned_update", label="Zmiana wpisanej niedyspozycji"),
    _w("DELETE", f"/silesia/offtimes/assigned/(?P<item>{SEG})", "offtimes", "ok_true", label="Usunięcie wpisanej niedyspozycji"),
    _w("POST", "/partner-offtimes", "offtimes", "partner_offtime_upsert", 201, label="Niedyspozycje partnera"),
    _w("PUT", f"/partner-offtimes/(?P<judge_id>{SEG})", "offtimes", "partner_offtime_upsert", label="Niedyspozycje partnera"),
    _w("DELETE", f"/partner-offtimes/(?P<judge_id>{SEG})", "offtimes", "ok_success", label="Usunięcie partnera"),
    _w("PUT", "/admin/zprp-unavailability/config", "offtimes", "ok_success_echo", label="Konfiguracja niedyspozycji ZPRP"),
    # ── ogłoszenia ─────────────────────────────────────────────────────────
    _w("POST", f"{ANN}/create", "announcements", "ann_create", 201, identity="body", label="Nowe ogłoszenie"),
    _w("PUT", f"{ANN}/{ID}", "announcements", "ann_update", identity="body", label="Zmiana ogłoszenia"),
    _w("POST", f"{ANN}/{ID}/reaction", "announcements", "ann_reaction", identity="body", label="Reakcja na ogłoszenie"),
    _w("POST", f"{ANN}/{ID}/comment", "announcements", "ann_comment", identity="body", label="Komentarz"),
    _w("POST", f"{ANN}/{ID}/comment_pin", "announcements", "ann_comment_edit", identity="body", label="Przypięcie komentarza"),
    _w("POST", f"{ANN}/{ID}/comment_delete", "announcements", "ann_comment_edit", identity="body", label="Usunięcie komentarza"),
    _w("DELETE", f"{ANN}/{ID}", "announcements", "ann_delete", 204, identity="body", label="Usunięcie ogłoszenia"),
    # ── wydarzenia i formularze okręgu ─────────────────────────────────────
    _w("POST", f"{PE}/v2", "events", "event_create", label="Nowe wydarzenie"),
    _w("PATCH", f"{PE}/v2/{ID}", "events", "event_patch", label="Zmiana wydarzenia"),
    _w("POST", f"{PE}/{ID}/cancel", "events", "ok_true", label="Odwołanie wydarzenia"),
    _w("POST", f"{PE}/{ID}/uncancel", "events", "ok_true", label="Przywrócenie wydarzenia"),
    _w("POST", f"{PE}/{ID}/trash", "events", "event_trash", label="Wydarzenie do kosza"),
    _w("POST", f"{PE}/restore", "events", "event_restore", label="Wydarzenie z kosza"),
    _w("POST", f"{PE}/templates", "events", "ok_created_id", label="Szablon wydarzenia"),
    _w("DELETE", f"{PE}/templates/{ID}", "events", "ok_true", label="Usunięcie szablonu"),
    _w("POST", f"{PE}/{ID}/rsvp", "events", "event_rsvp", label="Będę / nie będę"),
    _w("PUT", f"{PE}/{ID}/attendance/v2", "events", "event_attendance", label="Obecność"),
    _w("POST", f"{PE}/{ID}/checkin/open", "events", "event_checkin_open", label="Kod obecności"),
    _w("POST", f"{PE}/checkin", "events", "event_checkin", label="Potwierdzenie obecności kodem"),
    _w("POST", f"{PE}/{ID}/title-image", "events", "ok_true", label="Grafika wydarzenia"),
    _w("POST", PE, "events", "ok_created_id", label="Nowe wydarzenie (stare)"),
    _w("PATCH", f"{PE}/{ID}", "events", "event_legacy_item", label="Zmiana wydarzenia (stara)"),
    _w("DELETE", f"{PE}/{ID}", "events", "ok_success", label="Usunięcie wydarzenia (stare)"),
    _w("PATCH", f"{PE}/{ID}/attendance", "events", "event_legacy_item", label="Obecność (stara)"),
    _w("POST", f"{DF}/pair/(?P<code>{SEG})/approve", "events", "ok_true", label="Formularz: parowanie"),
    _w("POST", DF, "events", "ok_created_id", 200, label="Nowy formularz"),
    _w("PATCH", f"{DF}/{ID}", "events", "ok_true", label="Zmiana formularza"),
    _w("POST", f"{DF}/{ID}/(?P<action>publish|close|reopen|archive|unarchive|restore|duplicate|remind|silent|web|web/rotate|invite-to-event|public-link)", "events", "ok_true", label="Formularz: akcja"),
    _w("DELETE", f"{DF}/{ID}", "events", "ok_true", label="Usunięcie formularza"),
    _w("DELETE", f"{DF}/{ID}/public-link", "events", "ok_true", label="Formularz: link publiczny"),
    _w("PUT", f"{DF}/{ID}/me", "events", "ok_true", label="Odpowiedź na formularz"),
    _w("POST", f"{DF}/{ID}/me/confirm", "events", "ok_true", label="Potwierdzenie odpowiedzi"),
    _w("PATCH", f"{DF}/{ID}/rows/(?P<judge_id>{SEG})", "events", "ok_true", label="Formularz: wiersz sędziego"),
    _w("POST", f"{DF}/{ID}/rows/(?P<judge_id>{SEG})/clear", "events", "ok_true", label="Formularz: wyczyszczenie wiersza"),
    _w("POST", f"{DF}/{ID}/rows/bulk", "events", "ok_true", label="Formularz: zmiany grupowe"),
    _w("POST", f"{DF}/{ID}/uploads", "events", "ok_true", label="Formularz: plik"),
    # ── oceny młodych sędziów ──────────────────────────────────────────────
    _w("POST", YR, "ratings", "rating_create", 201, label="Ocena młodego sędziego"),
    _w("PUT", f"{YR}/{ID}", "ratings", "rating_update", identity="synthetic", label="Zmiana oceny młodego sędziego"),
    _w("DELETE", f"{YR}/{ID}", "ratings", "rating_delete", identity="synthetic", label="Usunięcie oceny młodego sędziego"),
)

READ_ROUTES: Tuple[ReadRoute, ...] = (
    _r("GET", f"{MM}/offers", "market", "merge_market_list"),
    _r("GET", f"{MM}/offers/{ID}", "market", "merge_market_detail"),
    _r("GET", f"{MM}/my-matches", "market", "merge_my_matches"),
    _r("POST", f"{MM}/my-matches", "market", "merge_my_matches"),
    _r("POST", f"{MM}/my-matches/recheck", "market", "merge_my_matches"),
    _r("GET", CREW, "market", "merge_crew_list"),
    _r("GET", f"{CREW}/{ID}", "market", "merge_crew_detail"),
    _r("GET", f"{PA}/draft", "obsada", "merge_draft"),
    _r("GET", f"{PA}/bootstrap", "obsada", "merge_bootstrap"),
    # obsada po udawanym zapisie (nakładka `lineup`, `app/presentation_lineup.py`)
    _r("GET", "/province/assignments", "obsada", "merge_assignments_list"),
    _r("GET", f"/province/assignments/(?P<match_id>{SEG})", "obsada", "merge_assignments_detail"),
    _r("GET", "/province/obsada-view/data", "obsada", "merge_obsada_view"),
    _r("GET", "/province/obsada-view/changes", "obsada", "merge_obsada_changes"),
    _r("POST", "/zprp/obsada/match-form", "obsada", "merge_match_form", identity="body"),
    _r("GET", ANN, "announcements", "merge_announcements"),
    _r("GET", f"{PE}/feed", "events", "merge_event_feed"),
    _r("GET", f"{PE}/item/{ID}", "events", "merge_event_item"),
    _r("GET", YR, "ratings", "merge_ratings_list"),
    _r("GET", f"{YR}/{ID}", "ratings", "merge_rating_detail", identity="synthetic"),
)


def match_write(method: str, path: str) -> Optional[Tuple[WriteRoute, Dict[str, str]]]:
    m = method.upper()
    for route in WRITE_ROUTES:
        if route.method != m:
            continue
        hit = route.pattern.match(path)
        if hit:
            return route, {k: v for k, v in hit.groupdict().items() if v is not None}
    return None


def match_read(method: str, path: str) -> Optional[Tuple[ReadRoute, Dict[str, str]]]:
    m = method.upper()
    for route in READ_ROUTES:
        if route.method != m:
            continue
        hit = route.pattern.match(path)
        if hit:
            return route, {k: v for k, v in hit.groupdict().items() if v is not None}
    return None


def route_table() -> List[Dict[str, str]]:
    """Tabela do dokumentacji i diagnostyki."""
    return [
        {"method": r.method, "path": r.pattern.pattern, "area": r.area, "sim": r.sim, "label": r.label}
        for r in WRITE_ROUTES
    ] + [
        {"method": r.method, "path": r.pattern.pattern, "area": r.area, "sim": r.merge, "label": "odczyt z nakładką"}
        for r in READ_ROUTES
    ]
