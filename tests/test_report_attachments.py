"""Zdjęcia w wiadomościach zgłoszeń: kilka na raz, stare pole i powiadomienie.

`app.reports` żąda żywej bazy przy imporcie, więc reguły siedzą w liściu
`app.report_attachments`, a okablowanie trasy czytamy ze źródła.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

from app.report_attachments import (
    ARCHIVED,
    MAX_ATTACHMENTS,
    AttachmentError,
    archived_values,
    last_message_preview,
    message_attachments,
    normalize_attachments,
    notification_line,
    own_upload_path,
    photo_label,
)

HEX = "0123456789abcdef0123456789abcdef"


def upload(report_id=7, n=0, ext="jpg"):
    return f"/static/reports/{report_id}_{HEX[:-2]}{n:02d}.{ext}"


# ── powiadomienie: nigdy pusty cytat ─────────────────────────────────────


def test_samo_zdjecie_nie_daje_pustego_cytatu():
    # Dokładnie ten błąd: administrator dostawał `„”`.
    line = notification_line("", 1)
    assert "„”" not in line
    assert line == "📷 Zdjęcie"


@pytest.mark.parametrize(
    "count, label",
    [(1, "📷 Zdjęcie"), (2, "📷 2 zdjęcia"), (4, "📷 4 zdjęcia"), (5, "📷 5 zdjęć"),
     (12, "📷 12 zdjęć"), (22, "📷 22 zdjęcia"), (0, "")],
)
def test_polska_odmiana_liczby_zdjec(count, label):
    assert photo_label(count) == label


def test_tekst_i_zdjecia_to_cytat_plus_linia_ze_zdjeciami():
    assert notification_line("Zobacz ekran", 3) == "„Zobacz ekran”\n📷 3 zdjęcia"


def test_sam_tekst_zostaje_cytatem_jak_dotad():
    assert notification_line("  Cześć  ", 0) == "„Cześć”"


def test_dlugi_tekst_jest_przyciety_z_wielokropkiem():
    line = notification_line("a" * 200, 0)
    assert line == "„" + "a" * 90 + "…”"


def test_pusta_wiadomosc_bez_zdjec_ma_zapasowy_opis():
    assert notification_line("   ", 0) == "💬 Nowa wiadomość"


def test_karta_watku_pokazuje_zdjecie_zamiast_pustki():
    assert last_message_preview("", 2) == "📷 2 zdjęcia"
    assert last_message_preview("Hej", 2) == "Hej"
    assert last_message_preview("", 0) is None


# ── kilka zdjęć i zgodność ze starą aplikacją ───────────────────────────


def test_stara_aplikacja_z_jednym_zdjeciem_dziala_jak_dotad():
    assert normalize_attachments(7, upload(), None) == [upload()]


def test_nowa_aplikacja_wysyla_liste_i_pierwsze_w_starym_polu():
    urls = [upload(n=i) for i in range(3)]
    assert normalize_attachments(7, urls[0], urls) == urls


def test_kolejnosc_zachowana_i_bez_powtorzen():
    a, b = upload(n=1), upload(n=2)
    assert normalize_attachments(7, a, [b, a, b]) == [b, a]


def test_obcy_adres_jest_odrzucony_z_powodem():
    with pytest.raises(AttachmentError) as err:
        normalize_attachments(7, "https://zly.example/foto.jpg", None)
    assert "Wybierz je jeszcze raz" in str(err.value)


def test_zdjecie_z_cudzego_zgloszenia_jest_odrzucone():
    with pytest.raises(AttachmentError):
        normalize_attachments(7, None, [upload(report_id=8)])


def test_limit_zdjec_na_wiadomosc():
    ok = [upload(n=i) for i in range(MAX_ATTACHMENTS)]
    assert len(normalize_attachments(7, None, ok)) == MAX_ATTACHMENTS
    with pytest.raises(AttachmentError) as err:
        normalize_attachments(7, None, ok + [upload(n=99)])
    assert str(MAX_ATTACHMENTS) in str(err.value)


@pytest.mark.parametrize("ext", ["jpg", "JPEG", "png", "webp", "heic"])
def test_rozszerzenia_z_trasy_wgrywania(ext):
    assert own_upload_path(upload(ext=ext), 7)


def test_rozszerzenie_spoza_listy_nie_przechodzi():
    assert not own_upload_path(upload(ext="gif"), 7)


# ── odczyt zapisanych wiadomości ─────────────────────────────────────────


def test_stara_wiadomosc_z_jednym_polem_daje_liste():
    assert message_attachments({"attachment_url": upload(), "attachment_urls": None}) == [upload()]


def test_jsonb_jako_napis_tez_jest_lista():
    # JSONB potrafi wrócić z bazy jako napis.
    row = {"attachment_url": upload(n=0), "attachment_urls": f'["{upload(n=0)}", "{upload(n=1)}"]'}
    assert message_attachments(row) == [upload(n=0), upload(n=1)]


def test_wiadomosc_bez_zdjec():
    assert message_attachments({"attachment_url": None, "attachment_urls": None}) == []


def test_sprzatanie_archiwizuje_kazde_zdjecie_z_listy():
    row = {"attachment_url": upload(n=0), "attachment_urls": [upload(n=0), upload(n=1)]}
    assert archived_values(row) == {"attachment_url": ARCHIVED, "attachment_urls": [ARCHIVED, ARCHIVED]}


def test_sprzatanie_starej_wiadomosci_nie_zaklada_listy():
    assert archived_values({"attachment_url": upload(), "attachment_urls": None}) == {"attachment_url": ARCHIVED}


# ── okablowanie w app/reports.py ────────────────────────────────────────

REPORTS = ast.parse(
    (pathlib.Path(__file__).resolve().parents[1] / "app" / "reports.py").read_text(encoding="utf-8")
)


def _calls(func: str) -> set[str]:
    for node in ast.walk(REPORTS):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == func:
            out: set[str] = set()
            for sub in ast.walk(node):
                if isinstance(sub, ast.Call):
                    f = sub.func
                    out.add(f.id if isinstance(f, ast.Name) else getattr(f, "attr", ""))
            return out
    raise AssertionError(f"nie ma funkcji {func}")


def test_odpowiedz_sklada_powiadomienie_z_linii_bez_pustego_cytatu():
    calls = _calls("reply")
    assert {"normalize_attachments", "notification_line"} <= calls


@pytest.mark.parametrize("func", ["_cleanup_old_attachments", "delete_report", "_msg_to_item"])
def test_kazde_miejsce_z_plikami_zna_liste_zdjec(func):
    # Tylko pierwsze zdjęcie w starym polu = reszta zostaje na wolumenie
    # albo znika z wątku.
    assert "message_attachments" in _calls(func)
