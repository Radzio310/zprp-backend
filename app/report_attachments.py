# app/report_attachments.py
#
# Zdjęcia w wiadomościach zgłoszeń - czysty liść, bez bazy i FastAPI, żeby
# reguły dało się testować bez Postgresa (`app.reports` żąda bazy przy imporcie).
#
# DWA POLA NA JEDNO ZDJĘCIE. Do 11.09.2026 wiadomość niosła co najwyżej jedno
# zdjęcie w `attachment_url`. Od teraz wszystkie leżą w `attachment_urls`,
# a `attachment_url` dalej trzyma PIERWSZE - starsze wersje aplikacji czytają
# tylko tamto pole i zobaczą przynajmniej jedno zdjęcie zamiast pustego dymka.
#
# PUSTY CYTAT. Wiadomość z samym zdjęciem ma pustą treść, a powiadomienie dla
# administratora składało się z `„{treść}”`, więc przychodziło jako `„”`.
# Druga linia powiadomienia bierze się teraz z `notification_line`.

from __future__ import annotations

import json
import re
from typing import Any, List, Mapping, Optional

#: Znacznik pliku sprzątniętego po 60 dniach (patrz `_cleanup_old_attachments`).
ARCHIVED = "__archived__"

#: Ile zdjęć zmieści jedna wiadomość. Tyle samo pozwala wybrać aplikacja.
MAX_ATTACHMENTS = 10

_EXTENSIONS = "jpg|jpeg|png|webp|heic"


class AttachmentError(ValueError):
    """Zdjęcie, którego nie przyjmujemy - komunikat idzie wprost do człowieka."""


def _as_list(value: Any) -> list:
    """Lista z czegoś, co bywa listą, napisem JSON albo pojedynczym adresem.

    JSONB potrafi wrócić z bazy jako napis (patrz giełda meczów), więc nie
    zakładamy, że dostajemy już listę.
    """
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return []
        if text.startswith("["):
            try:
                parsed = json.loads(text)
            except ValueError:
                return []
            return parsed if isinstance(parsed, list) else []
        return [text]
    return []


def own_upload_path(url: str, report_id: int) -> bool:
    """Czy to plik wgrany do TEGO zgłoszenia przez `upload-attachment`.

    Tylko taki adres trafia do wątku. Inaczej ktoś mógłby wkleić cudzy adres
    albo adres spoza serwera, a administrator otworzyłby go w podglądzie.
    """
    pattern = rf"/static/reports/{int(report_id)}_[0-9a-f]{{32}}\.(?:{_EXTENSIONS})"
    return re.fullmatch(pattern, str(url or ""), flags=re.IGNORECASE) is not None


def normalize_attachments(report_id: int, single: Any, many: Any) -> List[str]:
    """Zdjęcia nowej wiadomości w kolejności wysłania, bez powtórzeń.

    Nowa aplikacja wysyła listę i dubluje pierwsze zdjęcie w `single`, stara -
    samo `single`. Oba kształty dają tu tę samą listę.
    """
    urls: List[str] = []
    for raw in [*_as_list(many), *_as_list(single)]:
        url = str(raw or "").strip()
        if not url or url in urls:
            continue
        if not own_upload_path(url, report_id):
            raise AttachmentError(
                "Zdjęcie nie pochodzi z tego zgłoszenia. Wybierz je jeszcze raz "
                "i wyślij ponownie."
            )
        urls.append(url)
    if len(urls) > MAX_ATTACHMENTS:
        raise AttachmentError(
            f"Jedna wiadomość może mieć najwyżej {MAX_ATTACHMENTS} zdjęć. "
            "Resztę wyślij w kolejnej wiadomości."
        )
    return urls


def message_attachments(row: Mapping[str, Any]) -> List[str]:
    """Wszystkie zdjęcia zapisanej wiadomości - także te sprzed listy."""
    urls = [str(u).strip() for u in _as_list(row.get("attachment_urls")) if str(u or "").strip()]
    if urls:
        return urls
    single = str(row.get("attachment_url") or "").strip()
    return [single] if single else []


def _photo_word(count: int) -> str:
    if count == 1:
        return "zdjęcie"
    if 2 <= count % 10 <= 4 and not 12 <= count % 100 <= 14:
        return "zdjęcia"
    return "zdjęć"


def photo_label(count: int) -> str:
    """„📷 Zdjęcie", „📷 3 zdjęcia", „📷 5 zdjęć" - albo pusto."""
    if count <= 0:
        return ""
    if count == 1:
        return "📷 Zdjęcie"
    return f"📷 {count} {_photo_word(count)}"


def text_preview(content: Optional[str], limit: int = 90) -> str:
    text = (content or "").strip()
    return text[:limit] + ("…" if len(text) > limit else "")


def notification_line(content: Optional[str], photo_count: int, limit: int = 90) -> str:
    """Druga linia powiadomienia: cytat, zdjęcia albo jedno i drugie.

    Nigdy pusty cytat - on właśnie przychodził jako `„”`.
    """
    text = text_preview(content, limit)
    photos = photo_label(photo_count)
    if text and photos:
        return f"„{text}”\n{photos}"
    if text:
        return f"„{text}”"
    return photos or "💬 Nowa wiadomość"


def last_message_preview(content: Optional[str], photo_count: int) -> Optional[str]:
    """Podgląd ostatniej wiadomości na karcie wątku."""
    text = (content or "").strip()
    if text:
        return text
    return photo_label(photo_count) or None


def archived_values(row: Mapping[str, Any]) -> dict:
    """Kolumny po sprzątnięciu plików - każde zdjęcie staje się znacznikiem."""
    urls = message_attachments(row)
    values: dict = {"attachment_url": ARCHIVED}
    if _as_list(row.get("attachment_urls")):
        values["attachment_urls"] = [ARCHIVED] * len(urls)
    return values
