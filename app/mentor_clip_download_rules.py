"""Pobieranie klipów Mentora jako MP4 - reguły czyste (bez bazy i sieci).

Klip zaznaczony na wideo-linku (YouTube/Vimeo) nie ma pliku, ale mecz może mieć drugie nagranie: własny plik
albo nagranie Bastionu. Czas przeliczamy z synchronizacji nagrań meczu (`sync_json` w `mentor_match_videos`,
kształt z `mentor_video_rules.clean_sync`): `match_start_s` = sekunda pierwszego gwizdka, `second_half_s` =
sekunda początku II połowy. Obie kotwice muszą być na OBU nagraniach (decyzja właściciela 30.10.2026: „dwa gwizdki”).
Importów bazy tu nie ma, żeby reguły dało się testować bez środowiska.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

#: Kolejność kotwic synchronizacji i ich nazwy w sync_json / po polsku.
WHISTLES: Tuple[str, ...] = ("start", "second_half")
SYNC_KEY = {"start": "match_start_s", "second_half": "second_half_s"}
WHISTLE_LABEL = {"start": "pierwszy gwizdek", "second_half": "początek II połowy"}

#: Pierwszeństwo źródła przy klipie z linku: własny plik, potem Bastion.
SOURCE_ORDER = {"file": 0, "bastion": 1}

#: Plansza tytułowa: tyle sekund przed klipem.
CARD_SECONDS = 2
#: Szacowane czasy przygotowania (sekundy): plik tniemy lokalnie, Bastion przez kolejkę connectora.
ESTIMATE_FILE_S = 12
ESTIMATE_BASTION_S = 90
ESTIMATE_CARD_S = 8


def sync_gaps(sync: Optional[Mapping[str, Any]]) -> List[str]:
    """Które gwizdki nie są ustawione w synchronizacji nagrania (kolejność: start, II połowa)."""
    data = sync if isinstance(sync, Mapping) else {}
    return [w for w in WHISTLES if data.get(SYNC_KEY[w]) is None]


def map_time(src: Mapping[str, Any], dst: Mapping[str, Any], t: float) -> float:
    """Sekunda nagrania `src` -> sekunda nagrania `dst`. Przesunięcie liczymy per połowa (oba gwizdki);
    od początku II połowy źródła obowiązuje przesunięcie drugiego gwizdka. Wynik nie schodzi poniżej 0."""
    first = float(dst[SYNC_KEY["start"]]) - float(src[SYNC_KEY["start"]])
    second = float(dst[SYNC_KEY["second_half"]]) - float(src[SYNC_KEY["second_half"]])
    offset = second if t >= float(src[SYNC_KEY["second_half"]]) else first
    return max(0.0, float(t) + offset)


def convert_range(src: Mapping[str, Any], dst: Mapping[str, Any], start_s: float, end_s: float) -> Tuple[float, float]:
    """Zakres klipu z nagrania `src` na zakres w nagraniu `dst`. Rzuca ValueError, gdy zakres zniknąłby
    (np. koniec przed początkiem nagrania docelowego)."""
    a, b = map_time(src, dst, start_s), map_time(src, dst, end_s)
    if b - a < 0.5:
        raise ValueError("Klip wypada poza nagraniem docelowym.")
    return round(a, 2), round(b, 2)


def _missing(video: Mapping[str, Any]) -> List[Dict[str, Any]]:
    return [{"video_id": video["id"], "label": video.get("label") or "Nagranie", "whistle": w}
            for w in sync_gaps(video.get("sync"))]


def choose_source(clip_video: Mapping[str, Any], options: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    """Rozstrzyga, skąd wyciąć klip.

    `clip_video`: {id, label, kind: "file"|"bastion"|"link", sync, ready}. `options`: pozostałe nagrania meczu
    zdolne dać MP4, każde {id, label, kind: "file"|"bastion", sync, ready}.
    Zwraca {mode: "direct"|"convert"|"none", option, reason, missing}; reason: None | NEED_SYNC | NO_SOURCE | NOT_READY.
    """
    if clip_video.get("kind") in SOURCE_ORDER:
        return {"mode": "direct", "option": dict(clip_video), "reason": None if clip_video.get("ready") else "NOT_READY", "missing": []}
    ordered = sorted(options, key=lambda o: SOURCE_ORDER.get(o.get("kind"), 9))
    if not ordered:
        return {"mode": "none", "option": None, "reason": "NO_SOURCE", "missing": []}
    link_gaps = sync_gaps(clip_video.get("sync"))
    synced = [o for o in ordered if not link_gaps and not sync_gaps(o.get("sync"))]
    if synced:
        ready = [o for o in synced if o.get("ready")]
        if ready:
            return {"mode": "convert", "option": dict(ready[0]), "reason": None, "missing": []}
        return {"mode": "convert", "option": dict(synced[0]), "reason": "NOT_READY", "missing": []}
    # Preferujemy źródło, któremu brakuje najmniej: jeśli drugie jest bliższe synchronizacji, to je wskazujemy.
    best = min(ordered, key=lambda o: (len(sync_gaps(o.get("sync"))), SOURCE_ORDER.get(o.get("kind"), 9)))
    missing = _missing(clip_video) + _missing(best)
    return {"mode": "convert", "option": dict(best), "reason": "NEED_SYNC", "missing": missing}


def hint_for(reason: Optional[str], missing: Sequence[Mapping[str, Any]] = (), option: Optional[Mapping[str, Any]] = None) -> str:
    """Zdanie po polsku do pokazania pod przyciskiem „Pobierz”."""
    if reason == "NEED_SYNC":
        parts = [f"{WHISTLE_LABEL.get(m['whistle'], m['whistle'])} w nagraniu „{m.get('label') or 'Nagranie'}”" for m in missing]
        return ("Żeby wyciąć ten klip z drugiego nagrania meczu, zsynchronizuj nagrania dwoma gwizdkami. Brakuje: "
                + "; ".join(parts) + ".")
    if reason == "NO_SOURCE":
        return ("Ten klip jest zaznaczony na wideo-linku (YouTube/Vimeo), z którego nie zrobimy pliku. "
                "Dodaj do meczu nagranie z Bastionu albo wgraj własny plik, a potem zsynchronizuj je z linkiem.")
    if reason == "NOT_READY":
        return "Nagranie jeszcze się przetwarza. Spróbuj za chwilę."
    if reason == "BAD_RANGE":
        return "Bastion przyjmuje klipy od 2 do 300 sekund. Skróć albo wydłuż zaznaczony fragment."
    if option and option.get("kind") == "bastion":
        return "Plik przygotuje Bastion, zwykle około półtorej minuty."
    return "Plik przygotujemy w kilkanaście sekund."


# ─── Nazwy plików i folderów ────────────────────────────────────────────────

_FORBIDDEN = re.compile(r'[<>:"/\\|?*\x00-\x1f\x7f]+')
_RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}


def fs_part(text: Any, limit: int = 80, fallback: str = "") -> str:
    """Fragment nazwy bezpieczny w systemach plików (Windows, macOS, Android): bez znaków zakazanych, długich
    myślników i końcowych kropek/spacji; polskie litery zostają. Zarezerwowane nazwy Windows dostają podkreślnik."""
    out = str(text or "").replace("—", "-").replace("–", "-").replace("−", "-")
    out = _FORBIDDEN.sub(" ", out)
    out = re.sub(r"\s+", " ", out).strip(" .")
    out = out[:limit].rstrip(" .")
    if out.split(".")[0].upper() in _RESERVED:
        out = f"_{out}"
    return out or fallback


def match_clock(seconds: Optional[float]) -> str:
    """Minuta meczu w nazwie pliku: 26m23 (minuta, dwucyfrowe sekundy)."""
    total = max(0, int(seconds or 0))
    return f"{total // 60}m{total % 60:02d}"


def download_filename(title: Any, match_seconds: Optional[float]) -> str:
    """„26m23 Kara 2 min - czerwona.mp4” (bez tytułu: samo „26m23 klip.mp4”)."""
    name = fs_part(title, 60, "klip")
    return f"{match_clock(match_seconds)} {name}.mp4"


def folder_names(match: Mapping[str, Any], category: Any) -> Dict[str, str]:
    """{match: "2026-10-10 AGH Kraków - Gwardia (LCM-32)", category: "Do dyskusji"} oczyszczone dla systemu plików."""
    date = str(match.get("date") or "")[:10]
    teams = " - ".join(p for p in (str(match.get("home") or "").strip(), str(match.get("away") or "").strip()) if p)
    code = str(match.get("code") or "").strip()
    raw = " ".join(p for p in (date, teams, f"({code})" if code else "") if p)
    return {"match": fs_part(raw, 90, "Mecz"), "category": fs_part(category, 50, "Bez kategorii")}


FULL_NAME_LIMIT = 150


def full_filename(match: Mapping[str, Any], category: Any, filename: str, limit: int = FULL_NAME_LIMIT) -> str:
    """Nazwa niosąca mecz i kategorię (zwykłe pobranie bez folderów): „LCM-32 Do dyskusji 23m20 Kara 2 min - czerwona.mp4”.
    Mecz to numer (inaczej data i drużyny); gdy całość przekracza limit, skracamy najpierw mecz, potem kategorię,
    a minuta i tytuł klipu zostają."""
    base = filename[:-4] if filename.lower().endswith(".mp4") else filename
    base = fs_part(base, limit, "klip")
    code = fs_part(match.get("code"), 30)
    if code:
        head = code
    else:
        teams = " - ".join(p for p in (str(match.get("home") or "").strip(), str(match.get("away") or "").strip()) if p)
        head = fs_part(" ".join(p for p in (str(match.get("date") or "")[:10], teams) if p), 50)
    cat = fs_part(category, 50)
    room = limit - len(".mp4") - len(base) - 1
    if len(cat) + 1 > room:
        cat = cat[: max(0, room - 1)].rstrip(" .")
    room -= len(cat) + 1 if cat else 0
    head = head[: max(0, room - 1)].rstrip(" .") if len(head) + 1 > room else head
    return " ".join(p for p in (head, cat, base) if p)[: limit - 4].rstrip(" .") + ".mp4"


def card_signature(lines: Sequence[str]) -> str:
    """Odcisk treści planszy: gdy tytuł albo kategoria się zmienią, stary wariant przestaje być aktualny."""
    return hashlib.sha1("\n".join(lines).encode("utf-8")).hexdigest()[:16]


def match_time_s(match_ms: Any, video_s: float, sync: Optional[Mapping[str, Any]]) -> float:
    """Minuta meczu klipu do nazwy pliku: z protokołu (`match_ms`), inaczej z synchronizacji nagrania,
    inaczej sam czas nagrania."""
    if match_ms is not None:
        return max(0.0, float(match_ms) / 1000.0)
    data = sync if isinstance(sync, Mapping) else {}
    second, start, half = data.get("second_half_s"), data.get("match_start_s"), data.get("half_minutes")
    if second is not None and half and video_s >= float(second):
        return max(0.0, float(video_s) - float(second) + float(half) * 60)
    if start is not None:
        return max(0.0, float(video_s) - float(start))
    return max(0.0, float(video_s))


#: Ile zamówień Bastionu jeden użytkownik może mieć naraz w kolejce (worker robi je po jednym).
BASTION_ACTIVE_CAP = 12
BATCH_MAX = 50


def allocate_batch(plans: Sequence[Mapping[str, Any]], active_bastion: int, cap: Optional[int] = None) -> List[bool]:
    """Które plany z paczki wolno zamówić teraz. Pliki własne i klipy już gotowe/w toku nie liczą się do limitu;
    nowe zamówienia Bastionu - dopóki `active_bastion` + nowe mieści się w `cap`."""
    cap = BASTION_ACTIVE_CAP if cap is None else cap
    out: List[bool] = []
    used = active_bastion
    for plan in plans:
        if not plan.get("can_download"):
            out.append(False)
            continue
        if plan.get("mp4_status") in ("ready", "queued", "working"):
            out.append(True)  # nic nowego nie zakładamy (zamówienie jest idempotentne)
            continue
        if plan.get("source") == "bastion":
            if used >= cap:
                out.append(False)
                continue
            used += 1
        out.append(True)
    return out


def estimate_s(source: Optional[str], title_card: bool) -> int:
    base = ESTIMATE_BASTION_S if source == "bastion" else ESTIMATE_FILE_S
    return base + (ESTIMATE_CARD_S if title_card else 0)
