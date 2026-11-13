"""Montaż zestawienia w jeden film (12.11.2026) - reguły czyste: bez bazy, sieci i ffmpeg.

Decyzje właściciela (12.11.2026):
  - „Rozdziały”: okładka-plakat 4 s, duża plansza herbów 3 s tylko przy zmianie meczu, przed każdym klipem belka 1,5 s
    (minuta, etykieta, tytuł), na końcu spis klipów jak napisy końcowe,
  - dodatki: rozdziały w pliku MP4, wypalona ścieżka zoomu, licznik „3/12” i notatka na klipie, płynne przenikania,
  - montaż z zestawienia (całość albo wybrane N klipów) i z dowolnego zaznaczenia (szybki montaż),
  - 60 klipów i 30 minut filmu najwyżej; 1080p, gdy wszystkie źródła to mają, inaczej 720p; film żyje 30 dni.

Film składa się z odcinków renderowanych osobno i sklejanych bez ponownego kodowania obrazu (concat):
  okładka | odcinek 1 | odcinek 2 | ... | koniec.
Odcinek klipu zaczyna się OGONEM poprzedniego klipu (ostatnie `TAIL_S` sekund), który przenika się w planszę - dzięki temu
przejście między odcinkami jest prawdziwym przenikaniem, a sklejenie jest cięciem w miejscu, którego nie widać. Klip w swoim
odcinku kończy się więc `tail` sekund przed końcem: resztę pokaże następny odcinek (albo koniec filmu).
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

#: Wersja wyglądu: podbicie unieważnia zapamiętane odcinki i gotowe filmy przy ponownym zamówieniu.
LOOK_VERSION = 4  # 4: flagi reprezentacji zamiast tarcz z inicjałami (13.11.2026)
FPS = 30

COVER_S = 4.0
CHAPTER_S = 3.0
BAR_S = 1.5
END_BASE_S = 4.0
END_MAX_S = 14.0
#: Napisy końcowe: tyle sekund na każdy wiersz ponad te, które mieszczą się bez przewijania.
END_ROW_S = 0.42
#: Ogon klipu użyty w następnym odcinku (przenikanie w planszę). Krótki klip oddaje najwyżej 30% swojej długości.
TAIL_S = 0.6
XF_S = 0.35
#: Przejście w planszę nowego meczu: mocniejsze (miękkie przetarcie), dłuższe.
XF_CHAPTER_S = 0.6
#: Napis i licznik na klipie pojawiają się chwilę po wejściu obrazu.
OVERLAY_IN_S = 0.45
OVERLAY_FADE_S = 0.4

MAX_ITEMS = 60
MAX_FILM_S = 30 * 60
MIN_CLIP_S = 1.0
TTL_DAYS = 30
#: Montaż czekający na pliki klipów albo na akcję użytkownika (kopia, gwizdki) najdłużej tyle godzin.
PREPARE_LIMIT_H = 12

MAX_NAME = 60
MAX_DESCRIPTION = 500
MAX_LABEL = 40
MAX_NOTE = 280

#: Szacunek czasu pracy serwera: sekundy na sekundę filmu (kodowanie 1080p veryfast + plansze) i stała na odcinek.
RENDER_RATE = {1080: 0.55, 720: 0.3}
RENDER_PER_SEGMENT_S = 1.6
ZOOM_RATE = 1.1

STATUSES = ("preparing", "queued", "rendering", "ready", "failed", "expired", "cancelled")
ACTIVE = ("preparing", "queued", "rendering")

#: Etykiety zestawień: tak samo jak `playlist.ts` (BAZA_web) i `mentorPlaylist.ts` (BAZA). Barwy z ciemnego motywu Pod Ręką.
LABEL_TONES: Dict[str, str] = {
    "dobra decyzja": "good", "zła decyzja": "bad", "balans": "balance", "dysproporcja": "tilt", "wzorzec": "model",
    "do poprawy": "fix",
}
TONE_COLORS: Dict[str, str] = {
    "good": "#6CC79A", "bad": "#E5735F", "balance": "#8FBCC8", "tilt": "#E8D5A8", "model": "#E9C46A", "fix": "#E9A23B",
    "own": "#FF7A59",
}


class MontageError(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


def s(value: Any) -> str:
    return "" if value is None else str(value).strip()


def clean_text(value: Any, limit: int) -> str:
    """Tekst od użytkownika: dywiz zamiast długich myślników, jedna spacja, przycięty."""
    text = re.sub(r"\s+", " ", s(value).replace("—", "-").replace("–", "-")).strip()
    return text[:limit].rstrip()


def label_tone(label: Any) -> Optional[str]:
    text = clean_text(label, MAX_LABEL).lower()
    if not text:
        return None
    return LABEL_TONES.get(text, "own")


def label_color(label: Any) -> Optional[str]:
    tone = label_tone(label)
    return TONE_COLORS[tone] if tone else None


# ─── Pozycje ────────────────────────────────────────────────────────────────


def clean_items(raw: Iterable[Mapping[str, Any]]) -> List[Dict[str, str]]:
    """Pozycje montażu w kolejności: {clip_id, label, note}; powtórzony klip liczy się raz (pierwsze wystąpienie)."""
    out: List[Dict[str, str]] = []
    seen = set()
    for item in raw or ():
        cid = s(item.get("clip_id"))
        if not cid or cid in seen:
            continue
        seen.add(cid)
        out.append({"clip_id": cid, "label": clean_text(item.get("label"), MAX_LABEL), "note": clean_text(item.get("note"), MAX_NOTE)})
    return out


def pick_items(items: Sequence[Mapping[str, Any]], clip_ids: Optional[Sequence[Any]]) -> List[Dict[str, str]]:
    """Wybór N klipów z zestawienia w kolejności podanej przez klienta (przestawienie przed montażem). Bez `clip_ids` całość.
    Klip spoza zestawienia to błąd: montaż zestawienia nie dokłada cudzych klipów po cichu."""
    base = clean_items(items)
    if clip_ids is None:
        return base
    by_id = {i["clip_id"]: i for i in base}
    wanted = [s(c) for c in clip_ids if s(c)]
    unknown = [c for c in wanted if c not in by_id]
    if unknown:
        raise MontageError(422, "MONTAGE_ITEM_UNKNOWN", "Część wybranych klipów nie należy do tego zestawienia.")
    return clean_items(by_id[c] for c in wanted)


def check_count(items: Sequence[Any]) -> None:
    if not items:
        raise MontageError(422, "MONTAGE_EMPTY", "Wybierz co najmniej jeden klip do filmu.")
    if len(items) > MAX_ITEMS:
        raise MontageError(422, "MONTAGE_TOO_MANY", f"Film zmieści najwyżej {MAX_ITEMS} klipów. Wybierz mniej albo podziel zestawienie.")


def default_name(matches: Sequence[Mapping[str, Any]], today: str = "") -> str:
    """Nazwa szybkiego montażu: jeden mecz = „Gospodarz - Gość”, kilka = „Wybrane klipy · N meczów”."""
    real = [m for m in matches if m]
    if len(real) == 1:
        teams = " - ".join(p for p in (s(real[0].get("home")), s(real[0].get("away"))) if p)
        if teams:
            return clean_text(teams, MAX_NAME)
    count = len(real)
    if count > 1:
        return clean_text(f"Wybrane klipy · {count} {plural(count, 'mecz', 'mecze', 'meczów')}", MAX_NAME)
    return clean_text(f"Wybrane klipy{' · ' + today if today else ''}", MAX_NAME)


def plural(n: int, one: str, few: str, many: str) -> str:
    if n == 1:
        return one
    if n % 10 in (2, 3, 4) and n % 100 not in (12, 13, 14):
        return few
    return many


# ─── Czas ───────────────────────────────────────────────────────────────────


def frames(seconds: float) -> int:
    return max(0, int(round(float(seconds) * FPS)))


def fs(n: int) -> float:
    """Klatki -> sekundy (dokładnie, bez zaokrąglania do 0,01)."""
    return n / float(FPS)


def clock(seconds: Optional[float]) -> str:
    """Minuta meczu na planszy: 23:41 (bez godzin; dogrywka to dalej minuty)."""
    total = max(0, int(seconds or 0))
    return f"{total // 60}:{total % 60:02d}"


def duration_label(seconds: float) -> str:
    """Czas filmu: „6:40”, a od godziny „1:02:03”."""
    total = max(0, int(round(seconds)))
    h, rest = divmod(total, 3600)
    return f"{h}:{rest // 60:02d}:{rest % 60:02d}" if h else f"{rest // 60}:{rest % 60:02d}"


def end_seconds(rows: int, visible: int) -> float:
    return min(END_MAX_S, END_BASE_S + max(0, rows - visible) * END_ROW_S)


def tail_of(duration_s: float) -> float:
    """Ile sekund końca klipu pokazuje następny odcinek (w klatkach, żeby sklejka była co do klatki)."""
    return fs(frames(min(TAIL_S, max(0.0, duration_s) * 0.3)))


def timeline(durations: Sequence[float], chapters: Sequence[bool], end_rows: int, end_visible: int) -> Dict[str, Any]:
    """Plan filmu w klatkach dla klipów o długościach `durations` (w kolejności) i znacznikach nowego meczu `chapters`.

    Odcinek i: [ogon poprzedniego] -> (plansza meczu) -> belka -> klip bez własnego ogona. Zwraca odcinki z offsetami przejść
    (sekundy w osi odcinka), długość każdego odcinka i start w filmie (dla rozdziałów MP4)."""
    if len(durations) != len(chapters):
        raise ValueError("durations i chapters muszą mieć tę samą długość")
    cover_f = frames(COVER_S)
    segments: List[Dict[str, Any]] = []
    start_f = cover_f
    prev_tail = TAIL_S  # ogon okładki: jej nieruchoma ostatnia klatka
    for i, (dur, chapter) in enumerate(zip(durations, chapters)):
        clip_f = frames(dur)
        tail_in = fs(frames(prev_tail))
        tail_out = tail_of(dur)
        parts: List[Tuple[str, float]] = [("tail", tail_in)]
        if chapter:
            parts.append(("chapter", CHAPTER_S))
        parts.append(("bar", BAR_S))
        body = fs(clip_f) - tail_out
        parts.append(("clip", body))
        fades = []
        for j in range(1, len(parts)):
            kind = parts[j][0]
            want = XF_CHAPTER_S if (j == 1 and kind == "chapter") else XF_S
            fades.append(fs(frames(min(want, parts[j - 1][1], parts[j][1]))))
        total_f = sum(frames(p[1]) for p in parts) - sum(frames(f) for f in fades)
        offsets, at = [], 0.0
        for j in range(1, len(parts)):
            at += parts[j - 1][1] - (fades[j - 2] if j >= 2 else 0.0)
            offsets.append(round(at - fades[j - 1], 6))
        # Klip startuje (w osi odcinka) w chwili ostatniego przejścia; od tej chwili leci jego dźwięk.
        clip_at = offsets[-1]
        segments.append({"index": i, "chapter": bool(chapter), "parts": parts, "fades": fades, "offsets": offsets,
                         "clip_at": clip_at, "body_s": body, "tail_in": tail_in, "tail_out": tail_out,
                         "frames": total_f, "start_s": fs(start_f)})
        start_f += total_f
        prev_tail = tail_out
    end_s = end_seconds(end_rows, end_visible)
    end_fade = fs(frames(min(XF_S, prev_tail)))
    end_f = frames(prev_tail) + frames(end_s) - frames(end_fade)
    return {"cover_frames": cover_f, "segments": segments,
            "end": {"tail_in": fs(frames(prev_tail)), "card_s": end_s, "fade": end_fade, "frames": end_f, "start_s": fs(start_f)},
            "total_frames": start_f + end_f, "total_s": fs(start_f + end_f)}


def estimate_film_s(durations: Sequence[float], chapters: int, rows: int) -> float:
    """Długość filmu bez renderu (do limitu i podglądu): okładka, plansze meczów, belki, klipy, koniec."""
    cards = COVER_S + chapters * (CHAPTER_S - XF_S) + len(durations) * (BAR_S - XF_S)
    return round(cards + sum(max(0.0, float(d)) for d in durations) + end_seconds(rows, 9), 1)


def estimate_render_s(film_s: float, height: int, segments: int, zoomed_s: float = 0.0) -> int:
    rate = RENDER_RATE.get(height, RENDER_RATE[720])
    return int(round(film_s * rate + segments * RENDER_PER_SEGMENT_S + zoomed_s * ZOOM_RATE + 6))


def target_size(heights: Sequence[Optional[int]]) -> Tuple[int, int]:
    """1080p, gdy WSZYSTKIE źródła mają co najmniej 1080 linii, inaczej 720p. Zawsze 16:9 (pionowe dostają pasy)."""
    known = [int(h) for h in heights if h]
    if known and min(known) >= 1080:
        return 1920, 1080
    return 1280, 720


def chapter_flags(match_ids: Sequence[Any]) -> List[bool]:
    """Nowy mecz = plansza herbów. Ten sam mecz wracający po innym to znów nowy rozdział (jak w Seansie)."""
    out, prev = [], object()
    for mid in match_ids:
        out.append(mid != prev)
        prev = mid
    return out


def chapter_numbers(match_ids: Sequence[Any]) -> List[int]:
    """Numer rozdziału meczu (1..) dla każdej pozycji, do kropek postępu na planszy meczu."""
    out, n = [], 0
    for flag in chapter_flags(match_ids):
        n += 1 if flag else 0
        out.append(n)
    return out


# ─── Zoom (ten sam model co `zoomTrack.ts`) ────────────────────────────────

ZOOM_MAX = 6.0
ZOOM_SNAP = 1.02


def parse_zoom(raw: Any) -> Optional[List[Dict[str, float]]]:
    """Ścieżka zoomu z bazy: [{s, cx, cy, zoom}] ściśle rosnąco albo None (brak = klip bez zoomu, nigdy błąd)."""
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            return None
    if not isinstance(raw, list) or len(raw) < 2:
        return None
    out, last = [], float("-inf")
    for p in raw:
        try:
            point = {"s": float(p["s"]), "cx": min(1.0, max(0.0, float(p["cx"]))), "cy": min(1.0, max(0.0, float(p["cy"]))),
                     "zoom": min(ZOOM_MAX, max(1.0, float(p["zoom"])))}
        except (KeyError, TypeError, ValueError):
            return None
        if point["s"] <= last:
            return None
        last = point["s"]
        out.append(point)
    return out if any(p["zoom"] > ZOOM_SNAP for p in out) else None


def zoom_state(point: Mapping[str, float]) -> Tuple[float, float, float]:
    """(z, ox, oy) jak `stateOfPoint`: okno kadru ma bok 1/z i lewy górny róg (ox/z, oy/z)."""
    if point["zoom"] <= ZOOM_SNAP:
        return 1.0, 0.0, 0.0
    z = min(ZOOM_MAX, point["zoom"])
    size = 1.0 / z
    x = min(max(point["cx"] - size / 2, 0.0), 1.0 - size)
    y = min(max(point["cy"] - size / 2, 0.0), 1.0 - size)
    return z, x * z, y * z


def zoom_window(track: Sequence[Mapping[str, float]], t: float) -> Tuple[float, float, float]:
    """Okno kadru w sekundzie filmu `t`: (lewa, góra, bok) w ułamkach klatki. Interpolacja liniowa w przestrzeni (z, ox, oy),
    przed pierwszym i po ostatnim punkcie kadr stoi - tak samo jak `sampleTrack` w panelu."""
    if t <= track[0]["s"]:
        z, ox, oy = zoom_state(track[0])
    elif t >= track[-1]["s"]:
        z, ox, oy = zoom_state(track[-1])
    else:
        lo, hi = 0, len(track) - 1
        while hi - lo > 1:
            mid = (lo + hi) // 2
            if track[mid]["s"] <= t:
                lo = mid
            else:
                hi = mid
        a, b = track[lo], track[hi]
        k = (t - a["s"]) / (b["s"] - a["s"])
        za, xa, ya = zoom_state(a)
        zb, xb, yb = zoom_state(b)
        z, ox, oy = za + (zb - za) * k, xa + (xb - xa) * k, ya + (yb - ya) * k
    size = 1.0 / z
    return ox * size, oy * size, size


# ─── Stany pozycji (gotowość) ──────────────────────────────────────────────

#: Stan pozycji w montażu z planu pobrania klipu (`mentor_clip_download.build_plan`).
ITEM_STATES = ("ready", "pending", "cutting", "waiting", "copying", "blocked", "failed", "skipped")


def item_state(plan: Mapping[str, Any], *, own_provider: str = "", can_copy: bool = False,
               copy_status: Optional[str] = None) -> Dict[str, Any]:
    """Pozycja montażu: {state, reason, hint, action}. `action` mówi, co odblokuje klip:
    copy (kopia meczu z YouTube na serwer), sync (dwa gwizdki), retry (ponów plik) albo None (wystarczy poczekać)."""
    reason = plan.get("reason")
    status = plan.get("mp4_status") or "none"
    hint = plan.get("hint") or ""
    if plan.get("can_download"):
        if status == "ready":
            return {"state": "ready", "reason": None, "hint": "", "action": None}
        if status == "failed":
            return {"state": "failed", "reason": plan.get("error_code") or "MP4_FAILED",
                    "hint": plan.get("error_message") or "Nie udało się wyciąć tego klipu. Spróbuj ponownie.", "action": "retry"}
        if status == "none":
            # Nic jeszcze nie zamówione (podgląd przed „Zrób film”): klip DA SIĘ wyciąć, ale nikt go nie wycina.
            return {"state": "pending", "reason": None, "hint": hint, "action": None}
        return {"state": "cutting", "reason": None, "hint": hint, "action": None}
    if reason in ("QUEUE_LIMIT", "NOT_READY", "VEO_PROCESSING", "VEO_UNAVAILABLE"):
        return {"state": "waiting", "reason": reason, "hint": hint, "action": None}
    if reason == "NO_SOURCE" and own_provider == "youtube":
        if copy_status in ("queued", "downloading", "processing", "working", "waiting"):
            return {"state": "copying", "reason": reason,
                    "hint": "Robimy kopię meczu na serwerze. Klip odblokuje się sam, gdy będzie gotowa.", "action": None}
        if can_copy:
            return {"state": "blocked", "reason": "NEED_COPY",
                    "hint": "Ten mecz jest tylko na YouTube. Zrób kopię meczu na serwer, a klip wytniemy z niej sam.", "action": "copy"}
    if reason == "NEED_SYNC":
        return {"state": "blocked", "reason": reason, "hint": hint, "action": "sync"}
    return {"state": "blocked", "reason": reason or "NO_SOURCE", "hint": hint, "action": None}


def counts(states: Iterable[str]) -> Dict[str, int]:
    out = {k: 0 for k in ("total", "ready", "pending", "cutting", "waiting", "copying", "blocked", "failed", "skipped")}
    for st in states:
        out["total"] += 1
        out[st if st in out else "blocked"] += 1
    return out


def next_status(states: Sequence[str], skip_missing: bool) -> str:
    """Co dalej z montażem w przygotowaniu: `queued` (render), `preparing` (czekamy) albo `failed` (nie ma z czego).
    Pominięcie brakujących nie czeka na klipy wymagające akcji (blocked) ani na nieudane, ale czeka na te w drodze."""
    ready = sum(1 for st in states if st == "ready")
    moving = sum(1 for st in states if st in ("pending", "cutting", "waiting", "copying"))
    stuck = sum(1 for st in states if st in ("blocked", "failed"))
    if ready == len(states) and states:
        return "queued"
    if skip_missing and not moving:
        return "queued" if ready else "failed"
    if not moving and not ready and stuck:
        return "preparing"  # czekamy na akcję użytkownika (kopia, gwizdki, ponowienie)
    return "preparing"


# ─── Podpisy i nazwy ────────────────────────────────────────────────────────


def sig(*parts: Any) -> str:
    raw = json.dumps(parts, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:20]


def request_sig(name: str, description: str, items: Sequence[Mapping[str, Any]], clips: Mapping[str, Mapping[str, Any]],
                skip_missing: bool, ranges: Optional[Mapping[str, Any]] = None) -> str:
    """Odcisk zamówienia: te same klipy (z ich treścią), kolejność, etykiety, notatki i nazwa = ten sam film."""
    shaped = []
    for item in items:
        clip = clips.get(item["clip_id"]) or {}
        shaped.append([item["clip_id"], item.get("label"), item.get("note"), clip.get("start_s"), clip.get("end_s"), clip.get("title"),
                       s(clip.get("updated_at")), clip.get("media_rev"), s(clip.get("zoom_track_json")), clip.get("category_ids"),
                       # Skąd tniemy (nagranie i zakres z planu pobrania): inne źródło albo poprawione gwizdki = inny film.
                       # Sam postęp cięcia (status, rozmiar pliku) nie zmienia zamówienia.
                       (ranges or {}).get(item["clip_id"])])
    return sig("montage", LOOK_VERSION, name, description, shaped, bool(skip_missing))


def film_filename(name: Any) -> str:
    from app.mentor_clip_download_rules import fs_part

    return f"{fs_part(name, 90, 'Zestawienie')}.mp4"


def chapter_title(position: int, minute: str, label: str, title: str) -> str:
    parts = [p for p in (minute, label, title) if p]
    return f"{position}. " + " · ".join(parts) if parts else f"{position}. Klip"


def ffmetadata(chapters: Sequence[Mapping[str, Any]], title: str) -> str:
    """Plik FFMETADATA1 z rozdziałami (TIMEBASE 1/1000). Znaki specjalne formatu są poprzedzone ukośnikiem."""

    def esc(text: Any) -> str:
        return re.sub(r"([=;#\\\n])", r"\\\1", s(text))

    lines = [";FFMETADATA1", f"title={esc(title)}"]
    for ch in chapters:
        start = int(round(float(ch["start_s"]) * 1000))
        end = int(round(float(ch["end_s"]) * 1000))
        if end <= start:
            continue
        lines += ["[CHAPTER]", "TIMEBASE=1/1000", f"START={start}", f"END={end}", f"title={esc(ch['title'])}"]
    return "\n".join(lines) + "\n"


def film_chapters(plan: Mapping[str, Any], entries: Sequence[Mapping[str, Any]], name: str) -> List[Dict[str, Any]]:
    """Rozdziały filmu: okładka, każdy klip (od jego planszy) i spis na końcu. `entries` = pozycje w kolejności renderu."""
    out = [{"kind": "cover", "title": name or "Okładka", "start_s": 0.0, "clip_id": None}]
    for seg, entry in zip(plan["segments"], entries):
        out.append({"kind": "clip", "clip_id": entry["clip_id"], "start_s": round(seg["start_s"], 3), "match_id": entry.get("match_id"),
                    "title": chapter_title(entry["position"], entry.get("minute") or "", entry.get("label") or "", entry.get("title") or ""),
                    "chapter": bool(seg["chapter"]), "clip_start_s": round(seg["start_s"] + seg["clip_at"], 3)})
    out.append({"kind": "end", "title": "Spis klipów", "start_s": round(plan["end"]["start_s"], 3), "clip_id": None})
    total = float(plan["total_s"])
    for i, ch in enumerate(out):
        ch["end_s"] = round(out[i + 1]["start_s"] if i + 1 < len(out) else total, 3)
    return out
