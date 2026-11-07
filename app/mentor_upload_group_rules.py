"""
Nagranie meczu z kilku plików (07.11.2026) - LIŚĆ bez bazy i sieci (testowalny bez połączenia).

Kontrakt: `docs/mentor-panel.md` (4.5, „Nagranie z kilku plików”). Klient ustala kolejność (czas nagrania z metadanych,
potem numeracja kamery w nazwie, potem nazwa; przeciągnięcie przed wysłaniem), serwer skleja części w tej kolejności.

Tu mieszka wszystko, co da się policzyć bez bazy i bez ffmpeg:
  - walidacja grupy (2-12 plików, każdy jak pojedyncze wgrywanie, razem do 20 GB),
  - stan grupy z wierszy `mentor_uploads` (uploading / processing / ready / failed / removed),
  - odczyt ffprobe części, wybór wspólnego formatu (sklejenie bez przekodowania albo wyrównanie),
  - argumenty ffmpeg (wyrównanie części, concat), lista concat, postęp z sumy czasów, oś części (`parts`).
"""

from __future__ import annotations

import math
import re
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from app.mentor_panel_rules import MAX_UPLOAD_BYTES, RuleError, aware, s, validate_upload

MIN_FILES = 2
MAX_FILES = 12
ORDER_SOURCES = ("recorded", "manual")

#: Wspólny format po wyrównaniu: do 1080p, H.264 jak zwykłe wgrywanie, AAC 48 kHz stereo.
MAX_HEIGHT = 1080
MAX_FPS = 60
DEFAULT_FPS = 25
AUDIO_RATE = 48000
AUDIO_CHANNELS = 2

#: Część postępu przypadająca na wyrównanie części (reszta to sklejenie i plakat).
NORMALIZE_SHARE = 0.95

#: Status pliku w grupie (`mentor_uploads.status`): `uploading` -> `uploaded` (czeka na resztę) -> `processing`
#: (cała grupa w pracy; worker bierze tylko część 0) -> `ready` | `failed`; `removed` po DELETE grupy.
WAITING = "uploaded"


# ─── Zakładanie grupy ───────────────────────────────────────────────────────


def parse_recorded_at(value: Any) -> Optional[datetime]:
    """Czas nagrania z metadanych pliku (ISO 8601, także z `Z`). Nieczytelny = brak (to tylko podpowiedź kolejności)."""
    if isinstance(value, datetime):
        return aware(value)
    text = s(value)
    if not text:
        return None
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    # Python 3.10: fromisoformat zna tylko 3 albo 6 cyfr ułamka sekundy - przycinamy/dopełniamy do 6.
    text = re.sub(r"\.(\d+)", lambda m: "." + (m.group(1) + "000000")[:6], text, count=1)
    try:
        found = datetime.fromisoformat(text)
    except ValueError:
        return None
    return found if found.tzinfo else found.replace(tzinfo=timezone.utc)


def _duration(value: Any) -> Optional[float]:
    try:
        found = float(value)
    except (TypeError, ValueError):
        return None
    return round(found, 3) if math.isfinite(found) and found > 0 else None


def validate_group(files: Any, order_source: Any = None) -> Tuple[List[Dict[str, Any]], str]:
    """Pliki grupy w kolejności sklejania. Każdy jak `validate_upload`, 2-12 sztuk, razem do 20 GB."""
    items = files if isinstance(files, list) else []
    if not MIN_FILES <= len(items) <= MAX_FILES:
        raise RuleError(422, "UPLOAD_GROUP_COUNT", f"Nagranie z kilku plików składa się z {MIN_FILES}-{MAX_FILES} plików.")
    out: List[Dict[str, Any]] = []
    for index, raw in enumerate(items):
        item = raw if isinstance(raw, Mapping) else {}
        try:
            filename, size, content_type = validate_upload(item.get("filename"), item.get("size"), item.get("content_type"))
        except RuleError as exc:
            label = s(item.get("filename"))[:80]
            where = f"Plik {index + 1}" + (f" ({label})" if label else "")
            raise RuleError(exc.status, exc.code, f"{where}: {exc.message}") from exc
        out.append({"index": index, "filename": filename, "size": size, "content_type": content_type,
                    "recorded_at": parse_recorded_at(item.get("recorded_at")), "duration_s": _duration(item.get("duration_s"))})
    if sum(f["size"] for f in out) > MAX_UPLOAD_BYTES:
        raise RuleError(422, "UPLOAD_TOO_BIG", "Wszystkie pliki nagrania razem mogą mieć najwyżej 20 GB.")
    source = s(order_source).lower()
    return out, source if source in ORDER_SOURCES else "manual"


def group_title(first_filename: Any, count: int) -> str:
    """Nazwa nagrania: nazwa pierwszego pliku bez rozszerzenia + „ (N części)”."""
    name = s(first_filename)
    base, dot, ext = name.rpartition(".")
    if dot and base and ext and len(ext) <= 5 and ext.isalnum():
        name = base
    return f"{name or 'Nagranie'} ({int(count)} części)"


# ─── Stan grupy ─────────────────────────────────────────────────────────────


def ordered(rows: Sequence[Mapping[str, Any]]) -> List[Mapping[str, Any]]:
    return sorted(rows, key=lambda r: int(r.get("group_index") or 0))


def lead_of(rows: Sequence[Mapping[str, Any]]) -> Optional[Mapping[str, Any]]:
    """Część 0 trzyma stan całej grupy: nagranie (`video_id`), gotowy plik, błąd, postęp workera."""
    return next((r for r in rows if int(r.get("group_index") or 0) == 0), None)


def all_uploaded(rows: Sequence[Mapping[str, Any]]) -> bool:
    """Komplet: tyle wierszy, ile zapowiedziano, i każdy plik już leży w magazynie."""
    if not rows:
        return False
    count = int(rows[0].get("group_count") or len(rows))
    return len(rows) == count and all(s(r.get("status")) == WAITING for r in rows)


def group_state(rows: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    """Stan grupy dla klienta: status, błąd, nagranie, ile plików już wysłanych."""
    rows = ordered(rows)
    statuses = [s(r.get("status")) for r in rows]
    lead = lead_of(rows) or {}
    count = int((rows[0].get("group_count") if rows else 0) or len(rows))
    done = sum(1 for st in statuses if st not in ("uploading", "removed", "failed", "expired"))
    error = next((s(r.get("error")) for r in rows if s(r.get("status")) in ("failed", "expired", "removed") and r.get("error")), None)
    if rows and all(st == "removed" for st in statuses):
        status = "removed"
    elif any(st in ("failed", "expired", "removed") for st in statuses):
        status = "failed"
        error = error or "Wgrywanie przerwane."
    elif s(lead.get("status")) == "ready":
        status = "ready"
    elif s(lead.get("status")) == "processing":
        status = "processing"
    else:
        status = "uploading"
    return {"status": status, "error": error if status in ("failed", "removed") else None,
            "video_id": lead.get("video_id") or None, "done": done, "count": count}


# ─── ffprobe i wspólny format ───────────────────────────────────────────────


def parse_rate(value: Any) -> Optional[float]:
    """`30000/1001` -> 29.97; `0/0` i śmieci -> None."""
    text = s(value)
    try:
        if "/" in text:
            num, den = text.split("/", 1)
            found = float(num) / float(den) if float(den) else 0.0
        else:
            found = float(text)
    except (TypeError, ValueError):
        return None
    return round(found, 3) if math.isfinite(found) and found > 0 else None


def _rotation(stream: Mapping[str, Any]) -> int:
    raw: Any = (stream.get("tags") or {}).get("rotate")
    for side in stream.get("side_data_list") or []:
        if isinstance(side, Mapping) and side.get("rotation") is not None:
            raw = side.get("rotation")
    try:
        return int(round(float(raw))) % 360 if raw is not None else 0
    except (TypeError, ValueError):
        return 0


def _int(value: Any) -> Optional[int]:
    try:
        found = int(value)
    except (TypeError, ValueError):
        return None
    return found if found > 0 else None


def probe_info(data: Mapping[str, Any]) -> Dict[str, Any]:
    """Odczyt ffprobe (`-show_format -show_streams`) jednej części. Wymiary = wyświetlane (po obrocie 90/270)."""
    streams = [st for st in data.get("streams") or [] if isinstance(st, Mapping)]
    video = next((st for st in streams if st.get("codec_type") == "video"
                  and not (st.get("disposition") or {}).get("attached_pic")), None)
    if not video:
        raise ValueError("brak obrazu wideo")
    audio = next((st for st in streams if st.get("codec_type") == "audio"), None)
    width, height = _int(video.get("width")), _int(video.get("height"))
    if not width or not height:
        raise ValueError("brak wymiarów obrazu")
    rotation = _rotation(video)
    if rotation in (90, 270):
        width, height = height, width
    duration = _duration((data.get("format") or {}).get("duration")) or _duration(video.get("duration"))
    return {
        "width": width, "height": height, "rotation": rotation,
        "fps": parse_rate(video.get("avg_frame_rate")) or parse_rate(video.get("r_frame_rate")),
        "vcodec": s(video.get("codec_name")).lower(), "pix_fmt": s(video.get("pix_fmt")).lower(),
        "profile": s(video.get("profile")), "level": video.get("level"),
        "acodec": s(audio.get("codec_name")).lower() if audio else None,
        "sample_rate": _int(audio.get("sample_rate")) if audio else None,
        "channels": _int(audio.get("channels")) if audio else None,
        "duration_s": duration,
    }


def copy_compatible(infos: Sequence[Mapping[str, Any]]) -> bool:
    """Sklejenie bez przekodowania (concat + remux): wszystkie części H.264 + AAC, ten sam obraz (wymiary, obrót, fps,
    profil, piksele) i ten sam dźwięk, do 1080p. Inaczej przejście mogłoby się zaciąć albo rozjechać."""
    if not infos:
        return False
    first = infos[0]

    def same(key: str) -> bool:
        return all(i.get(key) == first.get(key) for i in infos)

    return (all(i.get("vcodec") == "h264" and i.get("acodec") == "aac" for i in infos)
            and all(i.get("duration_s") and i.get("fps") for i in infos)
            and first.get("pix_fmt") in ("yuv420p", "yuvj420p") and int(first.get("height") or 0) <= MAX_HEIGHT
            and all(same(k) for k in ("width", "height", "rotation", "fps", "pix_fmt", "profile", "level",
                                      "sample_rate", "channels")))


def _even(value: float) -> int:
    return max(2, int(round(value / 2.0)) * 2)


def common_fps(infos: Sequence[Mapping[str, Any]]) -> int:
    """Najczęstszy zaokrąglony fps części (remis: wcześniejsza część), najwyżej 60; brak danych = 25."""
    rounded = [min(MAX_FPS, int(round(float(i["fps"])))) for i in infos if i.get("fps")]
    rounded = [r for r in rounded if r > 0]
    return Counter(rounded).most_common(1)[0][0] if rounded else DEFAULT_FPS


def group_plan(infos: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    """Wspólny format: `copy` (te same parametry) albo `normalize` - wysokość min(1080, najwyższa część), szerokość
    najszerszych proporcji (węższe części dostają pas), parzyste wymiary, jeden fps."""
    if copy_compatible(infos):
        first = infos[0]
        return {"mode": "copy", "width": int(first["width"]), "height": int(first["height"]),
                "fps": float(first["fps"])}
    height = _even(min(MAX_HEIGHT, max(int(i.get("height") or 0) for i in infos) or MAX_HEIGHT))
    width = max(_even(int(i.get("width") or 16) * height / max(1, int(i.get("height") or 9))) for i in infos)
    return {"mode": "normalize", "width": width, "height": height, "fps": common_fps(infos)}


def fit_size(info: Mapping[str, Any], plan: Mapping[str, Any]) -> Tuple[int, int]:
    """Rozmiar części wpisanej w kadr wspólny z zachowaniem proporcji (parzysty), resztę dopełnia pas."""
    width, height = int(info.get("width") or plan["width"]), int(info.get("height") or plan["height"])
    scale = min(plan["width"] / width, plan["height"] / height)
    return min(plan["width"], _even(width * scale)), min(plan["height"], _even(height * scale))


def normalize_args(source: str, target: str, info: Mapping[str, Any], plan: Mapping[str, Any]) -> List[str]:
    """Wyrównanie jednej części do wspólnego formatu (H.264 jak zwykłe wgrywanie, AAC 48 kHz stereo; cisza bez dźwięku)."""
    width, height = fit_size(info, plan)
    video_filter = (f"scale={width}:{height},pad={plan['width']}:{plan['height']}:(ow-iw)/2:(oh-ih)/2,"
                    f"setsar=1,fps={plan['fps']},format=yuv420p")
    has_audio = bool(info.get("acodec"))
    silence = [] if has_audio else ["-f", "lavfi", "-i", f"anullsrc=channel_layout=stereo:sample_rate={AUDIO_RATE}"]
    audio_map = ["-map", "0:a:0"] if has_audio else ["-map", "1:a:0", "-shortest"]
    return [
        "ffmpeg", "-hide_banner", "-nostdin", "-y", "-i", source, *silence, "-map", "0:v:0", *audio_map,
        "-vf", video_filter, "-c:v", "libx264", "-preset", "veryfast", "-crf", "23", "-pix_fmt", "yuv420p",
        "-c:a", "aac", "-b:a", "128k", "-ar", str(AUDIO_RATE), "-ac", str(AUDIO_CHANNELS),
        "-video_track_timescale", "90000", "-movflags", "+faststart", "-progress", "pipe:1", "-nostats", target,
    ]


def concat_list(paths: Sequence[str]) -> str:
    """Plik listy demuxera concat; apostrof w ścieżce/adresie zapisany jak chce ffmpeg (`'\\''`)."""
    return "".join("file '" + str(p).replace("'", "'\\''") + "'\n" for p in paths)


def concat_args(list_path: str, target: str, remote: bool) -> List[str]:
    """Sklejenie bez przekodowania: tylko pierwszy obraz i dźwięk (ścieżki danych kamer, np. GoPro, odpadają)."""
    whitelist = ["-protocol_whitelist", "file,http,https,tcp,tls,crypto"] if remote else []
    return [
        "ffmpeg", "-hide_banner", "-nostdin", "-y", "-f", "concat", "-safe", "0", *whitelist, "-i", list_path,
        "-map", "0:v:0", "-map", "0:a:0", "-c", "copy", "-movflags", "+faststart", "-progress", "pipe:1", "-nostats", target,
    ]


# ─── Postęp i oś części ─────────────────────────────────────────────────────


def out_seconds(line: str) -> Optional[float]:
    """Sekundy wyjścia z `-progress pipe:1` (out_time_ms/us w mikrosekundach)."""
    found = re.match(r"^out_time_(?:ms|us)=(\d+)", s(line))
    return int(found.group(1)) / 1_000_000 if found else None


def group_progress(done_s: float, current_s: float, total_s: float, low: float = 0.0, high: float = 0.99) -> float:
    """Postęp z sumy czasów części: `done_s` gotowych + `current_s` bieżącej, rozpięty na [low, high]."""
    if not total_s or total_s <= 0:
        return round(low, 3)
    share = min(1.0, max(0.0, (float(done_s) + float(current_s)) / float(total_s)))
    return round(min(0.99, low + (high - low) * share), 3)


def parts_timeline(filenames: Sequence[str], durations: Sequence[Optional[float]]) -> List[Dict[str, Any]]:
    """Oś części gotowego filmu: start części 0 = 0, każda następna od końca poprzedniej."""
    out, start = [], 0.0
    for index, (name, duration) in enumerate(zip(filenames, durations)):
        length = round(float(duration or 0.0), 3)
        out.append({"index": index, "filename": s(name), "start_s": round(start, 3), "duration_s": length})
        start += length
    return out


def clean_timeline(raw: Any) -> Optional[List[Dict[str, Any]]]:
    """Pole `parts` nagrania: lista z `parts_json` albo null (pojedynczy plik, stare nagrania, zapis nieczytelny)."""
    if not isinstance(raw, list) or len(raw) < MIN_FILES:
        return None
    out = []
    for item in raw:
        if not isinstance(item, Mapping):
            return None
        try:
            out.append({"index": int(item.get("index")), "filename": s(item.get("filename")),
                        "start_s": float(item.get("start_s")), "duration_s": float(item.get("duration_s") or 0)})
        except (TypeError, ValueError):
            return None
    return sorted(out, key=lambda p: p["start_s"])


def part_error(index: int, filename: Any) -> str:
    """Polski powód błędu grupy wskazujący część (numeracja od 1)."""
    name = s(filename)
    return f"Część {int(index) + 1}" + (f" ({name})" if name else "") + " nie daje się odczytać."


def total_duration(durations: Sequence[Optional[float]]) -> float:
    return round(sum(float(d or 0) for d in durations), 3)
