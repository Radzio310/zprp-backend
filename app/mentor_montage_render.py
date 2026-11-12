"""Montaż (12.11.2026) - polecenia ffmpeg dla odcinków filmu i sklejki. Czyste: tylko budowanie argumentów.

Każdy odcinek ma TE SAME parametry strumieni (rozmiar, 30 kl/s, H.264 high, yuv420p, AAC 48 kHz stereo), więc sklejka
(`concat`) kopiuje obraz bez ponownego kodowania. Dźwięk sklejki kodujemy jeszcze raz: AAC na granicach plików zostawia
drobne luki „primingu”, a jedno przejście je wygładza.

Wejście klipu: `{"url", "start", "dur", "has_audio"}` - fragment pliku MP4 klipu (po przeliczeniu przesunięć Bastionu) albo
pliku po wypaleniu zoomu. Wejście planszy: PNG w pełnym rozmiarze kadru.
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from app import mentor_montage_rules as MR

FPS = MR.FPS
CHAPTER_TRANSITION = "smoothleft"

VIDEO_CODEC = ["-c:v", "libx264", "-preset", "veryfast", "-crf", "20", "-profile:v", "high", "-pix_fmt", "yuv420p", "-g", "60",
               "-colorspace", "bt709", "-color_primaries", "bt709", "-color_trc", "bt709", "-video_track_timescale", "15360"]
AUDIO_CODEC = ["-c:a", "aac", "-b:a", "160k", "-ar", "48000", "-ac", "2"]
BASE = ["ffmpeg", "-hide_banner", "-nostdin", "-y", "-loglevel", "error"]
#: Jak w planszy klipu: więcej wątków filtrów nie przyspiesza, a zabiera rdzenie kodowaniu.
FILTER_THREADS = ["-filter_complex_threads", "2"]


def norm(frames: int) -> str:
    """Ogon każdej gałęzi: stałe 30 kl/s, wspólna podstawa czasu, dokładna liczba klatek (klonuje ostatnią, gdy brakuje)."""
    return (f"fps={FPS},settb=1/{FPS},format=yuv420p,setsar=1,tpad=stop_mode=clone:stop_duration=3,"
            f"trim=end_frame={frames},setpts=PTS-STARTPTS")


def fit(width: int, height: int) -> str:
    return (f"setpts=PTS-STARTPTS,scale={width}:{height}:force_original_aspect_ratio=decrease:flags=bicubic,"
            f"pad={width}:{height}:(ow-iw)/2:(oh-ih)/2:color=black,setsar=1")


RGB_IN = "scale=out_color_matrix=bt709:out_range=tv"


class Graph:
    """Zbiera wejścia i gałęzie grafu filtrów; numeruje wejścia w kolejności dodania."""

    def __init__(self) -> None:
        self.inputs: List[str] = []
        self.chains: List[str] = []
        self._n = 0

    def still(self, path: str, seconds: float) -> int:
        self.inputs += ["-loop", "1", "-framerate", str(FPS), "-t", f"{seconds + 0.5:.3f}", "-i", path]
        return self._next()

    def clip(self, source: Mapping[str, Any], start: float, dur: float) -> int:
        self.inputs += ["-ss", f"{max(0.0, start):.3f}", "-t", f"{dur + 0.3:.3f}", "-i", str(source["url"])]
        return self._next()

    def _next(self) -> int:
        n = self._n
        self._n += 1
        return n

    def add(self, chain: str) -> None:
        self.chains.append(chain)

    def args(self, maps: Sequence[str], target: str, seconds: float) -> List[str]:
        return [*BASE, *self.inputs, *FILTER_THREADS, "-filter_complex", ";".join(self.chains), *maps, *VIDEO_CODEC, *AUDIO_CODEC,
                "-t", f"{seconds:.4f}", target]


def slide(target: float, start: float, delay: float, duration: float) -> str:
    """Dojazd z wyhamowaniem (ease-out quart), kończy dokładnie w pozycji docelowej."""
    return f"{int(target)}+({int(start - target)})*pow(1-clip((t-{delay:.3f})/{duration:.3f},0,1),4)"


def _clip_branch(g: Graph, source: Mapping[str, Any], start: float, dur: float, overlay: Optional[str], width: int, height: int,
                 label: str, *, fade_overlay: bool) -> Tuple[str, Optional[int]]:
    """Gałąź obrazu klipu (z pigułką i napisem). Zwraca (etykieta, numer wejścia z dźwiękiem albo None)."""
    n = g.clip(source, start, dur)
    frames = MR.frames(dur)
    g.add(f"[{n}:v]{fit(width, height)},{norm(frames)}[{label}0]")
    if overlay:
        o = g.still(overlay, dur)
        fade = f",fade=t=in:st={MR.OVERLAY_IN_S:.3f}:d={MR.OVERLAY_FADE_S:.3f}:alpha=1" if fade_overlay else ""
        g.add(f"[{o}:v]{RGB_IN},format=yuva420p{fade},setpts=PTS-STARTPTS[{label}o]")
        g.add(f"[{label}0][{label}o]overlay=0:0:format=yuv420:eof_action=repeat,{norm(frames)}[{label}]")
    else:
        g.add(f"[{label}0]null[{label}]")
    return label, (n if source.get("has_audio") else None)


def _card_branch(g: Graph, background: str, seconds: float, layers: Sequence[Mapping[str, Any]], width: int, label: str) -> str:
    """Plansza: tło (z nieruchomym tekstem) i warstwy, które dojeżdżają (`motion`: home z lewej, away/row z prawej,
    `rise` od dołu) i pojawiają się (`fade`)."""
    frames = MR.frames(seconds)
    b = g.still(background, seconds)
    g.add(f"[{b}:v]{RGB_IN},format=yuv444p,{norm_rgb(frames)}[{label}0]")
    current = f"{label}0"
    shift = int(width * 0.045)
    for i, layer in enumerate(layers, start=1):
        n = g.still(layer["path"], seconds)
        delay = float(layer.get("delay") or 0.0)
        fade = f",fade=t=in:st={delay:.3f}:d=0.35:alpha=1" if layer.get("fade") else ""
        g.add(f"[{n}:v]{RGB_IN},format=yuva444p{fade},setpts=PTS-STARTPTS[{label}l{i}]")
        motion = layer.get("motion")
        x, y = str(int(layer["x"])), str(int(layer["y"]))
        if motion == "home":
            x = slide(layer["x"], layer["x"] - shift, delay, MR_SLIDE)
        elif motion in ("away", "row"):
            x = slide(layer["x"], layer["x"] + shift, delay, MR_SLIDE)
        elif motion == "rise":
            y = slide(layer["y"], layer["y"] + int(width * 0.012), delay, 0.45)
        elif motion == "scroll":
            y = layer["y_expr"]
        g.add(f"[{current}][{label}l{i}]overlay=x='{x}':y='{y}':format=yuv444:eval=frame:eof_action=repeat[{label}{i}]")
        current = f"{label}{i}"
    g.add(f"[{current}]{norm(frames)}[{label}]")
    return label


MR_SLIDE = 0.55


def norm_rgb(frames: int) -> str:
    return f"fps={FPS},settb=1/{FPS},setsar=1,tpad=stop_mode=clone:stop_duration=3,trim=end_frame={frames},setpts=PTS-STARTPTS"


def _xfade_chain(g: Graph, labels: Sequence[str], fades: Sequence[float], offsets: Sequence[float], transitions: Sequence[str]) -> str:
    current = labels[0]
    for i in range(1, len(labels)):
        out = f"x{i}"
        g.add(f"[{current}][{labels[i]}]xfade=transition={transitions[i - 1]}:duration={fades[i - 1]:.4f}:offset={offsets[i - 1]:.4f}[{out}]")
        current = out
    return current


def _silence(g: Graph, seconds: float, label: str) -> str:
    g.add(f"anullsrc=r=48000:cl=stereo,atrim=duration={max(0.001, seconds):.4f},asetpts=PTS-STARTPTS[{label}]")
    return label


def _audio_part(g: Graph, n: Optional[int], seconds: float, label: str, *, fade_in: float = 0.0, fade_out: bool = False) -> str:
    if n is None:
        return _silence(g, seconds, label)
    fades = ""
    if fade_in > 0:
        fades += f",afade=t=in:st=0:d={fade_in:.3f}"
    if fade_out:
        fades += f",afade=t=out:st=0:d={max(0.01, seconds):.3f}"
    g.add(f"[{n}:a]aformat=sample_rates=48000:channel_layouts=stereo,aresample=async=1:first_pts=0,asetpts=PTS-STARTPTS,"
          f"apad,atrim=duration={seconds:.4f}{fades}[{label}]")
    return label


# ─── Odcinki ────────────────────────────────────────────────────────────────


def cover_args(card: Mapping[str, Any], seconds: float, width: int, height: int, target: str) -> List[str]:
    g = Graph()
    v = _card_branch(g, card["background"], seconds, card.get("layers") or [], width, "c")
    a = _silence(g, seconds, "a")
    return g.args(["-map", f"[{v}]", "-map", f"[{a}]"], target, MR.fs(MR.frames(seconds)))


def clip_segment_args(seg: Mapping[str, Any], *, tail: Mapping[str, Any], chapter: Optional[Mapping[str, Any]], bar: Mapping[str, Any],
                      body: Mapping[str, Any], width: int, height: int, target: str) -> List[str]:
    """Odcinek klipu według `seg` z `MR.timeline`.

    `tail`: {"still": png} (okładka) albo {"source", "start", "dur", "overlay"} (koniec poprzedniego klipu).
    `chapter`: plansza meczu {"background", "layers"} albo None. `bar`: {"background", "layers"}.
    `body`: {"source", "start", "overlay"} - start w pliku klipu; długość = `seg["body_s"]`."""
    g = Graph()
    labels: List[str] = []
    tail_s = float(seg["tail_in"])
    tail_audio: Optional[int] = None
    if tail.get("still"):
        n = g.still(tail["still"], tail_s)
        g.add(f"[{n}:v]{RGB_IN},{norm(MR.frames(tail_s))}[t]")
        labels.append("t")
    else:
        _, tail_audio = _clip_branch(g, tail["source"], float(tail["start"]), tail_s, tail.get("overlay"), width, height, "t",
                                     fade_overlay=False)
        labels.append("t")
    transitions = []
    if chapter:
        labels.append(_card_branch(g, chapter["background"], MR.CHAPTER_S, chapter.get("layers") or [], width, "m"))
        transitions.append(CHAPTER_TRANSITION)
    labels.append(_card_branch(g, bar["background"], MR.BAR_S, bar.get("layers") or [], width, "b"))
    transitions.append("fade")
    body_s = float(seg["body_s"])
    _, body_audio = _clip_branch(g, body["source"], float(body["start"]), body_s, body.get("overlay"), width, height, "k", fade_overlay=True)
    labels.append("k")
    transitions.append("fade")
    v = _xfade_chain(g, labels, seg["fades"], seg["offsets"], transitions)
    total = MR.fs(int(seg["frames"]))
    clip_at = float(seg["clip_at"])
    ta = _audio_part(g, tail_audio, tail_s, "ta", fade_out=True)
    gap = _silence(g, max(0.001, clip_at - tail_s), "ga")
    ba = _audio_part(g, body_audio, total - clip_at, "ba", fade_in=MR.XF_S)
    g.add(f"[{ta}][{gap}][{ba}]concat=n=3:v=0:a=1,apad,atrim=duration={total:.4f}[a]")
    return g.args(["-map", f"[{v}]", "-map", "[a]"], target, total)


def end_args(plan_end: Mapping[str, Any], *, tail: Mapping[str, Any], credits: Mapping[str, Any], width: int, height: int,
             target: str) -> List[str]:
    """Koniec: ogon ostatniego klipu przenika się w spis klipów (przewijany, gdy dłuższy niż okno)."""
    g = Graph()
    tail_s = float(plan_end["tail_in"])
    _, tail_audio = _clip_branch(g, tail["source"], float(tail["start"]), tail_s, tail.get("overlay"), width, height, "t", fade_overlay=False)
    card_s = float(plan_end["card_s"])
    v_card = _card_branch(g, credits["background"], card_s, credits.get("layers") or [], width, "e")
    fade = float(plan_end["fade"])
    v = _xfade_chain(g, ["t", v_card], [fade], [round(tail_s - fade, 6)], ["fade"])
    total = MR.fs(int(plan_end["frames"]))
    ta = _audio_part(g, tail_audio, tail_s, "ta", fade_out=True)
    rest = _silence(g, max(0.001, total - tail_s), "ra")
    g.add(f"[{ta}][{rest}]concat=n=2:v=0:a=1,apad,atrim=duration={total:.4f}[a]")
    return g.args(["-map", f"[{v}]", "-map", "[a]"], target, total)


def scroll_expr(y0: int, distance: int, card_s: float) -> str:
    """Przewijanie spisu: stoi 0,8 s, jedzie równo z miękkim startem i końcem, stoi 1 s na końcu."""
    if distance <= 0:
        return str(int(y0))
    run = max(0.5, card_s - 1.8)
    return f"{int(y0)}-{int(distance)}*(3*pow(clip((t-0.8)/{run:.3f},0,1),2)-2*pow(clip((t-0.8)/{run:.3f},0,1),3))"


def frame_args(source: Mapping[str, Any], at: float, width: int, height: int, target: str) -> List[str]:
    """Pierwsza klatka klipu (tło belki) w rozmiarze kadru, jako PNG."""
    return [*BASE, "-ss", f"{max(0.0, at):.3f}", "-i", str(source["url"]), "-frames:v", "1", "-vf", fit(width, height), target]


def concat_args(listing: str, metadata: str, target: str) -> List[str]:
    return [*BASE, "-f", "concat", "-safe", "0", "-i", listing, "-i", metadata, "-map", "0:v", "-map", "0:a", "-map_metadata", "1",
            "-map_chapters", "1", "-c:v", "copy", *AUDIO_CODEC, "-movflags", "+faststart", target]


def concat_listing(paths: Sequence[str]) -> str:
    def esc(path: str) -> str:
        return path.replace("'", "'\\''")

    return "".join(f"file '{esc(p)}'\n" for p in paths)


def zoom_decode_args(source: Mapping[str, Any], start: float, dur: float) -> List[str]:
    """Dekodowanie fragmentu klipu do surowych klatek RGB w rozmiarze źródła (zoom kadruje z pełnej rozdzielczości)."""
    return [*BASE, "-ss", f"{max(0.0, start):.3f}", "-t", f"{dur:.3f}", "-i", str(source["url"]), "-an", "-vf",
            f"setpts=PTS-STARTPTS,fps={FPS}", "-f", "rawvideo", "-pix_fmt", "rgb24", "pipe:1"]


def zoom_encode_args(width: int, height: int, source: Mapping[str, Any], start: float, dur: float, target: str) -> List[str]:
    """Kodowanie klatek po zoomie (prawie bezstratnie, to plik roboczy) z dźwiękiem z tego samego fragmentu źródła."""
    args = [*BASE, "-f", "rawvideo", "-pix_fmt", "rgb24", "-s", f"{width}x{height}", "-framerate", str(FPS), "-i", "pipe:0"]
    maps = ["-map", "0:v"]
    if source.get("has_audio"):
        args += ["-ss", f"{max(0.0, start):.3f}", "-t", f"{dur:.3f}", "-i", str(source["url"])]
        maps += ["-map", "1:a", "-c:a", "aac", "-b:a", "192k"]
    if not source.get("has_audio"):
        maps.append("-an")
    return [*args, *maps, "-c:v", "libx264", "-preset", "veryfast", "-crf", "14", "-pix_fmt", "yuv420p", "-vf", RGB_IN,
            "-t", f"{dur:.3f}", target]
