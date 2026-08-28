from fastapi import HTTPException
import pytest

from app.release_stories import (
    ReleaseStorySlide,
    _clean_and_validate_slides,
    _image_canvas,
    _prepare_image,
    _prepare_video,
    _recent_available_versions,
    _video_frame_args,
)


def _slide(**values):
    payload = {
        "id": "slide-1",
        "title": "Nowa BAZA",
        "media_key": "release/video.mp4",
    }
    payload.update(values)
    return ReleaseStorySlide(**payload)


def test_video_slide_keeps_generated_poster_and_uses_real_duration():
    result = _clean_and_validate_slides(
        [
            _slide(
                media_type="video",
                poster_key="release/poster.webp",
                video_duration_ms=7340,
                duration_ms=5000,
            )
        ],
        publishing=True,
        allowed_asset_types={
            "release/video.mp4": "video/mp4",
            "release/poster.webp": "image/webp",
        },
    )

    assert result[0]["duration_ms"] == 7340
    assert result[0]["poster_key"] == "release/poster.webp"
    assert "media_url" not in result[0]
    assert "poster_url" not in result[0]


def test_video_slide_without_generated_poster_is_rejected():
    with pytest.raises(HTTPException) as error:
        _clean_and_validate_slides(
            [_slide(media_type="video", video_duration_ms=5000)],
            publishing=True,
            allowed_asset_types={"release/video.mp4": "video/mp4"},
        )

    assert error.value.status_code == 422
    assert "posteru" in str(error.value.detail)


def test_legacy_image_slide_remains_compatible():
    slide = _slide(media_key="release/image.webp")
    result = _clean_and_validate_slides(
        [slide],
        publishing=True,
        allowed_asset_types={"release/image.webp": "image/webp"},
    )

    assert result[0]["media_type"] == "image"
    assert result[0]["poster_key"] is None


def test_recent_release_window_counts_versions_without_stories():
    assert _recent_available_versions(
        ["1.7.0", "2.0.0", "2.0.1", "2.0.2"], "2.0.1", limit=3
    ) == ["1.7.0", "2.0.0", "2.0.1"]


def test_recent_release_window_is_sorted_and_never_exceeds_three():
    assert _recent_available_versions(
        ["2.0.1", "1.9.9", "2.0.0", "2.0.1", "2.1.0"],
        "2.0.1",
        limit=3,
    ) == ["1.9.9", "2.0.0", "2.0.1"]


def _png(width: int, height: int) -> bytes:
    import io

    from PIL import Image

    buffer = io.BytesIO()
    Image.new("RGB", (width, height), (120, 60, 30)).save(buffer, format="PNG")
    return buffer.getvalue()


def _image_size(payload: bytes) -> tuple[int, int]:
    import io

    from PIL import Image

    with Image.open(io.BytesIO(payload)) as opened:
        return opened.size


@pytest.mark.parametrize(
    "width,height",
    [
        (1080, 2400),   # nagranie ekranu 20:9
        (1220, 2712),   # nagranie ekranu 9:20
        (1920, 1080),   # materiał poziomy
        (1000, 1000),   # kwadrat
        (100, 100),     # miniatura
    ],
)
def test_media_with_odd_ratio_is_normalised_instead_of_rejected(width, height):
    payload, out_w, out_h = _prepare_image(_png(width, height))

    assert _image_size(payload) == (out_w, out_h)
    assert abs(out_w / out_h - 9 / 16) < 0.001


def test_image_close_to_target_keeps_its_own_canvas():
    payload, out_w, out_h = _prepare_image(_png(720, 1280))

    assert (out_w, out_h) == (720, 1280)
    assert _image_size(payload) == (720, 1280)


def test_canvas_never_shrinks_the_source_below_its_own_resolution():
    # Kwadrat 1000x1000 na płótnie 1080x1920 byłby pomniejszony do 1080x1080
    # tylko po to, żeby zmieścić się w wysokości - płótno ma rosnąć razem z nim.
    assert _image_canvas(1000, 1000) == (999, 1776)
    assert _image_canvas(2000, 3000) == (1080, 1920)


def test_video_close_to_target_is_only_cropped():
    args = _video_frame_args(1080, 1920)

    assert args[0] == "-vf"
    assert "crop=720:1280" in args[1]
    assert "overlay" not in args[1]


def test_screen_recording_keeps_whole_frame_on_blurred_background():
    args = _video_frame_args(1080, 2400)

    assert args[0] == "-filter_complex"
    graph = args[1]
    assert "-2" in graph  # parzyste wymiary bez force_divisible_by (FFmpeg < 4.4)
    assert "force_divisible_by" not in graph
    assert "boxblur" in graph
    assert "overlay=(W-w)/2:(H-h)/2" in graph
    # Nagranie ekranu bywa bez dźwięku - mapowanie audio musi być opcjonalne.
    assert args[-2:] == ["-map", "0:a?"]


def test_landscape_video_is_accepted_too():
    args = _video_frame_args(1920, 1080)

    assert args[0] == "-filter_complex"


def test_blurred_frame_falls_back_to_crop_when_ffmpeg_rejects_the_filter():
    """Starszy FFmpeg bez tego filtra ma dać film z kadrowaniem, a nie błąd."""
    from pathlib import Path as _Path

    import app.release_stories as module
    from fastapi import HTTPException

    used = []

    def fake_run(command, error_detail):
        used.append(list(command))
        if "-filter_complex" in command:
            raise HTTPException(status_code=422, detail=error_detail)
        target = _Path(command[-1])
        if target.suffix == ".png":
            target.write_bytes(_png(720, 1280))
        else:
            target.write_bytes(b"fake-mp4")
        return None

    def fake_metadata(path):
        return (5.0, 1080, 2400) if _Path(path).stem == "source" else (5.0, 720, 1280)

    original_run, original_meta = module._run_media_command, module._video_metadata
    module._run_media_command, module._video_metadata = fake_run, fake_metadata
    try:
        video, poster, width, height, duration_ms = _prepare_video(b"raw", ".mp4")
    finally:
        module._run_media_command, module._video_metadata = original_run, original_meta

    assert video == b"fake-mp4"
    assert poster and (width, height) == (720, 1280)
    assert duration_ms == 5000
    assert "-filter_complex" in used[0]  # najpierw pełny kadr na rozmytym tle
    assert used[1][used[1].index("-vf") + 1].startswith("scale=720:1280")
