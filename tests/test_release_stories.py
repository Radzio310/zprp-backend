from fastapi import HTTPException
import pytest

from app.release_stories import ReleaseStorySlide, _clean_and_validate_slides


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
