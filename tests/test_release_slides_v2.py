import pytest
from fastapi import HTTPException

from app import release_slides_v2 as v2

TYPES = {
    "r/a.webp": "image/webp",
    "r/b.mp4": "video/mp4",
    "r/b-poster.webp": "image/webp",
}


def test_v1_slide_migrates_without_losing_media_or_text():
    old = {
        "id": "x", "template": "split", "media_key": "r/b.mp4", "media_type": "video",
        "poster_key": "r/b-poster.webp", "video_duration_ms": 6000,
        "kicker": "NOWE", "title": "", "body": "Opis", "accent": "#112233",
        "focal_x": 0.8, "focal_y": 0.5,
    }
    new = v2.migrate_slide_v1(old, {"r/b.mp4": (720, 1280)})
    assert new["schema"] == 2 and new["title"] == "NOWE" and new["layout"] == "side"
    assert new["media"]["key"] == "r/b.mp4" and new["media"]["duration_ms"] == 6000
    assert new["media"]["aspect"] == 0.5625 and new["focus"] is not None
    assert v2.slide_keys(new) == {"r/b.mp4", "r/b-poster.webp"}


def test_clean_slide_accepts_url_when_key_missing_and_rejects_unknown():
    slide = {"title": "T", "media": {"kind": "image", "url": "https://cdn/x/r/a.webp?sig=1", "aspect": 0.5}}
    out = v2.clean_slides_v2([slide], publishing=True, asset_types=TYPES)
    assert out[0]["media"]["key"] == "r/a.webp"
    with pytest.raises(HTTPException):
        v2.clean_slides_v2([{"title": "T", "media": {"kind": "image", "key": "nope"}}],
                           publishing=False, asset_types=TYPES)


def test_validation_rules():
    for bad in ({"tag": "x"}, {"layout": "spiral"}, {"accent": "red"}, {"flight": "fly"}):
        with pytest.raises(HTTPException):
            v2.clean_slides_v2([{"title": "T", **bad}], publishing=False, asset_types=TYPES)
    with pytest.raises(HTTPException):  # duo bez drugiego materiału
        v2.clean_slides_v2(
            [{"title": "T", "layout": "duo", "media": {"kind": "image", "key": "r/a.webp"}}],
            publishing=True, asset_types=TYPES,
        )
    with pytest.raises(HTTPException):  # film musi być mp4
        v2.clean_slides_v2([{"media": {"kind": "video", "key": "r/a.webp"}}],
                           publishing=False, asset_types=TYPES)


def test_projection_to_v1_keeps_old_clients_working():
    slide = v2.clean_slides_v2(
        [{"title": "T", "layout": "zoom", "media": {"kind": "video", "key": "r/b.mp4",
                                                     "poster_key": "r/b-poster.webp", "duration_ms": 20000}}],
        publishing=True, asset_types=TYPES)[0]
    old = v2.project_to_v1(slide)
    assert old["template"] == "hero" and old["media_type"] == "video"
    assert old["video_duration_ms"] == 10000 and old["duration_ms"] == 12000


def test_preview_shots_limit():
    with pytest.raises(HTTPException):
        v2.clean_preview_shots([{"kind": "image", "key": "r/a.webp"}] * 13, TYPES)
    assert len(v2.clean_preview_shots([{"kind": "image", "key": "r/a.webp"}], TYPES)) == 1


def test_draft_fallback_and_json_parsing():
    desc = "- Nowy ekran Giełdy: filtry po okręgu\n- Naprawiono błąd w protokole\n* Szybsze ładowanie"
    slides, warnings = v2.finalize_draft(v2.heuristic_draft(desc, 6), 6)
    assert [s["tag"] for s in slides] == ["new", "fixed", "improved"]
    assert any("dodaj zrzut" in w for w in warnings)
    parsed = v2.parse_draft_json('tekst {"slides":[{"title":"A","tag":"zly","layout":"duo"}]} koniec')
    out, w = v2.finalize_draft(parsed, 6)
    assert out[0]["tag"] == "new" and out[0]["layout"] is None
    with pytest.raises(ValueError):
        v2.parse_draft_json("brak")


# --- szkic przez Claude (mock klienta) ---
import asyncio
import json as _json
from types import SimpleNamespace


class _FakeClient:
    def __init__(self, stop="end_turn", text=None):
        self.calls = []
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self._create))
        self.stop, self.text = stop, text

    async def _create(self, **kw):
        self.calls.append(kw)
        return SimpleNamespace(
            stop_reason=self.stop, content=[SimpleNamespace(type="text", text=self.text)]
        )


_ANSWER = _json.dumps(
    {
        "slides": [
            {"title": "Giełda w kieszeni", "body": "Filtry po okręgu.", "tag": "new", "accent": "#112233",
             "icon": "trophy", "layout": "rise", "side": "right", "flight": "spin"},
            {"title": "X", "body": "", "tag": "zly", "accent": "red", "icon": "nieistnieje",
             "layout": "duo", "side": "x", "flight": "none"},
        ],
        "warnings": ["Pominięto zmianę techniczną."],
    }
)


def test_ai_draft_request_and_cleaning(monkeypatch):
    monkeypatch.setenv("RELEASE_AI_MODEL", "claude-opus-5-5")
    fake = _FakeClient(text=_ANSWER)
    raw, notes = asyncio.run(v2.ai_draft("- Giełda", 4, client=fake))
    kw = fake.calls[0]
    assert kw["model"] == "claude-opus-5-5" and kw["thinking"] == {"type": "adaptive"}
    assert kw["output_config"]["effort"] == "high" and kw["output_config"]["format"]["type"] == "json_schema"
    assert kw["betas"] == ["server-side-fallback-2026-07-01"] and kw["fallbacks"] == "default"
    assert "4" in kw["system"]
    slides, _ = v2.finalize_draft(raw, 4)
    assert slides[0]["icon"] == "trophy" and slides[0]["side"] == "right" and slides[0]["flight"] == "spin"
    assert slides[0]["accent"] == "#112233" and slides[0]["layout"] == "rise"
    assert slides[1]["icon"] is None and slides[1]["accent"] is None and slides[1]["layout"] is None
    assert slides[1]["side"] == "left" and slides[1]["flight"] is None and slides[1]["tag"] == "new"
    assert notes == ["Pominięto zmianę techniczną."]


@pytest.mark.parametrize("stop", ["refusal", "max_tokens"])
def test_ai_draft_bad_stop_reason(stop):
    with pytest.raises(RuntimeError):
        asyncio.run(v2.ai_draft("x", 3, client=_FakeClient(stop=stop, text="{}")))


def test_ai_draft_no_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):
        asyncio.run(v2.ai_draft("x", 3))


def test_draft_schema_is_strict():
    item = v2.DRAFT_SCHEMA["properties"]["slides"]["items"]
    assert item["additionalProperties"] is False and set(item["required"]) == set(item["properties"])
    assert "duo" not in item["properties"]["layout"]["enum"]
