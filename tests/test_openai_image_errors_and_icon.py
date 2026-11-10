import asyncio
import json

import pytest

from app import province_event_icon as I
from app import province_event_rules as R
from app.openai_image_errors import classify, is_retryable


def body(code="", etype="", msg="x"):
    return json.dumps({"error": {"code": code, "type": etype, "message": msg}})


@pytest.mark.parametrize(
    "status,code,etype,msg,kind,fragment",
    [
        (400, "moderation_blocked", "image_generation_user_error", "safety system", "moderation", "filtr treści"),
        (400, "content_policy_violation", "", "", "moderation", "filtr treści"),
        (429, "insufficient_quota", "insufficient_quota", "", "quota", "limit konta"),
        (400, "billing_hard_limit_reached", "", "", "quota", "limit konta"),
        (429, "rate_limit_exceeded", "", "", "rate", "za minutę"),
        (403, "", "", "Your organization must be verified to use the model", "verify", "weryfikacji"),
        (401, "invalid_api_key", "", "", "auth", "Klucz"),
        (503, "", "", "", "server", "chwilowo"),
        (400, "", "invalid_request_error", "Invalid size", "invalid", "Invalid size"),
        (418, "", "", "", "other", "nie wygenerował grafiki wydarzenia"),
    ],
)
def test_mapowanie_bledow(status, code, etype, msg, kind, fragment):
    k, logcode, text = classify(status, body(code, etype, msg), "wydarzenia")
    assert k == kind and fragment in text
    assert "turnieju" not in text


def test_nieczytelna_odpowiedz_i_domyslny_przedmiot():
    k, _, text = classify(400, "<html>oops</html>")
    assert k == "invalid" or k == "other"
    assert classify(500, "", "turnieju")[0] == "server"
    assert is_retryable("rate") and is_retryable("server") and not is_retryable("moderation")


def test_lagodny_prompt_bez_dopisku_nazwy_i_miejsca():
    kw = dict(name="Wigilia sędziowska 2026", event_type="integration", place="Katowice", date_label="")
    full = R.title_image_prompt(**kw, extra="dużo świec")
    soft = R.title_image_prompt(**kw, safe=True)
    assert "dużo świec" in full and "Wigilia" in full
    assert "dużo świec" not in soft and "Wigilia" not in soft and "Katowice" not in soft
    assert "copyrighted" not in full


def test_ikona_ze_slownika_i_walidacja():
    assert I.keyword_icon("Wigilia sędziowska 2026", "integration") == "🎄"
    assert I.keyword_icon("Test biegowy", "fitness_test") == "⏱️"
    assert I.keyword_icon("Coś", "exam") == "📝"
    assert I.valid_icon("🎄") == "🎄" and I.valid_icon("💩") is None
    assert all(I.valid_icon(i) for i in I._TYPE_DEFAULT.values())


def test_pick_icon_fallback_przy_bledzie(monkeypatch):
    async def boom(*a):
        raise RuntimeError("x")

    monkeypatch.setattr(I, "_ask_model", boom)
    assert asyncio.run(I.pick_icon("Wigilia", "integration")) == ("🎄", "keywords")

    async def ok(*a):
        return "🏆"

    monkeypatch.setattr(I, "_ask_model", ok)
    assert asyncio.run(I.pick_icon("Wigilia", "integration")) == ("🏆", "ai")


def test_ikona_w_szczegolach_tylko_gdy_przyslana():
    from datetime import datetime, timezone

    start = datetime(2026, 12, 20, 18, tzinfo=timezone.utc)
    assert "icon" not in R.clean_details({}, start)
    d = R.clean_details({"icon": "🎄", "icon_source": "ai"}, start)
    assert d["icon"] == "🎄" and d["icon_source"] == "ai"
    assert R.clean_details({"icon": "zly"}, start)["icon"] is None
    assert R.clean_details({"icon": "🎄"}, start)["icon_source"] == "manual"


def test_model_nie_istnieje_to_nie_moderacja():
    raw = json.dumps({"error": {"message": "The model 'gpt-image-1' does not exist.", "type": "image_generation_user_error", "param": "model", "code": "invalid_value"}})
    kind, _, text = classify(400, raw, "wydarzenia")
    assert kind == "model" and "OPENAI_IMAGE_MODEL" in text


def test_wybor_modelu_i_parametry():
    from app.openai_image_errors import image_payload, pick_image_model

    assert pick_image_model(["gpt-4o", "gpt-image-1", "gpt-image-1.5", "gpt-image-1-mini", "dall-e-3"]) == "gpt-image-1.5"
    assert pick_image_model(["gpt-image-1", "gpt-image-1-mini"]) == "gpt-image-1"
    assert pick_image_model(["dall-e-3", "gpt-4o"]) == "dall-e-3"
    assert pick_image_model(["gpt-4o"]) is None
    d = image_payload("dall-e-3", "p", "high")
    assert d["size"] == "1792x1024" and d["quality"] == "hd"
    assert image_payload("gpt-image-1.5", "p", "high")["size"] == "1536x1024"
