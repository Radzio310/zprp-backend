import io

from PIL import Image

from app.zprp_public import match_rules as MR


def _jpeg(w, h):
    out = io.BytesIO()
    Image.new("RGB", (w, h), (30, 120, 60)).save(out, "JPEG")
    return out.getvalue()


def test_thumbnail_shrinks_long_side():
    body = _jpeg(3000, 2000)
    thumb = MR.make_thumbnail(body, 480)
    im = Image.open(io.BytesIO(thumb))
    assert max(im.size) <= 480 and len(thumb) < len(body)


def test_thumbnail_garbage_is_none():
    assert MR.make_thumbnail(b"not an image") is None


def test_items_point_thumb_at_resized_variant():
    att = {"1": {"file_url": "https://baza.zprp.pl/zawody_zalaczniki/1_1.jpg", "filename": "a.jpg", "is_pdf": False}}
    item = MR.attachment_items(att, [], lambda u: f"/f?u={u}")[0]
    assert item["thumb_url"].endswith("&w=480") and item["thumb_url"] != item["url"]
