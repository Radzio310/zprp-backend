"""Arkusz oceny delegata (formularz `ocena2`) -> dane do statystyk.

Wierny odpowiednik `parseDelegateEvaluationHtml` z aplikacji
(`components/RefereeEvaluationModal.tsx`): te same wyrażenia, ta sama kolejność
i ten sam kształt wyniku. Serwer i telefon muszą dawać IDENTYCZNY JSON - od
tego zależy `content_hash`, więc arkusz zapisany z obu stron to jedna wersja.
Zgodność pilnuje `tests/test_delegate_evaluation_parser.py` na wyniku parsera
z aplikacji. Moduł-liść: bez `app.db`.
"""

from __future__ import annotations

import re
from typing import Any, Optional

_I = re.IGNORECASE
_ESCAPE = re.compile(r"[-/\\^$*+?.()|\[\]{}]")


def _escape_js(value: str) -> str:
    return _ESCAPE.sub(lambda m: "\\" + m.group(0), value)


def _clean(obj: dict[str, Any]) -> dict[str, Any]:
    """JSON.stringify pomija `undefined` - tu pomijamy None."""
    return {k: v for k, v in obj.items() if v is not None}


def decode_entities(value: str) -> str:
    if not value:
        return ""
    s = value.replace("&nbsp;", " ").replace("&amp;", "&").replace("&quot;", '"')
    s = s.replace("&#039;", "'").replace("&lt;", "<").replace("&gt;", ">")
    s = re.sub(r"&#(\d+);", lambda m: chr(int(m.group(1), 10)), s)
    s = re.sub(r"&#x([0-9a-fA-F]+);", lambda m: chr(int(m.group(1), 16)), s)
    return re.sub(r"\s+", " ", s).strip()


def strip_tags(value: str) -> str:
    if not value:
        return ""
    return decode_entities(re.sub(r"</?[^>]+>", " ", re.sub(r"<br\s*/?>", "\n", value, flags=_I)))


def _one_line(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def split_by_dash(label: str) -> tuple[str, Optional[str]]:
    t = decode_entities(label or "")
    parts = re.split(r"\s*[-–—]\s*", t)
    if len(parts) <= 1:
        return t.strip(), None
    return parts[0].strip(), " - ".join(parts[1:]).strip()


def _grade_from_label(label: str) -> str:
    t = decode_entities(label or "")
    first = re.split(r"\s+", t)[0].strip() if t else ""
    return first or "?"


def grade_label_parts(option_text: str) -> dict[str, Any]:
    t = decode_entities(option_text or "")
    grade = _grade_from_label(t)
    full = re.sub(r"^" + re.escape(grade) + r"\s+", "", t, count=1).strip()
    short, rest = split_by_dash(full)
    return {"grade": grade, "full": full, "short": short, "rest": rest}


def _first(html: str, pattern: str, flags: int = _I) -> str:
    m = re.search(pattern, html, flags)
    return m.group(0) if m else ""


def _attrs(tag: str) -> dict[str, str]:
    attrs: dict[str, str] = {}
    for m in re.finditer(r"([a-zA-Z0-9:_-]+)\s*=\s*[\"']([^\"']*)[\"']", tag):
        attrs[m.group(1).lower()] = m.group(2)
    for m in re.finditer(r"\s(checked|selected|disabled|readonly)\b", tag, _I):
        attrs.setdefault(m.group(1).lower(), "true")
    return attrs


def _selected_option(select_html: str) -> dict[str, Optional[str]]:
    if not select_html:
        return {}
    m = re.search(
        r"<option[^>]*\sselected(?:\s*=\s*[\"']selected[\"'])?[^>]*>([\s\S]*?)</option>",
        select_html,
        _I,
    )
    if not m:
        return {}
    tag = m.group(0)
    value = re.search(r"\svalue\s*=\s*[\"']([^\"']*)[\"']", tag, _I)
    ident = re.search(r"\sid\s*=\s*[\"']([^\"']*)[\"']", tag, _I)
    return {
        "value": value.group(1) if value else None,
        "id": ident.group(1) if ident else None,
        "label": _one_line(strip_tags(m.group(1))),
    }


def _person_like(value: str) -> bool:
    t = _one_line(decode_entities(str(value or "")))
    if not t:
        return False
    up = t.upper()
    if "MPJK/" in up or "S/" in up or "VS" in up:
        return False
    if re.search(r"[0-9]", t) or len(t) < 5:
        return False
    if len([p for p in t.split(" ") if p]) < 2:
        return False
    return bool(re.match(r"^[A-Za-zĄĆĘŁŃÓŚŹŻąćęłńóśźż.\- ]+$", t))


# ---------------------------------------------------------------- bloki


def _match_block(html: str) -> str:
    return _first(html, r"<b>\s*MECZ\s*</b>[\s\S]{0,200000}?</table>\s*</td>\s*</tr>")


def _character_block(html: str) -> str:
    if not html:
        return ""
    start = re.search(r"<b>\s*CHARAKTER MECZU\s*</b>", html, _I)
    if not start:
        return ""
    tail = html[start.start():]
    nxt = re.search(r"<b>\s*[IVX]+\.\s*[^<]+</b>", tail, _I)
    return tail[: nxt.start()] if nxt and nxt.start() > 0 else tail[:300000]


def _section_blocks(html: str) -> list[str]:
    out: list[str] = []
    for m in re.finditer(
        r"<b>\s*([IVX]+)\.\s*([^<]+)\s*</b>[\s\S]{0,350000}?</table>\s*</td>\s*</tr>", html, _I
    ):
        out.append(m.group(0))
        if len(out) > 200:
            break
    return out[:20]


def _block_by_bold(html: str, title: str) -> str:
    return _first(html, r"<b>\s*" + title + r"\s*</b>[\s\S]{0,350000}?</table>\s*</td>\s*</tr>")


# ---------------------------------------------------------------- info


def _protocol_statuses(html: str) -> dict[str, str]:
    out: dict[str, str] = {}
    block = re.search(r"<big><b>\s*Protokół zawodów\s*</b></big>[\s\S]{0,8000}?</table>", html, _I)
    if not block:
        return out
    txt = _one_line(strip_tags(block.group(0)))
    zatw = re.search(r"(ZATWIERDZONY[^Z]*?)(ZWERYFIKOWANY|$)", txt, _I)
    if zatw and zatw.group(1):
        out["protocolStatus"] = decode_entities(zatw.group(1)).strip()
    zw = re.search(r"(ZWERYFIKOWANY[^$]*)", txt, _I)
    if zw and zw.group(1):
        out["delegateVerified"] = decode_entities(zw.group(1)).strip()
    if not out.get("protocolStatus") and "ZATWIERDZONY" in txt.upper():
        out["protocolStatus"] = "ZATWIERDZONY"
    if not out.get("delegateVerified") and "ZWERYFIKOWANY" in txt.upper():
        out["delegateVerified"] = "ZWERYFIKOWANY PRZEZ DELEGATA"
    return out


def _info(block: str, html: str) -> dict[str, Any]:
    info: dict[str, Any] = dict(_protocol_statuses(html))

    comp = re.search(
        r"<tr[^>]*>\s*<td[^>]*>\s*([^<]*Mistrzostwa[\s\S]*?)</td>\s*<td[^>]*>\s*([\s\S]*?)</td>\s*<td[^>]*>\s*([\s\S]*?)</td>\s*</tr>",
        block,
        _I,
    )
    if comp:
        info["competition"] = strip_tags(comp.group(1)).strip()
        info["round"] = strip_tags(comp.group(2)).strip()
        info["kolejka"] = strip_tags(comp.group(3)).strip()
    else:
        first3 = re.search(r"<b>\s*MECZ\s*</b>[\s\S]*?<tr[^>]*>([\s\S]*?)</tr>", block, _I)
        if first3 and first3.group(1):
            cols = [strip_tags(x.group(1)).strip() for x in re.finditer(r"<td[^>]*>([\s\S]*?)</td>", first3.group(1), _I)]
            if len(cols) >= 3:
                info["competition"], info["round"], info["kolejka"] = cols[0], cols[1], cols[2]

    team_row = _first(block, r"<tr[^>]*>\s*<td[^>]*>\s*<big>[\s\S]*?</tr>")
    if team_row:
        bigs = [strip_tags(x.group(1)).strip() for x in re.finditer(r"<big[^>]*>\s*([\s\S]*?)\s*</big>", team_row, _I)]
        if len(bigs) >= 2:
            info["homeTeam"] = bigs[0]
            info["awayTeam"] = bigs[-1]
        score = re.search(r"<b>\s*<big>\s*([^<]+?)\s*</big>\s*</b>", team_row, _I)
        if score and score.group(1):
            info["scoreFull"] = decode_entities(score.group(1)).strip()
        half = re.search(r"\(\s*([0-9]+\s*:\s*[0-9]+)\s*\)", team_row, _I)
        if half and half.group(1):
            info["scoreHalf"] = f"( {decode_entities(half.group(1)).strip()} )"

    row = re.search(
        r"<tr[^>]*>\s*<td[^>]*align=\"right\"[^>]*>\s*([A-Z0-9/._-]+)\s*</td>\s*<td[^>]*align=\"center\"[^>]*>\s*([0-9]{2}\.[0-9]{2}\.[0-9]{4}\s+[0-9]{2}:[0-9]{2})[\s\S]*?</td>\s*<td[^>]*align=\"left\"[^>]*>\s*<a[^>]*>([^<]+)</a>\s*</td>\s*</tr>",
        block,
        _I,
    )
    if row:
        info["matchNumber"] = decode_entities(row.group(1)).strip()
        info["matchDateTime"] = decode_entities(row.group(2)).strip()
        info["city"] = decode_entities(row.group(3)).strip()
        hall = re.search(r"<a[^>]*\stitle\s*=\s*[\"']([^\"']+)[\"']", row.group(0), _I)
        if hall and hall.group(1):
            info["hallTitle"] = decode_entities(hall.group(1)).strip()
    else:
        mn = re.search(r"<td[^>]*align=\"right\"[^>]*>\s*([A-Z]{2,}[A-Z0-9/_-]+)\s*</td>", block, _I)
        if mn and mn.group(1):
            info["matchNumber"] = decode_entities(mn.group(1)).strip()
        dt = re.search(r"<td[^>]*align=\"center\"[^>]*>\s*([0-9]{2}\.[0-9]{2}\.[0-9]{4}\s+[0-9]{2}:[0-9]{2})", block, _I)
        if dt and dt.group(1):
            info["matchDateTime"] = decode_entities(dt.group(1)).strip()
        city = re.search(r"target=\"_blank\"[^>]*>\s*([^<]+)\s*</a>", block, _I)
        if city and city.group(1):
            info["city"] = decode_entities(city.group(1)).strip()

    dele = re.search(
        r"<tr[^>]*>\s*<td[^>]*align=\"right\"[^>]*>\s*&nbsp;\s*</td>\s*<td[^>]*align=\"center\"[^>]*>\s*([^<]+?)\s*</td>",
        block,
        _I,
    )
    if dele:
        d = decode_entities(dele.group(1)).strip()
        if d and d != "—":
            info["delegate"] = d

    try:
        rows = [m.group(0) for m in re.finditer(r"<tr[^>]*>[\s\S]*?</tr>", block, _I)]
        candidates = []
        for r in rows:
            mm = re.search(
                r"<td[^>]*align=\"right\"[^>]*>\s*([\s\S]*?)\s*</td>[\s\S]*?<td[^>]*align=\"left\"[^>]*>\s*([\s\S]*?)\s*</td>",
                r,
                _I,
            )
            if not mm:
                continue
            left = _one_line(strip_tags(mm.group(1)))
            right = _one_line(strip_tags(mm.group(2)))
            if not _person_like(left) or not _person_like(right):
                continue
            if re.search(r"<big", r, _I):
                continue
            candidates.append((left, right, r))
        if candidates:
            scored = []
            for left, right, r in candidates:
                txt = strip_tags(r).lower()
                score = 0.0
                if "http" not in txt and "target" not in txt:
                    score += 2
                if not re.search(r"\d{2}\.\d{2}\.\d{4}", txt):
                    score += 2
                if not re.search(r"mpjk|/\d+", txt):
                    score += 1
                score += rows.index(r) / 10
                scored.append((score, left, right))
            scored.sort(key=lambda item: -item[0])
            info["refereeLeft"] = scored[0][1]
            info["refereeRight"] = scored[0][2]
    except Exception:
        pass
    return info


# ---------------------------------------------------------------- charakter


def _character(block: str) -> dict[str, Any]:
    out: dict[str, Any] = {"criteria": []}
    try:
        checked = [m.group(0) for m in re.finditer(r"<input\b[^>]*\bchecked\b[^>]*>", block, _I)]
        picked_tag = None
        picked: dict[str, str] = {}
        for tag in checked:
            a = _attrs(tag)
            if a.get("type", "").lower() == "radio" and a.get("name", "").lower() == "ocena1":
                picked_tag, picked = tag, a
                break
        if picked_tag is None:
            for tag in checked:
                a = _attrs(tag)
                if a.get("type", "").lower() == "radio" and "ocena" in a.get("name", "").lower():
                    picked_tag, picked = tag, a
                    break
        checked_id = picked.get("id", "")
        label = ""
        if checked_id:
            m = re.search(
                r"<label[^>]*\sfor\s*=\s*[\"']" + _escape_js(checked_id) + r"[\"'][^>]*>([\s\S]*?)</label>",
                block,
                _I,
            )
            if m and m.group(1):
                label = _one_line(strip_tags(m.group(1)))
        if not label and picked_tag:
            idx = block.find(picked_tag)
            if idx >= 0:
                after = block[idx + len(picked_tag): idx + len(picked_tag) + 900]
                local = re.search(
                    r"^\s*(?:&nbsp;|\s)*([^<]{2,200})\s*(?:<br|</td|</label|<input|<select)", after, _I
                )
                if local and local.group(1):
                    label = _one_line(decode_entities(local.group(1)))
        if label:
            short, rest = split_by_dash(label)
            out["difficulty"] = _clean({"short": short, "rest": rest or None, "full": f"{short} - {rest}" if rest else short})
    except Exception:
        pass

    for m in re.finditer(
        r"<tr[^>]*>\s*<td[^>]*>\s*(\d+)\.\s*</td>\s*<td[^>]*>([\s\S]*?)</td>[\s\S]*?<select[\s\S]*?>[\s\S]*?</select>",
        block,
        _I,
    ):
        select = _first(m.group(0), r"<select[\s\S]*?</select>")
        label = _one_line(_selected_option(select).get("label") or "")
        val = (re.split(r"\s+", label)[0] if label else "") or label
        out["criteria"].append({"idx": int(m.group(1)), "title": _one_line(strip_tags(m.group(2))), "value": val.strip() or "ND"})
        if len(out["criteria"]) > 80:
            break
    return out


# ---------------------------------------------------------------- sekcje


def _main_grade(block: str) -> Optional[str]:
    first = re.search(r"\bid\s*=\s*[\"']s_\d+_(\d+)[\"']", block, _I)
    if not first:
        return None
    crit = int(first.group(1))
    for m in re.finditer(r"<input\b[^>]*\bname\s*=\s*[\"']ocena" + str(crit) + r"[\"'][^>]*>", block, _I):
        a = _attrs(m.group(0))
        if a.get("type", "").lower() != "radio" or "checked" not in a or not a.get("id"):
            continue
        label = re.search(
            r"<label[^>]*\bfor\s*=\s*[\"']" + _escape_js(a["id"]) + r"[\"'][^>]*>([\s\S]*?)</label>", block, _I
        )
        text = _one_line(strip_tags(label.group(1))) if label and label.group(1) else ""
        if text:
            return text
    tag = re.search(
        r"<input\b[^>]*\btype\s*=\s*[\"']radio[\"'][^>]*\bname\s*=\s*[\"']ocena" + str(crit) + r"[\"'][^>]*\bchecked\b[^>]*>",
        block,
        _I,
    )
    rid = re.search(r"\bid\s*=\s*[\"']([^\"']+)[\"']", tag.group(0), _I) if tag else None
    if rid:
        label = re.search(
            r"<label[^>]*\bfor\s*=\s*[\"']" + _escape_js(rid.group(1)) + r"[\"'][^>]*>([\s\S]*?)</label>", block, _I
        )
        text = _one_line(strip_tags(label.group(1))) if label and label.group(1) else ""
        if text:
            return text
    return None


def _section(block: str) -> Optional[dict[str, Any]]:
    head = re.search(r"<b>\s*([IVX]+)\.\s*([^<]+)\s*</b>", block, _I)
    if not head:
        return None
    roman = re.sub(r"[^IVX]", "", head.group(1)) or head.group(1)
    title = f"{roman}. {decode_entities(head.group(2)).strip()}"
    main: dict[str, Any] = {"grade": "?", "full": None, "short": None, "rest": None}
    try:
        label = _main_grade(block)
        if label:
            main = grade_label_parts(label)
    except Exception:
        pass
    comment_m = re.search(r"<textarea[^>]*>([\s\S]*?)</textarea>", block, _I)
    comment = decode_entities(comment_m.group(1)).strip() if comment_m and comment_m.group(1) else ""

    items = []
    for m in re.finditer(
        r"<tr[^>]*>\s*<td[^>]*>\s*(\d+)\.\s*</td>\s*<td[^>]*>([\s\S]*?)</td>[\s\S]*?<select[\s\S]*?>[\s\S]*?</select>[\s\S]*?</tr>",
        block,
        _I,
    ):
        select = _first(m.group(0), r"<select[\s\S]*?</select>")
        option = _one_line(_selected_option(select).get("label") or "")
        if not option:
            continue
        parts = grade_label_parts(option)
        items.append(_clean({
            "idx": int(m.group(1)),
            "title": _one_line(strip_tags(m.group(2))),
            "grade": parts["grade"],
            "gradeLabelFull": parts["full"],
            "gradeLabelShort": parts["short"],
            "gradeLabelRest": parts["rest"],
        }))
        if len(items) > 160:
            break
    return _clean({
        "key": roman,
        "title": title,
        "mainGrade": main["grade"],
        "mainLabelFull": main["full"],
        "mainLabelShort": main["short"],
        "mainLabelRest": main["rest"],
        "comment": comment or None,
        "items": items,
    })


def _key_situations(html: str) -> list[dict[str, Any]]:
    block = _block_by_bold(html, "KLUCZOWE SYTUACJE") or _block_by_bold(html, "Kluczowe sytuacje")
    if not block:
        return []
    out = []
    counter = 0
    for row in (m.group(0) for m in re.finditer(r"<tr[^>]*>([\s\S]*?)</tr>", block, _I)):
        if not re.search(r"name\s*=\s*[\"']kolumna1[\"']", row, _I):
            continue
        nr = re.search(r"<td[^>]*>\s*(\d+)\.\s*</td>", row, _I)
        if nr:
            idx = int(nr.group(1))
        else:
            counter += 1
            idx = counter
        desc_m = re.search(r"name=[\"']kolumna1[\"'][^>]*\svalue=[\"']([^\"']*)[\"']", row, _I)
        time_m = re.search(r"name=[\"']kolumna2[\"'][^>]*\svalue=[\"']([^\"']*)[\"']", row, _I)
        desc = decode_entities(desc_m.group(1) if desc_m else "").strip()
        when = decode_entities(time_m.group(1) if time_m else "").strip()
        sel = _selected_option(_first(row, r"<select[\s\S]*?</select>"))
        category = _one_line(sel.get("label") or "")
        if not (desc or when):
            continue
        out.append(_clean({
            "idx": idx,
            "category": category or None,
            "categoryValue": sel.get("value") or sel.get("id") or None,
            "description": desc or None,
            "time": when or None,
        }))
    return out


def _simple_cards(html: str, titles: list[str]) -> list[dict[str, str]]:
    block = next((b for b in (_block_by_bold(html, t) for t in titles) if b), "")
    if not block:
        return []
    items = []
    for row in (m.group(1) for m in re.finditer(r"<tr[^>]*>([\s\S]*?)</tr>", block, _I)):
        cols = [_one_line(strip_tags(x.group(1))) for x in re.finditer(r"<td[^>]*>([\s\S]*?)</td>", row, _I)]
        text = " ".join(cols).strip()
        if not text:
            continue
        low = text.lower()
        if "priorytet" in low or low == "vr" or "popraw" in low:
            continue
        items.append({"title": text})
        if len(items) > 100:
            break
    return items


def parse_delegate_evaluation_html(full_html: str) -> dict[str, Any]:
    html = full_html or ""
    match_block = _match_block(html)
    character = _character_block(html)
    sections = [s for s in (_section(b) for b in _section_blocks(html)) if s]
    return _clean({
        "info": _info(match_block, html) if match_block else None,
        "character": _character(character) if character else None,
        "sections": sections,
        "keySituations": _key_situations(html),
        "priorities": _simple_cards(html, ["CO POPRAWIĆ", "Co poprawić", "NAD CZYM PRACOWAĆ", "Nad czym pracować"]),
        "vr": _simple_cards(html, ["VR", "WIDEO", "Video"]),
    })
