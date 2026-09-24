"""
Maile powiadomień okręgu z Obsady - szablony (bez bazy i sieci).

Ta sama rodzina wyglądu, co alert o saldzie klubów (`province_alert_emails`):
granatowy nagłówek z herbem okręgu, złoty pasek, karty z lewą krawędzią w kolorze
wagi sprawy, tabelki z CSS w `style` (Gmail wycina <style>, Outlook nie zna
flexboksa). Wysyłka idzie tym samym `send_alert_email`, tylko z własną nazwą
nadawcy („BAZA - Obsada okręgu", env `ASSIGNMENT_ALERT_FROM_NAME`) i tagiem
`assignment-alert`, żeby statystyki dostarczeń się nie mieszały.

Każdy mecz ma własny przycisk: `BAZA_WEB_URL/assignments?match=<IdZawody>`
otwiera Obsadę od razu na tym meczu.
"""

from __future__ import annotations

import html
import os
from urllib.parse import quote
from dataclasses import dataclass, field
from typing import Optional, Sequence

from app.district_alert_rules import KIND_CITY, KIND_LABELS, KIND_OFFTIME, KIND_OVERLAP, missing_text
from app.province_alert_emails import (
    GOLD,
    INK,
    LINE,
    MUTED,
    NAVY,
    NAVY_DARK,
    PAGE,
    RED,
    AMBER,
    baza_web_url,
    logo_url,
)
from app.province_alert_rules import plural, province_title

GREEN = "#1E7F4F"
SLATE = "#44546A"


def sender_name() -> str:
    return (os.getenv("ASSIGNMENT_ALERT_FROM_NAME") or "BAZA - Obsada okręgu").strip()


TAG = "assignment-alert"


def obsada_url(match_id: str = "") -> str:
    """Obsada w BAZA_web; z numerem meczu - od razu na tym meczu."""
    base = f"{baza_web_url()}/assignments"
    return f"{base}?match={quote(str(match_id), safe='')}" if match_id else base


def settings_url() -> str:
    return f"{baza_web_url()}/assignments?alerts=1"


def _e(value: object) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


# ---------------------------------------------------------------------------
# Dane kart
# ---------------------------------------------------------------------------

@dataclass
class SlotLine:
    label: str
    person: Optional[str]
    #: Gniazdo wymagane od okręgu (puste = brak).
    required: bool = True
    #: Drugi stolikowy „od klubu".
    from_club: bool = False


@dataclass
class Suggestion:
    name: str
    km: Optional[float]
    why: str = ""


@dataclass
class UnassignedCard:
    match_id: str
    code: str
    teams: str
    when: str
    hours_left: float
    left_text: str
    competition: str = ""
    hall: str = ""
    city: str = ""
    address: str = ""
    missing: dict = field(default_factory=dict)
    slots: list[SlotLine] = field(default_factory=list)
    suggestions: list[Suggestion] = field(default_factory=list)
    suggest_kind: str = ""
    suggest_note: str = ""


@dataclass
class CollisionRow:
    judge: str
    kind: str
    headline: str
    detail: str


@dataclass
class CollisionCard:
    match_id: str
    code: str
    teams: str
    when: str
    previous: str = ""
    hall: str = ""
    city: str = ""
    rows: list[CollisionRow] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Klocki
# ---------------------------------------------------------------------------

def _pill(text: str, color: str, tint: str) -> str:
    return (
        f'<span style="display:inline-block;padding:3px 8px;border-radius:999px;background:{tint};'
        f'font-size:10px;font-weight:bold;letter-spacing:1px;color:{color};">{_e(text)}</span>'
    )


def _button(label: str, link: str, *, small: bool = False) -> str:
    pad = "9px 16px" if small else "13px 26px"
    size = "12px" if small else "14px"
    bg = NAVY if small else GOLD
    fg = "#FFFFFF" if small else NAVY_DARK
    return (
        f'<table role="presentation" cellpadding="0" cellspacing="0"><tr>'
        f'<td align="center" bgcolor="{bg}" style="border-radius:10px;background:{bg};">'
        f'<a href="{_e(link)}" target="_blank" style="display:inline-block;padding:{pad};'
        f'font-family:Arial,Helvetica,sans-serif;font-size:{size};font-weight:bold;color:{fg};'
        f'text-decoration:none;border-radius:10px;">{_e(label)} &rarr;</a></td></tr></table>'
    )


def _stat(label: str, value: str, color: str) -> str:
    return (
        f'<td align="center" width="33%" style="padding:12px 6px;font-family:Arial,Helvetica,sans-serif;">'
        f'<div style="font-size:20px;font-weight:bold;color:{color};">{_e(value)}</div>'
        f'<div style="margin-top:2px;font-size:11px;letter-spacing:0.5px;color:{MUTED};">{_e(label)}</div></td>'
    )


def _stats(cells: Sequence[tuple[str, str, str]]) -> str:
    return (
        f'<tr><td style="padding:18px 28px 16px 28px;"><table role="presentation" width="100%" cellpadding="0" '
        f'cellspacing="0" style="border:1px solid {LINE};border-radius:12px;background:#FAFBFD;"><tr>'
        + "".join(_stat(label, value, color) for label, value, color in cells)
        + "</tr></table></td></tr>"
    )


def _frame(
    *,
    province_key: str,
    province_display: str,
    kicker: str,
    heading: str,
    intro: str,
    body_rows: str,
    footer_note: str,
    test: bool,
    preview_note: str,
    cta_label: str,
    cta_link: str,
) -> str:
    name = province_title(province_display)
    logo = logo_url(province_key)
    logo_html = (
        f'<td width="64" valign="middle" style="padding-right:14px;">'
        f'<img src="{_e(logo)}" width="56" height="56" alt="{_e(name)}" '
        f'style="display:block;width:56px;height:56px;border-radius:28px;background:#FFFFFF;border:2px solid {GOLD};"></td>'
        if logo
        else ""
    )
    test_html = (
        f'<tr><td style="padding:14px 28px 0 28px;"><div style="padding:10px 12px;border-radius:10px;'
        f'border:1px dashed {GOLD};background:#FFF8E6;font-family:Arial,Helvetica,sans-serif;font-size:12px;'
        f'line-height:18px;color:{INK};"><b>Wiadomość próbna.</b> Tak będzie wyglądało powiadomienie. '
        f'{_e(preview_note)}</div></td></tr>'
        if test
        else ""
    )
    return f"""<!doctype html>
<html lang="pl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_e(name)} - {_e(kicker.lower())}</title></head>
<body style="margin:0;padding:0;background:{PAGE};">
<div style="display:none;max-height:0;overflow:hidden;color:{PAGE};">{_e(name)}: {_e(heading)}</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:{PAGE};">
<tr><td align="center" style="padding:26px 10px;">
  <table role="presentation" width="600" cellpadding="0" cellspacing="0"
         style="width:100%;max-width:600px;background:#FFFFFF;border-radius:16px;overflow:hidden;border:1px solid {LINE};">
    <tr><td style="background:{NAVY};padding:22px 28px;">
      <table role="presentation" cellpadding="0" cellspacing="0"><tr>
        {logo_html}
        <td valign="middle" style="font-family:Arial,Helvetica,sans-serif;">
          <div style="font-size:11px;font-weight:bold;letter-spacing:2px;color:{GOLD};">{_e(kicker)} &middot; {_e(name.upper())}</div>
          <div style="margin-top:6px;font-size:22px;line-height:28px;font-weight:bold;color:#FFFFFF;">{_e(heading)}</div>
        </td>
      </tr></table>
    </td></tr>
    <tr><td style="height:4px;line-height:4px;font-size:0;background:{GOLD};">&nbsp;</td></tr>
    {test_html}
    <tr><td style="padding:18px 28px 0 28px;font-family:Arial,Helvetica,sans-serif;font-size:14px;line-height:21px;color:{INK};">
      {_e(intro)}
    </td></tr>
    {body_rows}
    <tr><td align="center" style="padding:6px 28px 26px 28px;">{_button(cta_label, cta_link)}</td></tr>
    <tr><td style="padding:16px 28px 22px 28px;border-top:1px solid {LINE};font-family:Arial,Helvetica,sans-serif;
                   font-size:11px;line-height:17px;color:{MUTED};">
      {_e(footer_note)} Ustawienia: BAZA_web &rarr; Obsada &rarr; dzwonek „Powiadomienia okręgu”.
    </td></tr>
  </table>
  <div style="padding-top:12px;font-family:Arial,Helvetica,sans-serif;font-size:11px;color:#8A96A8;">BAZA &middot; Obsada okręgu</div>
</td></tr>
</table>
</body></html>"""


def _info_line(icon: str, text: str) -> str:
    if not text:
        return ""
    return (
        f'<div style="margin-top:4px;font-size:13px;line-height:19px;color:{SLATE};">'
        f'<span style="color:{MUTED};">{icon}</span>&nbsp; {_e(text)}</div>'
    )


# ---------------------------------------------------------------------------
# Mecz bez obsady
# ---------------------------------------------------------------------------

def _slot_row(slot: SlotLine, last: bool) -> str:
    border = "" if last else f"border-bottom:1px solid {LINE};"
    if slot.person:
        value = f'<span style="color:{INK};font-weight:bold;">{_e(slot.person)}</span>'
        mark = f'<span style="color:{GREEN};font-weight:bold;">&#10003;</span>'
    elif slot.from_club:
        value = f'<span style="color:{MUTED};">od klubu gospodarza</span>'
        mark = f'<span style="color:{MUTED};">&middot;</span>'
    elif slot.required:
        value = f'<span style="color:{RED};font-weight:bold;">BRAK</span>'
        mark = f'<span style="color:{RED};font-weight:bold;">&#10007;</span>'
    else:
        value = f'<span style="color:{MUTED};">niewymagany</span>'
        mark = f'<span style="color:{MUTED};">&middot;</span>'
    return (
        f'<tr><td width="18" style="padding:7px 0;{border}font-size:13px;">{mark}</td>'
        f'<td style="padding:7px 0;{border}font-size:13px;color:{MUTED};">{_e(slot.label)}</td>'
        f'<td align="right" style="padding:7px 0;{border}font-size:13px;">{value}</td></tr>'
    )


def _suggestions_html(card: UnassignedCard) -> str:
    if not card.suggestions and not card.suggest_note:
        return ""
    kind = {"field": "na boisko", "table": "do stolika"}.get(card.suggest_kind, "")
    head = (
        f'<div style="font-size:11px;font-weight:bold;letter-spacing:1px;color:{NAVY};">'
        f'&#10024;&nbsp; AUTOMAT PROPONUJE{(" " + _e(kind.upper())) if kind else ""}</div>'
    )
    if not card.suggestions:
        return (
            f'<div style="padding:10px 12px;border-radius:10px;background:#F4F7FC;">{head}'
            f'<div style="margin-top:6px;font-size:12.5px;line-height:18px;color:{SLATE};">{_e(card.suggest_note)}</div></div>'
        )
    rows = []
    for index, item in enumerate(card.suggestions, start=1):
        km = f"{int(round(item.km))} km" if item.km is not None else "km ?"
        why = f'<div style="font-size:11.5px;line-height:16px;color:{MUTED};">{_e(item.why)}</div>' if item.why else ""
        rows.append(
            f'<tr><td width="22" valign="top" style="padding:6px 0;font-size:12px;font-weight:bold;color:{GOLD};">{index}.</td>'
            f'<td valign="top" style="padding:6px 0;"><div style="font-size:13px;font-weight:bold;color:{INK};">{_e(item.name)}</div>{why}</td>'
            f'<td valign="top" align="right" style="padding:6px 0;white-space:nowrap;font-size:12px;font-weight:bold;color:{NAVY_DARK};">{_e(km)}</td></tr>'
        )
    return (
        f'<div style="padding:10px 12px;border-radius:10px;background:#F4F7FC;">{head}'
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin-top:4px;">{"".join(rows)}</table></div>'
    )


def _unassigned_card(card: UnassignedCard) -> str:
    urgent = card.hours_left <= 24
    tone = RED if urgent else AMBER
    tint = "#FDECEC" if urgent else "#FFF4E0"
    slots = "".join(_slot_row(slot, index == len(card.slots) - 1) for index, slot in enumerate(card.slots))
    place = " · ".join(part for part in (card.hall, card.city) if part) or "hala nieznana"
    comp = f" &middot; {_e(card.competition)}" if card.competition else ""
    return f"""
<tr><td style="padding:0 28px 16px 28px;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0"
         style="border:1px solid {LINE};border-left:5px solid {tone};border-radius:12px;background:#FFFFFF;">
    <tr><td style="padding:16px 18px 4px 18px;font-family:Arial,Helvetica,sans-serif;">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>
        <td valign="top">{_pill(card.left_text.upper(), tone, tint)}
          <div style="margin-top:8px;font-size:11px;font-weight:bold;letter-spacing:1px;color:{MUTED};">{_e(card.code)}{comp}</div>
          <div style="margin-top:3px;font-size:17px;line-height:22px;font-weight:bold;color:{INK};">{_e(card.teams)}</div>
          {_info_line("&#128197;", card.when)}
          {_info_line("&#128205;", place + (f", {card.address}" if card.address else ""))}
        </td>
        <td valign="top" align="right" style="white-space:nowrap;">
          <div style="font-size:11px;letter-spacing:1px;color:{MUTED};">BRAKUJE</div>
          <div style="font-size:15px;line-height:20px;font-weight:bold;color:{tone};">{_e(missing_text(card.missing))}</div>
        </td>
      </tr></table>
    </td></tr>
    <tr><td style="padding:6px 18px 6px 18px;font-family:Arial,Helvetica,sans-serif;">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0">{slots}</table>
    </td></tr>
    <tr><td style="padding:6px 18px 8px 18px;font-family:Arial,Helvetica,sans-serif;">{_suggestions_html(card)}</td></tr>
    <tr><td style="padding:4px 18px 16px 18px;">{_button("Obsadź ten mecz", obsada_url(card.match_id), small=True)}</td></tr>
  </table>
</td></tr>"""


def build_unassigned_message(
    *,
    province_key: str,
    province_display: str,
    threshold: int,
    cards: list[UnassignedCard],
    test: bool = False,
    preview_note: str = "",
) -> tuple[str, str, str]:
    """(temat, HTML, tekst) zestawienia meczów bez obsady."""
    name = province_title(province_display)
    count = len(cards)
    word = plural(count, "mecz", "mecze", "meczów")
    heading = f"{count} {word} bez obsady w ciągu {threshold} h" if count else "Wszystkie mecze w oknie obsadzone"
    subject = f"{name}: {heading}"
    if cards and count == 1:
        subject = f"{name}: brak obsady - {cards[0].code}, {cards[0].when}"
    if test:
        subject = "[TEST] " + subject
    field_n = sum(int(card.missing.get("field") or 0) for card in cards)
    table_n = sum(int(card.missing.get("table") or 0) for card in cards)
    stats = (
        _stats(
            [
                (word, str(count), NAVY),
                ("brak boiskowych", str(field_n), RED if field_n else MUTED),
                ("brak stolikowych", str(table_n), AMBER if table_n else MUTED),
            ]
        )
        if count
        else ""
    )
    body = stats + "".join(_unassigned_card(card) for card in cards)
    if not cards:
        body = (
            f'<tr><td style="padding:18px 28px;font-family:Arial,Helvetica,sans-serif;font-size:14px;'
            f'line-height:21px;color:{INK};">W najbliższych {threshold} h żaden mecz okręgu nie ma pustego wymaganego gniazda.</td></tr>'
        )
    intro = (
        f"Do tych meczów zostało mniej niż {threshold} h, a w obsadzie wciąż brakuje wymaganych sędziów. "
        "Przy każdym meczu Automat podpowiada trzech najlepszych wolnych kandydatów - propozycja niczego nie zapisuje."
    )
    html_body = _frame(
        province_key=province_key,
        province_display=province_display,
        kicker="OBSADA OKRĘGU",
        heading=heading,
        intro=intro,
        body_rows=body,
        footer_note=(
            "O każdym meczu piszemy raz, gdy przekroczy próg. Stolikowy od klubu, delegaci i stolik "
            "w kategoriach bez stolika okręgowego nie są brakiem."
        ),
        test=test,
        preview_note=preview_note,
        cta_label="Otwórz Obsadę",
        cta_link=obsada_url(),
    )
    lines: list[str] = []
    if test:
        lines += ["WIADOMOŚĆ PRÓBNA - tak będzie wyglądało powiadomienie. " + preview_note, ""]
    lines += [f"{name}: {heading}", ""]
    for card in cards:
        lines += [
            f"* {card.code} - {card.teams}",
            f"  {card.when} ({card.left_text})",
            f"  {', '.join(part for part in (card.hall, card.city, card.address) if part) or 'hala nieznana'}",
            f"  Brakuje: {missing_text(card.missing)}",
        ]
        for slot in card.slots:
            state = slot.person or ("od klubu" if slot.from_club else ("BRAK" if slot.required else "niewymagany"))
            lines.append(f"    {slot.label}: {state}")
        if card.suggestions:
            lines.append("  Automat proponuje: " + "; ".join(
                f"{item.name} ({int(round(item.km))} km)" if item.km is not None else item.name
                for item in card.suggestions
            ))
        elif card.suggest_note:
            lines.append(f"  Automat: {card.suggest_note}")
        lines += [f"  Obsadź: {obsada_url(card.match_id)}", ""]
    lines += [f"Obsada: {obsada_url()}"]
    return subject, html_body, "\n".join(lines)


# ---------------------------------------------------------------------------
# Kolizje
# ---------------------------------------------------------------------------

KIND_TONES = {
    KIND_OVERLAP: (RED, "#FDECEC"),
    KIND_OFFTIME: (RED, "#FDECEC"),
    KIND_CITY: (AMBER, "#FFF4E0"),
}


def _collision_row(row: CollisionRow, last: bool) -> str:
    tone, tint = KIND_TONES.get(row.kind, (AMBER, "#FFF4E0"))
    border = "" if last else f"border-bottom:1px solid {LINE};"
    return (
        f'<tr><td style="padding:10px 0;{border}font-family:Arial,Helvetica,sans-serif;">'
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>'
        f'<td valign="top"><div style="font-size:14px;font-weight:bold;color:{INK};">{_e(row.judge)}</div>'
        f'<div style="margin-top:3px;font-size:13px;line-height:19px;color:{SLATE};">{_e(row.headline)}</div>'
        + (f'<div style="margin-top:2px;font-size:12px;line-height:17px;color:{MUTED};">{_e(row.detail)}</div>' if row.detail else "")
        + f'</td><td valign="top" align="right" style="padding-left:8px;white-space:nowrap;">'
        f'{_pill(KIND_LABELS.get(row.kind, row.kind).upper(), tone, tint)}</td></tr></table></td></tr>'
    )


def _collision_card(card: CollisionCard) -> str:
    hard = any(row.kind != KIND_CITY for row in card.rows)
    tone = RED if hard else AMBER
    place = " · ".join(part for part in (card.hall, card.city) if part) or "hala nieznana"
    previous = (
        f'<div style="margin-top:4px;font-size:12px;color:{MUTED};">było: <s>{_e(card.previous)}</s></div>'
        if card.previous
        else ""
    )
    rows = "".join(_collision_row(row, index == len(card.rows) - 1) for index, row in enumerate(card.rows))
    return f"""
<tr><td style="padding:0 28px 16px 28px;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0"
         style="border:1px solid {LINE};border-left:5px solid {tone};border-radius:12px;background:#FFFFFF;">
    <tr><td style="padding:16px 18px 6px 18px;font-family:Arial,Helvetica,sans-serif;">
      {_pill("NOWY TERMIN", NAVY, "#E8EFFA")}
      <div style="margin-top:8px;font-size:11px;font-weight:bold;letter-spacing:1px;color:{MUTED};">{_e(card.code)}</div>
      <div style="margin-top:3px;font-size:17px;line-height:22px;font-weight:bold;color:{INK};">{_e(card.teams)}</div>
      <div style="margin-top:6px;font-size:15px;font-weight:bold;color:{NAVY_DARK};">&#128197;&nbsp; {_e(card.when)}</div>
      {previous}
      {_info_line("&#128205;", place)}
    </td></tr>
    <tr><td style="padding:2px 18px 4px 18px;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0">{rows}</table></td></tr>
    <tr><td style="padding:6px 18px 16px 18px;">{_button("Otwórz mecz w Obsadzie", obsada_url(card.match_id), small=True)}</td></tr>
  </table>
</td></tr>"""


def build_collision_message(
    *,
    province_key: str,
    province_display: str,
    cards: list[CollisionCard],
    personal: bool = False,
    test: bool = False,
    preview_note: str = "",
) -> tuple[str, str, str]:
    """(temat, HTML, tekst) o kolizjach po zmianie terminu.

    `personal` - wersja dla samego sędziego: tylko jego kolizje, w drugiej osobie.
    """
    name = province_title(province_display)
    count = sum(len(card.rows) for card in cards)
    hard = sum(1 for card in cards for row in card.rows if row.kind != KIND_CITY)
    word = plural(count, "kolizja", "kolizje", "kolizji")
    if personal:
        heading = "Zmiana terminu - sprawdź swój kalendarz"
    else:
        heading = f"{count} {word} po zmianie terminu" if count else "Brak kolizji po zmianie terminu"
    subject = f"{name}: {heading}"
    if len(cards) == 1:
        subject = f"{name}: {'kolizja' if hard else 'uwaga'} - {cards[0].code} przeniesiony na {cards[0].when}"
    if test:
        subject = "[TEST] " + subject
    stats = (
        _stats(
            [
                (plural(len(cards), "mecz przeniesiony", "mecze przeniesione", "meczów przeniesionych"), str(len(cards)), NAVY),
                ("twarde kolizje", str(hard), RED if hard else MUTED),
                ("ten sam dzień, inne miasto", str(count - hard), AMBER if count - hard else MUTED),
            ]
        )
        if cards and not personal
        else ""
    )
    body = stats + "".join(_collision_card(card) for card in cards)
    if not cards:
        body = (
            f'<tr><td style="padding:18px 28px;font-family:Arial,Helvetica,sans-serif;font-size:14px;'
            f'line-height:21px;color:{INK};">Żaden przeniesiony mecz nie koliduje teraz z terminarzem sędziów.</td></tr>'
        )
    intro = (
        "Mecz, w którym jesteś w obsadzie, zmienił termin i nowy termin nachodzi na coś w Twoim kalendarzu. "
        "Porozmawiaj z obsadowym albo zgłoś mecz na giełdzie."
        if personal
        else "Te mecze zmieniły termin i ktoś z ich obsady ma teraz kolizję. Dwa mecze naraz liczymy tak jak "
        "Automat: 2 h meczu, dojazd 60 km/h i 45 minut zapasu."
    )
    html_body = _frame(
        province_key=province_key,
        province_display=province_display,
        kicker="OBSADA OKRĘGU",
        heading=heading,
        intro=intro,
        body_rows=body,
        footer_note="O każdej kolizji piszemy raz - przy kolejnej zmianie terminu sprawdzamy od nowa.",
        test=test,
        preview_note=preview_note,
        cta_label="Otwórz Obsadę",
        cta_link=obsada_url(),
    )
    lines: list[str] = []
    if test:
        lines += ["WIADOMOŚĆ PRÓBNA - tak będzie wyglądało powiadomienie. " + preview_note, ""]
    lines += [f"{name}: {heading}", ""]
    for card in cards:
        lines += [f"* {card.code} - {card.teams}", f"  Nowy termin: {card.when}"]
        if card.previous:
            lines.append(f"  Było: {card.previous}")
        lines.append(f"  {', '.join(part for part in (card.hall, card.city) if part) or 'hala nieznana'}")
        for row in card.rows:
            lines.append(f"  - {row.judge} [{KIND_LABELS.get(row.kind, row.kind)}]: {row.headline}")
            if row.detail:
                lines.append(f"    {row.detail}")
        lines += [f"  Obsada: {obsada_url(card.match_id)}", ""]
    return subject, html_body, "\n".join(lines)
