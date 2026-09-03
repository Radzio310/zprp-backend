# app/training_spk_ai.py
#
# Krótka ocena podejścia pisana przez model językowy - co poszło dobrze, co
# źle i od czego zacząć następnym razem.
#
# CZYSTY MODUŁ: buduje rozmowę z modelem i porządkuje jego odpowiedź, ale sam
# z siecią nie rozmawia. Wywołanie OpenAI mieszka w trasie (training_spk.py),
# bo tylko tam jest pętla zdarzeń i klucz - a to, CO model dostaje i CO z jego
# odpowiedzi zapisujemy, musi dać się pokazać w teście bez sieci.
#
# MODEL DOSTAJE LICZBY I RÓŻNICE, NIE SUROWY PROTOKÓŁ. Raport oceny ma już
# wszystko policzone (dopasowane, pominięte, dopisane, złe numery, rozjazdy
# czasu) - model ma to UBRAĆ W SŁOWA, a nie liczyć od nowa. Surowe zdarzenia
# tylko rozmywałyby prompt i zapraszały do zmyślania.
#
# ODPOWIEDŹ JEST KRÓTKA Z ROZMYSŁU. Sędzia czyta ją na telefonie pod
# pierścieniem wyniku; ściana tekstu przegrywa z jednym akapitem, który mówi
# konkretnie, którą rzecz poprawić.

from __future__ import annotations

from typing import Any, Dict, List

from app.training_spk_slides import action_text, format_clock

#: Model rozmowy - ten sam, którym piszą się tytuły zgłoszeń plażówki.
AI_MODEL = "gpt-4o-mini"

#: Ile pozycji każdej listy różnic pokazujemy modelowi. Powyżej tego liczby
#: mówią więcej niż wyliczanka, a prompt przestaje mieścić się w rozsądku.
MAX_DIFF_LINES = 12

#: Twarda granica długości zapisanej odpowiedzi - wszystko ponad to jest już
#: esejem, a nie oceną.
MAX_SUMMARY_CHARS = 900

MODE_LABEL = {
    "video": "pełne nagranie meczu (oceniane też czasy zdarzeń)",
    "condensed": "skrót od drugiej połowy (czas luźno, tylko kary i czasy dla drużyn)",
    "slides": "prezentacja na sali (kolejność i numery, bez oceny czasu)",
    "guided": "nauka w aplikacji - prowadzenie za rękę (nie liczy się do zestawień)",
}


def _diff_line(entry: Dict[str, Any], *, with_delta: bool = False) -> str:
    """Jedno zdarzenie różnicy jako zdanie - tym samym językiem co slajdy."""
    text = action_text(
        {
            "type": entry.get("type"),
            "team": entry.get("team"),
            "player": entry.get("refPlayer") or entry.get("player"),
        }
    ) or str(entry.get("type") or "?")
    at = entry.get("refTime")
    at = entry.get("time") if at is None else at
    clock = format_clock(at) if at is not None else ""
    line = f"{clock} {text}".strip()
    if with_delta:
        try:
            delta_s = round(abs(int(entry.get("deltaMs") or 0)) / 1000)
            mine = str(entry.get("myPlayer") or "").strip()
            ref = str(entry.get("refPlayer") or "").strip()
            extras = []
            if delta_s:
                extras.append(f"rozjazd czasu {delta_s} s")
            if mine and ref and mine != ref:
                extras.append(f"wpisany nr {mine} zamiast {ref}")
            if extras:
                line += " (" + ", ".join(extras) + ")"
        except (TypeError, ValueError):
            pass
    return line


def _lines(entries: Any, *, with_delta: bool = False) -> List[str]:
    out: List[str] = []
    for entry in entries or []:
        if not isinstance(entry, dict):
            continue
        out.append(_diff_line(entry, with_delta=with_delta))
        if len(out) >= MAX_DIFF_LINES:
            remaining = len(entries) - MAX_DIFF_LINES
            if remaining > 0:
                out.append(f"...i jeszcze {remaining}")
            break
    return out


def ai_messages(report: Dict[str, Any]) -> List[Dict[str, str]]:
    """Rozmowa dla modelu - system + jedno pytanie z całym raportem."""
    counts = report.get("counts") or {}
    parts = report.get("parts") or {}
    result = report.get("result") or {}
    mode = str(report.get("mode") or "video")

    sections: List[str] = [
        f"Tryb: {MODE_LABEL.get(mode, mode)}",
        f"Wynik: {report.get('score')} / 100 ({report.get('grade', '')})",
        (
            "Zdarzenia: wzorzec {reference}, wpisane {mine}, dopasowane {matched}, "
            "pominięte {missed}, dopisane {extra}, złe numery {wrongPlayer}, "
            "poza tolerancją czasu {lateOrEarly}"
        ).format(
            reference=counts.get("reference", 0),
            mine=counts.get("mine", 0),
            matched=counts.get("matched", 0),
            missed=counts.get("missed", 0),
            extra=counts.get("extra", 0),
            wrongPlayer=counts.get("wrongPlayer", 0),
            lateOrEarly=counts.get("lateOrEarly", 0),
        ),
        "Składowe (0-100): zdarzenia {events}, numery {players}{timing}".format(
            events=parts.get("events", "-"),
            players=parts.get("players", "-"),
            timing=(
                f", czas {parts.get('timing')}" if parts.get("timing") is not None else ""
            ),
        ),
    ]

    final = result.get("final") or {}
    half = result.get("half") or {}
    if final:
        sections.append(
            f"Wynik końcowy: wzorzec {final.get('reference')}, u sędziego "
            f"{final.get('mine')} ({'zgadza się' if final.get('ok') else 'RÓŻNI SIĘ'})"
        )
    if half:
        sections.append(
            f"Do przerwy: wzorzec {half.get('reference')}, u sędziego "
            f"{half.get('mine')} ({'zgadza się' if half.get('ok') else 'RÓŻNI SIĘ'})"
        )

    missed = _lines(report.get("missed"))
    if missed:
        sections.append("Pominięte zdarzenia:\n- " + "\n- ".join(missed))
    extra = _lines(report.get("extra"))
    if extra:
        sections.append("Dopisane zdarzenia (nie było ich w meczu):\n- " + "\n- ".join(extra))
    rough = [
        e
        for e in (report.get("matched") or [])
        if isinstance(e, dict)
        and (
            str(e.get("myPlayer") or "") != str(e.get("refPlayer") or "")
            or abs(int(e.get("deltaMs") or 0)) > 10_000
        )
    ]
    rough_lines = _lines(rough, with_delta=True)
    if rough_lines:
        sections.append("Dopasowane, ale niedokładnie:\n- " + "\n- ".join(rough_lines))

    return [
        {
            "role": "system",
            "content": (
                "Jesteś doświadczonym szkoleniowcem sędziów piłki ręcznej. Sędzia "
                "właśnie ukończył sprawdzian: prowadził elektroniczny protokół meczu "
                "Superpucharu, a jego wpisy porównano z oficjalnym protokołem. "
                "Napisz krótką ocenę po polsku, wprost do sędziego (per ty). "
                "Dokładnie trzy akapity, bez nagłówków i bez wypunktowań: "
                "1) co poszło dobrze, 2) co poszło źle i jakie błędy się powtarzały, "
                "3) jedna konkretna rada na następne podejście. "
                "Maksymalnie 120 słów łącznie. Nie wymyślaj zdarzeń, których nie ma "
                "w danych. Nie powtarzaj surowych liczb więcej niż raz."
            ),
        },
        {"role": "user", "content": "\n\n".join(sections)},
    ]


def clean_ai_summary(raw: Any) -> str:
    """Odpowiedź modelu przycięta do zapisu - albo pusto, gdy nie ma czego."""
    text = str(raw or "").strip().strip('"').strip()
    if not text:
        return ""
    if len(text) > MAX_SUMMARY_CHARS:
        cut = text[:MAX_SUMMARY_CHARS]
        # Tniemy na końcu zdania, nie w pół słowa - to ma być ocena, nie urwis.
        dot = cut.rfind(".")
        text = cut[: dot + 1] if dot > 200 else cut
    return text
