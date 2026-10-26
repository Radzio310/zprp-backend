"""
Strona publiczna wyników egzaminu - reguły bez bazy (26.10.2026).

Najważniejsza funkcja to `public_payload`: z pełnego raportu komisji (`exam_report_service.build_report`)
wycina DOKŁADNIE to, na co pozwala poziom ustawiony przez komisję, i nic więcej. Budujemy
odpowiedź od zera z listy dozwolonych pól (nie kasujemy pól z raportu) - nowe pole w raporcie
nie przecieknie na stronę samo z siebie.

Poziomy (rosnąco):
  - `stats`     same liczby: bilet, pasek liczb, rozkład (anonimowe kropki), bez osób,
  - `initials`  + ranking z inicjałami i znakiem zdał/nie zdał (bez nazwisk, zdjęć, okręgu, procentów),
  - `names`     + imiona i nazwiska (okręg przy krajowym), zdjęcia, jeśli komisja je włączyła,
  - `points`    + procent i punkty każdej osoby.

Rozkład: przy `initials`/`names` tylko kubełki 10% (dokładne procenty ułożone w kolejności
rankingu zdradziłyby wynik każdej osoby). Dokładne kropki przy `stats` (bez osób) i `points`.
Kontrakt: BAZA/docs/egzamin-api.md, sekcja „Strona publiczna wyników”.
"""

from __future__ import annotations

import re
import secrets
from typing import Any, Dict, List, Mapping, Optional

from app.exam_rules import ExamError

LEVELS = ("stats", "initials", "names", "points")
LEVEL_LABELS = {
    "stats": "tylko statystyki",
    "initials": "ranking z inicjałami",
    "names": "imiona i nazwiska",
    "points": "imiona, nazwiska i punkty",
}
#: Bez 0/O, 1/l/i - kod bywa przepisywany z kartki.
CODE_ALPHABET = "23456789abcdefghjkmnpqrstuvwxyz"
CODE_LENGTH = 8
CODE_RE = re.compile(rf"^[{CODE_ALPHABET}]{{{CODE_LENGTH}}}$")
THEMES = ("province", "elegant", "premium")
PUBLIC_HOST = "https://bazapodreka.app"
#: Podglądy linków w komunikatorach nie są wejściami ludzi (licznik ich nie liczy).
BOT_MARKERS = ("bot", "crawler", "spider", "preview", "facebookexternalhit", "whatsapp", "telegram", "slack",
               "discord", "linkedin", "embedly", "vkshare", "skypeuripreview", "headless")
HARDEST_LIMIT = 5


def new_code() -> str:
    return "".join(secrets.choice(CODE_ALPHABET) for _ in range(CODE_LENGTH))


def normalize_code(raw: Any) -> Optional[str]:
    """Kod z adresu: wielkość liter i myślnik nie mają znaczenia. Zły kształt = None (od razu 404, bez bazy)."""
    code = re.sub(r"[\s-]", "", str(raw or "")).lower()
    return code if CODE_RE.match(code) else None


def link_path(code: str) -> str:
    return f"/wyniki/{code}"


def clean_settings(raw: Mapping[str, Any]) -> Dict[str, Any]:
    """Ustawienia od komisji. Zła wartość = 400 ze zdaniem, nie ciche przycięcie."""
    level = str(raw.get("level") or "stats").strip()
    if level not in LEVELS:
        raise ExamError("BAD_PUBLIC_LINK", "Poziom strony publicznej: dozwolone wartości to "
                        f"{', '.join(LEVELS)}.", 400)
    theme = str(raw.get("theme") or "province").strip()
    if theme not in THEMES:
        raise ExamError("BAD_PUBLIC_LINK", f"Motyw strony publicznej: dozwolone wartości to {', '.join(THEMES)}.", 400)
    out = {"level": level, "theme": theme}
    for key in ("photos", "hardest"):
        value = raw.get(key, False)
        if not isinstance(value, bool):
            raise ExamError("BAD_PUBLIC_LINK", f"Pole „{key}” przyjmuje tylko tak albo nie (true/false).", 400)
        out[key] = value
    return out


def effective_photos(level: str, photos: bool) -> bool:
    """Zdjęcia tylko obok nazwisk - przy inicjałach twarz zdradziłaby osobę."""
    return bool(photos) and level in ("names", "points")


def initials(name: Any) -> str:
    """„Jan Zwykły” -> „J. Z.” (najwyżej trzy człony; myślnik w nazwisku = jeden człon)."""
    parts = [p for p in re.split(r"\s+", str(name or "").strip()) if p]
    letters = [p[0].upper() + "." for p in parts[:3] if p[0].isalpha()]
    return " ".join(letters) or "?"


def is_bot(user_agent: Any) -> bool:
    """Nagłówek nieznany (wywołanie wewnętrzne) = człowiek; znany podgląd komunikatora = bot."""
    ua = str(user_agent or "").lower()
    return bool(ua) and any(m in ua for m in BOT_MARKERS)


def _iso(v: Any) -> Optional[str]:
    return v.isoformat() if hasattr(v, "isoformat") else (str(v) if v else None)


def link_view(exam_id: str, row: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    """`PublicLink` dla komisji (studio eksportu, teczka). Bez wiersza = link nigdy nie powstał."""
    if not row:
        return {"exam_id": exam_id, "active": False, "code": None, "url": None, "path": None, "level": "stats",
                "level_label": LEVEL_LABELS["stats"], "photos": False, "photos_effective": False, "hardest": False,
                "theme": "province", "cut_province": None, "views": 0, "last_view_at": None, "created_at": None,
                "created_by_name": None, "updated_at": None, "disabled_at": None}
    code = str(row["code"])
    level = str(row.get("level") or "stats")
    return {
        "exam_id": exam_id,
        "active": row.get("disabled_at") is None,
        "code": code,
        "url": PUBLIC_HOST + link_path(code),
        "path": link_path(code),
        "level": level,
        "level_label": LEVEL_LABELS.get(level, level),
        "photos": bool(row.get("photos")),
        "photos_effective": effective_photos(level, bool(row.get("photos"))),
        "hardest": bool(row.get("hardest")),
        "theme": str(row.get("theme") or "province"),
        "cut_province": row.get("cut_province"),
        "views": int(row.get("views") or 0),
        "last_view_at": _iso(row.get("last_view_at")),
        "created_at": _iso(row.get("created_at")),
        "created_by_name": row.get("created_by_name"),
        "updated_at": _iso(row.get("updated_at")),
        "disabled_at": _iso(row.get("disabled_at")),
    }


def _num(v: Any, digits: int = 2) -> Optional[float]:
    return None if v is None else round(float(v), digits)


def _hardest(questions: List[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    """Najtrudniejsze pytania BEZ klucza i bez rozkładu odpowiedzi (udział jednej odpowiedzi równy
    odsetkowi poprawnych zdradziłby klucz). Treść pytania jest jawna w katalogu ZPRP."""
    from app.exam_report_rules import rule_label

    return [{"number": q.get("number"), "rule": q.get("rule"), "rule_label": rule_label(q.get("rule")),
             "text": q.get("text"), "multi": bool(q.get("multi")), "correct_rate": _num(q.get("correct_rate"), 4),
             "total": int(q.get("total") or 0)} for q in questions[:HARDEST_LIMIT]]


def public_payload(report: Mapping[str, Any], link: Mapping[str, Any], *, backend_crest: Optional[str] = None) -> Dict[str, Any]:
    """Odpowiedź publiczna z raportu komisji, przycięta do poziomu linku. Lista pól jest JAWNA."""
    level = str(link.get("level") or "stats")
    if level not in LEVELS:
        level = "stats"
    photos_on = effective_photos(level, bool(link.get("photos")))
    exam = report.get("exam") or {}
    s = report.get("summary") or {}
    people_level = level != "stats"
    exact = level in ("stats", "points")

    summary = {
        "invited": s.get("invited"), "people": s.get("people"), "finished_people": s.get("finished_people"),
        "in_progress": s.get("in_progress"), "passed": s.get("passed"), "failed": s.get("failed"),
        "pass_rate": s.get("pass_rate"), "attendance_rate": s.get("attendance_rate"),
        "avg_percent": s.get("avg_percent"), "median_percent": s.get("median_percent"),
        "pass_percent": s.get("pass_percent"), "avg_duration_s": s.get("avg_duration_s"),
        "histogram_10pct": list(s.get("histogram_10pct") or [0] * 10),
        # Najlepszy wynik obok rankingu bez punktów zdradziłby procent zwycięzcy.
        "best_percent": s.get("best_percent") if exact else None,
    }
    ranking_src = list(report.get("ranking") or [])
    dots = sorted((_num(r.get("percent")) for r in ranking_src if r.get("percent") is not None), reverse=True) if exact else None

    ranking: Optional[List[Dict[str, Any]]] = None
    if people_level:
        national = exam.get("scope") == "national" and not exam.get("cut_province")
        photo_map = report.get("photos") or {}
        ranking = []
        for r in ranking_src:
            row: Dict[str, Any] = {"place": r.get("place"), "passed": bool(r.get("passed"))}
            name = r.get("judge_name") or ""
            if level == "initials":
                row["initials"] = initials(name)
            else:
                row["name"] = name or "?"
                row["initials"] = initials(name)
                if national:
                    row["province"] = r.get("province")
                if photos_on:
                    row["photo"] = photo_map.get(str(r.get("judge_id"))) or None
            if level == "points":
                row["percent"] = _num(r.get("percent"))
                row["points"] = _num(r.get("points"))
                row["max"] = _num(r.get("max"))
            ranking.append(row)

    province = exam.get("cut_province") or exam.get("province")
    return {
        "code": link.get("code"),
        "level": level,
        "photos": photos_on,
        "hardest_on": bool(link.get("hardest")),
        "theme": str(link.get("theme") or "province"),
        "generated_at": report.get("generated_at"),
        "exam": {
            "name": exam.get("name"), "scope": exam.get("scope"), "province": province,
            "cut": bool(exam.get("cut_province")),
            "window_start": exam.get("window_start"), "window_end": exam.get("window_end"), "state": exam.get("state"),
            "question_count": exam.get("question_count"), "time_total_min": exam.get("time_total_min"),
            "pass_percent": exam.get("pass_percent"),
        },
        "crest_url": backend_crest,
        "summary": summary,
        "dots": dots,
        "ranking": ranking,
        "hardest": _hardest(list(report.get("hardest") or [])) if link.get("hardest") else None,
    }
