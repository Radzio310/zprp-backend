"""Parsing helpers for beach-handball squad protocol spreadsheets.

The official protocol has a stable layout.  That layout must always be parsed
by its fixed cells first; the content-based scanner is only a recovery path for
shifted or otherwise damaged sheets.
"""

from __future__ import annotations

import io
import re
import unicodedata
from difflib import SequenceMatcher
from typing import Any, Callable


# Characters that NFD cannot decompose canonically must be pre-mapped.
_EXCEL_STROKE_MAP = str.maketrans("łŁøØđĐ", "lLoOdD")
_VALID_COMPANION_LETTERS = {"A", "B", "C", "D"}


def _excel_normalize(text: str) -> str:
    """Lowercase, trim and remove diacritics for spreadsheet comparisons."""
    if not text:
        return ""
    mapped = str(text).strip().translate(_EXCEL_STROKE_MAP).replace("ß", "ss")
    nfd = unicodedata.normalize("NFD", mapped.lower())
    return "".join(c for c in nfd if unicodedata.category(c) != "Mn")


def _excel_name_similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()


def _name_variants(norm: str) -> list[str]:
    """Return word-order and hyphen-order variants of a normalized name."""

    def _flip_hyphens(tokens: list[str]) -> list[str]:
        return ["-".join(reversed(t.split("-"))) if "-" in t else t for t in tokens]

    parts = norm.split()
    flipped = _flip_hyphens(parts)
    rev = list(reversed(parts))
    rev_flipped = _flip_hyphens(rev)

    seen: set[str] = set()
    result: list[str] = []
    for candidate in (
        " ".join(parts),
        " ".join(flipped),
        " ".join(rev),
        " ".join(rev_flipped),
    ):
        if candidate not in seen:
            seen.add(candidate)
            result.append(candidate)
    return result


def _best_name_match(raw: str, candidates: list, key_fn: Callable) -> tuple:
    """Return ``(best_candidate, best_score)`` across supported name variants."""
    if not raw or not candidates:
        return None, 0.0
    raw_variants = _name_variants(_excel_normalize(raw))

    best_score = 0.0
    best_cand = None
    for cand in candidates:
        cand_variants = _name_variants(_excel_normalize(key_fn(cand)))
        for raw_variant in raw_variants:
            for candidate_variant in cand_variants:
                score = _excel_name_similarity(raw_variant, candidate_variant)
                if score > best_score:
                    best_score = score
                    best_cand = cand
    return best_cand, best_score


# Template headings, signatures and metadata which are never squad members.
_EXCEL_SKIP_ROW_RE = re.compile(
    r"\b(zawodnic\w*|nazwisko|imie|druzyn\w*|wynik\w*|podpis\w*|protok\w*"
    r"|numer|miejsce|godz\w*|widz\w*|data|shoot|jeden na jednego)\b"
    r"|time\s*out",
)

# Blocks below the host team which end recovery scanning.
_EXCEL_STOP_ROW_RE = re.compile(
    r"\b(sedziowie|sekretarz\w*|delegat\w*|miejscowosc|legenda)\b"
    r"|druzyna b\b|druzyna gosci|podpis oficjela b",
)


def _cell_text(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def _row_normalized(get_cell: Callable[[int, int], Any], row: int, columns=range(1, 8)) -> str:
    return _excel_normalize(
        " ".join(_cell_text(get_cell(row, column)) for column in columns)
    )


def _is_label(normalized: str) -> bool:
    return bool(
        _EXCEL_SKIP_ROW_RE.search(normalized)
        or _EXCEL_STOP_ROW_RE.search(normalized)
    )


def _is_plausible_name(value: str) -> bool:
    normalized = _excel_normalize(value)
    return bool(
        len(normalized) >= 3
        and not normalized.replace(" ", "").isdigit()
        and not _is_label(normalized)
    )


def _parse_member_cells(
    get_cell: Callable[[int, int], Any],
    row: int,
) -> tuple[str | None, int | None, str | None]:
    """Read a member row, including merged ``"22 Name"`` / ``"A Name"`` cells."""
    a_str = _cell_text(get_cell(row, 1))
    b_str = _cell_text(get_cell(row, 2))
    jersey: int | None = None
    letter: str | None = None
    name = b_str or None

    if a_str:
        try:
            number = int(float(a_str))
            if 1 <= number <= 99:
                jersey = number
        except (ValueError, TypeError):
            upper = a_str.upper()
            if upper in _VALID_COMPANION_LETTERS:
                letter = upper
            elif not b_str:
                parts = a_str.split(None, 1)
                if len(parts) == 2:
                    head, remainder = parts
                    try:
                        number = int(float(head))
                        if 1 <= number <= 99:
                            jersey = number
                        name = remainder
                    except (ValueError, TypeError):
                        if head.upper() in _VALID_COMPANION_LETTERS:
                            letter = head.upper()
                            name = remainder
                        else:
                            name = a_str
                else:
                    name = a_str

    name = _cell_text(name) or None
    if name and not _is_plausible_name(name):
        name = None
    return name, jersey, letter


def _has_standard_layout(get_cell: Callable[[int, int], Any]) -> bool:
    """Recognize the official fixed layout independently from entered names."""
    player_header = _row_normalized(get_cell, 14)
    host_footer = _row_normalized(get_cell, 34)
    guest_header = _row_normalized(get_cell, 36)

    has_player_header = (
        "zawodnic" in player_header
        and ("druzyna a" in player_header or "druzyn" in player_header)
    )
    has_host_boundary = (
        "podpis oficjela a" in host_footer
        or ("druzyna b" in guest_header and "zawodnic" in guest_header)
    )
    return has_player_header and has_host_boundary


def _read_standard_cells(get_cell: Callable[[int, int], Any]) -> dict:
    """Read the official layout using the original, fixed cell ranges."""
    team_name_raw = _cell_text(get_cell(10, 2)) or None

    players_raw: list[dict] = []
    for row in range(15, 30):
        name, jersey, _letter = _parse_member_cells(get_cell, row)
        if name:
            players_raw.append(
                {"row": row, "raw_name": name, "raw_number": jersey}
            )

    companions_raw: list[dict] = []
    seen_letters: set[str] = set()
    for row in range(30, 34):
        name, _jersey, letter = _parse_member_cells(get_cell, row)
        if not name:
            continue
        if letter in seen_letters:
            letter = None
        if letter:
            seen_letters.add(letter)
        if letter is None:
            # The official sheet often leaves A30:A33 blank.  Row position is
            # authoritative in the fixed layout, exactly as in the old parser.
            letter = {30: "A", 31: "B", 32: "C", 33: "D"}[row]
        companions_raw.append(
            {"row": row, "raw_name": name, "raw_letter": letter}
        )

    return {
        "team_name_raw": team_name_raw,
        "players_raw": players_raw,
        "companions_raw": companions_raw,
    }


def _find_player_header(get_cell: Callable[[int, int], Any]) -> int | None:
    for row in range(8, 46):
        normalized = _row_normalized(get_cell, row)
        if (
            "zawodnic" in normalized
            and ("druzyna a" in normalized or "gospodarz" in normalized)
            and "druzyna b" not in normalized
            and "gosci" not in normalized
        ):
            return row
    return None


def _find_host_label(get_cell: Callable[[int, int], Any]) -> int | None:
    for row in range(5, 25):
        normalized = _row_normalized(get_cell, row)
        if "zawodnic" in normalized:
            continue
        if "gospodarz" in normalized or re.search(r"\bdruzyna a\b", normalized):
            return row
    return None


def _find_recovery_team_name(
    get_cell: Callable[[int, int], Any],
    player_header_row: int | None,
) -> tuple[str | None, int]:
    """Locate a shifted team name without treating metadata labels as a team."""
    host_label_row = _find_host_label(get_cell)
    if host_label_row is not None:
        end_row = min(
            host_label_row + 4,
            (player_header_row - 1) if player_header_row else host_label_row + 4,
        )
        for row in range(host_label_row + 1, end_row + 1):
            candidate = _cell_text(get_cell(row, 2))
            if _is_plausible_name(candidate):
                return candidate, row

    # Preserve the official team cell as the safest generic fallback.
    candidate = _cell_text(get_cell(10, 2))
    if _is_plausible_name(candidate):
        return candidate, 10

    # Last-resort support for sheets shifted by a few rows.  Only inspect rows
    # before the detected player table; squad rows can never become a team name.
    for row in (9, 11, 8, 12, 7, 13):
        if player_header_row is not None and row >= player_header_row:
            continue
        candidate = _cell_text(get_cell(row, 2))
        if _is_plausible_name(candidate):
            return candidate, row
    return None, 10


def _read_recovery_cells(get_cell: Callable[[int, int], Any]) -> dict:
    """Content-based recovery for shifted, merged or partly damaged sheets."""
    player_header_row = _find_player_header(get_cell)
    team_name_raw, team_name_row = _find_recovery_team_name(
        get_cell, player_header_row
    )

    # In the official layout there are 15 player slots after the heading.
    # This relative boundary also recovers shifted sheets whose A-D letters
    # disappeared, without turning companion names into players.
    inferred_companion_start = (
        player_header_row + 16 if player_header_row is not None else None
    )
    scan_start = (
        player_header_row + 1
        if player_header_row is not None
        else max(11, team_name_row + 1)
    )

    players_raw: list[dict] = []
    companions_raw: list[dict] = []
    seen_letters: set[str] = set()
    companions_started = False

    for row in range(scan_start, 61):
        combined_normalized = _row_normalized(get_cell, row, columns=(1, 2))
        if not combined_normalized:
            continue

        if "osob" in combined_normalized and "towarzysz" in combined_normalized:
            companions_started = True
            continue

        if "podpis oficjela a" in combined_normalized:
            break

        if _EXCEL_STOP_ROW_RE.search(combined_normalized):
            # A location label can occur before a damaged table.  Before the
            # first member it is metadata to skip; after members it is a footer.
            if players_raw or companions_raw:
                break
            continue
        if _EXCEL_SKIP_ROW_RE.search(combined_normalized):
            continue

        name, jersey, letter = _parse_member_cells(get_cell, row)
        if not name:
            continue

        is_inferred_companion = (
            inferred_companion_start is not None
            and row >= inferred_companion_start
        )
        if letter is not None or companions_started or is_inferred_companion:
            if letter in seen_letters:
                letter = None
            if letter:
                seen_letters.add(letter)
            if len(companions_raw) < 4:
                companions_raw.append(
                    {"row": row, "raw_name": name, "raw_letter": letter}
                )
                companions_started = True
        elif jersey is not None:
            if len(players_raw) < 15:
                players_raw.append(
                    {"row": row, "raw_name": name, "raw_number": jersey}
                )
        elif player_header_row is not None or players_raw:
            # A name-only row is safe only inside a detected player table or
            # after a numbered player.  This prevents a city/meta value from
            # starting a phantom squad when the sheet is damaged.
            if len(players_raw) < 15:
                players_raw.append(
                    {"row": row, "raw_name": name, "raw_number": None}
                )

    free_letters = [
        letter
        for letter in ("A", "B", "C", "D")
        if letter not in seen_letters
    ]
    for companion in companions_raw:
        if companion["raw_letter"] is None and free_letters:
            companion["raw_letter"] = free_letters.pop(0)

    return {
        "team_name_raw": team_name_raw,
        "players_raw": players_raw,
        "companions_raw": companions_raw,
    }


def _read_excel_cells(file_bytes: bytes, filename: str) -> dict:
    """Read squad cells from an ``.xls`` or ``.xlsx`` protocol.

    The official layout (B10, rows 15-29 and rows 30-33) is authoritative.
    Recovery scanning is used only when the fixed layout markers are missing.
    """
    name_lower = (filename or "").lower()

    if name_lower.endswith(".xls") and not name_lower.endswith(".xlsx"):
        import xlrd

        workbook = xlrd.open_workbook(file_contents=file_bytes)
        worksheet = workbook.sheet_by_index(0)

        def get_cell(row1: int, col1: int):
            try:
                value = worksheet.cell_value(row1 - 1, col1 - 1)
                return value if value != "" else None
            except Exception:
                return None

    else:
        import openpyxl

        workbook = openpyxl.load_workbook(io.BytesIO(file_bytes), data_only=True)
        worksheet = workbook.active

        def get_cell(row1: int, col1: int):
            return worksheet.cell(row=row1, column=col1).value

    if _has_standard_layout(get_cell):
        return _read_standard_cells(get_cell)
    return _read_recovery_cells(get_cell)
