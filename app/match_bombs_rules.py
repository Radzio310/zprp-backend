# app/match_bombs_rules.py
#
# Reguły „bomb" - zgłoszeń, że sędziego nie było na meczu.
#
# Liść: bez bazy, bez sieci, bez zegara systemowego. Wszystkie funkcje dostają
# czas w argumencie.
#
# Dlaczego to w ogóle mieszka osobno: zgłoszenie mówi o CUDZEJ rzetelności i
# trafia do rejestru, z którego okręg czyta ranking. Pomyłka w oknie czasowym
# albo w tym, kto komu może je wystawić, nie kończy się brzydkim ekranem, tylko
# nieuzasadnionym wpisem przy nazwisku człowieka. Ma się dać sprawdzić testem.
#
# DECYZJE OKRĘGU (2026-09-05), które ten plik pilnuje:
#  1. Zgłasza WYŁĄCZNIE obsada tego meczu i wyłącznie o kimś z tej samej obsady.
#     Kto tam był, ten wie. Komisja sędziowska dochodzi osobno - jako ta, która
#     rejestr prowadzi, nie jako świadek.
#  2. Autor jest jawny dla komisji i dla osoby zgłoszonej. Reszta widzi sam fakt.
#  3. Okno: od pierwszego gwizdka przez 14 dni. Wcześniej nie ma czego zgłaszać,
#     później sprawa należy już do komisji.
#  4. Autor cofa własne zgłoszenie zawsze; komisja unieważnia cudze z powodem, a
#     unieważnione zostaje w rejestrze i NIE liczy się do rankingu.

from __future__ import annotations

import re
import unicodedata
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

#: Odznaka, która daje wgląd w rejestr okręgu i prawo unieważniania.
COMMISSION_BADGE = "Komisja sędziowska"

#: Ile dni po pierwszym gwizdku zwykły sędzia może zgłosić nieobecność.
#:
#: Dwa tygodnie to tyle, ile trwa rozliczenie kolejki - sprawa jest wtedy jeszcze
#: świeża i sprawdzalna. Później zgłoszenie dopisuje komisja, żeby stara historia
#: nie wracała po pół sezonu.
REPORT_WINDOW_DAYS = 14

#: Ile trzyma się zgłoszenie, zanim dowie się o nim osoba zgłoszona.
#:
#: Doba to okno na cofnięcie pomyłki. Nikt nie ma dostawać w nocy „nie było Cię
#: na meczu", co za dziesięć minut zniknie bez śladu.
SUBJECT_NOTICE_DELAY_HOURS = 24

#: Miesiąc, od którego liczy się sezon (wrzesień). Ta sama granica, co w
#: `BAZA/utils/seasonWindow.ts` - rejestr i przełącznik sezonu w aplikacji muszą
#: dzielić mecz na sezony tak samo, inaczej ranking nie zgadza się z listą.
SEASON_START_MONTH = 9

#: Gniazda obsady, których zgłoszenie może dotyczyć - CAŁA obsada, nie tylko
#: giełdowa czwórka. Delegat też bywa nieobecny.
CREW_SLOTS: Dict[str, str] = {
    "sedzia1": "sędzia 1",
    "sedzia2": "sędzia 2",
    "sekretarz": "sekretarz",
    "czas": "mierzący czas",
    "delegat": "delegat",
    "delegat2": "drugi delegat",
}

#: Gniazdo → pole z nazwiskiem w stanie meczu (`province_matches.state_json`).
CREW_NAME_FIELDS: Dict[str, str] = {
    "sedzia1": "NrSedzia_pierwszy_nazwisko",
    "sedzia2": "NrSedzia_drugi_nazwisko",
    "sekretarz": "NrSedzia_sekretarz_nazwisko",
    "czas": "NrSedzia_czas_nazwisko",
    "delegat": "NrSedzia_delegat_nazwisko",
    "delegat2": "NrSedzia_delegat2_nazwisko",
}

#: Gniazdo → pole z numerem sędziego w stanie meczu.
CREW_ID_FIELDS: Dict[str, str] = {
    "sedzia1": "NrSedzia_pierwszy",
    "sedzia2": "NrSedzia_drugi",
    "sekretarz": "NrSedzia_sekretarz",
    "czas": "NrSedzia_czas",
    "delegat": "NrSedzia_delegat",
    "delegat2": "NrSedzia_delegat2",
}

#: Stany zgłoszenia. `withdrawn` to „autor się rozmyślił", `voided` to decyzja
#: komisji - dwie różne rzeczy i rejestr ma je rozróżniać.
BOMB_STATUSES = ("active", "withdrawn", "voided")

#: Stany, które liczą się do statystyk i rankingu.
COUNTED_STATUSES = ("active",)


def slot_label(slot: Any) -> str:
    """Podpis gniazda dla człowieka; nieznane oddajemy bez zmiany."""
    key = str(slot or "").strip()
    return CREW_SLOTS.get(key, key)


def _fold(text: Any) -> str:
    """Tekst bez ogonków, małymi literami - „ł" ręcznie, bo NFD go nie tyka."""
    raw = str(text or "").replace("ł", "l").replace("Ł", "L")
    raw = unicodedata.normalize("NFD", raw)
    raw = "".join(ch for ch in raw if unicodedata.category(ch) != "Mn")
    return raw.lower().strip()


def name_parts(text: Any) -> List[str]:
    """Znaczące człony nazwiska - bez inicjałów i śmieci."""
    cleaned = re.sub(r"[^a-z0-9]+", " ", _fold(text))
    return sorted(p for p in cleaned.split() if len(p) > 1)


def same_person(a: Any, b: Any) -> bool:
    """Czy to ten sam człowiek, mimo innej kolejności członów.

    ZPRP pisze „NOWAK Jan", lista okręgu bywa prowadzona jako „Jan Nowak". Ta
    sama miara, co w giełdzie (`match_market_rules.names_match`) - kopia jest
    tu świadoma, bo bomby nie mają mieć nic wspólnego z modułem wymian i nie
    chcę, żeby zmiana w jednym module po cichu przestawiła drugi.
    """
    pa, pb = name_parts(a), name_parts(b)
    if not pa or not pb:
        return False
    if pa == pb:
        return True
    if len(pa) < 2 or len(pb) < 2:
        return False
    shorter, longer = (pa, pb) if len(pa) <= len(pb) else (pb, pa)
    return all(part in longer for part in shorter)


def is_blank_name(value: Any) -> bool:
    """Puste gniazdo w obsadzie.

    ZPRP wpisuje w wolne miejsce myślniki albo „0" - i jedno, i drugie znaczy
    „nikogo tu nie ma". Bez tego dałoby się zgłosić bombę na kreskę.
    """
    text = str(value or "").strip()
    if not text or text == "0":
        return True
    return not re.sub(r"[\s\-–—_.]+", "", text)


def crew_from_state(state: Mapping[str, Any]) -> List[Dict[str, str]]:
    """Obsada meczu z migawki terminarza okręgu - gniazdo, numer, nazwisko.

    To jest źródło, którym sprawdzamy zgłoszenie, gdy okręg ten mecz zna. Gdy
    nie zna (mecz centralny, turniej), zostaje obsada podana przez aplikację -
    patrz `crew_from_payload`.
    """
    out: List[Dict[str, str]] = []
    for slot, name_field in CREW_NAME_FIELDS.items():
        name = str((state or {}).get(name_field) or "").strip()
        if is_blank_name(name):
            continue
        out.append(
            {
                "slot": slot,
                "judgeId": str((state or {}).get(CREW_ID_FIELDS[slot]) or "").strip(),
                "name": name,
            }
        )
    return out


def crew_from_payload(crew: Iterable[Mapping[str, Any]]) -> List[Dict[str, str]]:
    """Obsada podana przez aplikację, sprowadzona do tych samych trzech pól.

    Przyjmujemy ją tylko dla meczów, których okręg nie ma u siebie - i wtedy
    rejestr zapisuje, skąd obsada pochodzi. Komisja ma prawo wiedzieć, że tego
    wpisu nie dało się potwierdzić terminarzem.
    """
    out: List[Dict[str, str]] = []
    for item in crew or ():
        slot = str((item or {}).get("slot") or "").strip()
        name = str((item or {}).get("name") or "").strip()
        if slot not in CREW_SLOTS or is_blank_name(name):
            continue
        out.append(
            {
                "slot": slot,
                "judgeId": str((item or {}).get("judgeId") or "").strip(),
                "name": name,
            }
        )
    return out


def find_in_crew(
    crew: Sequence[Mapping[str, Any]],
    *,
    judge_id: Any = "",
    full_name: Any = "",
    slot: Any = "",
) -> Optional[Dict[str, str]]:
    """Miejsce tej osoby w obsadzie albo `None`.

    NUMER PRZED NAZWISKIEM, jak wszędzie, gdzie rozstrzygamy „czyj to mecz":
    numer jest jednoznaczny, nazwisko bywa zapisane odwrotnie i bywa wspólne
    (w okręgu jest dwóch WITKOWICZÓW). `slot` zawęża, gdy ta sama osoba stoi w
    dwóch gniazdach - wtedy zgłaszamy o KONKRETNĄ rolę.
    """
    wanted_id = str(judge_id or "").strip()
    wanted_slot = str(slot or "").strip()
    pool = [c for c in crew if not wanted_slot or str(c.get("slot") or "") == wanted_slot]
    if wanted_id:
        hit = next((c for c in pool if str(c.get("judgeId") or "").strip() == wanted_id), None)
        if hit:
            return dict(hit)
    if full_name:
        hit = next((c for c in pool if same_person(c.get("name"), full_name)), None)
        if hit:
            return dict(hit)
    return None


def season_of(match_at: Optional[datetime]) -> Optional[int]:
    """Sezon jako ROK jego początku - 2025 znaczy 2025/26.

    Jedna liczba, bo po niej da się sortować i porównywać bez rozbierania
    etykiety. `None` dla meczu bez daty: nie wiadomo, do którego sezonu
    należy, a zgadywanie przestawiłoby wpis w cudzym rankingu.
    """
    if not isinstance(match_at, datetime):
        return None
    return match_at.year if match_at.month >= SEASON_START_MONTH else match_at.year - 1


def season_label(year: Any) -> str:
    """„2025/26" - etykieta na przełączniku, ta sama co w aplikacji."""
    try:
        start = int(year)
    except (TypeError, ValueError):
        return ""
    return f"{start}/{str((start + 1) % 100).zfill(2)}"


def report_window_end(match_at: Optional[datetime]) -> Optional[datetime]:
    """Chwila, po której zwykły sędzia nie zgłosi już nieobecności."""
    if not isinstance(match_at, datetime):
        return None
    return match_at + timedelta(days=REPORT_WINDOW_DAYS)


def may_report(
    match_at: Optional[datetime],
    now: datetime,
    *,
    is_commission: bool = False,
) -> Optional[str]:
    """Powód odmowy zgłoszenia albo `None`, gdy wolno.

    Odmowa jest ZDANIEM, nie wartością logiczną: kafel ma napisać, dlaczego
    opcji nie ma, a nie zgasnąć bez słowa.

    Mecz bez daty przepuszczamy. Brak terminu to luka w danych bazy związku, a
    nie powód, żeby odciąć obsadę od zgłoszenia - takich meczów w okręgu jest
    sporo (patrz mecze powierzone, bez `data_fakt`).
    """
    if is_commission:
        return None
    if match_at is None:
        return None
    if now < match_at:
        return "Mecz jeszcze się nie zaczął - nie ma czego zgłaszać."
    end = report_window_end(match_at)
    if end is not None and now > end:
        return (
            f"Minęło ponad {REPORT_WINDOW_DAYS} dni od meczu. Taką sprawę może "
            "dopisać już tylko komisja sędziowska."
        )
    return None


def may_withdraw(bomb: Mapping[str, Any], viewer_judge_id: Any) -> bool:
    """Czy TEN człowiek może cofnąć TO zgłoszenie.

    Cofa wyłącznie autor i wyłącznie zgłoszenie czynne. Komisja nie „cofa"
    cudzych zgłoszeń - ona je unieważnia, a to zostawia ślad (`void`).
    """
    if str(bomb.get("status") or "") != "active":
        return False
    return str(bomb.get("author_judge_id") or "").strip() == str(viewer_judge_id or "").strip()


def may_void(is_commission: bool, bomb: Mapping[str, Any]) -> bool:
    """Czy komisja może unieważnić to zgłoszenie."""
    return bool(is_commission) and str(bomb.get("status") or "") == "active"


def author_is_visible(
    bomb: Mapping[str, Any],
    viewer_judge_id: Any,
    *,
    is_commission: bool = False,
) -> bool:
    """Czy TEN widz ma prawo zobaczyć nazwisko autora zgłoszenia.

    Decyzja okręgu: komisja i osoba zgłoszona - tak; reszta obsady widzi sam
    fakt. Autor widzi siebie, bo inaczej nie wiedziałby, które zgłoszenie jest
    jego i czego może cofnąć.
    """
    viewer = str(viewer_judge_id or "").strip()
    if is_commission or not viewer:
        return bool(is_commission)
    return viewer in (
        str(bomb.get("author_judge_id") or "").strip(),
        str(bomb.get("subject_judge_id") or "").strip(),
    )


def counts_to_stats(status: Any) -> bool:
    """Czy zgłoszenie liczy się do statystyk i rankingu."""
    return str(status or "") in COUNTED_STATUSES


def rank_bombs(rows: Iterable[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    """Ranking sędziów według liczby bomb - od największej.

    Miejsca EX AEQUO liczone tak samo, jak w tabelach rozgrywek: dwie osoby z
    tym samym wynikiem stoją na tym samym miejscu, a następna dostaje numer
    pomniejszony o ich liczbę (9, 9, 11). Rozstrzyganie remisu kolejnością
    alfabetyczną byłoby wymyśleniem różnicy, której nie ma.

    Wiersze wchodzą jako `{"judgeId", "name", "count"}`.
    """
    ordered = sorted(
        (
            {
                "judgeId": str(r.get("judgeId") or "").strip(),
                "name": str(r.get("name") or "").strip(),
                "count": int(r.get("count") or 0),
            }
            for r in rows or ()
        ),
        key=lambda r: (-r["count"], _fold(r["name"])),
    )
    out: List[Dict[str, Any]] = []
    place = 0
    previous: Optional[int] = None
    for index, row in enumerate(ordered, start=1):
        if previous is None or row["count"] != previous:
            place = index
            previous = row["count"]
        out.append({**row, "place": place})
    return out


def month_key(stamp: Optional[datetime]) -> str:
    """„2026-09" - klucz miesiąca do wykresu w rejestrze."""
    if not isinstance(stamp, datetime):
        return ""
    return f"{stamp.year}-{str(stamp.month).zfill(2)}"


MONTHS_PL = (
    "styczeń", "luty", "marzec", "kwiecień", "maj", "czerwiec",
    "lipiec", "sierpień", "wrzesień", "październik", "listopad", "grudzień",
)


def month_label(key: Any) -> str:
    """„2026-09" → „wrzesień 2026". Nieznany klucz oddajemy bez zmiany."""
    text = str(key or "").strip()
    match = re.fullmatch(r"(\d{4})-(\d{2})", text)
    if not match:
        return text
    year, month = int(match.group(1)), int(match.group(2))
    if not 1 <= month <= 12:
        return text
    return f"{MONTHS_PL[month - 1]} {year}"


def bomb_sentence(bomb: Mapping[str, Any], *, with_author: bool = False) -> str:
    """Jedno zdanie o zgłoszeniu - do powiadomienia i do wiersza rejestru.

    Bez nazwiska autora, dopóki widz nie ma prawa go zobaczyć: to samo zdanie
    obsługuje ekran meczu i rejestr komisji, więc rozstrzyga o tym argument, a
    nie drugi, prawie taki sam tekst gdzie indziej.
    """
    who = str(bomb.get("subject_name") or "").strip() or "Sędzia"
    role = slot_label(bomb.get("subject_slot"))
    code = str(bomb.get("match_code") or "").strip()
    head = f"{who} ({role})" if role else who
    where = f" na meczu {code}" if code else " na meczu"
    text = f"{head} - zgłoszona nieobecność{where}."
    if with_author:
        author = str(bomb.get("author_name") or "").strip()
        if author:
            text += f" Zgłosił: {author}."
    return text
