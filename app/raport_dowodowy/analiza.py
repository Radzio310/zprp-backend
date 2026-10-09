"""Analiza zrzutu meczu - liść bez bazy, bez sieci i bez zależności.

Dostaje zrzut z `zrzut.py` (słownik) i oddaje wszystko, czego potrzebuje
wydruk: dane meczu, stan końcowy osoby, przebieg zmian wersja po wersji,
korekty w całym meczu, kalendarium i ustalenia zapisane zdaniami.

ZASADA: raport mówi, CO zapisano, KIEDY i KTO - nie ocenia, czy zmiana była
słuszna. Ustalenia są zdaniami bezosobowymi („wpisano", „usunięto") i każde
wynika wprost z porównania sąsiednich wersji.

Czas zdarzenia w przebiegu (`time`) to czas meczu od pierwszego gwizdka
w milisekundach (44:47 = 45. minuta, II połowa). Godziny zapisów są
przeliczane na czas polski bez `zoneinfo` - Windows nie ma bazy stref.
"""
from __future__ import annotations

from collections import Counter
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

# ─────────────────────────── słowniki ───────────────────────────

RODZAJE: Dict[str, str] = {
    "goal": "Bramka",
    "goalRemoved": "Bramka usunięta",
    "penaltyKickScored": "Rzut karny 7 m - bramka",
    "penaltyKickMissed": "Rzut karny 7 m - niewykorzystany",
    "warning": "Upomnienie (żółta kartka)",
    "penalty1": "I kara 2 min",
    "penalty2": "II kara 2 min",
    "penalty3": "III kara 2 min",
    "penaltyExtra": "Kara dodatkowa 2 min (Kd)",
    "disqualification": "Dyskwalifikacja (czerwona kartka)",
    "disqualificationBlue": "Dyskwalifikacja z opisem (niebieska kartka)",
    "teamTime": "Czas dla drużyny",
}
KROTKO: Dict[str, str] = {
    "warning": "U", "penalty1": "I", "penalty2": "II", "penalty3": "III",
    "penaltyExtra": "Kd", "disqualification": "D", "disqualificationBlue": "D+N",
    "goal": "B", "penaltyKickScored": "7m", "penaltyKickMissed": "7m×",
}
KARY = ("warning", "penalty1", "penalty2", "penalty3", "penaltyExtra",
        "disqualification", "disqualificationBlue")
#: Kary, po których osoba nie może już grać - ich zniknięcie ma osobne ustalenie.
WYKLUCZAJACE = ("penalty3", "disqualification", "disqualificationBlue")
BRAMKI = ("goal", "penaltyKickScored")
POLA_KARTY = ("warning", "penalty1", "penalty2", "penalty3", "penaltyExtra",
              "disqualification", "disqualificationDesc", "hasRedCard")

ZDARZENIA_DZIENNIKA: Dict[str, str] = {
    "match.created": "Założenie meczu",
    "match.live_started": "Start prowadzenia",
    "table.taken_over": "Przejęcie stolika",
    "match.finished": "Zakończenie meczu",
    "match.approved": "Zatwierdzenie protokołu",
    "match.unapproved": "Cofnięcie zatwierdzenia",
    "match.deleted": "Usunięcie zapisu",
    "match.restored": "Przywrócenie zapisu",
    "match.id_conflict": "Odrzucony zapis (inny mecz)",
    "match.doc_conflict": "Odrzucony zapis (nowsza wersja na serwerze)",
    "match.overwritten_by_choice": "Nadpisanie wersji z serwera wyborem sędziego",
    "match.promoted": "Przeniesienie do oficjalnego zapisu",
    "match.reopened": "Wznowienie meczu",
    "match.signed": "Podpis pod protokołem",
    "match.signature_removed": "Usunięcie podpisu",
    "match.resumed_local": "Powrót do meczu z autozapisu",
    "match.version_adopted": "Przyjęcie wersji z serwera",
    "match.approve_refused": "Odmowa zatwierdzenia",
    "match.snapshots_backfilled": "Dosłano historię wersji z telefonu",
    "match.snapshot_limit": "Limit wersji na dobę osiągnięty",
    "match.sms_sent": "Zgłoszenie wyniku SMS-em",
    "field.changed": "Zmiana pól",
    "protocol.pdf_generated": "Wygenerowanie protokołu PDF",
    "report.submitted": "Złożenie raportu dodatkowego",
    "zprp.summary_sent": "Wynik skrócony do ZPRP",
    "zprp.full_data_sent": "Pełne dane meczu do ZPRP",
    "zprp.players_sent": "Statystyki zawodników do ZPRP",
    "zprp.officials_sent": "Kary osób towarzyszących do ZPRP",
    "zprp.comment_sent": "Uwagi verte do ZPRP",
    "zprp.extra_report_comment_sent": "Dodatkowy raport dopisany do uwag ZPRP",
    "zprp.extra_report_in_zprp": "Dodatkowy raport potwierdzony w uwagach ZPRP",
    "zprp.attachment_sent": "Protokół PDF wysłany do ZPRP",
    "zprp.send_failed": "Nieudana próba wysyłki do ZPRP",
    "zprp.send_queued": "Wysyłka odłożona do dosyłki",
    "exam.confirmed": "Potwierdzenie badań",
    "exam.withdrawn": "Cofnięcie potwierdzenia badań",
    "evidence.marked": "Oznaczenie jako materiał dowodowy",
    "evidence.released": "Zdjęcie oznaczenia materiału dowodowego",
    "evidence.package": "Teczka dowodowa",
}
#: Zdarzenia, które składają się na kalendarium meczu (reszta idzie do załącznika).
KALENDARIUM = (
    "match.created", "match.live_started", "table.taken_over", "match.finished",
    "match.reopened", "match.approved", "match.unapproved", "match.deleted",
    "match.restored", "match.doc_conflict", "match.overwritten_by_choice",
    "match.promoted", "protocol.pdf_generated", "zprp.attachment_sent",
    "zprp.full_data_sent", "zprp.summary_sent", "evidence.marked", "evidence.released",
)
#: Zdarzenia, które same w sobie mówią o ingerencji w treść - idą do ustaleń.
INGERENCJE = ("match.unapproved", "match.restored", "match.doc_conflict",
              "match.overwritten_by_choice", "match.deleted", "table.taken_over")
KAMIENIE = {
    "start": "Założenie zapisu", "live": "Pierwszy gwizdek", "halftime": "Przerwa",
    "end": "Koniec meczu", "approve": "Zatwierdzenie", "unapprove": "Cofnięcie zatwierdzenia",
    "conflict": "Spór wersji", "restore": "Przywrócenie wersji",
}

# ─────────────────────────── czas ───────────────────────────


def _ostatnia_niedziela(rok: int, miesiac: int) -> date:
    d = date(rok, miesiac, 31)  # marzec i październik mają 31 dni
    return d - timedelta(days=(d.weekday() - 6) % 7)


def czas_utc(wartosc: Any) -> Optional[datetime]:
    if not wartosc:
        return None
    if isinstance(wartosc, datetime):
        t = wartosc
    else:
        try:
            t = datetime.fromisoformat(str(wartosc).replace("Z", "+00:00"))
        except ValueError:
            return None
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)
    return t.astimezone(timezone.utc)


def czas_pl(wartosc: Any) -> Optional[datetime]:
    """Godzina polska (CET/CEST) jako datetime bez strefy."""
    t = czas_utc(wartosc)
    if t is None:
        return None
    lato_od = datetime.combine(_ostatnia_niedziela(t.year, 3), datetime.min.time(), timezone.utc) + timedelta(hours=1)
    lato_do = datetime.combine(_ostatnia_niedziela(t.year, 10), datetime.min.time(), timezone.utc) + timedelta(hours=1)
    przesuniecie = 2 if lato_od <= t < lato_do else 1
    return (t + timedelta(hours=przesuniecie)).replace(tzinfo=None)


def godz(wartosc: Any) -> str:
    t = czas_pl(wartosc)
    return t.strftime("%H:%M:%S") if t else "-"


def data_godz(wartosc: Any) -> str:
    t = czas_pl(wartosc)
    return t.strftime("%d.%m.%Y %H:%M:%S") if t else "-"


def mmss(ms: Any) -> str:
    try:
        s = int(ms) // 1000
    except (TypeError, ValueError):
        return "-"
    return f"{s // 60:02d}:{s % 60:02d}"


def _ile_zdarzen(n: int) -> str:
    """„doszło 1 inne zdarzenie, które zostało" / „doszły 3 inne zdarzenia, które zostały"."""
    if n == 1:
        return "doszło 1 inne zdarzenie, które zostało"
    if 2 <= n % 10 <= 4 and not 12 <= n % 100 <= 14:
        return f"doszły {n} inne zdarzenia, które zostały"
    return f"doszło {n} innych zdarzeń, które zostały"


def _maly(etykieta: str) -> str:
    """Mała litera w środku zdania - ale „II kara" zostaje rzymska."""
    pierwsze = etykieta.split(" ", 1)[0]
    if pierwsze in ("I", "II", "III"):
        return etykieta
    return etykieta[:1].lower() + etykieta[1:]


def trwanie(sekundy: float) -> str:
    s = int(round(sekundy))
    if s < 60:
        return f"{s} s"
    m, s = divmod(s, 60)
    if m < 60:
        return f"{m} min {s} s" if s else f"{m} min"
    g, m = divmod(m, 60)
    return f"{g} godz. {m} min"


# ─────────────────────────── blob ───────────────────────────


def _slownik(v: Any) -> Dict[str, Any]:
    return v if isinstance(v, dict) else {}


def konfiguracja(blob: Any) -> Dict[str, Any]:
    return _slownik(_slownik(blob).get("matchConfig"))


def karty(blob: Any, druzyna: str) -> Dict[str, str]:
    """Numer -> „NAZWISKO Imię" z kart składu (w `matchConfig`)."""
    cfg = konfiguracja(blob)
    zrodlo = cfg.get(f"{druzyna}PlayerCards") or _slownik(blob).get(f"{druzyna}PlayerCards") or []
    out: Dict[str, str] = {}
    for c in zrodlo:
        if isinstance(c, dict) and c.get("number") is not None:
            out[str(c.get("number"))] = str(c.get("fullName") or "").strip()
    return out


def klucz_zdarzenia(e: Dict[str, Any]) -> Tuple:
    try:
        t = int(e.get("time") or 0)
    except (TypeError, ValueError):
        t = 0
    return (str(e.get("type") or ""), str(e.get("team") or ""), str(e.get("player") or ""),
            t, e.get("half"), bool(e.get("shootout")))


def przebieg(blob: Any) -> List[Dict[str, Any]]:
    return [e for e in _slownik(blob).get("protocol") or [] if isinstance(e, dict)]


def wiersz_karty(blob: Any, druzyna: str, numer: str) -> Dict[str, Any]:
    for r in _slownik(blob).get(f"{druzyna}PlayerStats") or []:
        if isinstance(r, dict) and str(r.get("number")) == str(numer):
            return {k: r.get(k) for k in POLA_KARTY + ("goals",) if r.get(k) not in (None, "", False)}
    return {}


def plec_z_kodu(numer_meczu: str) -> Optional[str]:
    """„k"/„m" z kodu rozgrywek (SK/24, S/JmM/24) - etykieta, nic więcej."""
    czesci = [c for c in str(numer_meczu or "").split("/") if c]
    if len(czesci) < 2:
        return None
    kod = czesci[-2]
    if kod and kod[-1] in "Kk":
        return "k"
    if kod and kod[-1] in "Mm":
        return "m"
    return None


# ─────────────────────────── opis zdarzeń ───────────────────────────


class Osoby:
    """Nazwiska z kart składu - z NAJNOWSZEJ wersji, bo składy się poprawia."""

    def __init__(self, blob: Any):
        self.cfg = konfiguracja(blob)
        self.karty = {d: karty(blob, d) for d in ("host", "guest")}

    def druzyna(self, d: str) -> str:
        return str(self.cfg.get(f"{d}TeamName") or ("gospodarze" if d == "host" else "goście"))

    def nazwisko(self, d: str, numer: str) -> str:
        return self.karty.get(d, {}).get(str(numer), "")

    def kto(self, d: str, numer: str) -> str:
        n = self.nazwisko(d, numer)
        stro = "gosp." if d == "host" else "goście"
        if str(numer) in ("Tr", "Os") or not str(numer).isdigit():
            return f"{stro} {numer}"
        return f"nr {numer}{' ' + n if n else ''} ({stro})"


def opis(k: Tuple, osoby: Optional[Osoby] = None, z_osoba: bool = True) -> str:
    rodzaj, d, numer, t, polowa, karne = k
    tekst = f"{RODZAJE.get(rodzaj, rodzaj)} {mmss(t)}"
    if polowa:
        tekst += f" ({polowa}. poł.)"
    if karne:
        tekst += " - seria rzutów karnych"
    if z_osoba and osoby is not None:
        tekst = f"{osoby.kto(d, numer)}: {tekst}"
    return tekst


# ─────────────────────────── porównanie wersji ───────────────────────────


def klasyfikuj(usuniete: Counter, dodane: Counter) -> List[Dict[str, Any]]:
    """Różnica dwóch wersji przebiegu jako lista nazwanych zmian.

    Kolejność dopasowań ma znaczenie: najpierw poprawka czasu tej samej kary
    (najczęstsza i najniewinniejsza), potem przeniesienie na inną osobę (ten
    sam rodzaj, ta sama chwila), potem zmiana rodzaju (ta sama osoba, ta sama
    chwila). Co zostało, to czyste dopisanie albo czyste usunięcie.
    """
    rem = list(usuniete.elements())
    add = list(dodane.elements())
    out: List[Dict[str, Any]] = []

    def dopasuj(warunek, rodzaj: str, odleglosc) -> None:
        i = 0
        while i < len(rem):
            r = rem[i]
            kand = [j for j, a in enumerate(add) if warunek(r, a)]
            if kand:
                j = min(kand, key=lambda j: odleglosc(r, add[j]))
                out.append({"rodzaj": rodzaj, "stare": r, "nowe": add.pop(j)})
                rem.pop(i)
            else:
                i += 1

    dopasuj(lambda r, a: a[:3] == r[:3] and a[5] == r[5] and abs(a[3] - r[3]) <= 120_000,
            "czas", lambda r, a: abs(a[3] - r[3]))
    dopasuj(lambda r, a: a[0] == r[0] and a[1:3] != r[1:3] and abs(a[3] - r[3]) <= 2_000,
            "osoba", lambda r, a: abs(a[3] - r[3]))
    dopasuj(lambda r, a: a[1:3] == r[1:3] and a[0] != r[0] and abs(a[3] - r[3]) <= 2_000,
            "rodzaj", lambda r, a: abs(a[3] - r[3]))
    out += [{"rodzaj": "usuniete", "stare": r, "nowe": None} for r in rem]
    out += [{"rodzaj": "dodane", "stare": None, "nowe": a} for a in add]
    return out


def _dotyczy(z: Dict[str, Any], druzyna: str, numer: str) -> bool:
    return any(k is not None and k[1] == druzyna and k[2] == str(numer) for k in (z["stare"], z["nowe"]))


def opis_zmiany(z: Dict[str, Any], osoby: Osoby, z_osoba: bool = True) -> str:
    s, n = z["stare"], z["nowe"]
    if z["rodzaj"] == "dodane":
        return f"Wpisano: {opis(n, osoby, z_osoba)}"
    if z["rodzaj"] == "usuniete":
        return f"Usunięto: {opis(s, osoby, z_osoba)}"
    if z["rodzaj"] == "czas":
        return f"Zmiana czasu: {opis(s, osoby, z_osoba)} → {mmss(n[3])}"
    if z["rodzaj"] == "osoba":
        return f"Przeniesienie: {opis(s, osoby, True)} → {osoby.kto(n[1], n[2])}"
    return f"Zmiana rodzaju: {opis(s, osoby, z_osoba)} → {RODZAJE.get(n[0], n[0])}"


def _meta(m: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": m.get("id"),
        "czas": m.get("created_at"),
        "odebrano": m.get("received_at"),
        "rev": m.get("doc_rev"),
        "zrodlo": m.get("source") or "server",
        "kamien": m.get("milestone"),
        "status": m.get("status"),
        "autor": m.get("writer_name") or m.get("writer_judge") or "",
        "urzadzenie": str(m.get("writer_install") or "")[-6:],
        "zegar": m.get("main_time_ms"),
        "wynik": f"{m.get('score_host') if m.get('score_host') is not None else '-'}:"
                 f"{m.get('score_guest') if m.get('score_guest') is not None else '-'}",
        "hash": m.get("content_hash"),
    }


def kroki(migawki: List[Dict[str, Any]]) -> Iterable[Tuple[Dict, Dict, Counter, Counter, Any, Any]]:
    """Pary sąsiednich wersji z treścią: (poprzednia, bieżąca, usunięte, dodane, blob_p, blob_b)."""
    poprz = None
    for m in migawki:
        blob = m.get("payload")
        if not isinstance(blob, dict):
            continue
        teraz = Counter(klucz_zdarzenia(e) for e in przebieg(blob))
        if poprz is not None:
            pm, pblob, pzd = poprz
            yield pm, m, pzd - teraz, teraz - pzd, pblob, blob
        poprz = (m, blob, teraz)


def stan_kar(blob: Any, druzyna: str, numer: str) -> List[Tuple]:
    return sorted(
        (k for k in (klucz_zdarzenia(e) for e in przebieg(blob))
         if k[1] == druzyna and k[2] == str(numer) and k[0] in KARY),
        key=lambda k: k[3],
    )


def skrot_stanu(kary: List[Tuple], karta: Dict[str, Any]) -> str:
    czesci = [f"{KROTKO.get(k[0], k[0])} {mmss(k[3])}" for k in kary]
    if karta.get("hasRedCard") and not any(k[0] in ("disqualification", "disqualificationBlue") for k in kary):
        czesci.append("dyskwalifikacja w karcie")
    return " · ".join(czesci) if czesci else "bez kar"


# ─────────────────────────── analiza ───────────────────────────


def znajdz_osobe(blob: Any, numer: Optional[str], druzyna: Optional[str], nazwisko: Optional[str]) -> Dict[str, str]:
    """Kogo dotyczy raport. Niejednoznaczność ma się wytłumaczyć, nie zgadywać."""
    wszyscy = [(d, n, nm) for d in ("host", "guest") for n, nm in karty(blob, d).items()]
    trafienia = wszyscy
    if druzyna:
        trafienia = [t for t in trafienia if t[0] == druzyna]
    if numer:
        trafienia = [t for t in trafienia if t[1] == str(numer)]
    if nazwisko:
        trafienia = [t for t in trafienia if nazwisko.upper() in t[2].upper()]
    if len(trafienia) == 1:
        d, n, nm = trafienia[0]
        return {"druzyna": d, "numer": n, "nazwisko": nm}
    if not trafienia and numer and druzyna:
        # Numer bez karty (skład ręczny) - raport i tak ma sens.
        return {"druzyna": druzyna, "numer": str(numer), "nazwisko": ""}
    lista = ", ".join(f"{'gosp.' if d == 'host' else 'goście'} nr {n} {nm}" for d, n, nm in trafienia[:10])
    raise ValueError(
        "Nie da się jednoznacznie wskazać osoby"
        + (f" - pasują: {lista}" if trafienia else " - nikt nie pasuje do podanych danych")
    )


def _dane_meczu(zrzut: Dict[str, Any], blob: Dict[str, Any], osoby: Osoby) -> Dict[str, Any]:
    cfg = konfiguracja(blob)
    extras = _slownik(cfg.get("extras"))
    oficjalni = _slownik(extras.get("officials"))

    def osoba_funkcyjna(klucz: str) -> str:
        return str(cfg.get(klucz) or _slownik(oficjalni.get(klucz)).get("fullName") or "").strip()

    mecz = zrzut.get("mecz") or {}
    zatw = [w for w in zrzut.get("dziennik") or [] if w.get("event") == "match.approved"]
    dzien = str(extras.get("matchDate") or cfg.get("matchDate") or "").strip()[:10]
    if len(dzien) == 10 and dzien[4] == "-":
        dzien = f"{dzien[8:10]}.{dzien[5:7]}.{dzien[:4]}"
    data_meczu = ", ".join(
        x for x in (dzien, str(extras.get("matchTime") or cfg.get("matchTime") or "").strip()) if x
    )
    wynik = f"{blob.get('scoreHost', '-')}:{blob.get('scoreGuest', '-')}"
    karne = str(blob.get("penaltyScore") or "").strip()
    if karne and karne not in ("0 - 0", "0-0"):
        wynik += f" (rzuty karne {karne})"
    hala = ", ".join(x for x in (str(cfg.get("venueAddress") or "").strip(),
                                 str(cfg.get("venueCity") or "").strip()) if x)
    return {
        "numer": mecz.get("match_number") or zrzut.get("klucz"),
        "id_zprp": mecz.get("zprp_match_id") or cfg.get("matchId") or "",
        "data": data_meczu,
        "hala": hala,
        "gospodarze": osoby.druzyna("host"),
        "goscie": osoby.druzyna("guest"),
        "wynik": wynik,
        "status": {"approved": "Zatwierdzony", "finished": "Zakończony, niezatwierdzony",
                   "in_progress": "W toku"}.get(str(mecz.get("status")), str(mecz.get("status") or "-")),
        "zatwierdzil": (zatw[-1].get("actor_name") or zatw[-1].get("actor_judge_id")) if zatw else "",
        "zatwierdzono": zatw[-1].get("created_at") if zatw else None,
        "sedzia1": osoba_funkcyjna("referee1"),
        "sedzia2": osoba_funkcyjna("referee2"),
        "delegat": osoba_funkcyjna("delegate"),
        "sekretarz": osoba_funkcyjna("secretary"),
        "mierzacy": osoba_funkcyjna("timekeeper"),
        "wersja": mecz.get("doc_rev"),
    }


def _zwijaj_dziennik(wpisy: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Seria identycznych wpisów (np. 20 × „medic.fullName" przy pisaniu) jako jeden wiersz."""
    out: List[Dict[str, Any]] = []
    for w in wpisy:
        det = dict(_slownik(w.get("details_json")))
        det.pop("rev", None)
        podpis = (w.get("event"), w.get("actor_name") or w.get("actor_judge_id"), repr(sorted(det.items(), key=str)))
        if out and out[-1]["_podpis"] == podpis:
            out[-1]["ile"] += 1
            out[-1]["do"] = w.get("created_at")
            continue
        out.append({"_podpis": podpis, "ile": 1, "od": w.get("created_at"), "do": w.get("created_at"), "wpis": w})
    return out


def opis_szczegolow(event: str, det: Any) -> str:
    det = _slownik(det)
    if not det:
        return ""
    if event == "field.changed" and isinstance(det.get("paths"), list):
        sciezki = [str(p) for p in det["paths"]]
        return ", ".join(sciezki[:6]) + (f" i {len(sciezki) - 6} innych" if len(sciezki) > 6 else "")
    if event in ("match.signed", "match.signature_removed") and isinstance(det.get("signatures"), list):
        return ", ".join(str(_slownik(s).get("who") or _slownik(s).get("path") or "") for s in det["signatures"])
    if "from" in det and "to" in det:
        return f"{det['from']} → {det['to']}"
    pomin = {"rev", "src"}
    return "; ".join(f"{k}: {v}" for k, v in det.items() if k not in pomin and not isinstance(v, (dict, list)))[:240]


def analizuj(
    zrzut: Dict[str, Any],
    numer: Optional[str] = None,
    druzyna: Optional[str] = None,
    nazwisko: Optional[str] = None,
) -> Dict[str, Any]:
    mecz = zrzut.get("mecz") or {}
    blob = _slownik(mecz.get("data_json"))
    migawki = list(zrzut.get("migawki") or [])
    osoby = Osoby(blob)
    dane = _dane_meczu(zrzut, blob, osoby)

    osoba = None
    if numer or nazwisko:
        osoba = znajdz_osobe(blob, numer, druzyna, nazwisko)

    # Pierwsze pojawienie się każdego zdarzenia - „kiedy to zapisano". Poprawka
    # czasu, rodzaju albo osoby to wciąż TA SAMA czynność stolika, więc nowy
    # klucz dziedziczy chwilę pierwotnego wpisu. Inaczej kara z poprawionym
    # czasem wyglądałaby na zapisaną dopiero przy poprawce.
    pierwszy: Dict[Tuple, Dict[str, Any]] = {}
    poczatek = next((m for m in migawki if isinstance(m.get("payload"), dict)), None)
    if poczatek is not None:
        for e in przebieg(poczatek["payload"]):
            pierwszy.setdefault(klucz_zdarzenia(e), poczatek)
    for _pm, m, rem, add, _pb, _b in kroki(migawki):
        for z in klasyfikuj(rem, add):
            n = z["nowe"]
            if n is None or n in pierwszy:
                continue
            if z["rodzaj"] != "dodane" and z["stare"] in pierwszy:
                pierwszy[n] = pierwszy[z["stare"]]
            else:
                pierwszy[n] = m
    koncowe = Counter(klucz_zdarzenia(e) for e in przebieg(blob))

    # ── korekty w całym meczu (każdy krok, w którym coś zniknęło lub się zmieniło)
    korekty: List[Dict[str, Any]] = []
    for pm, m, rem, add, _pb, _b in kroki(migawki):
        if not rem:
            continue
        zmiany = klasyfikuj(rem, add)
        korekty.append({
            "przed": _meta(pm), "po": _meta(m),
            "zmiany": [{**z, "tekst": opis_zmiany(z, osoby),
                        "osoby": bool(osoba and _dotyczy(z, osoba["druzyna"], osoba["numer"]))}
                       for z in zmiany],
        })

    wynik: Dict[str, Any] = {
        "mecz": dane,
        "osoba": None,
        "korekty": korekty,
        "ustalenia": [],
        "kalendarium": [],
        "dziennik": [],
        "pdf": [],
        "zrodla": {},
    }

    # ── kalendarium: dziennik + kamienie milowe migawek
    kal: List[Dict[str, Any]] = []
    for w in zrzut.get("dziennik") or []:
        if w.get("event") in KALENDARIUM:
            kal.append({"czas": w.get("created_at"),
                        "co": ZDARZENIA_DZIENNIKA.get(w["event"], w["event"]),
                        "kto": w.get("actor_name") or w.get("actor_judge_id") or "",
                        "szczegoly": opis_szczegolow(w["event"], w.get("details_json"))})
    for m in migawki:
        if m.get("milestone") in ("halftime", "end", "conflict", "restore", "unapprove"):
            kal.append({"czas": m.get("created_at"),
                        "co": f"Wersja: {KAMIENIE.get(m['milestone'], m['milestone'])}",
                        "kto": m.get("writer_name") or "",
                        "szczegoly": f"zegar {mmss(m.get('main_time_ms'))}, wynik "
                                     f"{m.get('score_host')}:{m.get('score_guest')}"})
    kal.sort(key=lambda x: czas_utc(x["czas"]) or datetime.min.replace(tzinfo=timezone.utc))
    wynik["kalendarium"] = kal
    wynik["dziennik"] = [
        {"od": z["od"], "do": z["do"], "ile": z["ile"],
         "co": ZDARZENIA_DZIENNIKA.get(z["wpis"].get("event"), z["wpis"].get("event")),
         "kto": z["wpis"].get("actor_name") or z["wpis"].get("actor_judge_id") or "?",
         "potwierdzony": bool(z["wpis"].get("actor_verified")),
         "aplikacja": z["wpis"].get("app_version") or "",
         "szczegoly": opis_szczegolow(z["wpis"].get("event"), z["wpis"].get("details_json"))}
        for z in _zwijaj_dziennik(list(zrzut.get("dziennik") or []))
    ]

    ustalenia: List[Dict[str, str]] = []

    # ── osoba objęta raportem
    if osoba:
        d, nr = osoba["druzyna"], osoba["numer"]
        etykieta = f"nr {nr}" + (f" {osoba['nazwisko']}" if osoba["nazwisko"] else "")
        plec = plec_z_kodu(dane["numer"])
        osoba_out = {
            **osoba,
            "etykieta": etykieta,
            "druzyna_nazwa": osoby.druzyna(d),
            "strona": "gospodarze" if d == "host" else "goście",
            "rola": {"k": "Zawodniczka", "m": "Zawodnik"}.get(plec or "", "Zawodnik / zawodniczka"),
        }
        kary_koniec = stan_kar(blob, d, nr)
        karta_koniec = wiersz_karty(blob, d, nr)
        zdarzenia_koniec = sorted(
            (k for k in koncowe.elements() if k[1] == d and k[2] == nr), key=lambda k: k[3]
        )
        osoba_out["kary_koniec"] = [
            {"opis": RODZAJE.get(k[0], k[0]), "czas": mmss(k[3]), "polowa": k[4],
             "zapisano": (pierwszy.get(k) or {}).get("created_at")}
            for k in kary_koniec
        ]
        osoba_out["zdarzenia_koniec"] = [
            {"opis": RODZAJE.get(k[0], k[0]), "czas": mmss(k[3]), "polowa": k[4],
             "zapisano": (pierwszy.get(k) or {}).get("created_at"), "kara": k[0] in KARY,
             # Bramka niesie wynik po sobie; kara nie - bierzemy wynik z wersji, w której ją wpisano.
             "wynik": next((str(e.get("score") or "") for e in przebieg(blob) if klucz_zdarzenia(e) == k), "")
             or (_meta(pierwszy[k])["wynik"] if k in pierwszy else "")}
            for k in zdarzenia_koniec
        ]
        osoba_out["karta_koniec"] = karta_koniec
        osoba_out["bramki"] = karta_koniec.get("goals")

        # Przebieg zmian wersja po wersji.
        historia: List[Dict[str, Any]] = []
        pierwsza = next((m for m in migawki if isinstance(m.get("payload"), dict)), None)
        if pierwsza is not None:
            start = stan_kar(pierwsza["payload"], d, nr)
            if start:
                historia.append({"meta": _meta(pierwsza), "zmiany": ["Stan na początku zachowanej historii"],
                                 "rodzaje": ["poczatek"],
                                 "stan": skrot_stanu(start, wiersz_karty(pierwsza["payload"], d, nr))})
        usuniecia: List[Dict[str, Any]] = []
        poprawki_czasu: List[Dict[str, Any]] = []
        inne: List[Dict[str, Any]] = []
        for pm, m, rem, add, pb, b in kroki(migawki):
            zmiany = [z for z in klasyfikuj(rem, add) if _dotyczy(z, d, nr)]
            # Dopisanie bramki to zwykły przebieg - w tabeli kar zostają tylko kary
            # i KAŻDA ingerencja (usunięcie, zmiana) niezależnie od rodzaju.
            zmiany = [z for z in zmiany if z["rodzaj"] != "dodane" or z["nowe"][0] in KARY]
            karta_p, karta_b = wiersz_karty(pb, d, nr), wiersz_karty(b, d, nr)
            karta_zmiana = {k: (karta_p.get(k), karta_b.get(k)) for k in POLA_KARTY
                            if karta_p.get(k) != karta_b.get(k)}
            if not zmiany and not karta_zmiana:
                continue
            teksty = [opis_zmiany(z, osoby, z_osoba=False) if z["rodzaj"] != "osoba" else opis_zmiany(z, osoby)
                      for z in zmiany]
            if karta_zmiana.get("hasRedCard"):
                teksty.append("Dyskwalifikacja w karcie: " + ("pojawia się" if karta_b.get("hasRedCard") else "znika"))
            if not zmiany and karta_zmiana and not teksty:
                teksty.append("Zmiana w karcie: " + ", ".join(f"{k}: {a or '-'} → {b2 or '-'}" for k, (a, b2) in karta_zmiana.items()))
            historia.append({
                "meta": _meta(m), "zmiany": teksty, "rodzaje": [z["rodzaj"] for z in zmiany],
                "stan": skrot_stanu(stan_kar(b, d, nr), karta_b),
            })
            for z in zmiany:
                if z["rodzaj"] == "usuniete":
                    usuniecia.append({"z": z, "przed": pm, "po": m, "blob": b, "inne": [
                        opis_zmiany(x, osoby) for x in klasyfikuj(rem, add) if not _dotyczy(x, d, nr)
                    ], "karta_przed": karta_p, "karta_po": karta_b})
                elif z["rodzaj"] == "czas":
                    poprawki_czasu.append({"z": z, "po": m})
                elif z["rodzaj"] in ("osoba", "rodzaj"):
                    inne.append({"z": z, "po": m})
        osoba_out["historia"] = historia
        wynik["osoba"] = osoba_out

        # ── ustalenia o osobie
        if kary_koniec:
            lista = "; ".join(f"{RODZAJE.get(k[0], k[0])} - {mmss(k[3])} ({k[4]}. poł.)" for k in kary_koniec)
            ustalenia.append({"waga": "info", "tekst":
                f"W końcowym zapisie protokołu {etykieta} ma: {lista}."
                + ("" if any(k[0] in WYKLUCZAJACE for k in kary_koniec) else " Brak dyskwalifikacji.")})
        else:
            ustalenia.append({"waga": "info", "tekst": f"W końcowym zapisie protokołu {etykieta} nie ma żadnej kary."})

        for u in usuniecia:
            k = u["z"]["stare"]
            wpis = pierwszy.get(k) or u["przed"]
            t0, t1 = czas_utc(wpis.get("created_at")), czas_utc(u["po"].get("created_at"))
            wrocila = k in koncowe
            zdanie = (
                f"{RODZAJE.get(k[0], k[0])} z {mmss(k[3])} ({k[4]}. poł.) wpisano o {godz(wpis.get('created_at'))}"
                f" (zegar {mmss(wpis.get('main_time_ms'))}, wynik {_meta(wpis)['wynik']}, zapisał: {wpis.get('writer_name') or '-'})"
                f" i usunięto o {godz(u['po'].get('created_at'))} (zegar {mmss(u['po'].get('main_time_ms'))},"
                f" wynik {_meta(u['po'])['wynik']}, zapisał: {u['po'].get('writer_name') or '-'})"
            )
            if t0 and t1:
                zdanie += f". Kara była w zapisie przez {trwanie((t1 - t0).total_seconds())}"
            if u["karta_przed"].get("hasRedCard") and not u["karta_po"].get("hasRedCard"):
                zdanie += "; razem z nią z karty zniknęła dyskwalifikacja"
            zdanie += "."
            if u["inne"]:
                zdanie += " W tym samym zapisie zmieniono też: " + "; ".join(u["inne"]) + "."
            else:
                zdanie += " W tym samym zapisie nie wpisano tej kary nikomu innemu."
            if t0 and t1:
                pomiedzy = [x for x in koncowe.elements()
                            if (pierwszy.get(x) is not None
                                and t0 < czas_utc(pierwszy[x].get("created_at")) < t1)]
                if pomiedzy:
                    zdanie += (f" Między wpisaniem a usunięciem do przebiegu {_ile_zdarzen(len(pomiedzy))}"
                               " w protokole - usunięcie nie było cofnięciem ostatniej czynności.")
            if wrocila:
                zdanie += " Później tę samą karę wpisano ponownie."
            ustalenia.append({"waga": "uwaga", "tekst": zdanie})

            if k[0] in WYKLUCZAJACE and t1 and not wrocila:
                po = [x for x in zdarzenia_koniec
                      if pierwszy.get(x) is not None and czas_utc(pierwszy[x].get("created_at")) > t1]
                if po:
                    ustalenia.append({"waga": "uwaga", "tekst":
                        f"Po usunięciu tej kary (o {godz(u['po'].get('created_at'))}) dla {etykieta} zapisano: "
                        + "; ".join(
                            f"{_maly(RODZAJE.get(x[0], x[0]))} {mmss(x[3])}"
                            f" (zapisano o {godz(pierwszy[x].get('created_at'))})" for x in po)
                        + "."})

        if poprawki_czasu:
            ustalenia.append({"waga": "info", "tekst":
                "Poprawki czasu kar: " + "; ".join(
                    f"{RODZAJE.get(p['z']['stare'][0], p['z']['stare'][0])} {mmss(p['z']['stare'][3])} → "
                    f"{mmss(p['z']['nowe'][3])} (o {godz(p['po'].get('created_at'))}, zegar {mmss(p['po'].get('main_time_ms'))})"
                    for p in poprawki_czasu) + "."})
        for p in inne:
            ustalenia.append({"waga": "uwaga", "tekst":
                f"{opis_zmiany(p['z'], osoby)} (o {godz(p['po'].get('created_at'))}, zapisał: {p['po'].get('writer_name') or '-'})."})

        autorzy = Counter(h["meta"]["autor"] for h in historia if h["meta"]["autor"])
        if autorzy:
            ustalenia.append({"waga": "info", "tekst":
                f"Wszystkie zapisy dotyczące {etykieta} pochodzą od: "
                + ", ".join(f"{a} ({n})" for a, n in autorzy.most_common()) + "."})

    # ── protokoły PDF: zgodność z końcowym zapisem
    for p in zrzut.get("protokoly_pdf") or []:
        stan = _slownik(p.get("state_gzip"))
        zrodlo = stan if "protocol" in stan else _slownik(stan.get("matchData") or stan.get("data"))
        poz = {"kod": p.get("code"), "czas": p.get("created_at"),
               "kto": p.get("actor_name") or p.get("judge_id") or "?",
               "aplikacja": p.get("app_version") or "", "pdf_sha256": p.get("pdf_sha256") or "",
               "stan_sha256": p.get("state_sha256") or "", "podpis": bool(p.get("signature")),
               "zgodny": None, "roznice": []}
        if osoba and "protocol" in zrodlo:
            w_pdf = Counter(k for k in (klucz_zdarzenia(e) for e in przebieg(zrodlo))
                            if k[1] == osoba["druzyna"] and k[2] == osoba["numer"] and k[0] in KARY)
            w_kon = Counter(k for k in koncowe.elements()
                            if k[1] == osoba["druzyna"] and k[2] == osoba["numer"] and k[0] in KARY)
            poz["zgodny"] = w_pdf == w_kon
            poz["roznice"] = ([f"tylko w PDF: {opis(k)}" for k in (w_pdf - w_kon).elements()]
                              + [f"tylko w końcowym zapisie: {opis(k)}" for k in (w_kon - w_pdf).elements()])
        tekst = str(p.get("pdf_text_gzip") or "")
        if osoba and osoba["nazwisko"]:
            nazw = osoba["nazwisko"].split()[0].upper()
            poz["wydruk"] = [ln.strip() for ln in tekst.splitlines() if nazw in ln.upper()][:5]
        wynik["pdf"].append(poz)
        if poz["zgodny"] is True:
            ustalenia.append({"waga": "info", "tekst":
                f"Protokół PDF {poz['kod']} (wygenerowany {data_godz(poz['czas'])}, {poz['kto']}) "
                f"w zakresie kar {wynik['osoba']['etykieta'] if wynik['osoba'] else ''} zgadza się z końcowym zapisem."})
        elif poz["zgodny"] is False:
            ustalenia.append({"waga": "uwaga", "tekst":
                f"Protokół PDF {poz['kod']} różni się od końcowego zapisu: " + "; ".join(poz["roznice"]) + "."})

    # ── ingerencje w cały zapis
    ingerencje = [w for w in zrzut.get("dziennik") or [] if w.get("event") in INGERENCJE]
    spory = zrzut.get("historia_sporow") or []
    usuniete = zrzut.get("usuniete") or []
    if not ingerencje and not spory and not usuniete:
        ustalenia.append({"waga": "info", "tekst":
            "Zapis meczu nie był przedmiotem sporu wersji, nie był usuwany ani przywracany, "
            "a zatwierdzenia nie cofano."})
    for w in ingerencje:
        ustalenia.append({"waga": "uwaga", "tekst":
            f"{ZDARZENIA_DZIENNIKA.get(w['event'], w['event'])} o {data_godz(w.get('created_at'))}"
            f" ({w.get('actor_name') or w.get('actor_judge_id') or '?'})."})
    if spory:
        ustalenia.append({"waga": "uwaga", "tekst": f"W historii sporów wersji jest {len(spory)} wpisów."})

    # ── źródła i kompletność
    z_trescia = [m for m in migawki if isinstance(m.get("payload"), dict)]
    wygasa = sorted(czas_utc(m.get("expires_at")) for m in migawki if m.get("expires_at"))
    zrodla = {
        "migawki": len(migawki),
        "migawki_z_trescia": len(z_trescia),
        "migawki_urzadzenie": sum(1 for m in migawki if m.get("source") == "device"),
        "pierwsza": migawki[0].get("created_at") if migawki else None,
        "ostatnia": migawki[-1].get("created_at") if migawki else None,
        "dziennik": len(zrzut.get("dziennik") or []),
        "spory": len(spory),
        "usuniete": len(usuniete),
        "pdf": len(zrzut.get("protokoly_pdf") or []),
        "najblizsze_wygasniecie": wygasa[0].isoformat() if wygasa else None,
        "wykonano": zrzut.get("wykonano"),
        "narzedzie": zrzut.get("narzedzie") or {},
    }
    wynik["zrodla"] = zrodla
    if len(z_trescia) < len(migawki):
        ustalenia.append({"waga": "uwaga", "tekst":
            f"{len(migawki) - len(z_trescia)} z {len(migawki)} wersji nie ma zachowanej treści "
            "(za duża albo wygasła) - przebieg między nimi jest odtworzony z sąsiednich wersji."})
    if not migawki:
        ustalenia.append({"waga": "uwaga", "tekst":
            "Brak zachowanych wersji - raport opiera się wyłącznie na końcowym zapisie i dzienniku."})

    wynik["ustalenia"] = ustalenia
    return wynik
