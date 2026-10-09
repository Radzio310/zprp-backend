"""Teczka jednej osoby - zwięzłe fakty do raportu „o zawodniczce/zawodniku".

Liść bez bazy i bez sieci. Bierze zrzut meczu (`zrzut.py` albo teczkę
z panelu) i składa WYŁĄCZNIE to, co dotyczy jednej osoby:

* każdą jej karę jako „życiorys": kiedy wpisana, jak poprawiana, czy i kiedy
  usunięta, przez kogo i przy jakim wyniku,
* jej bramki z chwilą zapisu (żeby było widać, co padło PO usunięciu kary),
* kontekst meczu w sekundzie usuniętej kary (inne zdarzenia tej samej akcji),
* kto dotykał jej zapisów, kto zatwierdził protokół i co poszło do ZPRP.

Zdania są bezosobowe i wynikają wprost z porównania wersji - raport mówi,
CO zapisano, a nie, czy słusznie.
"""
from __future__ import annotations

import re
from collections import Counter, OrderedDict
from typing import Any, Dict, List, Optional, Tuple

import analiza as A

#: Zdarzenia dziennika, które składają się na „drogę protokołu" po meczu.
DROGA = OrderedDict([
    ("match.finished", "Zakończenie meczu"),
    ("match.reopened", "Wznowienie meczu"),
    ("zprp.summary_sent", "Wynik skrócony do ZPRP"),
    ("zprp.players_sent", "Statystyki zawodników do ZPRP"),
    ("zprp.full_data_sent", "Pełne dane meczu do ZPRP"),
    ("protocol.pdf_generated", "Wygenerowanie protokołu PDF"),
    ("zprp.attachment_sent", "Protokół PDF w ZPRP"),
    ("match.approved", "Zatwierdzenie protokołu"),
    ("match.unapproved", "Cofnięcie zatwierdzenia"),
    ("match.restored", "Przywrócenie zapisu"),
    ("match.overwritten_by_choice", "Nadpisanie wersji z serwera"),
])

ROLE = {
    "referee1": "sędzia 1", "referee2": "sędzia 2", "delegate": "delegat",
    "delegate2": "delegat 2", "secretary": "sekretarz", "timekeeper": "mierzący czas",
}

#: Nazwy zdarzeń w bierniku („wpisano III karę") i dopełniaczu („usunięcie III kary").
BIERNIK = {
    "warning": "upomnienie", "penalty1": "I karę 2 min", "penalty2": "II karę 2 min",
    "penalty3": "III karę 2 min", "penaltyExtra": "karę dodatkową 2 min",
    "disqualification": "dyskwalifikację", "disqualificationBlue": "dyskwalifikację z opisem",
    "goal": "bramkę", "penaltyKickScored": "bramkę z rzutu karnego",
}
DOPELNIACZ = {
    "warning": "upomnienia", "penalty1": "I kary 2 min", "penalty2": "II kary 2 min",
    "penalty3": "III kary 2 min", "penaltyExtra": "kary dodatkowej 2 min",
    "disqualification": "dyskwalifikacji", "disqualificationBlue": "dyskwalifikacji z opisem",
    "goal": "bramki", "penaltyKickScored": "bramki z rzutu karnego",
}

#: Ile sekund czasu meczu wokół usuniętej kary uznajemy za „tę samą akcję".
OKNO_AKCJI_S = 10


def _norm(nazwisko: str) -> str:
    return " ".join(str(nazwisko or "").upper().split())


def role_obsady(blob: Dict[str, Any]) -> Dict[str, str]:
    """„CHRIST GRZEGORZ" -> „sekretarz" - z obsady zapisanej w protokole."""
    cfg = A.konfiguracja(blob)
    oficjalni = A._slownik(A._slownik(cfg.get("extras")).get("officials"))
    out: Dict[str, str] = {}
    for klucz, rola in ROLE.items():
        for nazwa in (cfg.get(klucz), A._slownik(oficjalni.get(klucz)).get("fullName")):
            if nazwa and _norm(nazwa):
                out.setdefault(_norm(nazwa), rola)
                # „JERLECKA Paulinac" w protokole vs „JERLECKA Paulina" w dzienniku -
                # literówka w obsadzie nie może zgubić roli. Porównujemy też samo nazwisko.
                out.setdefault(_norm(nazwa).split(" ")[0], rola)
    return out


def rola(osoba: str, role: Dict[str, str]) -> str:
    n = _norm(osoba)
    return role.get(n) or role.get(n.split(" ")[0] if n else "", "")


def osoba_towarzyszaca(blob: Dict[str, Any], druzyna: str, litera: str) -> str:
    """„PASCA Horatiu, trener A" dla litery B osób towarzyszących."""
    cfg = A.konfiguracja(blob)
    for c in cfg.get(f"{druzyna}Companions") or []:
        if isinstance(c, dict) and str(c.get("id")) == str(litera):
            nazwa = str(c.get("fullName") or "").strip()
            funkcja = str(c.get("function") or "").strip().lower()
            # „TRENER A" -> „trener A": litera licencji zostaje wielka.
            czesci = funkcja.split(" ")
            if len(czesci) > 1 and len(czesci[-1]) == 1:
                czesci[-1] = czesci[-1].upper()
            funkcja = " ".join(czesci)
            return ", ".join(x for x in (nazwa, funkcja) if x)
    return ""


def kto_zdarzenia(blob: Dict[str, Any], k: Tuple, osoby: A.Osoby) -> str:
    _rodzaj, d, numer, *_ = k
    strona = osoby.druzyna(d)
    if str(numer).isdigit():
        n = osoby.nazwisko(d, numer)
        return f"nr {numer}{' ' + n if n else ''} ({strona})"
    t = osoba_towarzyszaca(blob, d, str(numer))
    if t:
        return f"{t} ({strona})"
    return strona


def _wynik(e: Dict[str, Any]) -> str:
    """Wynik po zdarzeniu („24-25") albo pusty, gdy zdarzenie go nie niesie („-------")."""
    t = str(e.get("score") or "").strip()
    return t.replace(":", "-").replace(" ", "") if re.fullmatch(r"\d+\s*[-:]\s*\d+", t) else ""


def _wynik_liczby(wynik: str) -> Optional[Tuple[int, int]]:
    try:
        a, b = str(wynik).replace(":", "-").split("-")
        return int(a), int(b)
    except ValueError:
        return None


def dossier(
    zrzut: Dict[str, Any],
    numer: Optional[str] = None,
    druzyna: Optional[str] = None,
    nazwisko: Optional[str] = None,
) -> Dict[str, Any]:
    if not (numer or nazwisko):
        raise ValueError("Podaj osobę: --nazwisko albo --zawodnik (z --druzyna).")
    baza = A.analizuj(zrzut, numer=numer, druzyna=druzyna, nazwisko=nazwisko)
    osoba = baza["osoba"]
    d, nr = osoba["druzyna"], osoba["numer"]
    mecz = zrzut.get("mecz") or {}
    blob = A._slownik(mecz.get("data_json"))
    osoby = A.Osoby(blob)
    role = role_obsady(blob)
    migawki = list(zrzut.get("migawki") or [])

    def moja(k: Optional[Tuple]) -> bool:
        return k is not None and k[1] == d and k[2] == nr

    def chwila(m: Dict[str, Any]) -> Dict[str, Any]:
        autor = m.get("writer_name") or m.get("writer_judge") or ""
        return {
            "czas": m.get("created_at"),
            "zegar": m.get("main_time_ms"),
            "wynik": A._meta(m)["wynik"],
            "autor": autor,
            "rola": rola(autor, role),
            "urzadzenie": str(m.get("writer_install") or "")[-8:],
            "numer_sedziego": m.get("writer_judge") or "",
            "migawka": m.get("id"),
            "wersja": m.get("doc_rev"),
            "z_telefonu": (m.get("source") or "server") != "server",
        }

    # ── życiorysy zdarzeń osoby (kary i bramki)
    zyciorysy: List[Dict[str, Any]] = []
    aktualny: Dict[Tuple, Dict[str, Any]] = {}

    pierwsza = next((m for m in migawki if isinstance(m.get("payload"), dict)), None)
    if pierwsza is not None:
        for e in A.przebieg(pierwsza["payload"]):
            k = A.klucz_zdarzenia(e)
            if moja(k):
                z = {"rodzaj": k[0], "klucz": k, "klucz_wpisu": k, "wpis": chwila(pierwsza), "poprawki": [],
                     "usuniecie": None, "przeniesienie": None, "od_poczatku_historii": True}
                zyciorysy.append(z)
                aktualny[k] = z

    for _pm, m, rem, add, _pb, _b in A.kroki(migawki):
        for z in A.klasyfikuj(rem, add):
            s, n = z["stare"], z["nowe"]
            if not (moja(s) or moja(n)):
                continue
            if z["rodzaj"] == "dodane":
                zy = {"rodzaj": n[0], "klucz": n, "klucz_wpisu": n, "wpis": chwila(m), "poprawki": [],
                      "usuniecie": None, "przeniesienie": None, "od_poczatku_historii": False}
                zyciorysy.append(zy)
                aktualny[n] = zy
            elif s in aktualny:
                zy = aktualny.pop(s)
                if z["rodzaj"] == "usuniete":
                    zy["usuniecie"] = chwila(m)
                elif z["rodzaj"] == "osoba" and not moja(n):
                    zy["przeniesienie"] = {**chwila(m), "na": kto_zdarzenia(blob, n, osoby)}
                else:
                    zy["poprawki"].append({**chwila(m), "rodzaj": z["rodzaj"], "z": s, "na": n})
                    zy["klucz"] = n
                    zy["rodzaj"] = n[0]
                    aktualny[n] = zy
            elif moja(n):
                # Zdarzenie przeniesione NA tę osobę od kogoś innego.
                zy = {"rodzaj": n[0], "klucz": n, "klucz_wpisu": n, "wpis": chwila(m), "poprawki": [],
                      "usuniecie": None, "przeniesienie": None, "od_poczatku_historii": False,
                      "przyszlo_od": kto_zdarzenia(blob, s, osoby)}
                zyciorysy.append(zy)
                aktualny[n] = zy

    koncowe = Counter(A.klucz_zdarzenia(e) for e in A.przebieg(blob))
    wynik_koncowy = (blob.get("scoreHost"), blob.get("scoreGuest"))
    for zy in zyciorysy:
        k = zy["klucz"]
        zy["w_protokole"] = zy["usuniecie"] is None and zy["przeniesienie"] is None and k in koncowe
        zy["opis"] = A.RODZAJE.get(k[0], k[0])
        zy["czas_meczu"] = A.mmss(k[3])
        zy["polowa"] = k[4]
        zy["kara"] = k[0] in A.KARY
        zy["wykluczajaca"] = k[0] in A.WYKLUCZAJACE
        zy["wynik_po"] = next((_wynik(e) for e in A.przebieg(blob) if A.klucz_zdarzenia(e) == k), "")
        if zy["usuniecie"]:
            t0, t1 = A.czas_utc(zy["wpis"]["czas"]), A.czas_utc(zy["usuniecie"]["czas"])
            zy["trwanie_s"] = (t1 - t0).total_seconds() if t0 and t1 else None

    usuniete = [z for z in zyciorysy if z["kara"] and (z["usuniecie"] or z["przeniesienie"])]

    # ── bramki osoby PO usunięciu kary wykluczającej
    po_usunieciu: List[Dict[str, Any]] = []
    glowne = next((z for z in usuniete if z["wykluczajaca"]), usuniete[0] if usuniete else None)
    if glowne:
        moment = A.czas_utc((glowne["usuniecie"] or glowne["przeniesienie"])["czas"])
        for z in zyciorysy:
            if z["w_protokole"] and z["rodzaj"] in A.BRAMKI and A.czas_utc(z["wpis"]["czas"]) > moment:
                para = _wynik_liczby(z["wynik_po"])
                z["decydujaca"] = bool(
                    para and para == tuple(wynik_koncowy) and abs(para[0] - para[1]) == 1
                )
                z["po_usunieciu_s"] = (A.czas_utc(z["wpis"]["czas"]) - moment).total_seconds()
                po_usunieciu.append(z)

    # ── kontekst akcji: inne zdarzenia w tej samej chwili meczu co usunięta kara
    kontekst: List[Dict[str, Any]] = []
    if glowne:
        t = glowne["klucz"][3]
        for e in A.przebieg(blob):
            k = A.klucz_zdarzenia(e)
            if k == glowne["klucz"] or abs(k[3] - t) > OKNO_AKCJI_S * 1000:
                continue
            kontekst.append({"opis": A.RODZAJE.get(k[0], k[0]), "czas_meczu": A.mmss(k[3]),
                             "kto": kto_zdarzenia(blob, k, osoby),
                             "wynik": _wynik(e),
                             "roznica_s": round((k[3] - t) / 1000)})
        kontekst.sort(key=lambda x: x["roznica_s"])
        # Zdarzenia, które doszły do przebiegu, gdy kara jeszcze stała.
        t0 = A.czas_utc(glowne["wpis"]["czas"])
        t1 = A.czas_utc((glowne["usuniecie"] or glowne["przeniesienie"])["czas"])
        pierwszy: Dict[Tuple, Any] = {}
        for m in migawki:
            if isinstance(m.get("payload"), dict):
                for e in A.przebieg(m["payload"]):
                    pierwszy.setdefault(A.klucz_zdarzenia(e), A.czas_utc(m.get("created_at")))
        glowne["zdarzen_w_miedzyczasie"] = sum(
            1 for k in koncowe.elements() if pierwszy.get(k) and t0 < pierwszy[k] < t1
        )

    # ── jedyne usunięcie w meczu?
    wszystkie_usuniecia = [z for k in baza["korekty"] for z in k["zmiany"] if z["rodzaj"] == "usuniete"]
    inne_korekty = Counter(z["rodzaj"] for k in baza["korekty"] for z in k["zmiany"]
                           if not z.get("osoby") and z["rodzaj"] != "dodane")

    # ── kto dotykał jej zapisów
    edytorzy: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
    for zy in zyciorysy:
        kw = zy["klucz_wpisu"]
        kroki = [(zy["wpis"], f"wpisanie {DOPELNIACZ.get(kw[0], kw[0])} ({A.mmss(kw[3])})")]
        for p in zy["poprawki"]:
            if p["rodzaj"] == "czas":
                kroki.append((p, f"poprawka czasu {DOPELNIACZ.get(p['z'][0], p['z'][0])}: "
                                 f"{A.mmss(p['z'][3])} → {A.mmss(p['na'][3])}"))
            else:
                kroki.append((p, f"zmiana {DOPELNIACZ.get(p['z'][0], p['z'][0])} na "
                                 f"{A.RODZAJE.get(p['na'][0], p['na'][0]).lower()}"))
        if zy["usuniecie"]:
            kroki.append((zy["usuniecie"], f"usunięcie {DOPELNIACZ.get(zy['rodzaj'], zy['rodzaj'])} ({zy['czas_meczu']})"))
        if zy["przeniesienie"]:
            kroki.append((zy["przeniesienie"], f"przeniesienie {DOPELNIACZ.get(zy['rodzaj'], zy['rodzaj'])} na {zy['przeniesienie']['na']}"))
        for ch, tekst in kroki:
            if zy["rodzaj"] in A.BRAMKI and tekst.startswith("wpisanie"):
                continue  # zwykłe dopisanie bramki to nie edycja
            klucz = f"{ch['autor']}|{ch['urzadzenie']}"
            e = edytorzy.setdefault(klucz, {"autor": ch["autor"], "rola": ch["rola"],
                                            "urzadzenie": ch["urzadzenie"],
                                            "numer": ch["numer_sedziego"], "czynnosci": []})
            e["czynnosci"].append((A.czas_utc(ch["czas"]), A.godz(ch["czas"]), tekst))
    for e in edytorzy.values():
        e["czynnosci"] = [(g, t) for _ts, g, t in sorted(e["czynnosci"], key=lambda x: x[0])]

    # ── droga protokołu po meczu
    droga: List[Dict[str, Any]] = []
    for w in zrzut.get("dziennik") or []:
        if w.get("event") not in DROGA:
            continue
        kto = w.get("actor_name") or w.get("actor_judge_id") or "?"
        x = {"czas": w.get("created_at"), "co": DROGA[w["event"]], "kto": kto,
             "rola": rola(kto, role), "zdarzenie": w["event"]}
        t = A.czas_utc(x["czas"])
        if droga:
            ost = droga[-1]
            blisko = t and A.czas_utc(ost["czas"]) and (t - A.czas_utc(ost["czas"])).total_seconds() < 60
            # Ten sam wpis dwa razy (znacznik pola i zdarzenie wysyłki) - zostaje jeden.
            if blisko and ost["zdarzenie"] == x["zdarzenie"] and ost["kto"] == kto:
                continue
            # „Zakończ - wznów - zakończ" w jednej minucie to jedno zakończenie meczu.
            if blisko and ost["zdarzenie"] == "match.reopened" and x["zdarzenie"] == "match.finished":
                droga.pop()
                continue
        droga.append(x)
    zatwierdzenie = next((x for x in reversed(droga) if x["zdarzenie"] == "match.approved"), None)
    cofniecia = [x for x in droga if x["zdarzenie"] in ("match.unapproved", "match.restored",
                                                         "match.overwritten_by_choice")]

    # ── obsada z protokołu (do stopki i do ról)
    cfg = A.konfiguracja(blob)
    obsada = [(ROLE[k], str(cfg.get(k) or "").strip()) for k in ROLE if str(cfg.get(k) or "").strip()]

    pdf = baza["pdf"]
    return {
        "mecz": baza["mecz"],
        "osoba": osoba,
        "zyciorysy": zyciorysy,
        "usuniete": usuniete,
        "glowne": glowne,
        "po_usunieciu": po_usunieciu,
        "kontekst": kontekst,
        "usuniec_w_meczu": len(wszystkie_usuniecia),
        "inne_korekty": dict(inne_korekty),
        "edytorzy": list(edytorzy.values()),
        "droga": droga,
        "zatwierdzenie": zatwierdzenie,
        "cofniecia": cofniecia,
        "obsada": obsada,
        "pdf": pdf,
        "zrodla": baza["zrodla"],
        "wynik_koncowy": wynik_koncowy,
    }
