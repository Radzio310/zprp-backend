"""Alarmy meczu - usunięte i przeniesione kary, i które z nich są podejrzane.

Liść bez bazy i bez sieci. Wejście to zrzut meczu (ten sam format co teczka
dowodowa), wyjście: lista znalezisk na osobę i poziom całego meczu.

DWA POZIOMY, bo nie każde usunięcie kary jest podejrzane (decyzja 09.10.2026):

* „uwaga" - każda usunięta albo przeniesiona kara (także upomnienie i Kd).
  Stolik poprawia pomyłki i to jest normalna praca - plakietka w Dzienniku,
  bez powiadomienia.
* „podejrzane" - kara stała w protokole na tyle długo, że to nie była
  poprawka „na gorąco" (co najmniej `PROG_S` albo w międzyczasie doszły inne
  zdarzenia), I do tego była wykluczająca (III kara, czerwona, niebieska)
  albo osoba, której ją zdjęto, rzuciła potem bramkę. Tylko to idzie pushem
  do administratorów.

Kara usunięta i wpisana ponownie (cofnij - powtórz) nie jest alarmem.
Wzorzec przypadku: SK/24, 07.10.2026 - III kara nr 39 stała 10 min 35 s,
zniknęła przy remisie, 14 s później bramka tej samej zawodniczki.
"""
from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional, Tuple

from . import analiza as A
from .dossier import DOPELNIACZ, dossier, osoba_towarzyszaca

#: Ile sekund kara musi stać w protokole, żeby jej usunięcie nie było „na gorąco".
PROG_S = 60

POZIOMY = {"podejrzane": 2, "uwaga": 1}


def _pierwszy_zapis(migawki: List[Dict[str, Any]]) -> Dict[Tuple, Any]:
    out: Dict[Tuple, Any] = {}
    for m in migawki:
        if isinstance(m.get("payload"), dict):
            t = A.czas_utc(m.get("created_at"))
            for e in A.przebieg(m["payload"]):
                out.setdefault(A.klucz_zdarzenia(e), t)
    return out


def osoby_ze_zmianami(zrzut: Dict[str, Any]) -> List[Tuple[str, str]]:
    """(drużyna, numer) każdej osoby, której karę usunięto albo przeniesiono."""
    out: List[Tuple[str, str]] = []
    for _pm, _m, rem, add, _pb, _b in A.kroki(list(zrzut.get("migawki") or [])):
        if not rem:
            continue
        for z in A.klasyfikuj(rem, add):
            s = z["stare"]
            if z["rodzaj"] in ("usuniete", "osoba") and s and s[0] in A.KARY:
                para = (s[1], s[2])
                if para not in out:
                    out.append(para)
    return out


def _nazwa(blob: Dict[str, Any], druzyna: str, numer: str, nazwisko: str) -> str:
    if nazwisko:
        return f"nr {numer} {nazwisko}"
    if not str(numer).isdigit():
        t = osoba_towarzyszaca(blob, druzyna, numer)
        return t or f"osoba {numer}"
    return f"nr {numer}"


def alarmy_meczu(zrzut: Dict[str, Any]) -> Dict[str, Any]:
    """Znaleziska całego meczu. Nigdy nie rzuca dla osoby bez karty - ma ją pominąć."""
    blob = A._slownik((zrzut.get("mecz") or {}).get("data_json"))
    migawki = list(zrzut.get("migawki") or [])
    koncowe = {A.klucz_zdarzenia(e) for e in A.przebieg(blob)}
    pierwszy = _pierwszy_zapis(migawki)
    osoby_out: List[Dict[str, Any]] = []

    for druzyna, numer in osoby_ze_zmianami(zrzut):
        try:
            d = dossier(zrzut, numer=numer, druzyna=druzyna)
        except ValueError:
            continue
        o = d["osoba"]
        nazwa = _nazwa(blob, druzyna, numer, o.get("nazwisko") or "")
        znaleziska: List[Dict[str, Any]] = []
        for z in d["zyciorysy"]:
            if not z["kara"] or not (z["usuniecie"] or z["przeniesienie"]):
                continue
            # Cofnij - powtórz: ta sama kara (rodzaj i chwila) jest w końcowym protokole.
            if z["usuniecie"] and z["klucz"] in koncowe:
                continue
            koniec = z["usuniecie"] or z["przeniesienie"]
            t0, t1 = A.czas_utc(z["wpis"]["czas"]), A.czas_utc(koniec["czas"])
            trwanie = (t1 - t0).total_seconds() if t0 and t1 else 0.0
            miedzy = sum(1 for k in koncowe if pierwszy.get(k) and t0 and t1 and t0 < pierwszy[k] < t1)
            bramki_po = [b for b in d["zyciorysy"]
                         if b["rodzaj"] in A.BRAMKI and b["w_protokole"] and t1
                         and A.czas_utc(b["wpis"]["czas"]) > t1]
            nie_od_razu = trwanie >= PROG_S or miedzy > 0
            podejrzane = nie_od_razu and (z["wykluczajaca"] or bool(bramki_po))
            rodzaj = ("przeniesiona" if z["przeniesienie"]
                      else "usunieta_wykluczajaca" if z["wykluczajaca"] else "usunieta_kara")
            opis = (f"{'Przeniesiono' if z['przeniesienie'] else 'Usunięto'} "
                    f"{DOPELNIACZ.get(z['rodzaj'], z['opis']).replace('kary', 'karę', 1) if False else A.RODZAJE.get(z['rodzaj'], z['rodzaj'])}"
                    f" z {z['czas_meczu']}")
            znaleziska.append({
                "rodzaj": rodzaj,
                "poziom": "podejrzane" if podejrzane else "uwaga",
                "kara": A.RODZAJE.get(z["rodzaj"], z["rodzaj"]),
                "kara_typ": z["rodzaj"],
                "czas_meczu": z["czas_meczu"],
                "wpisano": z["wpis"]["czas"],
                "usunieto": koniec["czas"],
                "zegar_usuniecia": koniec["zegar"],
                "wynik_przy_usunieciu": koniec["wynik"],
                "kto": koniec["autor"],
                "rola": koniec["rola"],
                "trwanie_s": round(trwanie),
                "zdarzen_w_miedzyczasie": miedzy,
                "bramki_po": [{"czas_meczu": b["czas_meczu"], "wynik": b["wynik_po"].replace("-", ":"),
                               "zapisano": b["wpis"]["czas"], "decydujaca": bool(b.get("decydujaca"))}
                              for b in bramki_po],
                "przeniesiono_na": (z["przeniesienie"] or {}).get("na"),
                "opis": opis,
            })
        if not znaleziska:
            continue
        poziom = max((f["poziom"] for f in znaleziska), key=lambda p: POZIOMY[p])
        osoby_out.append({"druzyna": druzyna, "numer": str(numer), "nazwa": nazwa,
                          "nazwisko": o.get("nazwisko") or "", "poziom": poziom,
                          "znaleziska": znaleziska})

    wszystkie = [(o, f) for o in osoby_out for f in o["znaleziska"]]
    poziom = max((f["poziom"] for _o, f in wszystkie), key=lambda p: POZIOMY[p], default=None)
    glowne = max(wszystkie, key=lambda of: (POZIOMY[of[1]["poziom"]], of[1]["trwanie_s"]), default=None)
    podejrzane = sorted(f"{o['druzyna']}|{o['numer']}|{f['kara_typ']}|{f['czas_meczu']}"
                        for o, f in wszystkie if f["poziom"] == "podejrzane")
    return {
        "poziom": poziom,
        "liczba": len(wszystkie),
        "podejrzanych": len(podejrzane),
        "naglowek": naglowek(*glowne) if glowne else "",
        # Odcisk zbioru podejrzanych znalezisk - push idzie tylko, gdy pojawi się NOWE.
        "odcisk": hashlib.sha1("\n".join(podejrzane).encode("utf-8")).hexdigest()[:16] if podejrzane else "",
        "ostatnie_podejrzane": max((f["usunieto"] for _o, f in wszystkie if f["poziom"] == "podejrzane"),
                                   default=None, key=lambda t: A.czas_utc(t) or 0),
        "osoby": osoby_out,
    }


def _trwanie(s: int) -> str:
    return f"{s // 60} min {s % 60} s" if s >= 60 else f"{s} s"


def naglowek(osoba: Dict[str, Any], f: Dict[str, Any]) -> str:
    """Jedno zdanie do plakietki i do powiadomienia."""
    co = "Przeniesiona" if f["rodzaj"] == "przeniesiona" else "Usunięta"
    tekst = f"{co} {f['kara'].replace('kara', 'kara', 1)} {osoba['nazwa']} ({f['czas_meczu']})"
    if f["trwanie_s"] >= PROG_S:
        tekst += f" po {_trwanie(int(f['trwanie_s']))} w protokole"
    if f["bramki_po"]:
        n = len(f["bramki_po"])
        tekst += f", potem {n} {'bramka' if n == 1 else 'bramki' if n < 5 else 'bramek'}"
        if any(b["decydujaca"] for b in f["bramki_po"]):
            tekst += " (w tym decydująca)"
    return tekst
