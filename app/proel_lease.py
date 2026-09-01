"""Kto prowadzi mecz — czysta arytmetyka leasingu, bez bazy.

Wydzielone z `app/proel.py` z jednego konkretnego powodu: `app.proel` ciągnie
za sobą `app.db`, a ten przy imporcie zakłada tabele — czyli test tej logiki
wymagałby żywej bazy. Reguła „kto może pisać w trakcie meczu" jest zbyt
kosztowna w skutkach (dwa protokoły jednego meczu), żeby zostać bez testów.

Zegarem porządkującym w całym systemie jest Postgres. Tutaj używamy zegara
procesu wyłącznie do policzenia MOMENTU WYGAŚNIĘCIA, który zaraz potem zapisuje
się do bazy — nigdy do porównywania czasów pochodzących z różnych urządzeń.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

#: Zwykły leasing aplikacji: 90 s, bicie serca co 25 s.
LEASE_TTL_SECONDS = 90
#: Aplikacja w tle bije rzadziej — wtedy wydłużamy okno, żeby zminimalizowana
#: aplikacja prowadzącego nie oddawała meczu po półtorej minuty.
LEASE_TTL_BACKGROUND_SECONDS = 300
#: Leasing-widmo obejmowany za starą aplikację. Dłuższy, bo stary klient pisze
#: co 60 s i nie ma czym bić serca — dwa przegapione zapisy nie mogą oddać
#: meczu komuś innemu.
LEGACY_LEASE_TTL_SECONDS = 180


def may_open_state_on_lease(action: str) -> bool:
    """Czy brak wiersza stanu wolno naprawić zamiast odmawiać.

    `POST /proel/lease` odpowiadał 404, gdy wiersza stanu nie było, i kazał
    zawołać najpierw `/proel/ensure`. Ekran meczu tego nie robił - `/ensure`
    wołała wyłącznie konfiguracja, i to dopiero przy pierwszej zmianie pola
    współdzielonego. Mecz poprowadzony bez tknięcia żadnego z nich nie zostawiał
    na serwerze śladu prowadzenia, a reszta obsady widziała „Rozegraj w ProElu"
    dla meczu, który właśnie trwał.

    Nowa aplikacja zakłada ten wiersz sama, ale te w polu jeszcze długo nie -
    a skutkiem są dwa protokoły jednego meczu. `acquire` ZNACZY „zaczynam
    prowadzić", więc zakładamy wiersz na miejscu. Bicie serca zostaje przy
    odmowie: przedłużanie leasingu, którego nikt nie objął, nie ma sensu, a
    klient odpowiada na 404 objęciem od nowa.
    """
    return action == "acquire"


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _as_aware(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime) and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def lease_active(state: Optional[Dict[str, Any]]) -> bool:
    until = _as_aware((state or {}).get("lease_until"))
    return until is not None and until > now_utc()


#: Bicie serca trafiło we własny, żywy leasing - tylko go przedłużamy.
HEARTBEAT_OK = "ok"
#: Leasing wygasł i NIKT go nie ma - prowadzący wraca do swojego meczu.
HEARTBEAT_RECLAIM = "reclaim"
#: Mecz prowadzi teraz kto inny - dopiero to jest utrata prowadzenia.
HEARTBEAT_LOST = "lost"


def heartbeat_decision(
    *,
    held: bool,
    mine: bool,
    epoch: int,
    claimed_epoch: Optional[int],
) -> str:
    """Co zrobić z biciem serca prowadzącego.

    Rozróżnienie, którego wcześniej nie było: **wygaśnięcie to nie przejęcie**.

    Leasing żyje 90 s, a bicie serca idzie co 25 s - ale tylko dopóki telefon
    liczy czas. Wygaszony ekran albo przełączenie na inną aplikację usypia ten
    interwał, więc prowadzenie gaśnie samo. Serwer odpowiadał wtedy tym samym
    412 co przy prawdziwym przejęciu i sędzia dostawał pełnoekranowe „mecz
    prowadzi teraz ktoś inny", choć nikt niczego nie tknął.

    Skoro leasingu nie ma NIKT, nie ma też kogo skrzywdzić: prowadzący wraca do
    swojego meczu dokładnie tak, jak zrobiłby to `acquire` (patrz gałąź
    `not held` w `/proel/lease`).

    Niezgodna epoka przy żywym, własnym leasingu zostaje utratą: to znaczy, że
    prowadzenie obejęła druga sesja na tym samym urządzeniu i stara musi zamilknąć.
    """
    if held and not mine:
        return HEARTBEAT_LOST
    if not held:
        return HEARTBEAT_RECLAIM
    if claimed_epoch is not None and int(claimed_epoch) != int(epoch):
        return HEARTBEAT_LOST
    return HEARTBEAT_OK


def same_judge_lease(state: Optional[Dict[str, Any]], actor_judge_id: str) -> bool:
    """Czy leasing trzyma TEN SAM sędzia — to samo albo inne jego urządzenie.

    Po to, żeby przesiadka na drugi telefon nie wymagała czekania, aż wygaśnie
    leasing sprzed przesiadki. Blokada istnieje przeciwko dwóm OSOBOM piszącym
    jeden protokół; jedna osoba z dwóch swoich urządzeń to nie ten przypadek.

    Warunek jest celowo wąski:
      • `lease_kind == "app"` — leasing-widmo obejmowane za starą aplikację nie
        wie, kto go trzyma, i nie wolno go przypisać nikomu,
      • niepusty numer po OBU stronach — puste równe pustemu uznałoby każdego
        za właściciela cudzego leasingu.
    """
    jid = str(actor_judge_id or "").strip()
    holder = str((state or {}).get("lease_judge_id") or "").strip()
    if not jid or not holder or holder != jid:
        return False
    return (state or {}).get("lease_kind") == "app"


def legacy_lease_values(
    state: Dict[str, Any], writer_install: str
) -> Optional[Dict[str, Any]]:
    """Pola leasingu-widma dla zapisu ze starej aplikacji, albo `None`.

    Stara wersja aplikacji nigdy nie zawoła `/lease`, więc mecz przez nią
    prowadzony wyglądałby dla nowej aplikacji na nieprowadzony przez nikogo —
    i nowa aplikacja weszłaby w niego bez ostrzeżenia. Widmo obejmujemy za nią
    przy zapisie bloba.

    `None` znaczy „nie ruszamy leasingu": prowadzenie objął ktoś świadomie i to
    on nim rozporządza.
    """
    writer = str(writer_install or "")
    mine = (
        state.get("lease_kind") == "legacy"
        and str(state.get("lease_install") or "") == writer
    )
    if not mine and lease_active(state):
        return None

    values: Dict[str, Any] = {
        "lease_install": writer,
        "lease_judge_id": "",
        "lease_name": "",
        "lease_kind": "legacy",
        "lease_until": now_utc() + timedelta(seconds=LEGACY_LEASE_TTL_SECONDS),
    }
    # Epokę podbijamy tylko przy OBJĘCIU widma — przedłużenie własnego nie może
    # unieważniać niczyjego bicia serca.
    if not mine:
        values["lease_epoch"] = int(state.get("lease_epoch") or 0) + 1
    return values


def lease_view(
    state: Optional[Dict[str, Any]],
    actor_install: str,
    actor_judge_id: str = "",
) -> Dict[str, Any]:
    """Kto trzyma prowadzenie - i czy to przypadkiem nie pytający.

    TOŻSAMOŚĆ WYCHODZI STĄD ZAWSZE, TAKŻE PRZY ODDANYM LEASINGU.
    To nie jest ozdoba, tylko naprawa konkretnej usterki. Aplikacja uznaje mecz
    za prowadzony na żywo także wtedy, gdy leasingu nie ma NIKT, ale pełny
    autozapis jest świeży (`hasRecentProelAutosave` w `utils/proelRoute.ts`) -
    autozapis idzie co 60 s, a okno świeżości ma 120 s. Wcześniej oddanie
    leasingu kasowało `lease_install`, więc odpowiedź nie miała już czym
    udowodnić, że tym ostatnim prowadzącym jest sam pytający: `is_you`
    i `same_judge` przychodziły puste, aplikacja czytała to jako „prowadzi ktoś
    inny" i pokazywała sędziemu podgląd JEGO WŁASNEGO meczu, z którego przed
    chwilą wyszedł.

    Sygnał obecności przeżywał oddanie leasingu, a tożsamość nie - a jedno bez
    drugiego zawsze wskaże obcego.
    """
    if not state:
        return {"held": False}
    until = _as_aware(state.get("lease_until"))
    is_you = bool(actor_install and state.get("lease_install") == actor_install)
    identity = {
        "kind": state.get("lease_kind") or "app",
        "name": state.get("lease_name") or "",
        "judge_id": state.get("lease_judge_id") or "",
        "epoch": int(state.get("lease_epoch") or 0),
        "until": until.isoformat() if until is not None else None,
        "is_you": is_you,
        "same_judge": is_you or same_judge_lease(state, actor_judge_id),
    }
    if until is None:
        # Leasing ODDANY przy wyjściu z meczu. Nikt go nie trzyma, ale wiadomo,
        # kto trzymał go ostatni - i to musi dojść do aplikacji.
        return {"held": False, "expired": False, **identity}
    if until <= now_utc():
        # Tożsamość ostatniego prowadzącego nadal jest potrzebna, gdy heartbeat
        # na chwilę wygaśnie, ale pełny autosave pozostaje świeży.
        return {"held": False, "expired": True, **identity}
    return {"held": True, **identity}
