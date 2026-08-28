"""Zapis obsady do ZPRP - jedyna droga zapisu w aplikacji.

Trzy rzeczy, których pilnują te testy, to trzy sposoby, na jakie ten zapis
potrafi udać się POZORNIE:

* bez pola `akcja_edycja` ZPRP oddaje poprawną stronę i nie zapisuje nic,
* `value` opcji nie jest stałym numerem sędziego, więc wartość z jednego widoku
  filtra wskazuje kogo innego w drugim,
* odpowiedź trzeba przeczytać, bo status 200 nie znaczy, że zmiana weszła.

Warstwa HTTP jest podmieniona - te testy sprawdzają nasze reguły, a nie ZPRP.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

import pytest

from app.zprp import assignments as A

SELECTS = [
    "NrSedzia_pierwszy",
    "NrSedzia_drugi",
    "NrSedzia_delegat",
    "NrSedzia_delegat2",
    "NrSedzia_sekretarz",
    "NrSedzia_czas",
]


def form_html(selected: Dict[str, str], options: Dict[str, List[Tuple[str, str]]]) -> str:
    """Minimalny formularz `zawody_UstawSedziow.php`.

    `options` to `{pole: [(value, nazwisko), ...]}`, `selected` to `{pole: value}`.
    """
    parts = ['<html><body><input type="hidden" name="IdZawody" value="208136">']
    for name in SELECTS:
        parts.append(f'<select name="{name}">')
        parts.append('<option value="">--- ---</option>')
        for value, label in options.get(name, []):
            mark = " selected" if selected.get(name) == value else ""
            parts.append(f'<option value="{value}"{mark}>{label}</option>')
        parts.append("</select>")
    parts.append("</body></html>")
    return "".join(parts)


class FakeHttp:
    """Podstawka pod `fetch_with_correct_encoding`.

    Pierwsze wywołanie oddaje formularz wyjściowy, drugie - odpowiedź po
    zapisie. Zapamiętuje wysłane dane, bo to one są tu przedmiotem badania.
    """

    def __init__(self, first: str, second: str | None = None):
        self.pages = [first, second if second is not None else first]
        self.calls: List[Dict[str, Any]] = []

    async def __call__(self, client, path, method="GET", data=None, cookies=None, **kw):
        self.calls.append({"path": path, "data": dict(data or {})})
        page = self.pages[min(len(self.calls) - 1, len(self.pages) - 1)]
        return None, page

    @property
    def submitted(self) -> Dict[str, Any]:
        assert len(self.calls) >= 2, "nie doszło do wysyłki formularza"
        return self.calls[1]["data"]


BASE_OPTIONS = {
    name: [("1", "NOWAK Jan"), ("2", "KOWALSKI Piotr"), ("3", "MAZUR Adam")]
    for name in SELECTS
}


@pytest.fixture
def http(monkeypatch):
    def install(first: str, second: str | None = None) -> FakeHttp:
        fake = FakeHttp(first, second)
        monkeypatch.setattr(A, "fetch_with_correct_encoding", fake)
        return fake

    return install


async def apply(changes, **kw):
    return await A.apply_referee_assignment(None, {}, "208136", changes, **kw)


@pytest.mark.asyncio
async def test_submit_carries_the_save_button(http):
    fake = http(form_html({"NrSedzia_pierwszy": "1"}, BASE_OPTIONS))
    await apply({"NrSedzia_pierwszy": ("2", "KOWALSKI Piotr")})

    # Bez tego pola ZPRP odświeża filtr i nie zapisuje niczego.
    assert fake.submitted["akcja_edycja"] == "ZAPISZ ZMIANY"
    assert fake.submitted["akcja"] == "UstawSedziow"
    assert fake.submitted["IdZawody"] == "208136"


@pytest.mark.asyncio
async def test_value_is_resolved_from_the_name_not_trusted(http):
    # Telefon przysyła wartość z widoku, w którym KOWALSKI miał numer 9.
    # Na świeżo wczytanym formularzu ten sam sędzia stoi pod numerem 2.
    fake = http(form_html({"NrSedzia_pierwszy": "1"}, BASE_OPTIONS))
    await apply({"NrSedzia_pierwszy": ("9", "KOWALSKI Piotr")})

    assert fake.submitted["NrSedzia_pierwszy"] == "2"


@pytest.mark.asyncio
async def test_untouched_slots_keep_their_values(http):
    # Wysłanie samego zmienionego pola skasowałoby resztę obsady.
    fake = http(
        form_html(
            {"NrSedzia_pierwszy": "1", "NrSedzia_drugi": "3", "NrSedzia_czas": "2"},
            BASE_OPTIONS,
        )
    )
    await apply({"NrSedzia_pierwszy": ("2", "KOWALSKI Piotr")})

    assert fake.submitted["NrSedzia_drugi"] == "3"
    assert fake.submitted["NrSedzia_czas"] == "2"


@pytest.mark.asyncio
async def test_success_only_when_the_response_confirms_the_name(http):
    before = form_html({"NrSedzia_pierwszy": "1"}, BASE_OPTIONS)
    after = form_html({"NrSedzia_pierwszy": "2"}, BASE_OPTIONS)
    http(before, after)

    out = await apply({"NrSedzia_pierwszy": ("2", "KOWALSKI Piotr")})
    assert out["success"] is True
    assert out["verified_slots"]["sedzia1"]["name"] == "KOWALSKI Piotr"


@pytest.mark.asyncio
async def test_unconfirmed_save_is_a_failure(http):
    # Odpowiedź pokazuje starą obsadę - status 200 tego nie ratuje.
    before = form_html({"NrSedzia_pierwszy": "1"}, BASE_OPTIONS)
    http(before, before)

    out = await apply({"NrSedzia_pierwszy": ("2", "KOWALSKI Piotr")})
    assert out["success"] is False
    assert out["code"] == "VERIFICATION_FAILED"


@pytest.mark.asyncio
async def test_guard_refuses_when_the_slot_changed_owner(http):
    # Giełda: mecz wystawił NOWAK, ale w bazie związku siedzi już MAZUR.
    fake = http(form_html({"NrSedzia_pierwszy": "3"}, BASE_OPTIONS))

    out = await apply(
        {"NrSedzia_pierwszy": ("2", "KOWALSKI Piotr")},
        expect=("NrSedzia_pierwszy", "NOWAK Jan"),
    )

    assert out["success"] is False
    assert out["code"] == "SLOT_CHANGED"
    assert "MAZUR Adam" in out["error"]
    # Kluczowe: NIE doszło do wysyłki. Cudza decyzja jest świeższa niż nasza.
    assert len(fake.calls) == 1


@pytest.mark.asyncio
async def test_guard_passes_when_the_owner_matches(http):
    before = form_html({"NrSedzia_pierwszy": "1"}, BASE_OPTIONS)
    after = form_html({"NrSedzia_pierwszy": "2"}, BASE_OPTIONS)
    fake = http(before, after)

    out = await apply(
        {"NrSedzia_pierwszy": ("2", "KOWALSKI Piotr")},
        expect=("NrSedzia_pierwszy", "NOWAK Jan"),
    )

    assert out["success"] is True
    assert len(fake.calls) == 2


@pytest.mark.asyncio
async def test_guard_ignores_case_and_spacing(http):
    before = form_html({"NrSedzia_czas": "1"}, BASE_OPTIONS)
    after = form_html({"NrSedzia_czas": "2"}, BASE_OPTIONS)
    http(before, after)

    out = await apply(
        {"NrSedzia_czas": ("2", "KOWALSKI Piotr")},
        expect=("NrSedzia_czas", "  nowak   jan "),
    )
    assert out["success"] is True


@pytest.mark.asyncio
async def test_missing_name_falls_back_to_the_sent_value(http):
    # Nazwiska nie ma wśród opcji - jedzie wartość, ale to jest ostatnia deska
    # ratunku, a nie normalna droga. Log ostrzega, wynik i tak przejdzie
    # weryfikację albo nie.
    before = form_html({"NrSedzia_drugi": "1"}, BASE_OPTIONS)
    fake = http(before, before)

    await apply({"NrSedzia_drugi": ("3", "KTOŚ SPOZA LISTY")})
    assert fake.submitted["NrSedzia_drugi"] == "3"


@pytest.mark.asyncio
async def test_unknown_name_must_not_clear_the_slot(http):
    """Najgroźniejszy przypadek w całym module.

    Giełda nie zna numeru opcji, więc wysyła samo nazwisko i pustą wartość.
    Pusta wartość w formularzu ZPRP nie znaczy „zostaw", tylko „wyczyść
    gniazdo" - sędzia, którego związek nie dopuszcza do tych rozgrywek,
    skasowałby obsadę zamiast ją przejąć.
    """
    fake = http(form_html({"NrSedzia_pierwszy": "1"}, BASE_OPTIONS))

    out = await apply(
        {"NrSedzia_pierwszy": ("", "SPOZA LISTY Ktoś")},
        require_name_match=True,
    )

    assert out["success"] is False
    assert out["code"] == "NAME_NOT_IN_OPTIONS"
    # Nie doszło do wysyłki, więc w bazie związku nic się nie zmieniło.
    assert len(fake.calls) == 1


@pytest.mark.asyncio
async def test_known_name_passes_with_the_guard_on(http):
    before = form_html({"NrSedzia_pierwszy": "1"}, BASE_OPTIONS)
    after = form_html({"NrSedzia_pierwszy": "2"}, BASE_OPTIONS)
    fake = http(before, after)

    out = await apply(
        {"NrSedzia_pierwszy": ("", "KOWALSKI Piotr")},
        require_name_match=True,
    )

    assert out["success"] is True
    assert fake.submitted["NrSedzia_pierwszy"] == "2"


@pytest.mark.asyncio
async def test_assigner_module_keeps_its_fallback(http):
    # Moduł obsadowego podaje wartość z formularza, który sam oglądał - tam
    # zapas ma sens i zostaje.
    before = form_html({"NrSedzia_drugi": "1"}, BASE_OPTIONS)
    fake = http(before, before)

    await apply({"NrSedzia_drugi": ("3", "KTOŚ SPOZA LISTY")})
    assert fake.submitted["NrSedzia_drugi"] == "3"
