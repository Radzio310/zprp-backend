# Plik księgowej - ryczałty sędziowskie do enova365 (04.11.2026)

Księgowa okręgu wczytuje ryczałty do enova z własnego skoroszytu: zakładka
„dane do importu” zasila formułami zakładkę „Import” (kolumny enova). Dane
przepisywała ręcznie z list od Wojtka. Teraz do każdego zestawienia, szkicu
i oficjalnego z Rejestru, BAZA wydaje ten skoroszyt gotowy.

## Skoroszyt

Szablon `app/templates/ksiegowa_ryczalty.xlsx` to jej plik 1:1 bez danych osobowych
(„Import”, „dane do importu”, „Zestaw. umów”, „Uwagi” ze zrzutami enova). Generator
`app/settlement_accounting_excel.py` dokłada na początku zakładkę **„Ryczałty
sędziowskie”**. Dane przechodzą formułami:

```
Ryczałty sędziowskie (wartości z BAZA)  →  dane do importu (formuły)  →  Import (jej formuły)
```

Formuły mają wpisany wynik, więc plik czyta się też w podglądzie na telefonie
i w poczcie. Excel i tak przelicza wszystko przy otwarciu (`fullCalcOnLoad`).

| Kolumna Import | Skąd |
|---|---|
| Pracownik:Kod | słownik kodów okręgu (`province_accounting_codes`) albo podpowiedź z reguły |
| Data | ostatni dzień okresu rozliczenia |
| Opis | numer dokumentu (na szkicu **pusty**, żeby enova nie przyjęła go przez pomyłkę) |
| Okres | okres rozliczenia `dd.mm.rrrr...dd.mm.rrrr` |
| Wartosc | kwota brutto (każda część puli osobno, bo to osobna umowa) |
| reszta | stałe z Ustawień → Księgowość (domyślnie jak w jej pliku) |

## Ustawienia „Księgowość” (`doc_settings.extra_json`)

- `tax_formula`: `baza` (domyślna, jak ekran), `enova` (KUP z groszami, podstawa do zł,
  podatek zawsze równy BAZA) albo `arkusz` (KUP i podstawa z groszami, jak dawne listy).
  Przy ok. 3% kwot `baza` i `arkusz` różnią się o 1 zł (brutto 318 zł: 30 albo 31 zł),
  plik zaznacza takie wiersze.
- `number_scheme`: `season` (`SL/2026_27/14`) albo `calendar` (`14/S/2026`, licznik w roku
  wydania). Każdy wzór ma własny licznik (`register.number_scheme`, nowy indeks
  unikalności); kontynuacja numeracji kalendarzowej leży w `register_settings` pod
  rodzajem `zestawienie@calendar`.
- `show_consent`, `consent_text`: klauzula zgody na samym dole zestawienia.
- `enova`: stałe kolumn zakładki Import.

## Trasy `/province/settlements/accounting`

`GET/PUT /codes`, `POST /preview`, `POST /xlsx`, `GET /download/{token}`. Szkic
przyjmuje te same pola co PDF zestawienia; oficjalny przyjmuje `document_id`
z Rejestru. Data wypłaty zostaje przy dokumencie (`register.accounting_json`).
Zapisy idą przez bramkę panelu Rozliczeń.
