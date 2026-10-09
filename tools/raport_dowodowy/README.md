# Raport z historii zapisu meczu (raport dowodowy)

Narzędzie administratora. Zbiera pełny zapis meczu ProEl (każdą wersję protokołu,
dziennik, spory wersji, kosz, wygenerowane PDF-y), zapisuje go lokalnie z sumą
SHA-256 i robi z niego raport PDF: kto, kiedy i co zmienił, z ustaleniami
zapisanymi zdaniami.

Raport mówi, co zapisano. Nie ocenia, czy zmiana była słuszna.

## Użycie (z katalogu `zprp-backend`)

```powershell
# raport o jednej osobie (nazwisko albo numer + drużyna)
python tools\raport_dowodowy\raport.py SK/24 --nazwisko NOSEK --autor "Imię Nazwisko"
python tools\raport_dowodowy\raport.py SK/24 --zawodnik 39 --druzyna goscie

# raport o całym meczu (wszystkie korekty przebiegu)
python tools\raport_dowodowy\raport.py SK/24

# sam zrzut - gdy historia zaraz wygaśnie, a raport zrobisz później
python tools\raport_dowodowy\raport.py SK/24 --tylko-zrzut

# raport z zapisanego wcześniej zrzutu albo z teczki pobranej z Dziennika meczu
python tools\raport_dowodowy\raport.py --z-pliku ..\output\raporty_dowodowe\SK-24_...\zrzut.json.gz --nazwisko NOSEK
python tools\raport_dowodowy\raport.py --z-pliku teczka_SK-24_nr1.json.gz --nazwisko NOSEK
```

Wyniki trafiają do `BAZA_ALL\output\raporty_dowodowe\<mecz>_<data>\`:
`zrzut.json.gz` (materiał źródłowy), `zrzut.sha256.txt`, `RD-....html` i `RD-....pdf`.
PDF drukuje Edge albo Chrome bez okna. Wystarczy sam Python, bez dodatkowych pakietów.

## Gdy `railway ssh` nie chce ruszyć z Pythona

Zrób zrzut ręcznie i podaj plik tekstowy:

```powershell
$b = [Convert]::ToBase64String([IO.File]::ReadAllBytes("tools\raport_dowodowy\zrzut.py"))
railway ssh -s zprp-backend "echo $b | base64 -d | python - SK/24" > zrzut_SK24.txt
python tools\raport_dowodowy\raport.py --z-pliku zrzut_SK24.txt --nazwisko NOSEK
```

## Ważne

- Zwykłe wersje protokołu serwer trzyma **7 dni**, kamienie milowe 90 dni.
  Mecz, który może być sprawą, oznacz w panelu jako **materiał dowodowy**
  (Dziennik meczu, karta „Materiał dowodowy”). Wtedy nic z jego historii nie
  wygasa, a pełny zapis leży w teczkach na serwerze.
- `zrzut.py` działa w kontenerze w sesji bazy READ ONLY. Niczego nie zapisuje.
- Format teczki z panelu i zrzutu z tego narzędzia jest ten sam.
