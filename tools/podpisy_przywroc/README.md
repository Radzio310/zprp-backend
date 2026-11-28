# Przywrócenie podpisów protokołu (ProEl)

Narzędzie administratora na sytuację z SM/61 (28.11.2026): podpisy sekretarza,
mierzącego czas i delegata zebrano, wysłano na serwer, a w protokole ich nie ma.

Działa bez wdrażania backendu: skrypt jedzie do kontenera przez `railway ssh`.

## Użycie (z katalogu `zprp-backend`, Railway CLI zalogowane i podpięte do projektu)

```powershell
# 1. Sama diagnoza - NIC nie zmienia. Raport ląduje też w output\podpisy\
python tools\podpisy_przywroc\przywroc.py SM/61

# 2. Przywrócenie - najpierw pokazuje plan, potem pyta (wpisz TAK)
python tools\podpisy_przywroc\przywroc.py SM/61 --zapisz
```

Potem w aplikacji: otwórz podsumowanie meczu (podpisy wskoczą same przez
synchronizację pól), wygeneruj protokół PDF jeszcze raz i podmień załącznik w ZPRP.

## Co pokazuje diagnoza

- **obsada znana serwerowi** - nazwiska i numery sędziów z wiersza stanu. Od nich
  zależy, czy telefon piszący podpis dostał rolę w meczu.
- **rubryki podpisów** - dla każdej rubryki: wpis w overlayu pól, wartość w bieżącej
  treści i KAŻDA zmiana w zapisanych wersjach (migawki serwera, wersje odłożone przy
  sporze), z godziną i autorem wersji. Stąd wiadomo, który obrazek stał w której
  rubryce - bez zgadywania po kolejności składania.
- **dziennik** - podpisy, spory wersji (`match.doc_conflict`), wysyłki do ZPRP, PDF.
- **audyt overlaya** - które zapisy podpisów serwer naprawdę PRZYJĄŁ. Podpis wysłany
  z telefonu, którego tu nie ma, został odrzucony (odpowiedź 200 z polem `rejected`).
- **pliki podpisów** - czy obrazek istnieje na dysku serwera i kiedy dotarł.

## Plan przywrócenia - reguły

- Kandydat dla rubryki = ostatni niepusty podpis, jaki miała w którejkolwiek wersji.
- Rubryka, która ma dziś podpis, nie jest ruszana (chyba że `--nadpisz`).
- Rubryka z PUSTYM wpisem w overlayu (ktoś świadomie skasował podpis) jest pomijana,
  chyba że wskażesz ją wprost: `--tylko official.secretary.signature`.
- Brak pliku obrazka na dysku = nic nie zapisujemy.
- Protokół zatwierdzony wymaga `--mimo-zatwierdzenia`.

Ręczne wskazanie (gdy historia nie wystarcza):

```powershell
python tools\podpisy_przywroc\przywroc.py SM/61 --zapisz `
  --podpis official.secretary.signature=/static/<uuid>.png `
  --tylko official.secretary.signature
```

Ścieżki: `official.<referee1|referee2|secretary|timekeeper|delegate|delegate2>.signature`,
`sig.team.host`, `sig.team.guest`, `medic.signature`.

## Co robi zapis

W jednej transakcji z blokadą wierszy meczu, dla każdej przywracanej rubryki:

1. wpis w overlayu pól (`proel_match_state.fields_json`, `src: "restore"`) - od tej
   chwili serwer nakłada podpis na każdy kolejny pełny zapis z dowolnego telefonu,
2. ten sam adres w bieżącej treści (`proel_matches.data_json`), bez podbijania
   `doc_rev` (telefony nie dostaną arkusza sporu wersji),
3. wpis `match.signed` w dzienniku meczu z `restored: true` i źródłem.

Ponowne uruchomienie niczego nie dubluje: rubryki z podpisem są pomijane.

## Gdy `railway ssh` nie rusza z Pythona

```powershell
python -c "import base64,gzip;print(base64.b64encode(gzip.compress(open('tools/podpisy_przywroc/w_kontenerze.py','rb').read())).decode())" > b64.txt
railway ssh -s zprp-backend "echo $(Get-Content b64.txt) | base64 -d | gunzip | python - SM/61"
```

Migawki zwykłych wersji żyją 7 dni - zrób diagnozę przed upływem tygodnia albo
oznacz mecz w panelu jako **materiał dowodowy** (wtedy nic nie wygasa).
