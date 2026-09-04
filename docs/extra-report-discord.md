# Dodatkowy raport PDF na Discordzie

Discord przyjmuje plik PDF przez Execute Webhook: `multipart/form-data`,
`payload_json` z opisem oraz `files[0]` z plikiem. `wait=true` zwraca
potwierdzoną wiadomość z identyfikatorem.

Dokumentacja: [Execute Webhook](https://docs.discord.com/developers/resources/webhook#execute-webhook)
i [Uploading Files](https://docs.discord.com/developers/reference#uploading-files).

## Uruchomienie

1. Wdróż backend. Przy starcie `app/db.py` dodaje idempotentnie kolumnę
   `discord_webhook_url` w `extra_report_recipients` i
   `extra_report_province_recipients`. Istniejące adresy e-mail pozostają.
2. W nowej wersji BAZY otwórz panel administratora → dodatkowy raport.
3. Edytuj grupę ligową lub okręg. W polu „Kopia PDF na Discordzie” wklej
   webhook wybranego kanału i zapisz. Można skonfigurować sam Discord bez e-maila.
4. W szczegółach lub podsumowaniu prawdziwego meczu otwórz dodatkowy raport.
   Przed generowaniem pojawią się nazwy skonfigurowanych celów Discorda.
5. „Generuj raport” zapisuje treść, składa PDF i wysyła jego kopię przez backend.
   Ekran wyniku pokazuje potwierdzenie lub informację o niedostarczonych kopiach.
   „Wyślij mailem” nadal otwiera pocztę sędziego z tym samym plikiem.

Puste pole webhooka wyłącza automatyczną kopię dla danej grupy/okręgu.
Żadne adresy webhooków nie są zaszyte w kodzie. Wysyłanie nie wymaga bota.
Webhook forum wymaga istniejącego wątku: dopisz `?thread_id=NUMER_WĄTKU`.

## Dobór odbiorców

- Wszystkie grupy obejmujące kategorię meczu oraz okręg prowadzący rozgrywki
  otrzymują kopię, jeśli mają skonfigurowany webhook.
- Okręg dochodzi tylko dla kategorii okręgowych (II liga, III liga, młodzież).
  Backend odczytuje go przez zapisany identyfikator ZPRP meczu. Nie zgaduje go
  po numerze spotkania ani po województwie klubu.
- Identyczny webhook w grupie i okręgu dostaje jedną wiadomość przy danym
  generowaniu. Osobne wątki tego samego kanału są osobnymi celami.
- Jeżeli nie uda się odczytać okręgu, wysyłane są dostępne kopie grup ligowych.
  Ekran ostrzega o braku kopii okręgowej, jeśli istnieje konfiguracja okręgowa.
- Raporty testowe (`localOnly`), treść inline i brak zapisanej wersji raportu
  nigdy nie uruchamiają wysyłki.

## Transport i wynik

Wzorzec jak przy backupie i dziennym stanie BAZY Beach: serwerowy webhook,
kolorowy embed, własny User-Agent, timeout oraz osobne logowanie powodzenia
lub błędu. Blokujące wywołanie HTTP działa przez `asyncio.to_thread`.
Jednocześnie wysyłane są maksymalnie cztery kopie w ramach żądania.

Załącznik jest dokładnie tym PDF-em, który klient otrzymuje w `pdfBase64`.
Nie wysyłamy linku do jednorazowego pobrania. Aplikacyjny limit pliku wynosi
10 MiB; każdy POST ma timeout 10 sekund.

Odpowiedź generowania zawiera `discord.status`:

| Status | Znaczenie |
| --- | --- |
| `disabled` | Brak pasujących webhooków. |
| `skipped` | Test, treść inline lub starszy klient bez kategorii. |
| `sent` | Wszystkie wybrane kopie potwierdzone przez Discord. |
| `partial` | Tylko część kopii potwierdzona. |
| `failed` | Wysyłka odrzucona albo brak potwierdzenia. |

`deliveries` zawiera nazwę celu, status i identyfikator wiadomości przy sukcesie.
Opcjonalne `warning` wyjaśnia np. nieustalony okręg. Błąd wysyłki nie zmienia
wyniku generowania w błąd i nie odbiera możliwości pobrania PDF czy wysyłki mailowej.

Każde kolejne świadome wygenerowanie raportu jest nową wysyłką, również dla
niezmienionej treści. Nie ma trwałej kolejki ani automatycznych ponowień POST:
przy timeout wiadomość mogła już dotrzeć. Przed ponownym generowaniem po
niepotwierdzonej wysyłce warto sprawdzić kanał. Przerwanie procesu backendu
może przerwać nieukończone wysyłki.

## Konfiguracja i zgodność

`discordWebhookUrl` jest opcjonalnym polem adminowych GET/PUT grup i okręgów.
Brak pola lub `null` w zapisie zachowuje dotychczasowy webhook; `""` usuwa go.
Grupa usunięta z konfiguracji traci także webhook. Starszy panel pomijający
okręgi bez maili nie usuwa ich webhooków; nowy panel przesyła jawne puste pola.

Publiczny endpoint adresatów oddaje tylko `discordDestinations` (nazwy)
i `discordProvinceUnresolved`. URL z tokenem jest dostępny tylko w konfiguracji
admina oraz transporcie backendu. Walidacja dopuszcza wyłącznie webhooki HTTPS
Discorda, a transport odrzuca przekierowania. Logi nie zawierają URL/tokena
ani odpowiedzi HTTP mogących go ujawnić. `allowed_mentions: {parse: []}`
wyłącza oznaczanie osób i ról przez treść raportu.

Nowy klient przesyła `category` i `localOnly` do endpointu generowania PDF.
Starszy backend zignoruje nowe pola; nowa aplikacja toleruje brak `discord`
w odpowiedzi. Starszy klient na nowym backendzie generuje plik bez kopii Discord.

## Diagnostyka zapisu 422

Sam wpis `PUT /admin/extra-report/recipients ... 422` nie wskazuje przyczyny.
Zapis konfiguracji nie wysyła niczego na Discord, więc nie jest to odpowiedź
Discorda na próbę wysłania PDF. Błąd może dotyczyć dowolnej grupy w przesłanej
liście albo kształtu całego żądania, nie tylko właśnie edytowanego webhooka.

Panel odczytuje zarówno `error` (koperta HTTPException z `main.py`), jak i
`detail` (walidacja FastAPI), a komunikat zostaje przy przycisku zapisu.
Backend loguje `Extra report webhook rejected` z przyczyną walidacji URL lub
`Extra report config validation rejected` z polem i typem błędu modelu.
Żaden z tych wpisów nie zawiera tokena, body ani wejściowych wartości pól.
Nieudany zapis nie usuwa poprzedniej konfiguracji.

Pełny adres Discord z liczbowym ID i tokenem jest obsługiwany także z wersją
API oraz parametrami `wait`, `thread_id` i `with_components`. Ostatni parametr
nie wpływa na raport bez komponentów; `wait=true` ustawiamy przy wysyłce PDF.

## Testy bez zewnętrznych wysyłek

```sh
python -m pytest tests/test_extra_report_discord.py tests/test_extra_report_discord_flow.py tests/test_extra_report_province.py tests/test_extra_report_pdf.py tests/test_extra_report_signatures.py -q
```

Testy sprawdzają multipart z rzeczywistymi bajtami pliku, dobór odbiorców,
konfigurację bez maila, zgodność starych zapisów, brak wycieku sekretów,
pomijanie testów, timeout, częściową wysyłkę i zachowanie gotowego PDF przy błędzie.
Transport Discord i API ZPRP są zastępowane atrapami, baza przepływu jest w pamięci.
