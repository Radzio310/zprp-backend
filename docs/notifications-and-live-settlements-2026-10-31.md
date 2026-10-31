# Powiadomienia i bieżące rozliczenia — 31.10.2026

## Ustalenia z analizy kodu

- Token FCM mógł należeć do kilku instalacji. Jedno urządzenie mogło przez to otrzymać kilka wysyłek tego samego zdarzenia.
- Tożsamość i preferencje z chwili utworzenia kolejki nie były ponownie sprawdzane przed wysyłką. Skrzynka meczowa filtrowała po instalacji, bez bieżącego właściciela konta.
- Klucz zatwierdzenia protokołu zależał od odcisku całego meczu. Niezależne zmiany danych mogły więc rozróżniać powtórzenia tego samego zatwierdzenia.
- Późniejsza rewizja meczu mogła unieważnić wcześniejszą wiadomość dotyczącą innej kategorii. Wspólny wątek powiadomień dodatkowo scalał różne rewizje.
- Panel zapisywał zdarzenia z pominięciem części informacji o kategorii i preferencjach przekazanych przez wspólny klasyfikator.
- Giełda i panel poprawiały `province_matches`, ale rozliczenia czytały osobną tabelę `province_settlement_matches`, aktualizowaną przez pełny przebieg.
- Stary terminarz telefonu mógł dołożyć oddany mecz jako prognozę po usunięciu oficjalnej obsady.

## Powiadomienia po zmianie

Rejestracja tokenu odbywa się w transakcji z blokadą na token. Starsze identyfikatory tego samego tokenu tracą token i tożsamość; inne urządzenia sędziego zachowują swoje rejestracje. Wysyłka natychmiastowa i kolejka uwzględniają aktualnego właściciela tokenu. Kolejka ponownie sprawdza konto, preferencje oraz aktywną obsadę, z wyjątkiem wiadomości o usunięciu meczu.

Zatwierdzenie jest powiązane z cyklem protokołu. Rzeczywiste cofnięcie zatwierdzenia pozwala wygenerować kolejne zatwierdzenie. Niezależne edycje nie tworzą nowego cyklu. Odrębne kategorie zmian zachowują odrębne powiadomienia, a ponowne dostarczenie tego samego zdarzenia ma stały identyfikator.

BAZA serializuje decyzje o prezentacji, zapisuje przedstawione zdarzenia na dysku i pamięta je także w procesie. Sprawdza odbiorcę i bieżące preferencje. Uwzględnia centrum powiadomień iOS oraz otwarcie wiadomości pokazanej w tle. Dane strukturalne FCM są kodowane jako JSON. Skrzynka otwartej aplikacji jest sprawdzana co 30 sekund jako uzupełnienie odbioru push.

Giełda aktualizuje również rejestr obsady monitora, bez ponownego wysyłania informacji już przekazanej odbiorcom giełdy. Monitor odróżnia jednoznaczne zastąpienie numeru sędziego od niepełnej odpowiedzi API; dla brakujących pól zachowuje dotychczasową ostrożność.

Samo `apns-collapse-id` nie jest dziennikiem odbioru w aplikacji. Apple opisuje scalanie i przypisanie identyfikatora żądania tutaj: [APNs](https://developer.apple.com/documentation/usernotifications/sending-notification-requests-to-apns), [UNNotificationRequest.identifier](https://developer.apple.com/documentation/usernotifications/unnotificationrequest/identifier). Obsługa wiadomości przy otwartej aplikacji jest opisana w [dokumentacji Firebase](https://firebase.google.com/docs/cloud-messaging/ios/receive-messages).

## Rozliczenia po zmianie

`app/settlement_live.py` aktualizuje wyłącznie zmieniony mecz po zapisie z giełdy, panelu oraz po zmianie wykrytej przez monitor. Projekcja obsad jest wspólna z pełnym przebiegiem (`_district_rows`). Stawki, podatki, okresy, wyłączenia, nieobecności, podziały i sam silnik rozliczeń pozostają wspólne dla telefonu i WWW.

Ścieżka zapisu korzysta z lokalnych tabel i pamięci odległości. Nie czeka na pełne pobranie ZPRP ani na nowe pomiary Google. Brakujące pomiary są uzupełniane w tle przez istniejący Atlas tras. Do czasu uzyskania pomiaru kwota dojazdu pozostaje nieuzupełniona — odległość nie jest zgadywana.

Aktualizacje bieżące i zapis pełnego przebiegu współdzielą blokadę transakcyjną. Pełny przebieg chroni mecze zaktualizowane po jego rozpoczęciu, również po przejściu między kluczami `d:` i `o:`. Nie odtwarza starego sędziego ani nie usuwa nowego przydziału. Zapisy usunięcia blokują odtworzenie oddanego meczu przez prognozę ze starego terminarza telefonu. Starsza odpowiedź monitora, rozpoczęta przed potwierdzonym zapisem, nie nadpisuje zapisanych pól obsady.

Otwarty ekran rozliczenia BAZA odświeża dane po pushu, powrocie do aplikacji i co 15 sekund podczas aktywnego używania. WWW unieważnia dane po udanym zapisie obsady, hali lub daty i sprawdza widoczne dane co 15 sekund. Odświeżanie korzysta z dotychczasowego cache i deduplikacji zapytań.

## Weryfikacja i wdrożenie

Testy obejmują powtórzenia i równoległy odbiór, iOS z identycznym `apns-collapse-id`, awarię zapisu dziennika, preferencje, zmianę konta, przywrócony token, przekazanie i ponowne przydzielenie meczu oraz zapis starego pełnego przebiegu po wymianie. Zapis rozliczeń i rejestrację tokenów sprawdzono również na lokalnym magazynie SQL; blokady PostgreSQL wymagają sprawdzenia w środowisku integracyjnym.

Kontrola typów BAZA_Web przeszła. Pełna kontrola BAZA wykazała także błędy poza zakresem tej poprawki (m.in. deklaracje bibliotek, komponenty ikon i typ daty tokenu); nie jest czystym sprawdzeniem całego repozytorium.

Wynik końcowy: **592 testy backendu oraz 71 testów BAZA zakończone powodzeniem**. Ograniczona kontrola typów trzech zmienianych modułów mobilnych i ich zależności zgłasza wyłącznie istniejący błąd `context/AuthContext.tsx:318` (`expiresAt: Date` wobec deklarowanego `string`).

Zmiany nie wymagają nowych kolumn ani migracji danych. Wymagają wdrożenia backendu i WWW oraz nowego wydania BAZA. Nie wykonywano wdrożenia produkcyjnego ani prób na fizycznym iPhonie. Ostateczna próba odbioru powinna objąć otwartą aplikację, tło, zimny start, ponowną instalację, zmianę konta i powrót po utracie sieci. Testy lokalne nie stanowią dowodu bezwarunkowego dostarczenia dokładnie raz przez FCM/APNs.
