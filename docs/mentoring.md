# Mentoring — uruchomienie i granice modułu

## Kolejność wdrożenia

1. Wdrożyć backend. Standardowy start `app.db` tworzy tabele mentoringu i uzupełnia kolumny pierwszej synchronizacji. Nie należy importować `app.db` tylko w celu uruchomienia testów — otwiera rzeczywistą bazę.
2. Wdrożyć aplikację. Administrator wchodzi do okręgowego **Więcej → Mentorzy i pary**. Może tworzyć pary bez włączania zarządzania komisji.
3. Dla wybranego okręgu administrator włącza zarządzanie okręgowe. Pusta lista zarządzających oznacza istniejącą odznakę **Komisja sędziowska**; lista niepusta zastępuje ten dostęp wskazanymi osobami. Wyłączenie tej opcji odbiera zarządzanie komisji, nie kończy automatycznie istniejącej opieki.
4. Utworzyć dwóch podopiecznych i przypisać mentorów. Jedno aktywne członkostwo podopiecznego jest zabezpieczone kluczem głównym i transakcją. Bycie mentorem innej pary nie jest blokowane.

## Dane i synchronizacja

Źródłem jest istniejący `province_match_monitor`. Musi być uruchomiony i mieć skonfigurowane konta okręgowe w `configured_provinces()`. Moduł nie dodaje nowych poświadczeń ani nie loguje się za podopiecznych. Bez źródła dla ich okręgów nie należy obiecywać pełnej listy lub nowych pushy.

Podopieczni są dodawani do monitorowanych sędziów nawet bez tokena push. Pierwsze poprawne odczytanie obu list stanowi bazę: istniejące mecze pojawiają się bez historycznych powiadomień. Starsze mecze bieżącego sezonu są uzupełniane, jeżeli brakuje danych lub identyfikatorów obsady. Sezon zaczyna się 1 września, zgodnie z pozostałym monitorem.

Dopasowanie wymaga identyfikatorów obu boiskowych, w dowolnej kolejności. Brak ID nie jest zastępowany zgadywaniem po nazwisku. Należy sprawdzić na środowisku testowym, czy źródło zwraca komplet obsady także dla rozgrywek centralnych i par mieszanych między okręgami.

## Dostęp i interfejs

- Nowy podgląd jest osobnym komponentem, nie formularzem edycji meczu. Dostępne są publiczne informacje o spotkaniu, składy i mapa. Nie ma zapisu wyniku, raportu, rozliczenia ani uruchomienia ProEla.
- Nie dopisuje meczów podopiecznych do własnych plików meczów/statystyk. Dane mentoringu pozostają w pamięci, powiązane z kontem, i są ponownie pobierane po powrocie aplikacji na pierwszy plan.
- Widoczność na głównym i powiadomienia są niezależnymi ustawieniami per mentor i para. Ukryta para pozostaje w rozwijanej sekcji „Moje pary”.
- Własny mecz mentora nie jest dublowany na głównym; otrzymuje znacznik „Podopieczni”. Dotychczasowe wejście we własny mecz zachowuje uprawnienia.
- Serwer natychmiast odmawia dostępu po zakończeniu opieki. Otwarty interfejs sprawdza relację co minutę, przy wznowieniu aplikacji oraz przed pobraniem składów. Nie ma możliwości zdalnego usunięcia już obejrzanej treści na urządzeniu offline.
- Zdarzenia trafiają do istniejącej kolejki push. Przed wysłaniem następuje ponowne sprawdzenie relacji, wyciszenia, czasu przydziału oraz konta urządzenia. Wejście z powiadomienia prowadzi do ograniczonego podglądu.
- Uprawnienia administracyjne i odznaki komisji wykorzystują istniejące źródła autoryzacji aplikacji. Ich zapisy muszą pozostawać chronione przez serwer; mentoring nie jest osobnym systemem nadawania odznak.

## Weryfikacja

Testy izolowane nie importują produkcyjnego `app.db`:

```powershell
python -m unittest discover -s tests -p "test_mentoring*.py"
```

Przed udostępnieniem: sprawdzić na urządzeniu utworzenie pary, dostęp komisji, zmianę konta, odwołanie opieki, powiadomienie po zmianie prawdziwego meczu oraz brak powiadomień po pierwszej synchronizacji. Testy jednostkowe używają atrap bazy i nie zastępują testu na testowym PostgreSQL ani odbioru FCM na urządzeniu.
