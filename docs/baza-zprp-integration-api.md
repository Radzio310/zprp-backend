# Integracja baza.zprp.pl ↔ aplikacja zewnętrzna (ProEl) — specyfikacja API

**Status:** propozycja robocza (draft do uzgodnienia z zespołem baza.zprp.pl)
**Wersja:** 0.1
**Odbiorca:** zespół rozwijający baza.zprp.pl
**Cel dokumentu:** opisać, jakie endpointy powinna wystawić **baza.zprp.pl** po swojej
stronie, aby aplikacja zewnętrzna mogła publikować wyniki, protokoły i załączniki
meczów **na podstawie tokenu nadanego przez administratora** — bez konieczności
logowania się jako sędzia przypisany do meczu.

---

## 1. Kontekst i problem

Dziś wynik meczu może wprowadzić wyłącznie **użytkownik zalogowany jako sędzia
przypisany do tego meczu** (po zalogowaniu w panelu i otwarciu formularza meczu).
Aplikacja zewnętrzna nie ma żadnego oficjalnego interfejsu — może działać tylko
„udając" zalogowanego sędziego.

Potrzebna zmiana: baza.zprp.pl ma **pozwolić na publikację wyniku także
użytkownikowi nieprzypisanemu do meczu jako sędzia**, przy czym o tym, **kto i do
którego meczu** dostaje takie prawo, decyduje **administrator po stronie
baza.zprp.pl**, wydając token dostępowy.

Niniejszy dokument opisuje:
- model autoryzacji (token nadawany przez admina + zachowana ścieżka sędziego),
- endpointy do **publikacji** (wynik skrócony, protokół, załączniki),
- endpointy do **odczytu** stanu meczu (status protokołu, załączniki, wynik, składy),
- wymagania przekrojowe (walidacje, idempotentność, audyt, format błędów).

---

## 2. Słownik pojęć

| Pojęcie | Znaczenie |
|---|---|
| **IdZawody** | Unikalny identyfikator meczu w systemie baza.zprp.pl. |
| **Wynik skrócony** | Podstawowy zestaw danych meczu: wynik końcowy, do przerwy, rzuty karne, czasy (timeouty), liczba widzów. |
| **Protokół** | Pełne dane meczu: statystyki zawodników, kary, osoby towarzyszące, komentarz. |
| **Osoby towarzyszące (A–E)** | Sztab przy stoliku (np. trener) oznaczany literami A–E; może otrzymać kary. |
| **Token dostępowy (grant)** | Poświadczenie wydane przez administratora, uprawniające posiadacza do określonych operacji na wskazanym meczu (lub zakresie meczów). |
| **Subject** | Identyfikator odbiorcy tokenu (np. konto/aplikacja zewnętrzna lub użytkownik). |
| **Konsument API** | Aplikacja zewnętrzna wywołująca to API (tu: ProEl). |

---

## 3. Zasady ogólne

- **Bazowy URL (propozycja):** `https://baza.zprp.pl/api/v1`
- **Format danych:** JSON (`Content-Type: application/json`), poza uploadem plików
  (`multipart/form-data`).
- **Kodowanie:** UTF-8 w API (po stronie baza.zprp.pl następuje ewentualna konwersja
  do wewnętrznego kodowania — konsument nie musi się tym zajmować).
- **Wersjonowanie:** prefiks `/api/v1`. Zmiany łamiące → `/api/v2`.
- **Strefa czasowa:** wszystkie znaczniki czasu w ISO 8601 UTC (np.
  `2026-06-19T12:00:00Z`).

---

## 4. Model autoryzacji

Baza.zprp.pl akceptuje **dwie niezależne ścieżki** dla każdego endpointu publikacji
i odczytu:

### 4.1. Ścieżka tokenu (nowość)

Posiadacz tokenu wydanego przez administratora przekazuje go w nagłówku:

```
Authorization: Bearer <token>
```

Przy każdym żądaniu baza.zprp.pl sprawdza, czy token:
1. jest ważny (nie wygasł, nie został odwołany),
2. obejmuje **dany mecz** (`IdZawody` mieści się w zakresie grantu),
3. uprawnia do **danej operacji** (np. `short_result`, `attachment`).

Jeśli którykolwiek warunek nie jest spełniony → odpowiedź `403`.

### 4.2. Ścieżka sędziego (zachowana, jak obecnie)

Sędzia przypisany do meczu może działać jak dotychczas (sesja / logowanie
standardowe). Ta ścieżka nie wymaga tokenu i pozostaje bez zmian. Endpointy
publikacji powinny ją akceptować równolegle, aby nie psuć obecnego przepływu.

> **Uwaga projektowa:** token z punktu 4.1 zastępuje wymóg „bycia sędzią tego
> meczu". To administrator baza.zprp.pl, wydając token, bierze odpowiedzialność za
> nadanie prawa publikacji osobie/aplikacji nieprzypisanej do meczu.

---

## 5. Zarządzanie tokenami (panel administratora baza.zprp.pl)

Operacje dostępne wyłącznie dla administratora baza.zprp.pl.

### 5.1. Nadanie tokenu

```
POST /api/v1/admin/access-grants
```

**Request:**
```json
{
  "scope": { "matchId": "123456" },
  "subject": "proel:client:main",
  "permissions": ["read", "short_result", "protocol", "attachment"],
  "expiresAt": "2026-07-01T00:00:00Z",
  "note": "Publikacja wyników przez aplikację ProEl"
}
```

- `scope` — zakres grantu. Warianty:
  - pojedynczy mecz: `{ "matchId": "123456" }`
  - zakres rozgrywek/sezonu: `{ "season": "2025/2026", "competition": "..." }`
- `permissions` — lista uprawnień: `read`, `short_result`, `protocol`, `attachment`.
- `expiresAt` — data wygaśnięcia (opcjonalna; brak = bezterminowo, niezalecane).

**Response `201`:**
```json
{
  "grantId": "grant_abc123",
  "token": "zprp_pat_9f8e7d6c5b4a...",
  "expiresAt": "2026-07-01T00:00:00Z"
}
```

> `token` jest pokazywany **tylko raz**, przy utworzeniu. Baza.zprp.pl przechowuje
> wyłącznie jego skrót (hash).

### 5.2. Lista tokenów

```
GET /api/v1/admin/access-grants?matchId=123456&subject=proel:client:main&active=true
```

**Response `200`:**
```json
{
  "grants": [
    {
      "grantId": "grant_abc123",
      "scope": { "matchId": "123456" },
      "subject": "proel:client:main",
      "permissions": ["read", "short_result", "protocol", "attachment"],
      "createdAt": "2026-06-19T10:00:00Z",
      "expiresAt": "2026-07-01T00:00:00Z",
      "revokedAt": null
    }
  ]
}
```

### 5.3. Zmiana zakresu / ważności

```
PATCH /api/v1/admin/access-grants/{grantId}
```

**Request (pola opcjonalne):**
```json
{
  "permissions": ["read", "short_result"],
  "expiresAt": "2026-06-30T00:00:00Z"
}
```

### 5.4. Odwołanie tokenu

```
DELETE /api/v1/admin/access-grants/{grantId}
```

**Response `200`:** `{ "success": true }`

### 5.5. Introspekcja tokenu (dla konsumenta)

Pozwala konsumentowi sprawdzić, co obejmuje jego własny token.

```
GET /api/v1/access-grants/me
Authorization: Bearer <token>
```

**Response `200`:**
```json
{
  "subject": "proel:client:main",
  "scope": { "matchId": "123456" },
  "permissions": ["read", "short_result", "protocol", "attachment"],
  "expiresAt": "2026-07-01T00:00:00Z"
}
```

---

## 6. Publikacja danych meczu

Wszystkie operacje publikacji wymagają uprawnienia odpowiadającego typowi danych
(`short_result`, `protocol`, `attachment`) **lub** sesji sędziego przypisanego.

### 6.1. Wynik skrócony

```
POST /api/v1/matches/{idZawody}/short-result
```

**Request:**
```json
{
  "result":   { "home": 30, "away": 28 },
  "halfTime": { "home": 15, "away": 14 },
  "shootout": { "home": 3,  "away": 2 },
  "penalties": {
    "home": { "attempts": 4, "scored": 3 },
    "away": { "attempts": 2, "scored": 2 }
  },
  "timeouts": {
    "home": ["12:34", "45:10"],
    "away": ["20:00"]
  },
  "spectators": 250
}
```

Pola:

| Pole | Typ | Wymagane | Opis |
|---|---|---|---|
| `result.home` / `result.away` | int | tak | Wynik końcowy. |
| `halfTime.home` / `halfTime.away` | int | tak | Wynik do przerwy. |
| `shootout.home` / `shootout.away` | int | tylko przy remisie | Seria rzutów karnych (rozstrzygająca). |
| `penalties.{strona}.attempts` / `.scored` | int | nie | Rzuty karne w regulaminowym czasie (rzucone / trafione). |
| `timeouts.{strona}` | string[] `mm:ss` | nie | Czasy wzięte przez drużynę (0–3 wartości). |
| `spectators` | int | tak | Liczba widzów. |

**Response `200`:** `{ "success": true }`

Walidacje, które baza powinna wykonać po swojej stronie (niezależnie od klienta):
- wynik do przerwy ≤ wynik końcowy (dla każdej drużyny),
- trafione karne ≤ rzucone karne,
- przy remisie wymagana niepusta seria `shootout`,
- maks. 1 czas w ostatnich 5 minutach na drużynę; nie wszystkie 3 w jednej połowie.

### 6.2. Protokół (pełne dane)

```
POST /api/v1/matches/{idZawody}/protocol
```

**Request:**
```json
{
  "teams": {
    "home": {
      "players": [
        {
          "number": 11,
          "entered": true,
          "goals": 5,
          "warning": true,
          "twoMinutes": 2,
          "disqualification": false,
          "penaltyShots": { "attempts": 1, "scored": 1 }
        }
      ],
      "companions": [
        { "id": "A", "warning": true, "twoMinutes": 1, "disqualification": false }
      ]
    },
    "away": {
      "players": [],
      "companions": []
    }
  },
  "comment": "Mecz bez uwag."
}
```

Pola zawodnika (`teams.{strona}.players[]`):

| Pole | Typ | Opis |
|---|---|---|
| `number` | int | Numer na koszulce (klucz identyfikujący zawodnika w meczu). |
| `entered` | bool | Czy zawodnik wystąpił. |
| `goals` | int | Liczba bramek. |
| `warning` | bool | Upomnienie (żółta kartka). |
| `twoMinutes` | int | Liczba kar 2 minut. |
| `disqualification` | bool | Dyskwalifikacja (czerwona). |
| `penaltyShots.attempts` / `.scored` | int | Rzuty z serii karnych (rozstrzygającej). |

Pola osoby towarzyszącej (`teams.{strona}.companions[]`):

| Pole | Typ | Opis |
|---|---|---|
| `id` | string `A`–`E` | Oznaczenie osoby przy stoliku. |
| `warning` | bool | Upomnienie. |
| `twoMinutes` | int | Liczba kar 2 minut. |
| `disqualification` | bool | Dyskwalifikacja. |

**Response `200`:** `{ "success": true }`

> Identyfikacja zawodnika następuje po `number` w obrębie drużyny. Jeśli przesłany
> numer nie istnieje w składzie meczu po stronie baza.zprp.pl — pozycja jest
> pomijana (odpowiedź powinna zwrócić listę pominiętych w `warnings`).

### 6.3. Załączniki (PDF / zdjęcie)

```
POST /api/v1/matches/{idZawody}/attachments
Content-Type: multipart/form-data
```

**Pola formularza:**
- `file` — plik `application/pdf` lub `image/jpeg`.

**Response `201`:**
```json
{
  "success": true,
  "attachment": {
    "id": "att_001",
    "filename": "protokol_2026-06-19.pdf",
    "contentType": "application/pdf",
    "url": "https://baza.zprp.pl/zawody_zalaczniki/..."
  }
}
```

### 6.4. Usunięcie załącznika (opcjonalne)

```
DELETE /api/v1/matches/{idZawody}/attachments/{attachmentId}
```

**Response `200`:** `{ "success": true }`

---

## 7. Odczyt stanu meczu

Operacje odczytu wymagają uprawnienia `read` (lub sesji sędziego).

### 7.1. Metadane meczu

```
GET /api/v1/matches/{idZawody}
```

**Response `200`:**
```json
{
  "idZawody": "123456",
  "competitionCode": "IIM 12/34",
  "season": "2025/2026",
  "round": "Runda zasadnicza",
  "datetime": "2026-06-20T18:00:00Z",
  "teams": {
    "home": { "name": "Klub A" },
    "away": { "name": "Klub B" }
  },
  "officials": {
    "referees": ["Kowalski Jan", "Nowak Piotr"],
    "delegate": "Wiśniewski Adam",
    "secretary": "...",
    "timekeeper": "..."
  },
  "hall": { "name": "Hala Miejska", "city": "Miasto", "street": "Sportowa", "number": "1" }
}
```

> Pole `teams.home` powinno odpowiadać **rzeczywistemu gospodarzowi** (po
> uwzględnieniu ewentualnej „zmiany gospodarza"). Konsument nie powinien już musieć
> samodzielnie wykrywać i zamieniać stron.

### 7.2. Status protokołu i załączniki

```
GET /api/v1/matches/{idZawody}/status
```

**Response `200`:**
```json
{
  "protocolStatus": "before_approval",
  "attachments": [
    {
      "id": "att_001",
      "filename": "protokol.pdf",
      "contentType": "application/pdf",
      "url": "https://baza.zprp.pl/zawody_zalaczniki/..."
    }
  ]
}
```

`protocolStatus` ∈ `before_match` | `before_approval` | `approved`.

### 7.3. Aktualny wynik

```
GET /api/v1/matches/{idZawody}/results
```

Zwraca aktualnie zapisany w bazie wynik w tym samym kształcie co request z
sekcji **6.1** (do synchronizacji po stronie konsumenta).

### 7.4. Składy

```
GET /api/v1/matches/{idZawody}/lineup
```

**Response `200`:**
```json
{
  "teams": {
    "home": {
      "players": [
        { "number": 11, "fullName": "Kowalski Jan", "photoUrl": "https://..." }
      ],
      "companions": [
        { "id": "A", "fullName": "Trener X", "function": "Trener" }
      ]
    },
    "away": { "players": [], "companions": [] }
  }
}
```

---

## 8. Format błędów

Wszystkie błędy zwracane w jednolitym kształcie:

```json
{
  "error": {
    "code": "FORBIDDEN_MATCH",
    "message": "Token nie obejmuje tego meczu."
  }
}
```

| HTTP | `code` | Znaczenie |
|---|---|---|
| `400` | `VALIDATION_ERROR` | Niepoprawne dane (np. połowa > wynik końcowy). |
| `401` | `UNAUTHORIZED` | Brak / nieważny token i brak sesji sędziego. |
| `403` | `FORBIDDEN_MATCH` | Token nie obejmuje meczu. |
| `403` | `FORBIDDEN_OPERATION` | Token nie obejmuje danej operacji. |
| `404` | `MATCH_NOT_FOUND` | Mecz o podanym `IdZawody` nie istnieje. |
| `409` | `MATCH_LOCKED` | Protokół zatwierdzony / zablokowany do edycji. |
| `415` | `UNSUPPORTED_MEDIA_TYPE` | Niedozwolony typ pliku załącznika. |
| `422` | `BUSINESS_RULE` | Naruszona reguła (np. brak serii karnych przy remisie). |

---

## 9. Wymagania przekrojowe

- **Idempotentność.** Endpointy publikujące (`POST` w sekcji 6) powinny obsługiwać
  nagłówek `Idempotency-Key: <uuid>`. Powtórzenie żądania z tym samym kluczem nie
  tworzy duplikatu (ważne przy ponawianiu po timeout).
- **Walidacja po stronie serwera.** Wszystkie reguły poprawności wyniku/protokołu
  muszą być egzekwowane przez baza.zprp.pl, niezależnie od klienta.
- **Audyt.** Każda operacja publikacji powinna być zapisana z informacją: który
  token / subject / sędzia, jaką operację, na którym meczu i kiedy wykonał. Jest to
  kluczowe, ponieważ wynik może wprowadzić osoba nieprzypisana do meczu.
- **Blokada po zatwierdzeniu.** Gdy `protocolStatus = approved`, operacje
  publikacji zwracają `409 MATCH_LOCKED`.
- **Najmniejszy zakres uprawnień.** Token powinien obejmować możliwie wąski zakres
  (pojedynczy mecz, konkretne operacje, termin ważności).

---

## 10. Mapowanie na obecne (wewnętrzne) operacje baza.zprp.pl

Pomocniczo — do czego odnoszą się nowe endpointy w istniejącym systemie:

| Nowy endpoint | Obecny mechanizm wewnętrzny |
|---|---|
| `POST /matches/{id}/short-result` | Formularz „Wynik skrócony". |
| `POST /matches/{id}/protocol` | Zapis pól protokołu zawodników / osób towarzyszących / komentarza. |
| `POST /matches/{id}/attachments` | Formularz dodawania załącznika do meczu. |
| `GET /matches/{id}` / `/status` / `/results` | Strona szczegółów meczu (status, załączniki, wynik). |
| `GET /matches/{id}/lineup` | Składy i osoby towarzyszące meczu. |

---

## 11. Otwarte kwestie do uzgodnienia

1. **Zakres tokenu** — czy wystarczy granularność „pojedynczy mecz", czy potrzebne
   są granty obejmujące całe rozgrywki / sezon?
2. **Tożsamość subjectu** — jak baza.zprp.pl ma identyfikować odbiorcę tokenu
   (konto aplikacji, konkretny użytkownik, oba)?
3. **Korekty po zatwierdzeniu** — czy istnieje ścieżka publikacji po `approved`
   (np. rola nadrzędna), czy `409` jest ostateczne?
4. **Limity** — rate limiting i maksymalny rozmiar załącznika.
5. **Środowisko testowe** — czy będzie dostępna instancja staging baza.zprp.pl do
   integracji.
