# Mentor - panel mentorski pary (kontrakt web + aplikacja + backend)

Decyzje właściciela z 21.10.2026. Ten plik jest JEDYNYM kontraktem między
`zprp-backend` (API), `BAZA_web` (panel na komputerze, trasa `/mentor`) i `BAZA`
(pełny panel natywnie). Zmiana kształtu odpowiedzi = zmiana tutaj najpierw.

## 1. Decyzje (stan na 21.10.2026)

| Temat | Decyzja |
|---|---|
| Nazwa | **Mentor**. Web: `https://www.bazapodreka.app/mentor` (lista moich par) i `/mentor/{pairId}` (stały link pary). |
| Technologia web | BAZA_web (Expo Router web, system projektowy Pod Ręką, Reanimated), nowa grupa tras `app/(mentor)/`. Telefon w przeglądarce: ekran „Otwórz na komputerze albo w aplikacji BAZA” (publiczne klipy/zestawienia/raporty działają też na telefonie). |
| Logowanie web | Kod QR na komputerze → zatwierdzenie w aplikacji BAZA (zalogowany sędzia). Zapasowo login+hasło ZPRP. Sesja w ciasteczku httpOnly 30 dni + CSRF (wzór: `pod_reka` club session). |
| Dostęp | Para (2 sędziów) + jej aktywni mentorzy + admin: pełny. Komisja/menedżerowie mentoringu okręgu: podgląd swoich par okręgowych. Publiczne linki tylko do wybranych klipów, zestawień i raportów. |
| Włączanie panelu | Admin (wszystkie pary, w tym Mentor 2028) + menedżerowie mentoringu okręgu (pary okręgowe swojego okręgu). |
| Mecze | Wszystkie mecze pary z całej historii (sezony jako rozdziały), nowe dokładają się same. Gwiazdka „istotny” ręcznie (z powodem). Zgłoszenie meczu do omówienia (tablica „Do omówienia”, termin). |
| Układ web | Pulpit pary (bento) + oś sezonu z meczami; mecz otwiera **Pokój meczu**. |
| Odtwarzacz | Tryb **Studio** (wideo + zdarzenia ProEl/klipy obok, oś z falą meczu, skróty) i **Kino** (pełny ekran, akcje wysuwają się z krawędzi i chowają). |
| Zestawienia | Klipy łączone w nazwane zestawienia („kontrast” - dwie kolumny przeciwstawne, „podobne”, „wolne”), „Dodaj do zestawienia” z dowolną nazwą, odtwarzanie kolejką. |
| Wątki | Przy meczu i przy klipie; odpowiedzi, @wzmianki, kotwica w sekundzie wideo, status pytanie/rozwiązane. Push (BAZA) + e-mail. Na żywo bez odświeżania. |
| Źródła wideo | YouTube + Vimeo (pełne API) + **własne nagrania** (upload do Cloudflare R2). Facebook/Twitch tylko jako zwykły link zewnętrzny (bez synchronizacji). |
| Klipy | **Wirtualne klipy** zawsze (zakres z oryginału, pętla). **MP4** tylko z własnych nagrań (cięcie ffmpeg na serwerze). YouTube przez konto Premium/yt-dlp: NIE (regulamin, blokada IP). |
| Retencja | Pełne wgrane nagrania 12 mies. od meczu, klipy do ręcznego usunięcia. Publiczny link do klipu z meczu młodzieżowego - ostrzeżenie przed publikacją. |
| Kategorie | Per para + domyślne (5 dzisiejszych) + globalne admina; nazwa, kolor z palety, ikona z biblioteki, opis; „Przywróć domyślne”; klip może mieć kilka kategorii. |
| Uprawnienia klipów | Para i mentorzy tworzą klipy, znaczniki, kategorie, komentarze; edytują/usuwają tylko swoje (autor widoczny). Komisja: podgląd. |
| Arkusze | Wszystkie arkusze delegatów pary (nowa reguła dostępu), arkusze mentorów z wersjami, trendy (sekcje I-X w czasie, priorytety, delegat vs mentor), kluczowe sytuacje z arkusza jako znaczniki na osi wideo. |
| Raporty | Kreator z podglądem A4 na żywo (zakres: mecz/okres/sezon; sekcje do zaznaczenia), PDF + publiczny link. |
| Aplikacja | Pełny panel natywnie; kafel „Mentor” w Więcej (gdy mam parę z włączonym panelem); w szczegółach meczu dotychczasowa ikona (wideo + prośba o ocenę) rozbudowana do huba „Mentor” tego meczu; „Otwórz na komputerze” (kopiuj link / wyślij / QR). |
| Hosting nagrań | Cloudflare R2 tym samym schematem co kopie zapasowe (`BACKUP_S3_*`), z własnym prefiksem i opcjonalnym nadpisaniem `MENTOR_S3_*`. Cięcie i transkodowanie ffmpeg na serwerze. |
| Etapy | Wszystko w jednej rundzie. |

## 2. Model danych (nowe tabele, `app/mentor_panel_tables.py`)

Schemat jak reszta repo: `define_tables(metadata)` + rejestracja w `app/db.py`
(`create_all` + `ALTER ... IF NOT EXISTS` przy starcie). Identyfikatory tekstowe (uuid4 hex).

- `mentor_panels`: `pair_id` PK (FK `mentoring_pairs.id`), `enabled` bool, `enabled_by`, `enabled_at`,
  `rev` BigInteger (licznik zmian - long-poll), `settings_json` JSON, `updated_at`.
- `mentor_match_flags`: PK (`pair_id`, `match_id`), `starred` bool, `star_reason` (≤120), `starred_by`,
  `submitted` bool, `submitted_by`, `submitted_at`, `due_at`, `review_status` (`open|discussed|closed`), `note` (≤500), `updated_at`.
- `mentor_categories`: `id`, `pair_id` (NULL = globalna admina), `key` (np. `dobra`, dla domyślnych), `name` (≤40),
  `color` (token z palety, np. `emerald`), `icon` (nazwa z biblioteki ikon, np. `checkmark-circle`), `description` (≤160),
  `sort`, `archived` bool, `created_by`, `created_at`.
  Domyślne (seed per para przy pierwszym wejściu): dobra „Dobra decyzja” emerald, zla „Zła decyzja” rose,
  dyskusja „Do dyskusji” amber, pytanie „Pytanie do mentora” sky, kluczowa „Kluczowa akcja meczu” pink.
- `mentor_clips`: `id`, `pair_id`, `match_id`, `video_id` (FK `mentor_match_videos.id`), `start_s` float, `end_s` float
  (≤600 s długości), `title` (≤80), `note` (≤1000), `category_ids` JSON[], `source` (`manual|proel|sheet|marker`),
  `source_key` (klucz zdarzenia ProEl / sytuacji arkusza), `match_ms`, `half`, `author_id`, `created_at`, `updated_at`,
  `deleted_at`, `mp4_status` (`none|queued|working|ready|failed`), `mp4_key`, `mp4_size`, `public_token`, `published_at`.
- `mentor_compilations`: `id`, `pair_id`, `name` (≤60), `description` (≤500), `mode` (`contrast|similar|free`),
  `created_by`, `created_at`, `updated_at`, `public_token`, `published_at`.
- `mentor_compilation_items`: PK (`compilation_id`, `clip_id`), `position` int, `column` (`a|b`, dla `contrast`), `note` (≤280), `label` (≤40, od 24.10.2026).
- `mentor_threads`: `id`, `pair_id`, `target_kind` (`match|clip|compilation|pair`), `target_id`, `match_id` (gdy dotyczy),
  `title` (≤120), `kind` (`question|note|task`), `status` (`open|resolved`), `created_by`, `created_at`, `updated_at`, `last_comment_at`.
- `mentor_comments`: `id`, `thread_id`, `author_id`, `body` (≤4000), `video_id`, `video_s` (kotwica), `drawing_json`
  (strzałki/kółka na stopklatce, ≤20 kształtów), `mentions` JSON[], `created_at`, `edited_at`, `deleted_at`.
- `mentor_reads`: PK (`pair_id`, `judge_id`), `seen_rev`, `seen_at` (nieprzeczytane w pulpicie).
- `mentor_uploads`: `id`, `pair_id`, `match_id`, `video_id` (po zakończeniu), `uploader_id`, `filename`, `size`,
  `content_type`, `r2_key`, `upload_id` (multipart), `status` (`uploading|processing|ready|failed|expired`),
  `duration_s`, `width`, `height`, `play_key` (H.264 MP4 faststart), `poster_key`, `error`, `created_at`, `expires_at` (+12 mies. od meczu).
- `mentor_reports`: `id`, `pair_id`, `title`, `config_json` (zakres + sekcje), `snapshot_json`, `created_by`, `created_at`,
  `public_token`, `published_at`, `pdf_key`.
- `mentor_web_sessions`: jak `pod_reka_club_sessions`: `id`, `judge_id`, `session_hash`, `csrf_hash`, `created_at`,
  `expires_at` (30 dni), `last_seen_at`, `revoked_at`, `user_agent`.
- `mentor_qr_logins`: `code` PK (8 znaków bez dwuznacznych), `poll_hash`, `created_at`, `expires_at` (+3 min),
  `approved_by`, `approved_at`, `consumed_at`.
- `mentor_audit`: `id`, `pair_id`, `actor_id`, `action`, `data` JSON, `created_at`.

Istniejące i zostające: `mentoring_*` (pary, mentorzy), `mentor_match_videos` (+ nowe kolumny:
`kind` `link|upload`, `upload_id`), `mentor_evaluations*`, `delegate_evaluations*`.
Istniejące znaczniki (`markers_json`) zostają dla aplikacji; panel pokazuje znaczniki z zakresem (`end_s`)
jako klipy tylko do odczytu („z aplikacji”), a przycisk „Zrób klip” kopiuje je do `mentor_clips`.

## 3. Uprawnienia (`app/mentor_panel_rules.py`, czyste, z testami)

`role_in_pair(actor, pair, assignments, config) -> "pair" | "mentor" | "admin" | "committee" | None`
- `pair`: `actor.judge_id in pair.judge_ids`.
- `mentor`: aktywny wiersz `mentoring_assignments` (ended_at IS NULL) dla tej pary.
- `admin`: `is_admin(judge_id)`.
- `committee`: menedżer okręgu pary (`mentoring_config.manager_ids` albo odznaka „Komisja sędziowska” tego okręgu wg `may_manage`); nigdy dla par `mentor2028`/`MIĘDZYOKRĘGOWE` (tam tylko admin).

| Akcja | pair | mentor | admin | committee |
|---|---|---|---|---|
| widzieć panel (gdy włączony) | ✓ | ✓ | ✓ (także wyłączony) | ✓ (podgląd) |
| gwiazdka / zgłoszenie meczu | ✓ | ✓ | ✓ | - |
| wideo: dodać link / wgrać | ✓ | ✓ | ✓ | - |
| klip / komentarz / zestawienie: tworzyć | ✓ | ✓ | ✓ | - |
| edytować / usuwać | tylko swoje | tylko swoje | wszystko | - |
| kategorie pary: dodać/zmienić/przywróć domyślne | ✓ | ✓ | ✓ | - |
| publikować link (klip/zestawienie/raport) | ✓ | ✓ | ✓ | - |
| włączyć/wyłączyć panel | - | - | ✓ | ✓ tylko okręgowe swojego okręgu |
| arkusze delegatów pary | ✓ | ✓ | ✓ | ✓ |

## 4. API (prefiks `/mentor-panel`, router `app/mentor_panel.py` + moduły)

Uwierzytelnianie: **albo** nagłówek `Authorization: Bearer <JWT sędziego>` (aplikacja BAZA),
**albo** ciasteczko `baza_mentor_session` + nagłówek `X-CSRF-Token` przy zapisie (web).
Wspólna zależność `mentor_actor` → `{judge_id, display_name, is_admin, province, via: "jwt"|"web"}`.
Błędy: `{detail: {code, message}}` po polsku, kody HTTP 401/403/404/409/422/429.
Każdy zapis podbija `mentor_panels.rev` i zwraca świeży obiekt (klient podmienia bez drugiego zapytania).

### 4.1 Logowanie web
- `POST /auth/qr` → `{code, poll_token, expires_at, approve_url}`; `approve_url` = `https://www.bazapodreka.app/mentor/zaloguj/{code}` (QR na komputerze; telefon z BAZA otwiera deep link `refhandballapp://mentor/login/{code}`, przeglądarka telefonu pokazuje „Otwórz w aplikacji BAZA”).
- `GET /auth/qr/{code}?poll_token=&wait=20` (long-poll) → `{status: "waiting"|"approved"|"expired"}`; przy `approved` ustawia ciasteczka sesji (+ `baza_mentor_csrf` czytelne dla JS) i zwraca `me`.
- `POST /auth/qr/{code}/approve` (JWT sędziego, z aplikacji) → `{ok, device_hint}`.
- `POST /auth/login` `{username, password}` (ZPRP, jak `exam_live._web_login`, z limitem prób) → ustawia sesję.
- `GET /auth/me` → `{judge_id, display_name, is_admin, csrf}`; `POST /auth/logout`.
- `GET /auth/csrf` → odświeża token CSRF.

### 4.2 Pary i włączanie
- `GET /pairs` → `{pairs: PairCard[]}` - pary, do których mam dostęp (jako para / mentor / admin / komisja), z `enabled`, `role`, `unread`, `next_match`, `counts`.
- `PATCH /pairs/{pairId}/panel` `{enabled}` (admin / komisja okręgu) → `PanelState`. Aplikacja: przełącznik na karcie pary w zakładce Mentoring.
- `GET /pairs/{pairId}` → `PairDashboard`:
  ```
  { pair: {id, program, province, judges:[{judge_id, full_name, photo_url}], mentors:[...], created_at},
    role, enabled, rev, me,
    next_match: MatchCard|null, last_match: MatchCard|null,
    to_discuss: MatchCard[] (zgłoszone, open), starred_recent: MatchCard[],
    new_clips: Clip[] (ostatnie 8), open_threads: ThreadSummary[] (ostatnie 8),
    sheets_summary: {delegate:{count, last_points, trend:[{date, points}]}, mentor:{count, last_points}},
    seasons: [{season, label, matches, starred, clips}],
    links: {web: "https://www.bazapodreka.app/mentor/{pairId}", app: "refhandballapp://mentor/{pairId}"} }
  ```

### 4.3 Mecze
- `GET /pairs/{pairId}/matches?season=&starred=&submitted=&q=` → `{matches: MatchCard[], seasons:[...]}`.
  Źródło: `zprp_public_matches` gdzie oba numery sędziów = para (dowolna kolejność) + `province_matches`
  (bieżący sezon, gdy publiczne nie mają) + `zprp_archive_matches` (starsze sezony). Indeksy na `referee_1_id`,`referee_2_id`.
  `MatchCard = {match_id, season, scheduled_at, competition_name, category, round_name, home:{name, logo_url, score}, away:{...},
   halftime, venue_city, match_code, delegate_name, starred, star_reason, submitted, review_status, due_at,
   has_proel, videos:{count, uploads}, clips:{count}, threads:{open, total}, sheets:{delegate: points|null, mentor: points|null},
   stream_url}`
- `GET /pairs/{pairId}/matches/{matchId}` → `MatchRoom`:
  ```
  { match: MatchCard, videos: Video[], clips: Clip[], markers_from_app: Clip[] (tylko odczyt),
    timeline: {available, half_minutes, break_minutes, events: TimelineEvent[], clock?},  // jak /mentor-evaluations/match/{id}/timeline
    sheet_situations: [{source:"delegate"|"mentor", author, category, description, time, match_ms}],
    delegate_sheets: DelegateSheet[], mentor_sheets: MentorSheet[],
    threads: Thread[] (z komentarzami), rev }
  ```
- `PUT /pairs/{pairId}/matches/{matchId}/flag` `{starred?, star_reason?, submitted?, due_at?, review_status?, note?}` → `MatchCard`.
  Zgłoszenie (`submitted=true`) wysyła push + e-mail do mentorów (para zgłasza) albo do pary (mentor zgłasza).

### 4.4 Wideo
- `POST /pairs/{pairId}/matches/{matchId}/videos` `{url}` → `Video` (link YouTube/Vimeo/inne; reużywa `mentor_evaluations` add + link preview + stream start).
- `PATCH .../videos/{videoId}` `{sync}` → `Video` (kotwice: `match_start_s`, `second_half_s`, ...; jak dziś).
- `DELETE .../videos/{videoId}` (autor albo admin).
- `Video = {id, kind:"link"|"upload", provider:"youtube"|"vimeo"|"upload"|"facebook"|..., url, title, thumbnail_url,
   duration_s, sync, added_by, created_at, playable: bool, play_url? (upload: presigned GET 6 h), poster_url?, upload_status?}`

### 4.5 Wgrywanie nagrań (R2)
- `POST /pairs/{pairId}/matches/{matchId}/uploads` `{filename, size, content_type}` (≤ 20 GB) → `{upload_id, part_size, parts:[{n, url}]}` (presigned multipart; partie po 64 MB; kolejne partie: `POST .../uploads/{id}/parts?from=n`).
- `POST .../uploads/{uploadId}/complete` `{parts:[{n, etag}]}` → `{status:"processing"}`; serwer w tle: ffprobe → transkodowanie do H.264/AAC MP4 faststart (≤1080p, CRF 23, preset veryfast) + plakat JPG → `Video(kind=upload)`.
- `GET .../uploads/{uploadId}` → postęp `{status, progress, error}`; `DELETE` przerywa.
- Kolejka: tabela `mentor_uploads` + pętla w procesie (maks. 1 transkodowanie naraz), ffmpeg w obrazie (dodać do Dockerfile).
- Retencja: zadanie dzienne kasuje oryginał po udanym transkodowaniu i całe nagranie po `expires_at`.

### 4.6 Klipy i kategorie
- `GET /pairs/{pairId}/categories` → `{categories: Category[], palette:[...], icons:[...]}` (seed domyślnych przy pierwszym wywołaniu).
- `POST /pairs/{pairId}/categories` `{name, color, icon, description}`; `PATCH /categories/{id}`; `DELETE` (archiwizuje); `POST /pairs/{pairId}/categories/reset` (przywraca domyślne, własne archiwizuje).
- Każda kategoria w `GET` ma `clips_count` (żywe klipy pary). `PUT /pairs/{pairId}/categories/order` `{ids}` → pozycja = `sort` (klawisz 1-9 w pokoju meczu), globalne pomijane, brakujące na koniec. `POST /categories/{id}/merge` `{into}` → klipy dostają docelową, źródło do archiwum, odpowiedź = payload kategorii + `merged: {from, into, clips: [{id, added}]}`; `POST /categories/{id}/unmerge` `{into, clips}` cofa scalanie co do klipu.
- `POST /pairs/{pairId}/clips` `{match_id, video_id, start_s, end_s, title?, note?, category_ids[], source?, source_key?, match_ms?, half?}` → `Clip`.
- `PATCH /clips/{clipId}`, `DELETE /clips/{clipId}` (autor albo admin; miękkie).
- `GET /pairs/{pairId}/clips?category=&match_id=&author=&q=&markers=1` → `{clips: Clip[]}` (biblioteka klipów pary). Z `markers=1` (27.10.2026) lista niesie też znaczniki z aplikacji jako klipy (`source=marker`, `read_only`, `author`, `category_ids` po kluczu kategorii) - bez tych, z których już jest klip (także usunięty = nagrobek).
- Klipem jest KAŻDY ręczny znacznik (`marker_is_clip`): REC, z kategorią/komentarzem, oznaczony punkt i zwykły ręczny punkt; punkt dostaje zakres -5 s / +3 s. Nieoznaczony punkt z importu osi ProEla (ma `type`/`source_key`) klipem nie jest.
- `POST /pairs/{pairId}/clips/from-marker` `{video_id, marker_id}` → `Clip` - idempotentnie zamienia znacznik-klip w prawdziwy klip (`source=marker`, `source_key`=id znacznika, komentarz = notatka). Klient woła to przed pierwszą zmianą znacznika (flaga, kategoria, zestawienie, rozmowa).
- `POST /clips/{clipId}/mp4` → `{mp4_status}` (tylko klipy z `kind=upload`; ffmpeg `-ss/-to -c copy`, a gdy precyzja ważna - przekodowanie samego klipu); `GET /clips/{clipId}/mp4` → `{url}` (presigned 1 h, `Content-Disposition: attachment; filename="..."`).
- `Clip = {id, match_id, video_id, start_s, end_s, title, note, category_ids, source, source_key, match_ms, half,
   author:{judge_id, name}, created_at, updated_at, can_edit, mp4_status, public_url|null, thread:{id, open, comments}|null}`

### 4.7 Zestawienia
- `GET /pairs/{pairId}/compilations` → `{compilations:[{id, name, mode, description, items_count, cover_clip, created_by, updated_at, public_url}]}`.
- `POST /pairs/{pairId}/compilations` `{name, mode, description?}`; `PATCH /compilations/{id}`; `DELETE`.
- `PUT /compilations/{id}/items` `{items:[{clip_id, column?, note?, label?}], mode?}` (całość w kolejności) → `Compilation`; `POST /compilations/{id}/items` `{clip_id, column?, note?, label?}` („Dodaj do zestawienia”).
- `GET /compilations/{id}` → `{..., items:[{clip: Clip, column, note, label, position}]}`.
- **Playlista (24.10.2026, addytywnie).** Zestawienie = nazwa + opis („co pokazujemy”) + dowolna liczba klipów z różnych meczów; każdy klip ma `label` (podpowiedzi: Dobra decyzja, Zła decyzja, Balans, Dysproporcja, Wzorzec, Do poprawy, albo dowolny tekst ≤40) i `note` (≤280). Nowi klienci tworzą i zapisują `mode: "free"`. Stary `contrast` czytany jako playlista: `label` pusty = z kolumny (`a` → „Wzorzec”, `b` → „Do poprawy”, `rules.legacy_label`); `PUT .../items` z `mode:"free"` albo `PATCH {mode:"free"}` przepisuje go na playlistę (kolejność A1, B1, A2..., `rules.playlist_items`). Publiczny odczyt oddaje też `label`. Klip w `GET /compilations/{id}` ma też `match` (skrót karty: `match_id, season, scheduled_at, match_code, category, competition_name, home, away`, `rules.slim_match`) - klient dzieli playlistę na sekcje meczów (herby, numer, data, wynik). Migracja: `ALTER TABLE mentor_compilation_items ADD COLUMN IF NOT EXISTS label`.

### 4.8 Wątki
- `GET /pairs/{pairId}/threads?target_kind=&target_id=&status=` → `{threads: Thread[]}`.
- `POST /pairs/{pairId}/threads` `{target_kind, target_id, title?, kind, body, video_id?, video_s?, drawing?, mentions?}` → `Thread`.
- `POST /threads/{threadId}/comments` `{body, video_id?, video_s?, drawing?, mentions?}` → `Comment`; `PATCH/DELETE /comments/{id}` (autor).
- `PATCH /threads/{threadId}` `{status?, title?}`.
- Powiadomienia: nowy wątek/komentarz/wzmianka → push (`kind=mentor_panel`, `{pairId, matchId?, clipId?, threadId}`) do pozostałych osób pary i mentorów (preferencja `mentorPanel`), e-mail zbiorczy (Brevo) najwyżej co 30 min na osobę.
- `Thread = {id, target_kind, target_id, match_id, title, kind, status, created_by:{judge_id,name}, created_at, last_comment_at, comments: Comment[]}`;
  `Comment = {id, author:{judge_id,name,role}, body, video_id, video_s, drawing, mentions, created_at, edited_at, can_edit}`.
- Wątki przy klipie (26.10.2026, `target_kind=clip`), wiele na klip, te same funkcje co wątki meczu (follow/mute, wzmianki, `unread`, jeden push na wątek):
  - kotwica ZAWSZE w czasie oryginału (`video_id` klipu + `video_s`). Wejście: `video_s` (web) albo `clip_s` (sekunda od początku klipu, aplikacja/MP4), serwer liczy `video_s = start_s + clip_s`; poza zakresem ±5 s → 422 `ANCHOR_RANGE`;
  - `Thread` klipu ma dodatkowo `clip: {id, match_id, video_id, start_s, end_s, title, source, match_ms, half, category_ids, deleted}` i `anchor: {comment_id, video_id, video_s, clip_s, in_range} | null` (pierwszy komentarz z sekundą); `Comment` w wątku klipu ma `clip_s` i `in_range` (po przycięciu klipu kotwica może wypaść poza zakres);
  - wątek klipu bez tytułu: pierwszy = „Rozmowa”, kolejne = początek treści; stary płaski wątek dostał „Rozmowa” migracją;
  - `Clip.threads = {total, open, comments, unread, last_at, pins:[{thread_id, title, status, video_id, video_s, clip_s, in_range, author:{judge_id, initials}, unread}]}`; `Clip.thread` (pierwszy wątek) zostaje dla starszych buildów;
  - push wątku klipu: `clipId`, `threadId`, `clipS`, `videoS` (sekunda kotwicy: komentarza, a bez niej wątku), link web `/mentor/{pair}/klipy?klip={id}&watek={threadId}`.

### 4.9 Arkusze
- `GET /pairs/{pairId}/sheets?season=` → `{delegate: DelegateSheet[], mentor: MentorSheet[], trends: {sections:[{key, label, points:[{date, value, source}]}], priorities:[{text, count, last}], delegate_vs_mentor:[{match_id, delegate, mentor}]}}`.
  Nowa reguła: rola w parze (pair/mentor/admin/committee) widzi arkusze delegatów meczów tej pary (`delegate_evaluations.referee_ids` = para).

### 4.10 Zmiany na żywo
- `GET /pairs/{pairId}/changes?since={rev}&wait=25` (long-poll, wspólny zegar jak `zprp_public/live.py`) → `{rev, changed: bool, scopes:["matches","clips","threads","compilations","sheets","videos"], match_ids:[...], viewers:[{judge_id, name, where}]}`.
- `POST /pairs/{pairId}/presence` `{where: "dashboard"|"match:{id}"|"clip:{id}"}` co 30 s (wskaźnik „Mentor ogląda teraz”; w pamięci procesu, TTL 60 s).

### 4.11 Raporty
- `POST /pairs/{pairId}/reports/preview` `{scope:{kind:"match"|"range"|"season", match_id?, from?, to?, season?}, sections:[...], title?}` → `{html}` (A4, ten sam szablon co PDF).
  Sekcje: `summary` (liczby, forma), `matches` (lista), `clips` (miniatury + link/QR do każdego), `compilations`, `threads` (pytania i odpowiedzi), `sheets` (oceny delegatów/mentorów), `trends`, `priorities`, `goals` (notatka mentora).
- `POST /pairs/{pairId}/reports` (ta sama treść) → `{id, pdf_url, public_url?}`; `GET /pairs/{pairId}/reports`.

### 4.12 Publiczne linki (bez logowania)
- Publikacja: `POST /clips/{id}/publish`, `/compilations/{id}/publish`, `/reports/{id}/publish` → `{public_url}`; `DELETE .../publish` wyłącza (nowy token przy ponownej publikacji).
- Odczyt: `GET /mentor-panel/public/{token}` → `{kind:"clip"|"compilation"|"report", ...}` (bez nazwisk zawodników, bez arkuszy; klip: źródło + zakres + kategoria + opis; mecz młodzieżowy - ostrzeżenie przy publikacji, nie blokada).
- Web: `https://www.bazapodreka.app/mentor/k/{token}` (klip), `/mentor/z/{token}` (zestawienie), `/mentor/r/{token}` (raport) - działają też na telefonie.

### 4.13 Szczegóły backendu (wdrożone 21.10.2026, wszystko dodatkowe - kształty z 4.1-4.12 bez zmian)
- Moduły: `app/mentor_panel.py` (pary, pulpit, mecze, flagi, arkusze, zmiany), `_auth`, `_library` (kategorie, klipy, zestawienia, wątki, publiczne), `_media` (wideo, R2, ffmpeg, retencja), `_reports`, `_notify`, `_core`, czyste reguły `_rules` (testy `tests/test_mentor_panel_*.py`).
- Błędy zawsze `{detail: {code, message}}`; 401 `UNAUTHENTICATED` / `SESSION_EXPIRED`, 403 `NO_ACCESS` / `PANEL_DISABLED` / `READ_ONLY` / `NOT_OWNER` / `CSRF` / `NO_TOGGLE`, 404 `PAIR_NOT_FOUND` / `MATCH_NOT_FOUND` / `NOT_FOUND`, 409 `MP4_NOT_READY` / `MP4_LINK_VIDEO` / `QR_USED`, 422 kody walidacji (`CLIP_TOO_LONG`, `CLIP_RANGE`, `CATEGORY_COLOR`...), 429 `RATE_LIMITED`, 503 `STORAGE_OFF`.
- `me` = `{judge_id, display_name, is_admin, province, photo_url, via}` (+ `csrf` w `GET /auth/me`; `null` dla JWT). `POST /auth/qr` zwraca też `app_url` (`refhandballapp://mentor/login/{code}`); `GET /auth/qr/{code}` przy `approved` zwraca `{status, me, csrf}`; `POST /auth/login` → `{me, csrf}`. Token CSRF nie wygasa przy `GET /auth/me` (druga karta działa), wymienia go dopiero `GET /auth/csrf`.
- `PairCard = {id, program, province, judges, mentors, created_at, ended_at, enabled, role, unread, next_match, counts:{matches, clips, open_threads, to_discuss}, links}`; `GET /pairs` zwraca też `me`.
- `PairDashboard` ma dodatkowo `can: {flag, video, create, categories, publish, toggle}` i `compilations` (6 ostatnich, kształt z 4.7). `ThreadSummary` = Thread bez `comments`, z `comments_count` i `last_comment: {author, body (≤160), created_at}`. `MatchRoom` ma też `can`.
- `PanelState = {pair_id, enabled, enabled_by, enabled_at, rev}`. `GET /mentoring/management` - każda para ma `panel_enabled`.
- `Video` ma `can_edit`; dla `kind=upload` `url` = `play_url` (podpisany, 6 h), `thumbnail_url` = `poster_url`. `PATCH .../videos/{id}` przyjmuje też `title`; `sync` jest łączony z dotychczasowym.
- Wgrywanie: start → `{upload_id, part_size, total_parts, parts:[{n, url}] (do 40 naraz), expires_at}`; `complete` → `{status:"processing", video_id}` (nagranie od razu na liście z `upload_status`). R2 musi mieć CORS dla `PUT` z `bazapodreka.app` z `ExposeHeaders: ETag`.
- `Category = {id, key, name, color, icon, description, sort, archived, global, created_by}`; `GET` zwraca też zarchiwizowane (`archived: true`) - stare klipy mają czym się narysować. `POST` z `global: true` tylko admin; `PATCH` z `archived: false` przywraca z archiwum.
- `Clip` z `source=marker` w `markers_from_app` ma `read_only: true` i `category_key` (dawna kategoria znacznika).
- Zestawienie: `Compilation = {id, pair_id, name, mode, description, created_by, created_at, updated_at, public_url, can_edit, items}`; `POST` przyjmuje też `items`. Zmiana pozycji = edycja (tylko autor / admin).
- `Thread` i `Comment` mają `can_edit`; status wątku zmienia każdy z pary/mentorów, tytuł - autor.
- Publikacja → `{public_url, youth_warning: bool, warning: string|null}` (ostrzeżenie dla meczu młodzieżowego). Raport: `POST /reports/{id}/publish` i `DELETE`, `POST /pairs/{id}/reports` przyjmuje `publish: true`; `pdf_url` to podpisany adres R2 (1 h) albo `/mentor-panel/reports/{id}/pdf` (z logowaniem). Publiczny raport ma `pdf_url` = `/mentor-panel/public/{token}/pdf`.
- `GET /changes` → `scopes` z: `matches, clips, threads, compilations, sheets, videos, categories, reports, panel`; `since` większe niż `rev` = `changed: true` ze wszystkimi zakresami.
- `MatchRoom.suggested_streams: Stream[]` (22.10.2026, dodatkowe) - transmisje meczu wykryte dla portalu (`docs/streams.md`): tylko YouTube, pewność `official`/`confirmed`, bez filmów już dodanych do pokoju (porównanie po identyfikatorze filmu YouTube); `Stream = {id, match_id, platform, url, embed_url, video_id, title, thumbnail_url, channel, state, starts_at, duration_s, confidence}`. Web/aplikacja może pokazać je jako „Dodaj nagranie” (dalej zwykłe `POST .../videos` z `url`). Błąd odczytu = pusta lista.
- Push: `data = {type:"mentor_panel", kind:"mentor_panel", pairId, matchId?, clipId?, threadId?}`, przełącznik `mentorPanel`. E-mail zbiorczy z kolejki w pamięci procesu (po restarcie oczekujące listy przepadają, push już poszedł).

### 4.14 Nagrania z YouTube (24.10.2026, dodatkowe, `app/mentor_panel_streams.py`)
- `MatchRoom.suggested_streams` = transmisje meczu z `match_streams` (to samo `match_id`): YouTube, `official`/`confirmed` albo znalezione przez tę parę (także `possible` - pokazywać przygaszone), bez filmów dodanych do pokoju i bez odrzuconych przez parę.
- `MatchRoom.stream_search` = `StreamSearch | null` (null = błąd odczytu): `{allowed, reason, message, left, per_day, searched_at, last_found, channels}`. `reason`: `null` (wolno szukać), `FOUND` (są podpowiedzi), `ROLE` (tylko para i mentorzy), `OFF` (brak `YOUTUBE_API_KEY`), `TOO_EARLY` (przed dniem meczu), `LIMIT` (3 na mecz na dobę na parę), `QUOTA` (wspólna pula dobowa). `message` = gotowe zdanie („Spróbuj jutro albo wklej link."). `channels` = nazwy kanałów do animacji radaru (do 6).
- `POST /pairs/{pair}/matches/{id}/streams/search` → `{streams: Stream[], search: StreamSearch, cached: bool}`. Gdy są podpowiedzi albo poprzednie szukanie (< 6 h) coś znalazło - zwraca je bez YouTube (`cached: true`). Inaczej jedno `search.list` z puli `app/streams` (w dniu meczu przed startem `upcoming`, w trakcie `live`, potem zwykłe filmy od 2 h przed meczem) + `videos.list`, dopasowanie `rules.best_match` (pula meczów ±18 h), zapis do `match_streams` (`source = mentor`). Wynik wspólny dla pary i mentorów, podbija `rev` (zakres `videos`). Odmowy: 403 `NO_ACCESS`, 409 `STREAM_SEARCH_EARLY`, 429 `STREAM_SEARCH_LIMIT` / `STREAM_SEARCH_QUOTA`, 503 `STREAM_SEARCH_OFF` / `STREAM_SEARCH_FAILED` (próba się liczy - jednostki poszły).
- `POST /pairs/{pair}/matches/{id}/streams/reject` `{video_id}` → `{streams, search}`. Chowa film tylko w tej parze (portal dalej go pokazuje).
- „Dodaj do meczu" = zwykłe `POST .../videos` z `url` podpowiedzi.
- Tabela `mentor_stream_searches` (pair_id + match_id): `day`, `day_count`, `searched_at`, `searched_by`, `last_count`, `found_json`, `rejected_json`.

## 5. Web (BAZA_web, `app/(mentor)/`)
- `/mentor` - lista moich par (karty par, nieprzeczytane, następny mecz) albo logowanie QR.
- `/mentor/zaloguj/{code}` - strona dla telefonu bez aplikacji (otwórz w BAZA / pobierz).
- `/mentor/{pairId}` - **Pulpit**: bento (najbliższy mecz, Do omówienia, Nowe klipy, Otwarte wątki, Forma w arkuszach, Zestawienia) + **oś sezonu** (mecze jako pigułki na osi czasu, gwiazdki, ikony wideo/klipów/wątków, filtry, przełącznik sezonów).
- `/mentor/{pairId}/mecz/{matchId}` - **Pokój meczu**: tryb **Studio** (wideo 16:9 + prawa kolumna: Zdarzenia ProEl / Klipy / Wątki / Arkusze; pod wideo oś czasu z falą meczu, klipami, znacznikami z arkusza; skróty: Spacja, J/K/L, ←/→ 5 s, Shift+←/→ poprzednie/następne zdarzenie, M znacznik, I/O początek/koniec klipu, Enter zapisz klip, F tryb Kino, 1-9 kategoria) i tryb **Kino** (pełny ekran, bilety najbliższych zdarzeń przy krawędzi, pasek akcji wysuwany ruchem myszy, chowa się po 2 s, REC/I/O/M bez wychodzenia).
- `/mentor/{pairId}/klipy` - biblioteka klipów (siatka kafli z kategorią, filtry, zaznaczanie wielu → „Dodaj do zestawienia”).
- `/mentor/{pairId}/zestawienia/{id}` - zestawienie (kontrast: dwie kolumny A/B; odtwarzanie kolejką, przeciąganie kolejności).
- `/mentor/{pairId}/arkusze` - arkusze + trendy. `/mentor/{pairId}/raport` - kreator raportu z podglądem A4. `/mentor/{pairId}/ustawienia` - kategorie (kolor, ikona, przywróć domyślne).
- Odtwarzacz: `PlayerAdapter` (YouTube IFrame API, Vimeo player.js, HTML5 `<video>` dla nagrań) - `load/play/pause/seek/getTime/setRate/onTime/onState`, wirtualny klip = pętla `start..end`.
- Telefon w przeglądarce: ekran „Mentor najlepiej działa na komputerze albo w aplikacji BAZA” (+ otwórz w aplikacji, wyślij link na komputer); publiczne `/mentor/k|z|r/...` w pełni działają.

## 6. Aplikacja BAZA
- Kafel „Mentor” w Więcej (szeroki, gdy `GET /mentor-panel/pairs` zwraca co najmniej jedną włączoną parę).
- Pełny panel natywnie: lista par → pulpit → mecze (oś sezonu pionowo) → pokój meczu (istniejący `MatchVideoPlayer` rozszerzony o klipy, kategorie pary, zestawienia, wątki, arkusze) → biblioteka klipów → zestawienia → ustawienia kategorii.
- Szczegóły meczu: dotychczasowa ikona w nagłówku (wideo + prośba o ocenę) otwiera **hub „Mentor” meczu**: nagrania, prośba o ocenę (jak dziś), gwiazdka/zgłoś do omówienia, klipy i wątki meczu, „Otwórz pokój meczu”, „Otwórz na komputerze”.
- Logowanie QR: skaner (aparat) + deep link `refhandballapp://mentor/login/{code}` → arkusz „Zalogować komputer?” → `POST /auth/qr/{code}/approve`.
- „Otwórz na komputerze”: animowana karta z linkiem (Kopiuj / Wyślij / QR).
- Reguła iOS jednego modala (`docs/claude/modale-ios.md`) obowiązuje.

## 7. Projekt i ruch (wspólne)
- Zasady jak Communio (`Communio/docs/motion.md`): sprężyna osiada raz (`damping 24, stiffness 240, mass .85`), sukces `{13,240,.7}`; animujemy tylko transform/opacity; stan końcowy = stan bazowy; kaskady 45-90 ms, max ~8; reduced-motion; pętle tylko gdy widać.
- Web: system projektowy Pod Ręką (`components/pod-reka/ds`), ciemny motyw domyślny, tryb lekki na dotyku. Wektorowe ilustracje pustych stanów (np. pusta oś = tablica z gwizdkiem).
- Kolory kategorii z palety tokenów (bez hexów w ekranach).

## 5. Dopiski 24.10.2026: act_as, powiadomienia, kropki

- `?act_as=<judge_id mentora>` na trasach panelu: tylko administrator i tylko mentor tej pary (inaczej 403 `ACT_AS_FORBIDDEN` / `ACT_AS_NOT_MENTOR`). Wpisy mają autora = mentor oraz `acted_by` + `acted_by_name` (null gdy brak); ślad w `mentor_audit.acted_by`.
- Push `kind=mentor_panel`: `pairId, matchId, threadId, messageId, sheetId, target (sheet|thread|message), tag, notificationTag, notificationColor=#FF7A59` (+ `notificationSilent/Priority` przy cichej aktualizacji, `notificationImage` herb gospodarza). Tag: `mentor-thread-<threadId>`, `mentor-sheet-<matchId>`.
- Wątek: `my_follow` (`auto|follow|mute`), `unread`; `PUT /threads/{id}/follow {mode}`; `POST /threads/{id}/seen`.
- Kropki: `unread_threads`, `new_sheets` na liście par i w pulpicie; `unseen: {threads, sheet}` na karcie meczu (oś i pokój); `POST /pairs/{id}/matches/{mid}/sheet/seen`.

## 8. Handball Bastion (etap 1, 27.10.2026, za flagą `BASTION_ENABLED`)

Specyfikacja: handoff Bastion; wyniki bramki: `docs/bastion-integration.md`. Kod: `app/mentor_bastion*.py`.
`BASTION_ENABLED=false` (domyślnie) wyłącza wszystko: trasy niżej odpowiadają 404 `BASTION_DISABLED` (poza `GET /bastion/status`),
link do portalu jest zwykłym linkiem (`provider:"video"`), YouTube/Vimeo/uploady działają jak dotąd.

### 8.1 Zasady
- Trzy różne rzeczy: sesja BAZY, sesja Bastionu (tylko w connectorze), czasowy adres Bunny (tylko w odpowiedzi `playback`, `Cache-Control: no-store`, nigdy w bazie ani logach).
- Zarządzanie połączeniami używa PRAWDZIWEGO aktora (`base_actor`); `?act_as=` jest ignorowane (zapisywane tylko jako `acted_as_judge_id` próby). Połączenie domyślne tworzy/odnawia/rozłącza tylko prawdziwy admin (inaczej 403 `BASTION_CONNECTION_FORBIDDEN`).
- Dostęp do pokoju w `playback` sprawdzają zwykłe reguły Mentora (także `act_as`), ale połączenie wybiera prawdziwy użytkownik: domyślne, potem jego własne. Osobista sesja nigdy nie jest pożyczana.
- Błędy Bastionu nigdy nie są 401 (nie wylogowują): 409 `BASTION_AUTH_REQUIRED`, 403 `BASTION_RESOURCE_FORBIDDEN`, 503 `BASTION_UNAVAILABLE`, 429 `BASTION_RATE_LIMITED`. Awaria sieci lub portalu nie zmienia stanu sesji.
- `expires_at` połączenia = zawsze `null` (TTL sesji Bastionu nieznany).
- Odpowiedzi tras `/bastion/*` i `playback`: `Cache-Control: no-store`.

### 8.2 Wideo
`POST .../videos {url}` dla adresu `https://portal.handball-bastion.pl/game?bunny_item_id=N` (dokładny host, bez userinfo i portu) daje `Video` z `provider:"bastion"`, `url` kanonicznym (bez `at`), `external_id:"N"`, `playable:true`, bez `play_url`. Bez pobierania podglądu. Ten sam film = jeden wiersz. Pole `external_id` jest null u innych źródeł.

### 8.3 API
`ConnectionState = {enabled, status:"unconfigured|checking|ready|reauth_required|unavailable|revoked", last_known_status?, can_reconnect, account_label|null, last_validated_at|null, expires_at:null, last_error_code|null, generation}`

- `GET /bastion/status` -> `{enabled, service:"ok|unavailable|unconfigured|disabled", default: ConnectionState|null, personal: ConnectionState|null, effective_scope:"default|personal"|null, last_validated_at, expires_at:null, is_admin}`. `effective_scope` to podpowiedź, nie gwarancja dostępu do meczu. Przy awarii connectora `status:"unavailable"` + `last_known_status`.
- `POST /bastion/default/check` (admin), `POST /bastion/personal/check` -> `{checked:bool, connection: ConnectionState}` (`checked` tylko gdy ustawiono `BASTION_PROBE_BUNNY_ITEM_ID` i odczyt się udał).
- `POST /bastion/login-attempts {scope:"default|personal", return_context?:{pair_id,match_id,video_id,clip_id,video_s,start_s,end_s}, probe_bunny_item_id?}` -> `{id, scope, status, expires_at, error, return_context, ticket, ticket_ttl_s, ws_url, resumed}`. `ticket` jednorazowy (60 s), idzie w 1. wiadomości WSS `{"type":"auth","ticket":...}`, nie w URL. `return_context` przyjmuje tylko identyfikatory i liczby (nigdy URL). 409 `BASTION_LOGIN_BUSY`, gdy trwa próba innej osoby.
- `GET /bastion/login-attempts/{id}` -> `{id, scope, status:"creating|waiting_for_user|verifying|succeeded|failed|cancelled|expired", expires_at, error, return_context, connection?, service?}`. Sukces (`succeeded`, z `connection`) wyłącznie ze statusu connectora; zamknięcie okna to nie sukces. Cudza próba osobista (także dla admina) = 404 `BASTION_ATTEMPT_NOT_FOUND`.
- `POST /bastion/login-attempts/{id}/ticket` -> `{id, ticket, ticket_ttl_s, ws_url}` (odświeżenie karty); `POST .../cancel` -> stan próby.
- `DELETE /bastion/default` (admin), `DELETE /bastion/personal` -> `{ok:true, status:"revoked", scope}`. Zaimportowane klipy zostają; aktywne zadania klipów przechodzą w `waiting_for_auth`.
- `POST /pairs/{p}/matches/{m}/videos/{v}/playback` (no-store) -> `{provider:"bastion", mode:"bunny_embed", embed_url, expires_at|null, connection_scope:"default|personal", capabilities:{seek:true, rate:false, mute:false}, duration_s|null, video_state, bunny_item_id}`.
  Kolejność: domyślne, potem osobiste (odmowa 403 na domyślnym też próbuje własne konto). Błędy mają kopertę `{error, code, message, connections:{scope:"auth_required|forbidden|..."}, can_connect_personal, can_renew_default}`:
  409 `BASTION_AUTH_REQUIRED` ("Połączenie domyślne jest niedostępne. Możesz użyć własnego konta."), 403 `BASTION_RESOURCE_FORBIDDEN` ("To konto nie ma dostępu do tego nagrania."), 503 `BASTION_UNAVAILABLE` ("Bastion chwilowo nie odpowiada. Spróbuj ponownie za chwilę."), 429 `BASTION_RATE_LIMITED`, 422 `VIDEO_NOT_BASTION`, 404 `VIDEO_NOT_FOUND`, 403 `NO_ACCESS`.

### 8.4 Dane (`app/mentor_bastion_tables.py`)
`mentor_bastion_connections` (unikalny `connection_key` = `default` albo `personal-<judge_id>`, CHECK scope/owner), `mentor_bastion_login_attempts`, `mentor_bastion_clip_jobs` (unikalne `clip_id`+`clip_revision`, stany z `mentor_bastion_rules.JOB_STATES`, lease, przypięcie do `connection_id` i `external_identity_id`), `mentor_clip_assets` (`origin_provider`, `source_start_s`/`source_end_s` osobno; `mentor_clips.source` bez zmian), kolumna `mentor_match_videos.external_id`. Eksport do Bastionu (etap 4): całe sekundy zaokrąglone na zewnątrz, 2-300 s (`bastion_clip_range`). Worker kolejki MP4: 8.5-8.7.

### 8.5 Podgląd linku (bilet meczu, 27.10.2026)
`POST /pairs/{p}/matches/{m}/bastion/resolve {url}` -> `{bunny_item_id, match_summary|null, same_match: true|false|null, access: "ok|auth_required|forbidden|rate_limited|unavailable", connection_scope, video_state}`.
Bez embedu i bez zapisu (connector `/playback?include_embed=false`). `match_summary = {home, away, date, competition, code, zprp_match_id, zprp_season_id, zprp_competition_id}` (tylko pola, które game-context ma; ksztalt klucza `match` nie jest publiczna umowa, connector zwraca tez nazwy pol `match_keys` do sprawdzenia na zywo). `same_match`: najpierw ID ZPRP meczu, potem para drużyn (obie kolejności), potem kod; `null` = brak danych (np. konto bez dostępu: wtedy `match_summary: null`, `access` mówi dlaczego, a nagranie można dodać dalej). 422 `BAD_BASTION_URL`, 404 `BASTION_DISABLED`.

### 8.6 Klipy MP4 z nagrań Bastion (etap 4, za `BASTION_ENABLED`)
**MP4 nie powstaje samo.** Przy zapisie klipu z nagrania Bastion użytkownik wybiera: "zapisz też jako MP4" albo "tylko znaczniki czasu" (klip wirtualny: gra z pełnego meczu, bez cięcia w Bastionie). `source` klipu bez zmian (pochodzenie sytuacji).
- `POST /pairs/{p}/clips` i `PATCH /clips/{id}` przyjmują `mp4: true|false` (domyślnie false). `true` zakłada zadanie w tej samej operacji. Odpowiedź ma dodatkowo `mp4_offer` (dla dialogu, tylko nagrania Bastion przy włączonej integracji): `{estimated_s: 90, min_s: 2, max_s: 300, eligible, reason|null, connection: {ok, scope: default|personal|null, account_label|null}}`. Zakres do Bastionu: całe sekundy zaokrąglone na zewnątrz (początek w dół, koniec w górę); poza 2-300 s MP4 niedostępne (`eligible:false`), klip wirtualny działa.
- `POST /pairs/{p}/clips/{c}/mp4 {action: "order"|"cancel"}` (domyślnie `order`; autor/admin): `order` = zamówienie później, idempotentne po rewizji (`{mp4_status, media, mp4_offer}`; 404 `BASTION_DISABLED`, 422 `CLIP_RANGE`, 409 `MP4_LINK_VIDEO`); `cancel` = anuluje zadanie, jeśli nic nie poszło do Bastionu albo leży w błędzie (`{cancelled, mp4_status, media}`), po wysłaniu 409 `MP4_CANCEL_TOO_LATE`. Stare `POST /clips/{id}/mp4` dla klipu Bastion robi to samo co `order`.
- Zmiana zakresu (`PATCH start_s/end_s`) podbija `mentor_clips.media_rev`. Klip, który miał MP4 (zadanie albo plik), dostaje nowe zadanie nowej rewizji; klip wirtualny zostaje wirtualny. Zadania starszych rewizji są anulowane, spóźniony wynik nie nadpisuje nowej rewizji (kontrola przy zapisie), stary plik zostaje do sukcesu nowego (potem jest kasowany), nigdy nie jest oznaczany jako plik nowego zakresu. Usunięcie klipu anuluje zadania i kasuje pliki; worker nie przywraca usuniętego klipu.
- `Clip.media` (null dla nagrań spoza Bastionu = zakres oryginału jak dotąd): `{kind: "virtual"|"mp4", mode: "asset"|"source_range"|"waiting", status, stage: saved|bastion_cutting|storing|ready|waiting_for_auth|failed|null, message (PL, §11.6), revision, video_id, range:{start_s,end_s}, eligible, can_order_mp4, can_resume, can_cancel, file_offset_s, asset: {id,revision,duration_s,width,height,size,has_poster,source_start_s,source_end_s}|null, job: {state, attempts, error_code, next_attempt_at, updated_at, sent_range}|null}`. `status`: `ready`, etap zadania, `virtual`, `not_exported` (poza 2-300 s) albo `waiting_for_source`. `needs_reconciliation` = stage `failed` + `job.error_code NEEDS_RECONCILIATION` (nie wiadomo, czy Bastion przyjął klip; zero automatycznych ponowień). Stary `mp4_status` jest wyprowadzany z `media` (`ready|working|failed|none`). Zmiany stanu podbijają `rev` (zakres `clips` w `GET /changes`).
- **Resolver odtwarzania** (`mentor_bastion_rules.resolve_clip_playback`, jeden dla pokoju, biblioteki, kina, kolejek, zestawień i publicznego klipu): gotowy plik BIEŻĄCEJ rewizji -> `mode:"asset"` (plik BAZY gra 0..`asset.duration_s`); w przygotowaniu, wirtualny albo po błędzie -> `mode:"source_range"` (zakres oryginału `range` + `status`); brak źródła -> `mode:"waiting"`. Kotwice wątków zostają w czasie oryginału; `clip_s` = `video_s - clip.start_s` (liczone przy odczycie). Czas w pliku: `file_s = video_s - asset.source_start_s` (= `clip_s + file_offset_s`, bo cięcie Bastionu zaczyna od całej sekundy w dół), przycinany do 0..duration (`file_time`).
- `GET /clips/{id}/playback` (no-store): resolver + podpisane adresy gotowego pliku `{play_url, poster_url, download_url (attachment, nazwa pliku z numeru meczu i tytułu), play_expires_in, download_expires_in}`; R2 obsługuje Range. Działa po odłączeniu Bastionu i przy wyłączonej fladze. `GET /clips/{id}/media` = sam blok `media`. `GET /clips/{id}/mp4` (istniejące) daje adres pobrania gotowego MP4. Publiczny klip z Bastionu: `media` z `play_url` gotowego pliku (bez adresu portalu, embedu i sesji).
- `POST /clips/{id}/media/resume` ("Wznów"; 404 `BASTION_DISABLED`): `waiting_for_auth`, `failed`, `retryable_failed`, `needs_reconciliation` wracają do kolejki. Zadanie ze zdalnym id wraca TYLKO na to samo połączenie i konto zewnętrzne (409 `BASTION_WRONG_ACCOUNT`, 409 `BASTION_AUTH_REQUIRED`; cudze konto osobiste 403 `BASTION_CONNECTION_FORBIDDEN`). Niepewny wynik wznawiany ręcznie dostaje nowy odcisk (może powstać drugi, prywatny klip w Bastionie). Po odnowieniu sesji tego samego konta zadania `waiting_for_auth` wracają same.

### 8.7 Worker i connector
- Stan i dzierżawa w bazie (`lease_until`, `worker_id`, UPDATE z warunkiem wolnej dzierżawy), `run_bastion_worker` startuje w `main.py` tylko przy `BASTION_ENABLED` (2 pętle; restart wznawia od zapisanego kroku; zdalne id raz zapisane nie wraca do cięcia). Backoff błędów 15 s .. 15 min z jitterem +-25% (maks. 8 prób), pytania o gotowość co 10-45 s (maks. 40). Pobranie: osobny klient bez ciasteczek, host z `BASTION_DOWNLOAD_HOST_SUFFIXES`, limit `BASTION_MAX_DOWNLOAD_MB` (400), ffprobe zgodny z zakresem (+-2 s), miniatura, upload do `MENTOR_S3_*` (fallback `BACKUP_S3_*`) pod `<prefiks>/<para>/clips/<klip>/r<rewizja>.mp4|jpg`, `ready` po uploadzie i metadanych. Błąd R2 = ponowienie pobrania i zapisu bez nowego zlecenia.
- Connector: `POST /clips {scope, judge_id, bunny_item_id, start_s, end_s, fingerprint, correlation}` (idempotentne po odcisku; ONLY_ME, NORMAL, PLAY_ON, treść "BAZA Mentor <korelacja>"; 200 / 202 needs_reconciliation / 422), `GET /clips/{remote_id}` (`ready`), `POST /clips/{remote_id}/download-url` (podpisany adres po walidacji hostów; plik pobiera BAZA bez ciasteczek). `/playback` zwraca też `match` (podsumowanie meczu).
