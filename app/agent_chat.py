# app/agent_chat.py

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Literal, Optional, Tuple, Dict, Any
from sqlalchemy import select
import json
import math

from app.db import database, agent_document_chunks, agent_documents
from app.groq_client import groq_chat_completion


class ChatMessage(BaseModel):
    role: Literal["system", "user", "assistant"]
    content: str


# TRYBY:
# - "baza": pytania o aplikację BAZA
# - "proel": pytania o system ProEl
# - "rules": pytania o przepisy piłki ręcznej + regulaminy lig
AgentMode = Literal["baza", "proel", "rules"]


# DOMYŚLNE ID DOKUMENTÓW – łatwe do edycji w jednym miejscu:
DEFAULT_BAZA_PRIMARY_DOC_ID = 15
DEFAULT_BAZA_SECONDARY_DOC_ID = 4

DEFAULT_PROEL_PRIMARY_DOC_ID = 4
DEFAULT_PROEL_SECONDARY_DOC_ID = 15

DEFAULT_RULES_PRIMARY_DOC_ID = 6  # główny dokument przepisów gry

# Dokumenty, które są „bazowe” dla BAZA/ProEl – wykluczane z trybu przepisów/regulaminów
BAZA_PROEL_DOC_IDS = {
    DEFAULT_BAZA_PRIMARY_DOC_ID,
    DEFAULT_PROEL_PRIMARY_DOC_ID,
}

# Minimalne similarity, poniżej którego uznajemy, że dopasowania są bez sensu
MIN_SIMILARITY_BAZA = 0.25
MIN_SIMILARITY_PROEL = 0.25
MIN_SIMILARITY_RULES = 0.20
MIN_SIMILARITY_GENERAL = 0.20


class AgentQueryRequest(BaseModel):
    messages: List[ChatMessage]
    model: Optional[str] = "llama-3.1-8b-instant"
    temperature: float = 0.2
    # limit długości odpowiedzi
    max_tokens: int = 2048
    # pomocniczo – ile maksymalnie chunków chcemy użyć w kontekście
    max_context_chunks: int = 32
    # TRYB pracy Bazylego – BAZA / ProEl / przepisy
    mode: Optional[AgentMode] = None


class AgentQueryResponse(BaseModel):
    reply: str


router = APIRouter(prefix="/agent", tags=["agent"])


def cosine_similarity(a: List[float], b: List[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(x * x for x in b))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


async def embed_query(text: str) -> List[float]:
    # używamy tego samego „embedding hack” co w agent_docs.py
    from app.agent_docs import simple_embed  # unikamy duplikacji kodu

    vecs = await simple_embed([text])
    return vecs[0]


def build_system_prompt(mode: Optional[AgentMode]) -> str:
    """
    Buduje system prompt Bazylego w zależności od trybu.
    Bardzo mocno pilnujemy:
    - ZERO ściemy / zgadywania,
    - tylko wiedza z rozmowy + ukrytych źródeł (chunków),
    - brak odwołań do dokumentów jako dokumentów.
    """

    base = (
        "Jesteś asystentem Bazyli – praktycznym ekspertem pomagającym sędziom "
        "i działaczom w pracy z aplikacją BAZA, systemem ProEl oraz przepisami "
        "i regulaminami piłki ręcznej.\n\n"
        "Podstawowe zasady, których MUSISZ bezwzględnie przestrzegać:\n"
        "1. Możesz korzystać TYLKO z informacji, które pojawiają się w tej "
        "konkretnej rozmowie (pytania/odpowiedzi) oraz z dodatkowych ukrytych "
        "materiałów źródłowych przekazanych Ci w roli systemu. "
        "NIE wolno Ci używać żadnej innej, ogólnej wiedzy ani pamięci modelu.\n"
        "2. Jeśli jakaś informacja nie występuje w tych źródłach – traktuj ją "
        "jako NIEZNANĄ. Nie zgaduj, nie dopowiadaj „bo tak zwykle bywa”, "
        "nie uzupełniaj luk wyobraźnią.\n"
        "3. Jeżeli nie masz wystarczających danych, aby odpowiedzieć pewnie, "
        "powiedz wprost, że na podstawie dostępnych informacji nie możesz "
        "udzielić jednoznacznej odpowiedzi. Możesz poprosić użytkownika o "
        "doprecyzowanie (np. poziomu rozgrywek), ale NIE wolno Ci wymyślać szczegółów.\n"
        "4. Nigdy nie wspominaj o dokumentach, PDF-ach, plikach, załącznikach, "
        "kontekście, embeddingach ani o „fragmentach dokumentów”. Użytkownik "
        "nie powinien wiedzieć, że korzystasz z takich materiałów.\n"
        "5. Nigdy nie odsyłaj użytkownika do dokumentów i nie pisz w stylu "
        "„szczegóły znajdziesz w dokumencie…”. Zamiast tego sam streść wszystkie "
        "potrzebne informacje i wypisz je w odpowiedzi.\n"
        "6. Jeśli pytanie dotyczy przepisów, regulaminów, założeń, zasad lub list punktów, "
        "to wypisz WSZYSTKIE istotne punkty, limity, wyjątki i warunki, które "
        "występują w dostępnych źródłach – nawet jeśli odpowiedź będzie długa.\n"
        "7. Nie próbuj „ulepszać” odpowiedzi dodawaniem niepewnych szczegółów. "
        "Jeżeli w źródłach nie ma konkretnej liczby, terminu lub wyjątku, "
        "powiedz, że nie jest on podany.\n"
        "8. Odpowiadaj jak praktyczny ekspert systemu (BAZA / ProEl / przepisy), "
        "który tłumaczy dokładnie co zrobić: krok po kroku, z nazwami zakładek, "
        "przycisków i typowymi pułapkami – jeśli takie informacje masz.\n"
        "9. Możesz używać sformułowań typu „zgodnie z przepisami gry” lub "
        "„regulamin rozgrywek przewiduje, że…”, ale nie pisz nigdy, że „w dokumencie X "
        "na stronie Y jest napisane…”.\n"
        "10. Odpowiadasz po polsku, chyba że użytkownik wyraźnie poprosi o inny język.\n"
        "11. Jeżeli w danym trybie (BAZA / ProEl / przepisy) nie masz żadnych "
        "wiarygodnych informacji powiązanych z pytaniem, powiedz wprost, "
        "że w tym trybie nie masz danych na ten temat, zamiast zgadywać.\n\n"
    )

    if mode == "baza":
        mode_part = (
            "TRYB: Aplikacja BAZA.\n"
            "Jesteś ekspertem od działania aplikacji BAZA, jej konfiguracji, "
            "integracji (np. z systemem ZPRP) oraz typowych problemów użytkowników.\n"
            "Myśl jak asystent w aplikacji BAZA: gdy użytkownik pyta „jak coś zrobić”, "
            "opisz dokładnie, co i gdzie kliknąć, jakie menu wybrać, jakie opcje zaznaczyć, "
            "ale TYLKO jeśli masz te informacje w źródłach.\n"
            "Jeśli pytanie wyraźnie dotyczy systemu ProEl lub przepisów/regulaminów gry, "
            "napisz uprzejmie, że w trybie BAZA nie masz informacji na ten temat i że "
            "taki temat powinien być obsłużony w odpowiednim trybie (ProEl / przepisy).\n"
        )
    elif mode == "proel":
        mode_part = (
            "TRYB: System ProEl.\n"
            "Jesteś ekspertem od systemu ProEl, jego działania, konfiguracji i integracji, "
            "w tym powiązań z BAZĄ oraz innymi systemami.\n"
            "Odpowiadaj tak, jakbyś znał interfejs ProEl „na pamięć”: krok po kroku, "
            "z nazwami modułów, ekranów i typowymi scenariuszami użycia – ale tylko tam, "
            "gdzie masz konkretne informacje w źródłach.\n"
            "Jeśli pytanie wyraźnie dotyczy aplikacji BAZA lub przepisów/regulaminów gry, "
            "napisz, że w trybie ProEl nie masz informacji na ten temat i że ten temat "
            "powinien być obsłużony w odpowiednim trybie (BAZA / przepisy).\n"
        )
    elif mode == "rules":
        mode_part = (
            "TRYB: Przepisy i regulaminy piłki ręcznej.\n"
            "Jesteś ekspertem od przepisów gry w piłkę ręczną oraz regulaminów "
            "i wytycznych rozgrywek (np. I liga, II liga, Liga Centralna, Puchar Polski).\n"
            "Najpierw szukaj odpowiedzi w ogólnych przepisach gry. Jeżeli tam nie ma "
            "odpowiedzi, możesz korzystać z regulaminów konkretnych rozgrywek i wytycznych, "
            "ale TYLKO tam, gdzie masz konkretne dane w źródłach.\n"
            "Jeśli pytanie dotyczy rozgrywek (np. spadków/awansów, zasad marketingowych) "
            "i na podstawie pytania NIE da się jednoznacznie ustalić, o który poziom "
            "rozgrywkowy chodzi (I liga, II liga, Liga Centralna, Puchar Polski), "
            "poproś użytkownika o doprecyzowanie poziomu rozgrywek, zamiast zgadywać.\n"
            "Jeśli pytanie dotyczy działania aplikacji BAZA lub systemu ProEl, "
            "napisz, że w trybie przepisów nie masz informacji na ten temat i że "
            "taki temat powinien być obsłużony w odpowiednim trybie aplikacji/systemu.\n"
        )
    else:
        mode_part = (
            "TRYB: Ogólny.\n"
            "Na podstawie treści pytania staraj się rozpoznać, czy chodzi bardziej o "
            "aplikację BAZA, system ProEl, czy przepisy/regulaminy piłki ręcznej, "
            "i odpowiadaj jak ekspert w tej dziedzinie. Jeżeli nie masz źródeł dla "
            "danego obszaru, powiedz wprost, że nie masz danych, zamiast zgadywać.\n"
        )

    return base + mode_part


def build_mode_filtered_query(mode: Optional[AgentMode]):
    """
    Buduje SELECT na agent_document_chunks z dołączeniem agent_documents
    oraz filtrami na document_id zależnie od trybu.

    - 'baza': tylko dokumenty (15, 4)
    - 'proel': tylko dokumenty (4, 15)
    - 'rules': wszystkie dokumenty poza (4, 15)
    - None: brak dodatkowego filtra (wszystkie dokumenty)
    """
    base_query = (
        select(
            agent_document_chunks,
            agent_documents.c.title.label("doc_title"),
        )
        .select_from(
            agent_document_chunks.join(
                agent_documents,
                agent_document_chunks.c.document_id == agent_documents.c.id,
            )
        )
    )

    if mode == "baza":
        allowed_ids = [
            DEFAULT_BAZA_PRIMARY_DOC_ID,
            DEFAULT_BAZA_SECONDARY_DOC_ID,
        ]
        base_query = base_query.where(
            agent_document_chunks.c.document_id.in_(allowed_ids)
        )

    elif mode == "proel":
        allowed_ids = [
            DEFAULT_PROEL_PRIMARY_DOC_ID,
            DEFAULT_PROEL_SECONDARY_DOC_ID,
        ]
        base_query = base_query.where(
            agent_document_chunks.c.document_id.in_(allowed_ids)
        )

    elif mode == "rules":
        # wszystkie dokumenty poza „bazowymi” BAZA/ProEl
        base_query = base_query.where(
            ~agent_document_chunks.c.document_id.in_(BAZA_PROEL_DOC_IDS)
        )

    # dla mode=None nie dodajemy żadnego dodatkowego filtra
    return base_query


def detect_topic_from_question(text: str) -> Optional[AgentMode]:
    """
    Bardzo proste heurystyczne wykrywanie, czy pytanie dotyczy
    bardziej BAZA czy ProEl. Możesz później rozbudować listę słów kluczowych.
    """
    t = text.lower()

    if "proel" in t or "pro el" in t:
        return "proel"
    if "baza" in t or "aplikacja baza" in t:
        return "baza"

    # dla przepisów zostawiamy decyzję modelowi w trybie 'rules'
    return None


def detect_league_hint(text: str) -> Optional[str]:
    """
    Wykrywa, czy w pytaniu jest wprost wskazany poziom rozgrywek:
    I liga, II liga, Liga Centralna, Puchar Polski.
    Zwraca symboliczne oznaczenie albo None.
    """
    t = text.lower()

    if "liga centralna" in t or "centralna liga" in t:
        return "liga_centralna"
    if "puchar polski" in t:
        return "puchar_polski"
    if "i liga" in t or "1 liga" in t or "pierwsza liga" in t:
        return "i_liga"
    if "ii liga" in t or "2 liga" in t or "druga liga" in t:
        return "ii_liga"

    return None


def is_additional_regulations_question(text: str) -> bool:
    """
    Próbuje wykryć, czy pytanie dotyczy raczej dodatkowych regulaminów/wytycznych
    konkretnych lig (I, II, Liga Centralna, Puchar Polski), niż ogólnych przepisów gry.
    """
    t = text.lower()

    base_keywords = [
        "regulamin",
        "regulaminy",
        "wytyczne",
        "marketingowe",
        "marketing",
        "zasady ligi",
        "zapisy ligi",
        "warunki rozgrywek",
        "organizacja rozgrywek",
    ]
    if any(k in t for k in base_keywords):
        return True

    # Pytanie o ligę nawet bez słowa „regulamin”
    if "liga" in t and any(
        x in t
        for x in [
            "centralna",
            "i liga",
            "1 liga",
            "ii liga",
            "2 liga",
        ]
    ):
        return True

    if "puchar polski" in t:
        return True

    return False


def build_context_for_single_document(
    scored: List[Tuple[float, Dict[str, Any]]],
    target_doc_id: int,
    max_chars: int = 8000,
    max_chunks: int = 32,
    min_sim: float = 0.0,
    log_prefix: str = "",
) -> str:
    """
    Buduje kontekst wyłącznie z jednego dokumentu (po document_id),
    wybierając NAJBARDZIEJ PODOBNE chunki (po similarity >= min_sim),
    aż do limitu znaków oraz liczby chunków.
    Zwraca pusty string, jeśli brak sensownego dopasowania.
    """
    doc_rows: List[Tuple[float, Dict[str, Any]]] = [
        (sim, r)
        for (sim, r) in scored
        if r["document_id"] == target_doc_id and sim >= min_sim
    ]

    if not doc_rows:
        print(
            f"[agent_query] {log_prefix} Brak sensownych chunków (sim>={min_sim}) dla dokumentu {target_doc_id}"
        )
        return ""

    # sortujemy po similarity malejąco, wybieramy top N, a potem układamy po chunk_index
    doc_rows.sort(key=lambda x: x[0], reverse=True)
    top_rows = doc_rows[:max_chunks]
    best_sim = top_rows[0][0]

    top_rows.sort(key=lambda x: x[1]["chunk_index"])

    total_chars = 0
    parts: List[str] = []
    chunks_used = 0

    for sim, r in top_rows:
        part = f"{r['content']}\n\n---\n\n"
        if total_chars + len(part) > max_chars:
            break
        parts.append(part)
        total_chars += len(part)
        chunks_used += 1

    print(
        f"[agent_query] {log_prefix} Używam {chunks_used} fragmentów z dokumentu {target_doc_id} "
        f"(łącznie {total_chars} znaków, best_sim={best_sim:.4f})."
    )

    return "".join(parts)


@router.post("/query", response_model=AgentQueryResponse)
async def agent_query(payload: AgentQueryRequest):
    if not payload.messages:
        raise HTTPException(status_code=400, detail="Brak wiadomości")

    # znajdź ostatnią wiadomość użytkownika
    user_messages = [m for m in payload.messages if m.role == "user"]
    if not user_messages:
        raise HTTPException(
            status_code=400, detail="Brak wiadomości użytkownika w historii"
        )
    last_user_msg = user_messages[-1]

    print("[agent_query] Tryb:", payload.mode or "brak / ogólny")
    print("[agent_query] Ostatnia wiadomość usera:", last_user_msg.content)

    # temperatura – twardy limit 0.2 (żeby nie fantazjował)
    effective_temperature = min(payload.temperature, 0.2)

    # Detekcja tematu pytania (BAZA / ProEl) niezależnie od wybranego trybu
    detected_topic = detect_topic_from_question(last_user_msg.content)
    topic_mismatch = False

    if payload.mode in ("baza", "proel", "rules") and detected_topic is not None:
        # jeśli pytanie wygląda na ProEl, a tryb nie jest 'proel' → rozjazd
        if detected_topic == "proel" and payload.mode != "proel":
            topic_mismatch = True
        # jeśli pytanie wygląda na BAZA, a tryb nie jest 'baza' → rozjazd
        if detected_topic == "baza" and payload.mode != "baza":
            topic_mismatch = True

    # Jeśli jest rozjazd temat ↔ tryb – robimy grzeczny redirect, bez retrieval
    if topic_mismatch:
        system_prompt = build_system_prompt(payload.mode)

        if detected_topic == "proel":
            redirect_instr = (
                "Pytanie użytkownika dotyczy systemu ProEl (np. prowadzenia meczu, "
                "obsługi protokołu itp.), ale bieżący tryb NIE jest trybem ProEl. "
                "Twoje zadanie: odpowiedzieć JEDNYM krótkim akapitem, że szczegółowe "
                "informacje o obsłudze ProEl dostępne są tylko w trybie ProEl i że "
                "w tym trybie nie masz do nich dostępu. NIE opisuj żadnych kroków, "
                "nie podawaj szczegółów, nie próbuj zgadywać."
            )
        elif detected_topic == "baza":
            redirect_instr = (
                "Pytanie użytkownika dotyczy aplikacji BAZA, ale bieżący tryb NIE jest "
                "trybem BAZA. Twoje zadanie: odpowiedzieć JEDNYM krótkim akapitem, że "
                "szczegółowe informacje o aplikacji BAZA dostępne są tylko w trybie BAZA "
                "i że w tym trybie nie masz do nich dostępu. NIE opisuj żadnych kroków, "
                "nie podawaj szczegółów, nie próbuj zgadywać."
            )
        else:
            redirect_instr = (
                "Pytanie dotyczy innego trybu niż bieżący. Masz jedynie poprosić o zmianę "
                "trybu, bez wchodzenia w szczegóły merytoryczne."
            )

        groq_messages: List[dict] = [
            {"role": "system", "content": system_prompt},
            {"role": "system", "content": redirect_instr},
        ]
        for m in payload.messages:
            if m.role in ("user", "assistant"):
                groq_messages.append({"role": m.role, "content": m.content})

        reply = await groq_chat_completion(
            messages=groq_messages,
            model=payload.model or "llama-3.1-8b-instant",
            temperature=effective_temperature,
            max_tokens=payload.max_tokens or 2048,
        )
        print(
            "[agent_query] Odpowiedź z Groqa (redirect między trybami, początek):",
            reply[:500],
        )
        return AgentQueryResponse(reply=reply)

    # 1) embedding zapytania
    query_vec = await embed_query(last_user_msg.content)
    print("[agent_query] Długość wektora zapytania:", len(query_vec))
    print("[agent_query] Pierwsze kilka wartości zapytania:", query_vec[:5])

    # 2) pobierz chunki z uwzględnieniem trybu / document_id
    q = build_mode_filtered_query(payload.mode)
    rows = await database.fetch_all(q)
    print(
        "[agent_query] Liczba chunków w bazie po filtrze trybu:",
        len(rows),
    )

    # 3) jeśli w ogóle nie ma chunków – dalej też nie wolno zgadywać
    if not rows:
        print(
            "[agent_query] Brak chunków w bazie dla danego trybu – brak kontekstu, "
            "ale nadal obowiązuje zakaz zgadywania."
        )
        system_prompt = build_system_prompt(payload.mode)
        groq_messages: List[dict] = [{"role": "system", "content": system_prompt}]
        for m in payload.messages:
            if m.role in ("user", "assistant"):
                groq_messages.append({"role": m.role, "content": m.content})

        reply = await groq_chat_completion(
            messages=groq_messages,
            model=payload.model or "llama-3.1-8b-instant",
            temperature=effective_temperature,
            max_tokens=payload.max_tokens or 2048,
        )
        return AgentQueryResponse(reply=reply)

    # 4) policz similarity dla każdego chunku
    scored: List[Tuple[float, Dict[str, Any]]] = []
    for row in rows:
        r_dict = dict(row)
        try:
            emb = json.loads(r_dict["embedding"])
            sim = cosine_similarity(query_vec, [float(x) for x in emb])
        except Exception as e:
            print("[agent_query] Błąd przy liczeniu similarity:", e)
            sim = 0.0
        scored.append((sim, r_dict))

    # sort malejąco po similarity
    scored.sort(key=lambda x: x[0], reverse=True)

    # DEBUG: pokaż top 8 chunków wg similarity
    debug_top_n = min(8, len(scored))
    print(f"[agent_query] TOP {debug_top_n} chunków wg similarity:")
    for i, (sim, r) in enumerate(scored[:debug_top_n]):
        snippet = r["content"][:150].replace("\n", " ")
        print(
            f"  #{i} sim={sim:.4f}, doc_id={r['document_id']}, "
            f"title='{r.get('doc_title', '')}', "
            f"chunk_index={r['chunk_index']}, snippet='{snippet}'"
        )

    # 5) budowanie kontekstu wg trybu i priorytetów document_id
    context_text = ""
    max_context_chunks = payload.max_context_chunks or 32
    needs_league_clarification = False  # dla trybu 'rules'

    if not scored:
        print("[agent_query] Brak wyników po scoringu – brak kontekstu")
    else:
        if payload.mode == "baza":
            # najpierw dokument 15, potem 4, potem brak dopasowania
            context_text = build_context_for_single_document(
                scored,
                DEFAULT_BAZA_PRIMARY_DOC_ID,
                max_chars=8000,
                max_chunks=max_context_chunks,
                min_sim=MIN_SIMILARITY_BAZA,
                log_prefix="Tryb 'baza' (PRIMARY)",
            )
            if not context_text:
                context_text = build_context_for_single_document(
                    scored,
                    DEFAULT_BAZA_SECONDARY_DOC_ID,
                    max_chars=8000,
                    max_chunks=max_context_chunks,
                    min_sim=MIN_SIMILARITY_BAZA,
                    log_prefix="Tryb 'baza' (SECONDARY)",
                )
            if not context_text:
                print(
                    "[agent_query] Tryb 'baza': brak sensownego dopasowania w dokumentach "
                    f"{DEFAULT_BAZA_PRIMARY_DOC_ID}/{DEFAULT_BAZA_SECONDARY_DOC_ID} – brak kontekstu."
                )

        elif payload.mode == "proel":
            # najpierw dokument 4, potem 15, potem brak dopasowania
            context_text = build_context_for_single_document(
                scored,
                DEFAULT_PROEL_PRIMARY_DOC_ID,
                max_chars=8000,
                max_chunks=max_context_chunks,
                min_sim=MIN_SIMILARITY_PROEL,
                log_prefix="Tryb 'proel' (PRIMARY)",
            )
            if not context_text:
                context_text = build_context_for_single_document(
                    scored,
                    DEFAULT_PROEL_SECONDARY_DOC_ID,
                    max_chars=8000,
                    max_chunks=max_context_chunks,
                    min_sim=MIN_SIMILARITY_PROEL,
                    log_prefix="Tryb 'proel' (SECONDARY)",
                )
            if not context_text:
                print(
                    "[agent_query] Tryb 'proel': brak sensownego dopasowania w dokumentach "
                    f"{DEFAULT_PROEL_PRIMARY_DOC_ID}/{DEFAULT_PROEL_SECONDARY_DOC_ID} – brak kontekstu."
                )

        elif payload.mode == "rules":
            # Najpierw PRÓBA w głównych przepisach gry (doc_id = 6)
            rules_context = build_context_for_single_document(
                scored,
                DEFAULT_RULES_PRIMARY_DOC_ID,
                max_chars=8000,
                max_chunks=max_context_chunks,
                min_sim=MIN_SIMILARITY_RULES,
                log_prefix="Tryb 'rules' (PRIMARY RULES)",
            )

            if rules_context:
                # jeśli przepisy gry coś mówią – korzystamy w pierwszej kolejności
                context_text = rules_context
            else:
                # brak sensownego dopasowania w przepisach gry → może chodzi o
                # regulaminy lig / wytyczne dodatkowe
                question_text = last_user_msg.content
                league_hint = detect_league_hint(question_text)
                is_reg_q = is_additional_regulations_question(question_text)

                if is_reg_q and league_hint is None:
                    # wiemy, że pytanie jest o regulaminy/wytyczne ligowe,
                    # ale nie wiemy, o który poziom (I/II/LC/PP) – trzeba dopytać
                    needs_league_clarification = True
                    print(
                        "[agent_query] Tryb 'rules': pytanie o regulamin/wytyczne ligowe, "
                        "ale brak jednoznacznego poziomu rozgrywek – prosimy o doprecyzowanie."
                    )
                else:
                    # możemy budować szeroki kontekst z pozostałych dokumentów
                    max_chars = 8000
                    total_chars = 0
                    parts: List[str] = []

                    # tylko sensowne dopasowania spoza dokumentu z przepisami
                    scored_positive: List[Tuple[float, Dict[str, Any]]] = [
                        (sim, r)
                        for (sim, r) in scored
                        if sim >= MIN_SIMILARITY_RULES
                        and r["document_id"] != DEFAULT_RULES_PRIMARY_DOC_ID
                    ]

                    if not scored_positive:
                        print(
                            "[agent_query] Tryb 'rules': brak sensownych dopasowań "
                            "w regulaminach/wytycznych ligowych."
                        )
                    else:
                        remaining_by_doc: Dict[int, List[Tuple[float, Dict[str, Any]]]] = {}
                        for sim, r in scored_positive:
                            doc_id = r["document_id"]
                            # BAZA/ProEl już są wykluczone na poziomie zapytania,
                            # więc tu przyjmujemy wszystko inne
                            remaining_by_doc.setdefault(doc_id, []).append((sim, r))

                        # sort dokumenty po maksymalnym similarity (descending)
                        sorted_doc_ids = sorted(
                            remaining_by_doc.keys(),
                            key=lambda doc_id: max(
                                sim for (sim, _r) in remaining_by_doc[doc_id]
                            ),
                            reverse=True,
                        )

                        local_chunks_used = 0
                        for doc_id in sorted_doc_ids:
                            doc_rows = remaining_by_doc[doc_id]
                            doc_rows.sort(key=lambda x: x[0], reverse=True)
                            local_count = 0
                            for sim, r in doc_rows:
                                if local_chunks_used >= max_context_chunks:
                                    break
                                part = f"{r['content']}\n\n---\n\n"
                                if total_chars + len(part) > max_chars:
                                    break
                                parts.append(part)
                                total_chars += len(part)
                                local_chunks_used += 1
                                local_count += 1
                            print(
                                f"[agent_query] Tryb 'rules': dodaję {local_count} fragmentów z dokumentu {doc_id}."
                            )
                            if total_chars >= max_chars or local_chunks_used >= max_context_chunks:
                                break

                        context_text = "".join(parts)
                        print(
                            f"[agent_query] Tryb 'rules': łączny kontekst {total_chars} znaków "
                            "z regulaminów/wytycznych."
                        )

        else:
            # tryb ogólny – najlepszy dokument po similarity,
            # ale wybieramy NAJBARDZIEJ PODOBNE chunki z tego dokumentu
            best_sim, best_row = scored[0]
            if best_sim < MIN_SIMILARITY_GENERAL:
                print(
                    "[agent_query] Tryb 'ogólny': najlepsze similarity < MIN_SIMILARITY_GENERAL "
                    "– brak sensownego dopasowania."
                )
            else:
                best_doc_id = best_row["document_id"]
                print(
                    f"[agent_query] Tryb 'ogólny': najlepszy dokument doc_id={best_doc_id} "
                    f"(sim={best_sim:.4f})."
                )

                context_text = build_context_for_single_document(
                    scored,
                    best_doc_id,
                    max_chars=8000,
                    max_chunks=max_context_chunks,
                    min_sim=MIN_SIMILARITY_GENERAL,
                    log_prefix="Tryb 'ogólny'",
                )

    # Jeśli w trybie 'rules' trzeba doprecyzować ligę – robimy osobne wywołanie Groqa
    if payload.mode == "rules" and needs_league_clarification:
        system_prompt = build_system_prompt(payload.mode)
        clarify_instr = (
            "Pytanie dotyczy regulaminu lub wytycznych ligowych (np. I liga, II liga, "
            "Liga Centralna, Puchar Polski), ale na podstawie treści pytania nie da się "
            "jednoznacznie ustalić, o który poziom rozgrywek chodzi.\n"
            "Twoje zadanie: odpowiedzieć JEDNYM krótkim, uprzejmym akapitem po polsku, "
            "w którym poprosisz użytkownika o doprecyzowanie, czy chodzi o I ligę, "
            "II ligę, Ligę Centralną czy Puchar Polski. NIE próbuj zgadywać, "
            "nie opisuj jeszcze żadnych szczegółowych zasad ani przepisów."
        )

        groq_messages: List[dict] = [
            {"role": "system", "content": system_prompt},
            {"role": "system", "content": clarify_instr},
        ]
        for m in payload.messages:
            if m.role in ("user", "assistant"):
                groq_messages.append({"role": m.role, "content": m.content})

        reply = await groq_chat_completion(
            messages=groq_messages,
            model=payload.model or "llama-3.1-8b-instant",
            temperature=effective_temperature,
            max_tokens=payload.max_tokens or 2048,
        )
        print(
            "[agent_query] Odpowiedź z Groqa (doprecyzowanie ligi, początek):",
            reply[:500],
        )
        return AgentQueryResponse(reply=reply)

    if context_text:
        print("[agent_query] KONTEKST (początek):")
        print(context_text[:2000])
    else:
        print(
            "[agent_query] Brak kontekstu – odpowiedź musi być oparta wyłącznie na pytaniu "
            "użytkownika (bez zgadywania)."
        )

    # 6) System prompt – zależny od trybu (z mocnym zakazem ściemniania)
    system_prompt = build_system_prompt(payload.mode)

    # 7) budujemy wiadomości dla Groqa
    groq_messages: List[dict] = [{"role": "system", "content": system_prompt}]

    if context_text:
        groq_messages.append(
            {
                "role": "system",
                "content": (
                    "Poniżej masz ukryte dla użytkownika dodatkowe informacje "
                    "źródłowe. Użyj ich, aby udzielić jak najlepszej odpowiedzi, "
                    "ale NIE wspominaj, że korzystasz z jakichkolwiek dokumentów "
                    "czy kontekstu. Pamiętaj: jeśli czegoś w tych źródłach nie ma, "
                    "masz powiedzieć, że tego nie wiesz, zamiast zgadywać:\n\n"
                    f"{context_text}"
                ),
            }
        )

    # dodaj historię czatu (bez wcześniejszych systemów)
    for m in payload.messages:
        if m.role in ("user", "assistant"):
            groq_messages.append({"role": m.role, "content": m.content})

    print("[agent_query] Liczba wiadomości wysyłanych do Groqa:", len(groq_messages))

    reply = await groq_chat_completion(
        messages=groq_messages,
        model=payload.model or "llama-3.1-8b-instant",
        temperature=effective_temperature,
        max_tokens=payload.max_tokens or 2048,
    )

    # dla debug – utnij log do 500 znaków
    print("[agent_query] Odpowiedź z Groqa (początek):", reply[:500])

    return AgentQueryResponse(reply=reply)
