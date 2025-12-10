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
# - "rules": pytania o przepisy piłki ręcznej
AgentMode = Literal["baza", "proel", "rules"]


# DOMYŚLNE ID DOKUMENTÓW – łatwe do edycji w jednym miejscu:
DEFAULT_BAZA_PRIMARY_DOC_ID = 15
DEFAULT_BAZA_SECONDARY_DOC_ID = 4

DEFAULT_PROEL_PRIMARY_DOC_ID = 4
DEFAULT_PROEL_SECONDARY_DOC_ID = 15

DEFAULT_RULES_PRIMARY_DOC_ID = 6

# Dokumenty, które są „bazowe” dla BAZA/ProEl – wykluczane z trybu przepisów
BAZA_PROEL_DOC_IDS = {
    DEFAULT_BAZA_PRIMARY_DOC_ID,
    DEFAULT_PROEL_PRIMARY_DOC_ID,
}


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
        "piłki ręcznej.\n\n"
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
        "udzielić jednoznacznej odpowiedzi. Możesz zaproponować doprecyzowanie "
        "pytania, ale NIE wolno Ci wymyślać szczegółów.\n"
        "4. Nigdy nie wspominaj o dokumentach, PDF-ach, plikach, załącznikach, "
        "kontekście, embeddingach ani o „fragmentach dokumentów”. Użytkownik "
        "nie powinien wiedzieć, że korzystasz z takich materiałów.\n"
        "5. Nigdy nie odsyłaj użytkownika do dokumentów i nie pisz w stylu "
        "„szczegóły znajdziesz w dokumencie…”. Zamiast tego sam streść wszystkie "
        "potrzebne informacje i wypisz je w odpowiedzi.\n"
        "6. Jeśli pytanie dotyczy przepisów, założeń, zasad lub list punktów, "
        "to wypisz WSZYSTKIE istotne punkty, limity, wyjątki i warunki, które "
        "występują w dostępnych źródłach – nawet jeśli odpowiedź będzie długa.\n"
        "7. Nie próbuj „ulepszać” odpowiedzi dodawaniem niepewnych szczegółów. "
        "Jeżeli w źródłach nie ma konkretnej liczby, terminu lub wyjątku, "
        "powiedz, że nie jest on podany.\n"
        "8. Odpowiadaj jak praktyczny ekspert systemu (BAZA / ProEl / przepisy), "
        "który tłumaczy dokładnie co zrobić: krok po kroku, z nazwami zakładek, "
        "przycisków i typowymi pułapkami – jeśli takie informacje masz.\n"
        "9. Możesz używać sformułowań typu „zgodnie z przepisami gry”, "
        "„regulamin przewiduje, że…”, ale nie pisz nigdy, że „w dokumencie X "
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
            "Jeśli pytanie wyraźnie dotyczy systemu ProEl lub przepisów gry w piłkę ręczną, "
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
            "Jeśli pytanie wyraźnie dotyczy aplikacji BAZA lub przepisów gry w piłkę ręczną, "
            "napisz, że w trybie ProEl nie masz informacji na ten temat i że ten temat "
            "powinien być obsłużony w odpowiednim trybie (BAZA / przepisy).\n"
        )
    elif mode == "rules":
        mode_part = (
            "TRYB: Przepisy piłki ręcznej.\n"
            "Jesteś ekspertem od przepisów piłki ręcznej oraz ich praktycznej "
            "interpretacji z perspektywy sędziego.\n"
            "Wykorzystuj szeroki kontekst z wielu źródeł naraz, łącząc informacje "
            "z różnych miejsc regulaminów i wytycznych, ale TYLKO tam, gdzie "
            "masz konkretne dane w źródłach.\n"
            "Jeśli pytanie dotyczy działania aplikacji BAZA lub systemu ProEl, "
            "napisz, że w trybie przepisów nie masz informacji na ten temat i że "
            "taki temat powinien być obsłużony w odpowiednim trybie aplikacji/systemu.\n"
        )
    else:
        mode_part = (
            "TRYB: Ogólny.\n"
            "Na podstawie treści pytania staraj się rozpoznać, czy chodzi bardziej o "
            "aplikację BAZA, system ProEl, czy przepisy piłki ręcznej, i odpowiadaj "
            "jak ekspert w tej dziedzinie. Jeżeli nie masz źródeł dla danego obszaru, "
            "powiedz wprost, że nie masz danych, zamiast zgadywać.\n"
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


def build_context_for_single_document(
    scored: List[Tuple[float, Dict[str, Any]]],
    target_doc_id: int,
    max_chars: int = 8000,
    max_chunks: int = 32,
    log_prefix: str = "",
) -> str:
    """
    Buduje kontekst wyłącznie z jednego dokumentu (po document_id),
    wybierając NAJBARDZIEJ PODOBNE chunki (po similarity),
    aż do limitu znaków oraz liczby chunków.
    Zwraca pusty string, jeśli brak sensownego dopasowania
    (brak chunków z sim > 0).
    """
    doc_rows: List[Tuple[float, Dict[str, Any]]] = [
        (sim, r)
        for (sim, r) in scored
        if r["document_id"] == target_doc_id and sim > 0
    ]

    if not doc_rows:
        print(
            f"[agent_query] {log_prefix} Brak sensownych chunków (sim>0) dla dokumentu {target_doc_id}"
        )
        return ""

    # sortujemy po similarity malejąco – chcemy najpierw najbardziej trafne fragmenty
    doc_rows.sort(key=lambda x: x[0], reverse=True)

    total_chars = 0
    parts: List[str] = []
    chunks_used = 0

    best_sim = doc_rows[0][0]

    for sim, r in doc_rows:
        if chunks_used >= max_chunks:
            break
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
            temperature=payload.temperature,
            max_tokens=payload.max_tokens,
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
                log_prefix="Tryb 'baza' (PRIMARY)",
            )
            if not context_text:
                context_text = build_context_for_single_document(
                    scored,
                    DEFAULT_BAZA_SECONDARY_DOC_ID,
                    max_chars=8000,
                    max_chunks=max_context_chunks,
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
                log_prefix="Tryb 'proel' (PRIMARY)",
            )
            if not context_text:
                context_text = build_context_for_single_document(
                    scored,
                    DEFAULT_PROEL_SECONDARY_DOC_ID,
                    max_chars=8000,
                    max_chunks=max_context_chunks,
                    log_prefix="Tryb 'proel' (SECONDARY)",
                )
            if not context_text:
                print(
                    "[agent_query] Tryb 'proel': brak sensownego dopasowania w dokumentach "
                    f"{DEFAULT_PROEL_PRIMARY_DOC_ID}/{DEFAULT_PROEL_SECONDARY_DOC_ID} – brak kontekstu."
                )

        elif payload.mode == "rules":
            # najpierw dokument 6, potem wszystkie pozostałe (bez 4 i 15),
            # z szerokim kontekstem z wielu dokumentów
            max_chars = 8000
            total_chars = 0
            parts: List[str] = []

            # tylko sensowne dopasowania
            scored_positive: List[Tuple[float, Dict[str, Any]]] = [
                (sim, r) for (sim, r) in scored if sim > 0
            ]

            if not scored_positive:
                print(
                    "[agent_query] Tryb 'rules': wszystkie similarity <= 0 – brak sensownego kontekstu."
                )
            else:
                # 1) dokument 6 (PRIMARY RULES) – bierzemy najbardziej podobne chunki
                doc6_rows = [
                    (sim, r)
                    for (sim, r) in scored_positive
                    if r["document_id"] == DEFAULT_RULES_PRIMARY_DOC_ID
                ]
                local_chunks_used = 0
                if doc6_rows:
                    doc6_rows.sort(key=lambda x: x[0], reverse=True)
                    for sim, r in doc6_rows:
                        if local_chunks_used >= max_context_chunks:
                            break
                        part = f"{r['content']}\n\n---\n\n"
                        if total_chars + len(part) > max_chars:
                            break
                        parts.append(part)
                        total_chars += len(part)
                        local_chunks_used += 1
                    print(
                        f"[agent_query] Tryb 'rules': używam {local_chunks_used} fragmentów z dokumentu "
                        f"{DEFAULT_RULES_PRIMARY_DOC_ID} (PRIMARY RULES)."
                    )
                else:
                    print(
                        "[agent_query] Tryb 'rules': brak sensownego dopasowania w dokumencie "
                        f"{DEFAULT_RULES_PRIMARY_DOC_ID}."
                    )

                # 2) pozostałe dokumenty (bez 4, 15 i bez doc 6)
                remaining_by_doc: Dict[int, List[Tuple[float, Dict[str, Any]]]] = {}
                for sim, r in scored_positive:
                    doc_id = r["document_id"]
                    if doc_id == DEFAULT_RULES_PRIMARY_DOC_ID:
                        continue
                    if doc_id in BAZA_PROEL_DOC_IDS:
                        continue
                    remaining_by_doc.setdefault(doc_id, []).append((sim, r))

                # sort dokumenty po maksymalnym similarity (descending)
                sorted_doc_ids = sorted(
                    remaining_by_doc.keys(),
                    key=lambda doc_id: max(
                        sim for (sim, _r) in remaining_by_doc[doc_id]
                    ),
                    reverse=True,
                )

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
                    f"[agent_query] Tryb 'rules': łączny kontekst {total_chars} znaków."
                )

        else:
            # tryb ogólny – najlepszy dokument po similarity,
            # ale wybieramy NAJBARDZIEJ PODOBNE chunki z tego dokumentu
            best_sim, best_row = scored[0]
            if best_sim <= 0:
                print(
                    "[agent_query] Tryb 'ogólny': najlepsze similarity <= 0 – brak sensownego dopasowania."
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
                    log_prefix="Tryb 'ogólny'",
                )

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
        temperature=payload.temperature,
        max_tokens=payload.max_tokens or 2048,
    )

    # dla debug – utnij log do 500 znaków
    print("[agent_query] Odpowiedź z Groqa (początek):", reply[:500])

    return AgentQueryResponse(reply=reply)
