# app/agent_chat.py

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Literal, Optional, Tuple, Dict, Any
from sqlalchemy import select
import json
import math

from app.db import database, agent_document_chunks
from app.groq_client import groq_chat_completion


class ChatMessage(BaseModel):
    role: Literal["system", "user", "assistant"]
    content: str


class AgentQueryRequest(BaseModel):
    messages: List[ChatMessage]
    model: Optional[str] = "llama-3.1-8b-instant"
    temperature: float = 0.2
    # zwiększamy domyślny limit odpowiedzi
    max_tokens: int = 2048
    # to pole zostanie teraz użyte tylko pomocniczo, ale zostawiamy
    max_context_chunks: int = 32


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

    print("[agent_query] Ostatnia wiadomość usera:", last_user_msg.content)

    # 1) embedding zapytania
    query_vec = await embed_query(last_user_msg.content)
    print("[agent_query] Długość wektora zapytania:", len(query_vec))
    print("[agent_query] Pierwsze kilka wartości zapytania:", query_vec[:5])

    # 2) pobierz wszystkie chunki
    q = select(agent_document_chunks)
    rows = await database.fetch_all(q)
    print("[agent_query] Liczba chunków w bazie:", len(rows))

    if not rows:
        # nie ma żadnych dokumentów – fallback: normalny czat z Groq
        print("[agent_query] Brak chunków w bazie – fallback do czystego modelu")
        reply = await groq_chat_completion(
            messages=[{"role": m.role, "content": m.content} for m in payload.messages],
            model=payload.model or "llama-3.1-8b-instant",
            temperature=payload.temperature,
            max_tokens=payload.max_tokens,
        )
        return AgentQueryResponse(reply=reply)

    # 3) policz similarity dla każdego chunku
    scored: List[Tuple[float, Dict[str, Any]]] = []
    for row in rows:
        try:
            emb = json.loads(row["embedding"])
            sim = cosine_similarity(query_vec, [float(x) for x in emb])
        except Exception as e:
            print("[agent_query] Błąd przy liczeniu similarity:", e)
            sim = 0.0
        scored.append((sim, dict(row)))

    # sort malejąco po similarity
    scored.sort(key=lambda x: x[0], reverse=True)

    # DEBUG: pokaż top 8 chunków wg similarity
    debug_top_n = min(8, len(scored))
    print(f"[agent_query] TOP {debug_top_n} chunków wg similarity:")
    for i, (sim, r) in enumerate(scored[:debug_top_n]):
        snippet = r["content"][:150].replace("\n", " ")
        print(
            f"  #{i} sim={sim:.4f}, doc_id={r['document_id']}, "
            f"chunk_index={r['chunk_index']}, snippet='{snippet}'"
        )

    best_sim, best_row = scored[0]
    if best_sim <= 0:
        # nic niepasujące – lepiej szczerze powiedzieć, że nie wiemy
        print("[agent_query] Najlepsze similarity <= 0 – brak sensownego dopasowania")
        context_text = ""
    else:
        best_doc_id = best_row["document_id"]
        print(
            f"[agent_query] Najlepszy dokument: doc_id={best_doc_id} "
            f"(sim={best_sim:.4f})"
        )

        # 4) Zamiast brać top N *chunków z różnych dokumentów*,
        #    bierzemy WSZYSTKIE chunki z najlepszego dokumentu,
        #    w kolejności chunk_index, aż do limitu znaków.
        doc_rows: List[Dict[str, Any]] = [
            r for (_s, r) in scored if r["document_id"] == best_doc_id
        ]
        doc_rows.sort(key=lambda r: r["chunk_index"])

        max_chars = 8000  # limit znaków kontekstu
        total_chars = 0
        context_parts: List[str] = []

        for r in doc_rows:
            part = f"[Fragment #{r['chunk_index']}]\n{r['content']}\n\n---\n\n"
            if total_chars + len(part) > max_chars:
                break
            context_parts.append(part)
            total_chars += len(part)

        context_text = "".join(context_parts)
        print(
            f"[agent_query] Używam {len(context_parts)} fragmentów z dokumentu "
            f"{best_doc_id} jako kontekst (łącznie {total_chars} znaków)."
        )

    if context_text:
        print("[agent_query] KONTEKST (początek):")
        print(context_text[:2000])
    else:
        print("[agent_query] Brak kontekstu – żadnych fragmentów do użycia")

    # 5) System prompt – mocno nastawiony na PEŁNĄ, WYCIERPNUJĄCĄ odpowiedź
    system_prompt = (
        "Jesteś asystentem Bazyli.\n"
        "Masz odpowiadać WYŁĄCZNIE w oparciu o podany kontekst z dokumentów.\n"
        "Jeśli czegoś nie ma w kontekście – jasno napisz, że tego nie wiesz, "
        "zamiast zgadywać.\n\n"
        "Zasady odpowiedzi:\n"
        "1. Zawsze twórz pełne, wyczerpujące odpowiedzi w oparciu o kontekst.\n"
        "2. Jeśli pytanie dotyczy przepisów, założeń, zasad, list punktów itp., "
        "to wypisz WSZYSTKIE istotne punkty z kontekstu w czytelnej, "
        "ponumerowanej formie.\n"
        "3. Nie pomijaj wyjątków, liczb, limitów ani szczegółowych warunków, "
        "nawet jeśli odpowiedź będzie długa.\n"
        "4. Odpowiadaj po polsku, chyba że użytkownik wyraźnie prosi o inny język.\n"
    )

    # 6) budujemy wiadomości dla Groqa
    groq_messages: List[dict] = [{"role": "system", "content": system_prompt}]

    if context_text:
        groq_messages.append(
            {
                "role": "system",
                "content": (
                    "Kontekst do wykorzystania (fragmenty jednego dokumentu):\n\n"
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
