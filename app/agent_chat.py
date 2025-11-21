# app/agent_chat.py

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Literal, Optional
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
    max_tokens: int = 1024
    max_context_chunks: int = 8


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

    # embedding zapytania
    query_vec = await embed_query(last_user_msg.content)
    print("[agent_query] Długość wektora zapytania:", len(query_vec))
    print("[agent_query] Pierwsze kilka wartości zapytania:", query_vec[:5])

    # pobierz wszystkie chunki (v1 – prosty wariant, można potem dodać filtr po dokumencie)
    q = select(agent_document_chunks)
    rows = await database.fetch_all(q)

    print("[agent_query] Liczba chunków w bazie:", len(rows))

    scored: List[tuple[float, dict]] = []
    for row in rows:
        try:
            emb = json.loads(row["embedding"])
            sim = cosine_similarity(query_vec, [float(x) for x in emb])
        except Exception as e:
            print("[agent_query] Błąd przy liczeniu similarity:", e)
            sim = 0.0
        scored.append((sim, dict(row)))

    # posortuj po similarity malejąco
    scored.sort(key=lambda x: x[0], reverse=True)

    # DEBUG: pokaż top N z similarity (nawet jeśli 0)
    debug_top_n = min(payload.max_context_chunks, len(scored))
    print(f"[agent_query] TOP {debug_top_n} chunków wg similarity:")
    for i, (sim, r) in enumerate(scored[:debug_top_n]):
        snippet = r["content"][:150].replace("\n", " ")
        print(
            f"  #{i} sim={sim:.4f}, doc_id={r['document_id']}, chunk_index={r['chunk_index']}, "
            f"snippet='{snippet}'"
        )

    # do kontekstu bierzemy tylko te z similarity > 0
    top = [r for (s, r) in scored[: payload.max_context_chunks] if s > 0]

    print(f"[agent_query] Liczba chunków z sim>0 użytych w kontekście: {len(top)}")

    # zlep kontekst z chunków
    context_text = "\n\n---\n\n".join(
        f"[Fragment #{r['chunk_index']}] (doc_id={r['document_id']})\n{r['content']}"
        for r in top
    )

    # dla bezpieczeństwa nie logujmy całego kontekstu jeśli jest gigantyczny
    if context_text:
        print("[agent_query] KONTEKST (początek):")
        print(context_text[:2000])
    else:
        print("[agent_query] Brak kontekstu – żadnych chunków z sim>0")

    system_prompt = (
        "Jesteś asystentem Bazyli, który odpowiada wyłącznie w oparciu o podany kontekst.\n"
        "Jeśli czegoś nie ma w kontekście, jasno powiedz, że nie wiesz zamiast zmyślać.\n"
        "Kontekst może być po polsku, odpowiadaj po polsku, chyba że użytkownik wyraźnie prosi inaczej.\n"
    )

    # zbuduj historię dla Groqa:
    groq_messages: List[dict] = [{"role": "system", "content": system_prompt}]

    if context_text:
        groq_messages.append(
            {
                "role": "system",
                "content": f"Kontekst do wykorzystania (fragmenty dokumentów):\n\n{context_text}",
            }
        )

    # dodaj wszystkie dotychczasowe wiadomości użytkownika / asystenta,
    # ale bez wcześniejszych systemów, bo je nadpisaliśmy:
    for m in payload.messages:
        if m.role in ("user", "assistant"):
            groq_messages.append({"role": m.role, "content": m.content})

    print("[agent_query] Liczba wiadomości wysyłanych do Groqa:", len(groq_messages))

    reply = await groq_chat_completion(
        messages=groq_messages,
        model=payload.model or "llama-3.1-8b-instant",
        temperature=payload.temperature,
        max_tokens=payload.max_tokens,
    )

    print("[agent_query] Odpowiedź z Groqa:", reply[:500])

    return AgentQueryResponse(reply=reply)
