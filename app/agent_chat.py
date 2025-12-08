# app/agent_chat.py

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Literal, Optional, Tuple, Dict, Any
from sqlalchemy import select, or_
import json
import math

from app.db import database, agent_document_chunks, agent_documents
from app.groq_client import groq_chat_completion


class ChatMessage(BaseModel):
    role: Literal["system", "user", "assistant"]
    content: str


AgentMode = Literal["app", "rules"]


class AgentQueryRequest(BaseModel):
    messages: List[ChatMessage]
    model: Optional[str] = "llama-3.1-8b-instant"
    temperature: float = 0.2
    # zwiększamy domyślny limit odpowiedzi
    max_tokens: int = 2048
    # to pole zostanie teraz użyte tylko pomocniczo, ale zostawiamy
    max_context_chunks: int = 32
    # NOWE: tryb pracy Bazylego – aplikacja BAZA/ProEl albo przepisy
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
    Buduje system prompt Bazylego w zależności od trybu:
    - "app": fokus na BAZA / ProEl
    - "rules": fokus na przepisy piłki ręcznej
    """
    base = (
        "Jesteś asystentem Bazyli.\n"
        "Masz odpowiadać WYŁĄCZNIE w oparciu o podany kontekst z dokumentów.\n"
        "Jeśli czegoś nie ma w kontekście – jasno napisz, że tego nie wiesz, "
        "zamiast zgadywać.\n\n"
        "Zasady odpowiedzi (wspólne dla wszystkich trybów):\n"
        "1. Zawsze twórz pełne, wyczerpujące odpowiedzi w oparciu o kontekst.\n"
        "2. Jeśli pytanie dotyczy przepisów, założeń, zasad, list punktów itp., "
        "to wypisz WSZYSTKIE istotne punkty z kontekstu w czytelnej, "
        "ponumerowanej formie.\n"
        "3. Nie pomijaj wyjątków, liczb, limitów ani szczegółowych warunków, "
        "nawet jeśli odpowiedź będzie długa.\n"
        "4. Odpowiadaj po polsku, chyba że użytkownik wyraźnie prosi o inny język.\n\n"
    )

    if mode == "app":
        mode_part = (
            "TRYB: Aplikacja BAZA / ProEl.\n"
            "Jesteś ekspertem od działania aplikacji BAZA / ProEl, ich konfiguracji, "
            "integracji (np. z systemem ZPRP) oraz typowych problemów użytkowników.\n"
            "Kontekst pochodzi głównie z dokumentacji, regulaminów i instrukcji, "
            "których tytuł zawiera słowa 'BAZA' lub 'ProEl'.\n"
            "Jeżeli pytanie dotyczy przepisów gry w piłkę ręczną (a nie aplikacji), "
            "napisz uprzejmie, że to pytanie wymaga trybu przepisów i zasugeruj "
            "użytkownikowi przełączenie się na tryb pytań o przepisy.\n"
        )
    elif mode == "rules":
        mode_part = (
            "TRYB: Przepisy piłki ręcznej.\n"
            "Jesteś ekspertem od przepisów piłki ręcznej oraz ich interpretacji "
            "z perspektywy sędziego.\n"
            "Wykorzystuj szeroki kontekst z wielu dokumentów naraz, łącząc informacje "
            "z różnych miejsc regulaminów i wytycznych.\n"
            "Pamiętaj, że przepisy piłki ręcznej są zawarte nie tylko w dokumencie "
            "o nazwie 'Przepisy gry', ale również w plikach typu:\n"
            "- 'Regulamin_...'\n"
            "- 'Buzzery'\n"
            "- 'Wdrożenie kluczowych zmian'\n"
            "- 'Założenia'\n"
            "- 'Wytyczne'\n"
            "- 'Katalog pytania i odpowiedzi'\n"
            "- 'Katalog pytań'\n"
            "Jeśli pytanie dotyczy działania aplikacji BAZA / ProEl, "
            "napisz, że to pytanie wymaga trybu aplikacji.\n"
        )
    else:
        # fallback – zachowanie zbliżone do starej wersji
        mode_part = (
            "TRYB: Ogólny.\n"
            "Jeśli z kontekstu wynika, że pytanie dotyczy aplikacji BAZA/ProEl, "
            "skup się na dokumentach dotyczących aplikacji.\n"
            "Jeśli dotyczy przepisów piłki ręcznej, skup się na regulaminach, "
            "przepisach i wytycznych sędziowskich.\n"
        )

    return base + mode_part


def build_mode_filtered_query(mode: Optional[AgentMode]):
    """
    Buduje SELECT na agent_document_chunks z dołączeniem agent_documents
    oraz filtrami na tytuł dokumentu zależnie od trybu.
    Zwraca obiekt select.
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

    if mode == "app":
        # Dokumenty dotyczące aplikacji BAZA / ProEl
        patterns = [
            "%BAZA%",
            "%Baza%",
            "%baza%",
            "%ProEl%",
            "%Pro El%",
            "%Pro-EL%",
            "%Proel%",
        ]
        conditions = [agent_documents.c.title.ilike(p) for p in patterns]
        if conditions:
            base_query = base_query.where(or_(*conditions))
    elif mode == "rules":
        # Dokumenty zawierające przepisy / regulaminy / wytyczne itd.
        patterns = [
            "%regulamin%",
            "%Regulamin%",
            "%przepis%",
            "%Przepisy%",
            "%Buzzery%",
            "%buzzer%",
            "%Wdrożenie kluczowych zmian%",
            "%Założenia%",
            "%Wytyczne%",
            "%Katalog pytania i odpowiedzi%",
            "%Katalog pytań%",
        ]
        conditions = [agent_documents.c.title.ilike(p) for p in patterns]
        if conditions:
            base_query = base_query.where(or_(*conditions))

    return base_query


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

    # 2) pobierz chunki z uwzględnieniem trybu
    q = build_mode_filtered_query(payload.mode)
    rows = await database.fetch_all(q)
    print(
        "[agent_query] Liczba chunków w bazie po filtrze trybu:",
        len(rows),
    )

    if not rows:
        # nie ma żadnych dokumentów dla danego trybu – fallback: normalny czat z Groq
        print(
            "[agent_query] Brak chunków w bazie dla danego trybu – "
            "fallback do czystego modelu bez kontekstu"
        )
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

    context_text = ""
    if not scored:
        print("[agent_query] Brak wyników po scoringu – brak kontekstu")
    else:
        best_sim, best_row = scored[0]
        if best_sim <= 0:
            # nic niepasujące – lepiej szczerze powiedzieć, że nie wiemy
            print(
                "[agent_query] Najlepsze similarity <= 0 – brak sensownego dopasowania"
            )
            context_text = ""
        else:
            if payload.mode == "rules":
                # TRYB PRZEPISÓW: bierzemy fragmenty z WIELU dokumentów (szeroki kontekst)
                max_chars = 8000
                total_chars = 0
                context_parts: List[str] = []

                print(
                    "[agent_query] Buduję kontekst z wielu dokumentów (tryb 'rules')."
                )
                for sim, r in scored:
                    if sim <= 0:
                        break
                    title = r.get("doc_title") or f"Dokument {r['document_id']}"
                    part = (
                        f"[Dokument: {title} | Fragment #{r['chunk_index']} "
                        f"(sim={sim:.4f})]\n{r['content']}\n\n---\n\n"
                    )
                    if total_chars + len(part) > max_chars:
                        break
                    context_parts.append(part)
                    total_chars += len(part)

                context_text = "".join(context_parts)
                print(
                    f"[agent_query] Tryb 'rules': używam {len(context_parts)} "
                    f"fragmentów z wielu dokumentów (łącznie {total_chars} znaków)."
                )
            else:
                # TRYB APLIKACJI (lub ogólny): jak wcześniej – wszystkie chunki z najlepszego dokumentu
                best_doc_id = best_row["document_id"]
                best_title = best_row.get("doc_title", "")
                print(
                    f"[agent_query] Najlepszy dokument: doc_id={best_doc_id}, "
                    f"title='{best_title}' (sim={best_sim:.4f})"
                )

                # bierzemy WSZYSTKIE chunki z najlepszego dokumentu,
                # w kolejności chunk_index, aż do limitu znaków.
                doc_rows: List[Dict[str, Any]] = [
                    r for (_s, r) in scored if r["document_id"] == best_doc_id
                ]
                doc_rows.sort(key=lambda r: r["chunk_index"])

                max_chars = 8000  # limit znaków kontekstu
                total_chars = 0
                context_parts: List[str] = []

                for r in doc_rows:
                    title = r.get("doc_title") or f"Dokument {r['document_id']}"
                    part = (
                        f"[Dokument: {title} | Fragment #{r['chunk_index']}]\n"
                        f"{r['content']}\n\n---\n\n"
                    )
                    if total_chars + len(part) > max_chars:
                        break
                    context_parts.append(part)
                    total_chars += len(part)

                context_text = "".join(context_parts)
                print(
                    f"[agent_query] Tryb 'app/ogólny': używam {len(context_parts)} "
                    f"fragmentów z dokumentu {best_doc_id} (łącznie {total_chars} znaków)."
                )

    if context_text:
        print("[agent_query] KONTEKST (początek):")
        print(context_text[:2000])
    else:
        print("[agent_query] Brak kontekstu – żadnych fragmentów do użycia")

    # 5) System prompt – zależny od trybu
    system_prompt = build_system_prompt(payload.mode)

    # 6) budujemy wiadomości dla Groqa
    groq_messages: List[dict] = [{"role": "system", "content": system_prompt}]

    if context_text:
        groq_messages.append(
            {
                "role": "system",
                "content": (
                    "Kontekst do wykorzystania (wybrane fragmenty dokumentów):\n\n"
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
