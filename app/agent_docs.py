# app/agent_docs.py

from fastapi import APIRouter, UploadFile, File, HTTPException
from sqlalchemy import select
from datetime import datetime
from typing import List

from app.db import database, agent_documents, agent_document_chunks
from app.groq_client import groq_chat_completion

import fitz  # PyMuPDF – musisz dodać do dependencies (pip install pymupdf)
import json

router = APIRouter(prefix="/agent/docs", tags=["agent_docs"])


async def simple_embed(texts: List[str]) -> List[List[float]]:
    """
    Bardzo prosty embedding przez Groq:
    - używamy modelu, który generuje krótki embedding jako JSON (hack v1)
    W realu: lepiej użyć dedykowanego modelu embeddingów, np. z innego API.
    """
    embeddings: List[List[float]] = []

    for idx, t in enumerate(texts):
        prompt = (
            "Zamień poniższy tekst na prostą reprezentację numeryczną: "
            "zwróć TYLKO JSON z listą 16 liczb zmiennoprzecinkowych.\n\n"
            f"Tekst: {t[:2000]}"
        )

        print(f"[simple_embed] Tekst #{idx}, długość={len(t)}")
        # żeby log nie był gigantyczny:
        print(f"[simple_embed] Fragment tekstu #{idx}: {t[:200].replace(chr(10),' ')}")

        reply = await groq_chat_completion(
            messages=[
                {"role": "system", "content": "Jesteś funkcją generującą embeddingi."},
                {"role": "user", "content": prompt},
            ],
            model="llama-3.1-8b-instant",
            temperature=0.0,
            max_tokens=512,
        )

        print(f"[simple_embed] Surowa odpowiedź modelu dla chunk #{idx}: {reply}")

        try:
            vec = json.loads(reply)
            if isinstance(vec, list):
                emb = [float(x) for x in vec]
                embeddings.append(emb)
                print(f"[simple_embed] Udało się sparsować embedding dla chunk #{idx}, len={len(emb)}")
            else:
                raise ValueError("Embedding nie jest listą")
        except Exception as e:
            print(f"[simple_embed] BŁĄD parsowania embeddingu dla chunk #{idx}: {e}")
            print("[simple_embed] Fallback: wektor zerowy")
            embeddings.append([0.0] * 16)

    return embeddings


def chunk_text(text: str, max_chars: int = 800) -> List[str]:
    """Prosty chunker po znakach z cięciem na granicach zdań tam gdzie się da."""
    text = text.strip()
    if not text:
        return []

    chunks: List[str] = []
    start = 0
    while start < len(text):
        end = min(start + max_chars, len(text))
        slice_ = text[start:end]

        # spróbuj cofnąć do kropki / nowej linii, żeby nie ciąć w środku zdania
        cut = max(slice_.rfind("."), slice_.rfind("\n"))
        if cut != -1 and cut > 200:  # nie ucinaj za blisko początku
            end = start + cut + 1

        chunks.append(text[start:end].strip())
        start = end

    return [c for c in chunks if c]


# ---------- NOWE: lista dokumentów ----------

@router.get("")
async def list_docs():
    """
    Zwraca listę wszystkich dokumentów znanych Bazylemu,
    posortowaną malejąco po dacie utworzenia.
    """
    query = (
        agent_documents
        .select()
        .order_by(agent_documents.c.created_at.desc())
    )
    rows = await database.fetch_all(query)
    # frontend i tak umie obsłużyć zarówno [] jak i {documents: []},
    # ale zróbmy ładny wrapper:
    return {"documents": [dict(r) for r in rows]}


# ---------- ISTNIEJĄCY: upload PDF ----------

@router.post("/upload_pdf")
async def upload_pdf(file: UploadFile = File(...)):
    if file.content_type not in ("application/pdf", "application/x-pdf"):
        raise HTTPException(status_code=400, detail="Plik musi być w formacie PDF")

    try:
        pdf_bytes = await file.read()
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    except Exception:
        raise HTTPException(status_code=400, detail="Nie udało się odczytać PDF")

    full_text_parts: List[str] = []
    for page in doc:
        full_text_parts.append(page.get_text())

    full_text = "\n".join(full_text_parts)
    doc_title = file.filename or "Dokument"

    chunks = chunk_text(full_text)
    if not chunks:
        raise HTTPException(status_code=400, detail="PDF nie zawiera tekstu")

    # 1) Zapis dokumentu
    now = datetime.utcnow()
    insert_doc = (
        agent_documents.insert()
        .values(
            title=doc_title,
            source_type="pdf",
            source_path=None,
            created_at=now,
            updated_at=now,
        )
        .returning(agent_documents.c.id)
    )
    doc_id_row = await database.fetch_one(insert_doc)
    document_id = int(doc_id_row["id"])

    # 2) Embeddingi dla chunków
    embeddings = await simple_embed(chunks)

    # 3) Zapis chunków (embedding trzymamy jako JSON string)
    chunk_rows = []
    for idx, (content, emb) in enumerate(zip(chunks, embeddings)):
        chunk_rows.append(
            {
                "document_id": document_id,
                "chunk_index": idx,
                "content": content,
                "embedding": json.dumps(emb),
                "created_at": now,
            }
        )

    query = agent_document_chunks.insert()
    await database.execute_many(query, chunk_rows)

    return {
        "document_id": document_id,
        "title": doc_title,
        "chunks": len(chunks),
    }


# ---------- NOWE: kasowanie dokumentu + chunków ----------

@router.delete("/{doc_id}")
async def delete_doc(doc_id: int):
    # sprawdź, czy dokument istnieje
    doc = await database.fetch_one(
        agent_documents.select().where(agent_documents.c.id == doc_id)
    )
    if not doc:
        raise HTTPException(status_code=404, detail="Dokument nie istnieje")

    # usuń wszystkie chunki powiązane z dokumentem
    await database.execute(
      agent_document_chunks
      .delete()
      .where(agent_document_chunks.c.document_id == doc_id)
    )

    # usuń sam dokument
    await database.execute(
      agent_documents.delete().where(agent_documents.c.id == doc_id)
    )

    return {"ok": True, "deleted_id": doc_id}
