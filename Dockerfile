# 1. Wybieramy lekki obraz Pythona
FROM python:3.10-slim

# 2. Ustawiamy katalog roboczy wewnątrz kontenera
WORKDIR /app

# 3. Kopiujemy tylko plik z zależnościami i instalujemy
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 4. Kopiujemy cały kod aplikacji
COPY . .

# 5. Otwieramy port 8000 (ten, na którym działa Uvicorn)
EXPOSE 8000

# 6. Domyślna komenda startowa
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
