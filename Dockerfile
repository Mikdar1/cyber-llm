# Gunakan image Python resmi sebagai base
FROM python:3.9-slim

# Tetapkan direktori kerja di dalam container
WORKDIR /app

# Salin file requirements.txt ke dalam container
COPY requirements.txt .

# Install dependensi yang diperlukan
RUN pip install --no-cache-dir -r requirements.txt

# Salin sisa kode aplikasi ke dalam container
COPY . .

# Paparkan port yang akan digunakan oleh FastAPI
EXPOSE 8000

# Jalankan aplikasi menggunakan uvicorn
CMD ["uvicorn", "api_service:app", "--host", "0.0.0.0", "--port", "8000"]