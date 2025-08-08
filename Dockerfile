# ==============================================================================
# File: Dockerfile
# Description: Dockerfile untuk menjalankan Streamlit dan FastAPI
# secara bersamaan menggunakan reverse proxy Nginx.
# ==============================================================================

# Gunakan image dasar Python Alpine yang efisien
FROM python:alpine3.22

# Set working directory di dalam kontainer
WORKDIR /app

# Perbarui paket dan install Nginx, curl untuk health check
RUN apk add --no-cache nginx curl

# Salin requirements.txt dan install semua dependensi Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Salin semua file aplikasi, termasuk skrip startup dan konfigurasi Nginx
COPY . .

# Beri izin eksekusi pada skrip startup
RUN chmod +x ./startup.sh

# Salin konfigurasi Nginx ke lokasi yang benar
COPY nginx.conf /etc/nginx/nginx.conf

# Expose port 80 untuk Nginx sebagai satu-satunya titik masuk
EXPOSE 80

# Health check untuk FastAPI di port 8000 (lewat Nginx)
HEALTHCHECK CMD curl --fail http://localhost/docs || exit 1

# Jadikan skrip startup sebagai ENTRYPOINT
# Skrip ini akan menjalankan Nginx, FastAPI, dan Streamlit
ENTRYPOINT ["./startup.sh"]
