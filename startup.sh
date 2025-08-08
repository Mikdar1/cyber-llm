#!/bin/sh
# Skrip ini akan menjalankan FastAPI, Streamlit, dan Nginx secara bersamaan

# Muat variabel lingkungan dari .env jika ada
if [ -f .env ]; then
  export $(grep -v '^#' .env | xargs)
fi

# Jalankan FastAPI di port 8000 di latar belakang
uvicorn api_service:app --host 0.0.0.0 --port 8000 &

# Jalankan Streamlit di port 8501 di latar belakang
# Tambahkan --server.baseUrlPath untuk menginformasikan Streamlit tentang reverse proxy
streamlit run app.py --server.port=8501 --server.address=0.0.0.0 --server.baseUrlPath /streamlit &

# Jalankan Nginx di latar depan agar kontainer tetap hidup
nginx -g "daemon off;"
