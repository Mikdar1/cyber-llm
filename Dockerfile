# ==============================================================================
# File: Dockerfile
# Description: Dockerfile for the cybersecurity multi-framework platform
# Supports both Streamlit chat app and FastAPI service
# 
# To build: docker build -t cybersecurity-platform .
# To run chat app: docker run -p 8501:8501 --env-file .env cybersecurity-platform
# To run API: docker run -p 8000:8000 --env-file .env cybersecurity-platform uvicorn api_service:app --host 0.0.0.0 --port 8000
# ==============================================================================
FROM python:alpine3.22

WORKDIR /app

# Install curl for health checks
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Expose ports for both services
EXPOSE 8501 8000

# Health check for Streamlit by default
HEALTHCHECK CMD curl --fail http://localhost:8501/_stcore/health || exit 1

# Default to Streamlit app
ENTRYPOINT ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
