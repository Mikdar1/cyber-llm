"""
Application Configuration Settings Module

This module manages all configuration settings for the Cybersecurity ATT&CK
Assistant application. It loads environment variables for database connections,
API keys, and model configurations while providing fallback defaults.

Environment Variables Required:
    NEO4J_URI: Neo4j database connection URI
    NEO4J_USERNAME: Neo4j database username
    NEO4J_PASSWORD: Neo4j database password
    GEMINI_API_KEY: Google Gemini API key for LLM integration
    MODEL_NAME: (Optional) Gemini model name, defaults to gemini-2.5-flash-preview-05-20
    APP_USERNAME: Streamlit app login username
    APP_PASSWORD: Streamlit app login password
    JWT_SECRET_KEY: Secret key for JWT token generation
    JWT_ALGORITHM: JWT algorithm (defaults to HS256)
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: JWT token expiration time in minutes

Configuration Groups:
    - Neo4j Database Settings
    - Google Gemini LLM Settings
    - Authentication Settings
"""

import os

from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# --- Neo4j Database Configuration ---
NEO4J_URI = os.getenv("NEO4J_URI")
NEO4J_USERNAME = os.getenv("NEO4J_USERNAME")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")

# --- Google Gemini LLM Configuration ---
MODEL_NAME = os.getenv("MODEL_NAME", "gemini-2.5-flash-preview-05-20")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

# --- Authentication Configuration ---
APP_USERNAME = os.getenv("APP_USERNAME", "admin")
APP_PASSWORD = os.getenv("APP_PASSWORD", "cybersec2025")
JWT_SECRET_KEY = os.getenv(
    "JWT_SECRET_KEY", "your_jwt_secret_key_change_this_in_production"
)
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = int(
    os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "1440")
)
