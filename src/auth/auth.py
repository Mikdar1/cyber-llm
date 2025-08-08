"""
Authentication Module for Cybersecurity Multi-Framework Assistant

This module provides authentication functionality for both the Streamlit chat app
and the FastAPI service. It includes JWT token generation, password hashing,
and verification functions.

Features:
- JWT token generation and verification
- Password hashing and verification
- Streamlit session management
- FastAPI dependency injection for protected routes
"""

from datetime import datetime, timedelta
from typing import Optional, Dict, Any
try:
    from passlib.context import CryptContext
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("Warning: JWT/Passlib not available. Install with: pip install python-jose[cryptography] passlib[bcrypt]")

from src.config.settings import (
    APP_USERNAME, 
    APP_PASSWORD, 
    JWT_SECRET_KEY, 
    JWT_ALGORITHM, 
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES
)

# Password context for hashing
pwd_context = None
if CRYPTO_AVAILABLE:
    from passlib.context import CryptContext
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class AuthManager:
    """Authentication manager for handling JWT tokens and password verification."""
    
    def __init__(self):
        self.secret_key = JWT_SECRET_KEY
        self.algorithm = JWT_ALGORITHM
        self.access_token_expire_minutes = JWT_ACCESS_TOKEN_EXPIRE_MINUTES
        self.crypto_available = CRYPTO_AVAILABLE
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify a plain password against its hash."""
        if not self.crypto_available or pwd_context is None:
            # Fallback to simple comparison for development
            return plain_password == hashed_password
        return pwd_context.verify(plain_password, hashed_password)
    
    def get_password_hash(self, password: str) -> str:
        """Generate password hash."""
        if not self.crypto_available or pwd_context is None:
            # Fallback to simple hash for development
            return password
        return pwd_context.hash(password)
    
    def authenticate_user(self, username: str, password: str) -> bool:
        """
        Authenticate user credentials against environment variables.
        
        Args:
            username: The username to verify
            password: The password to verify
            
        Returns:
            True if credentials are valid, False otherwise
        """
        # For simplicity, we're comparing against environment variables
        # In production, this should check against a secure database
        if username == APP_USERNAME and password == APP_PASSWORD:
            return True
        return False
    
    def create_access_token(self, data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
        """
        Create a JWT access token.
        
        Args:
            data: The data to encode in the token
            expires_delta: Token expiration time delta
            
        Returns:
            Encoded JWT token
        """
        if not self.crypto_available:
            # Return a simple token for development
            return f"simple_token_{data.get('sub', 'user')}_{datetime.utcnow().timestamp()}"
        
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=self.access_token_expire_minutes)
        
        to_encode.update({"exp": expire})

        encoded_jwt = ""
        if self.crypto_available:
            from jose import jwt
            encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Verify and decode a JWT token.
        
        Args:
            token: The JWT token to verify
            
        Returns:
            Decoded token payload if valid, None otherwise
        """
        if not self.crypto_available:
            # Simple token verification for development
            if token.startswith("simple_token_"):
                parts = token.split("_")
                if len(parts) >= 3:
                    username = parts[2]
                    return {"sub": username}
            return None
        
        try:
            payload = {}
            if self.crypto_available:
                from jose import jwt
                payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload
        except Exception:  # Catch all JWT errors
            return None
    
    def create_user_token(self, username: str) -> str:
        """
        Create a JWT token for a specific user.
        
        Args:
            username: The username to create token for
            
        Returns:
            JWT token string
        """
        access_token_expires = timedelta(minutes=self.access_token_expire_minutes)
        access_token = self.create_access_token(
            data={"sub": username}, 
            expires_delta=access_token_expires
        )
        return access_token


# Global auth manager instance
auth_manager = AuthManager()


# Streamlit authentication functions
def check_streamlit_auth() -> bool:
    """
    Check if user is authenticated in Streamlit session.
    
    Returns:
        True if authenticated, False otherwise
    """
    import streamlit as st
    return st.session_state.get("authenticated", False)


def streamlit_login(username: str, password: str) -> bool:
    """
    Authenticate user in Streamlit and set session state.
    
    Args:
        username: The username
        password: The password
        
    Returns:
        True if login successful, False otherwise
    """
    import streamlit as st
    
    if auth_manager.authenticate_user(username, password):
        st.session_state["authenticated"] = True
        st.session_state["username"] = username
        st.session_state["token"] = auth_manager.create_user_token(username)
        return True
    return False


def streamlit_logout():
    """Logout user from Streamlit session."""
    import streamlit as st
    
    st.session_state["authenticated"] = False
    st.session_state.pop("username", None)
    st.session_state.pop("token", None)


def render_login_page():
    """
    Render the login page for Streamlit app.
    
    Returns:
        True if login successful, False otherwise
    """
    import streamlit as st
    
    st.markdown("""
    <div style="max-width: 400px; margin: 20px auto; padding: 20px; 
                border-radius: 8px; box-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
                background: var(--background-color, #1e1e1e); 
                border: 1px solid var(--border-color, #333);">
        <div style="text-align: center; margin-bottom: 15px;">
            <h3 style="color: var(--text-color, #e0e0e0); margin-bottom: 5px; font-size: 1.5em;">🛡️ Cybersecurity Assistant</h3>
            <p style="color: var(--secondary-text-color, #b0b0b0); margin: 0; font-size: 0.9em;">Please log in to access the platform</p>
        </div>
    </div>
    <style>
        :root {
            --background-color: #1e1e1e;
            --text-color: #e0e0e0;
            --secondary-text-color: #b0b0b0;
            --border-color: #333;
        }
        @media (prefers-color-scheme: light) {
            :root {
                --background-color: #f8f9fa;
                --text-color: #2c3e50;
                --secondary-text-color: #666;
                --border-color: #dee2e6;
            }
        }
        /* Dark theme for Streamlit */
        .stApp[data-theme="dark"] {
            --background-color: #1e1e1e;
            --text-color: #e0e0e0;
            --secondary-text-color: #b0b0b0;
            --border-color: #333;
        }
        /* Light theme for Streamlit */
        .stApp[data-theme="light"] {
            --background-color: #f8f9fa;
            --text-color: #2c3e50;
            --secondary-text-color: #666;
            --border-color: #dee2e6;
        }
    </style>
    """, unsafe_allow_html=True)
    
    # Create login form in the center
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        with st.form("login_form"):
            st.markdown("#### 🔐 Login")
            username = st.text_input("Username", placeholder="Enter your username")
            password = st.text_input("Password", type="password", placeholder="Enter your password")
            submit_button = st.form_submit_button("Login", use_container_width=True)
            
            if submit_button:
                if username and password:
                    if streamlit_login(username, password):
                        st.success("✅ Login successful! Redirecting...")
                        st.rerun()
                        return True
                    else:
                        st.error("❌ Invalid credentials. Please try again.")
                else:
                    st.warning("⚠️ Please enter both username and password.")
    
    return False


# FastAPI authentication functions
def get_current_user_from_token(token: str) -> Optional[str]:
    """
    Get current user from JWT token for FastAPI.
    
    Args:
        token: JWT token
        
    Returns:
        Username if token is valid, None otherwise
    """
    payload = auth_manager.verify_token(token)
    if payload is None:
        return None
    
    username = payload.get("sub")
    if username is None or not isinstance(username, str):
        return None
    
    return username
