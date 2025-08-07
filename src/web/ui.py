"""
UI styles and components for the cybersecurity Streamlit application.
"""

# --- Custom CSS styles for the application ---
def get_css():
    """Return custom CSS for the cybersecurity application."""
    return """
<style>
    .uploadedFile {
        display: none;
    }

    .main-header {
        text-align: center;
        color: #DC143C;
        padding: 20px 0;
        border-bottom: 3px solid #f0f2f6;
        margin-bottom: 30px;
    }
    .chat-container {
        background-color: #f8f9fa;
        padding: 20px;
        border-radius: 10px;
        margin-bottom: 20px;
        max-height: 600px;
        overflow-y: auto;
        color: #000000;
    }
    .kb-section {
        background-color: #ffffff;
        padding: 20px;
        border-radius: 10px;
        margin-bottom: 20px;
        border: 1px solid #e1e5e9;
        color: #000000;
    }
    .cyber-section {
        background-color: #ffffff;
        padding: 20px;
        border-radius: 10px;
        border: 1px solid #e1e5e9;
        color: #000000;
    }
    .user-message {
        background-color: #DC143C;
        color: white;
        padding: 10px;
        border-radius: 10px;
        margin: 10px 0;
        text-align: right;
    }
    .assistant-message {
        background-color: #e9ecef;
        color: #000000;
        padding: 10px;
        border-radius: 10px;
        margin: 10px 0;
        text-align: left;
    }
    .info-box {
        background-color: #ffe6e6;
        padding: 15px;
        border-radius: 8px;
        border-left: 4px solid #DC143C;
        margin: 10px 0;
        color: #000000;
    }
    .stButton > button {
        background-color: #DC143C;
        color: white;
        border: none;
        padding: 10px 20px;
        border-radius: 5px;
        font-weight: bold;
        width: 100%;
    }
    .stButton > button:hover {
        background-color: #B22222;
        color: white;
    }
    
    /* Metric styling for cybersecurity theme */
    .stMetric {
        background-color: #fff5f5;
        border: 1px solid #fecaca;
        border-radius: 8px;
        padding: 10px;
    }
    
    .stMetric > div {
        color: #000000 !important;
    }
    
    .stMetric label {
        color: #374151 !important;
    }
    
    /* Dark mode styles */
    [data-theme="dark"] .main-header {
        color: #FF6B6B;
        border-bottom: 3px solid #333333;
    }
    [data-theme="dark"] .chat-container {
        background-color: #2b2b2b;
        color: #ffffff;
    }
    [data-theme="dark"] .kb-section {
        background-color: #1e1e1e;
        border: 1px solid #404040;
        color: #ffffff;
    }
    [data-theme="dark"] .cyber-section {
        background-color: #1e1e1e;
        border: 1px solid #404040;
        color: #ffffff;
    }
    [data-theme="dark"] .assistant-message {
        background-color: #404040;
        color: #ffffff;
    }
    [data-theme="dark"] .info-box {
        background-color: #3d1a1a;
        color: #ffffff;
        border-left: 4px solid #FF6B6B;
    }
    [data-theme="dark"] .stMetric {
        background-color: #2d1e1e;
        border: 1px solid #5d4040;
    }
    
    [data-theme="dark"] .stMetric > div {
        color: #ffffff !important;
    }
    
    [data-theme="dark"] .stMetric label {
        color: #e5e7eb !important;
    }
    
    /* Additional dark mode metric styling */
    [data-theme="dark"] [data-testid="metric-container"] {
        background-color: #2d1e1e !important;
        border: 1px solid #5d4040 !important;
        color: #ffffff !important;
    }
    
    [data-theme="dark"] [data-testid="metric-container"] > div {
        color: #ffffff !important;
    }
</style>
"""
