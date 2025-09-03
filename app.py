"""Streamlit UI for the Cybersecurity Framework Assistant."""

import streamlit as st

from src.api.llm_service import get_llm
from src.auth.auth import check_streamlit_auth, render_login_page
from src.knowledge_base.database import create_graph_connection
from src.utils.initialization import initialize_knowledge_base
from src.web.components import chat_tab, knowledge_base_tab, sidebar_components
from src.web.ui import get_css


def configure_page():
    """Configure page settings and apply custom CSS."""
    st.set_page_config(
        page_title="Cybersecurity Framework Assistant",
        layout="wide",
        initial_sidebar_state="expanded",
        page_icon="🛡️",
    )

    st.markdown(get_css(), unsafe_allow_html=True)


def render_header():
    """Render the application header with framework indicators."""
    st.markdown(
        """
    <div class="main-header">
        <h1>🛡️ Cybersecurity Framework Assistant</h1>
        <p>AI-Powered Knowledge Graph for Cybersecurity Frameworks and Threat Intelligence</p>
        <div style="display: flex; gap: 10px; justify-content: center; margin-top: 10px;">
            <span style="background: #1f77b4; color: white; padding: 2px 8px; border-radius: 4px; font-size: 12px;">MITRE ATT&CK</span>
            <span style="background: #ff7f0e; color: white; padding: 2px 8px; border-radius: 4px; font-size: 12px;">Compliance Frameworks</span>
        </div>
    </div>
    """,
        unsafe_allow_html=True,
    )


def initialize_session_state():
    """Initialize session state for chat, services, and flags."""
    if "messages" not in st.session_state:
        st.session_state.messages = []
    if "knowledge_base_initialized" not in st.session_state:
        st.session_state.knowledge_base_initialized = False
    if "graph_connection" not in st.session_state:
        st.session_state.graph_connection = None
    if "llm_service" not in st.session_state:
        st.session_state.llm_service = None
    if "initialization_complete" not in st.session_state:
        st.session_state.initialization_complete = False


def render_error_troubleshooting():
    """Display a troubleshooting guide for common issues."""
    st.markdown(
        """
    ### 🔧 Troubleshooting Guide:
    
    **Database Connection:**
    - Ensure Neo4j instance is running and accessible
    - Verify database credentials in environment configuration
    - Check network connectivity to database server
    
    **Configuration:**
    - Validate `.env` file contains all required variables
    - Confirm Google Gemini API key is valid and active
    - Ensure proper file permissions for document processing
    
    **Dependencies:**
    - Install required packages: `pip install -r requirements.txt`
    - Verify Python version compatibility (3.8+)
    - Check for package version conflicts
    
    **Data Sources:**
    - Confirm framework documents are in `documents/` directory
    - Verify internet connectivity for ATT&CK data ingestion
    - Check document file permissions and format compatibility
    """
    )


def main():
    """App entry point: auth, initialize services, and render UI."""
    configure_page()
    initialize_session_state()

    if not check_streamlit_auth():
        render_login_page()
        return

    render_header()

    try:
        if not st.session_state.initialization_complete:
            initialization_status = st.empty()
            initialization_progress = st.progress(0)

            initialization_status.info(
                "🔄 Initializing cybersecurity knowledge base..."
            )
            initialization_progress.progress(20)

            try:
                graph = create_graph_connection()
                st.session_state.graph_connection = graph
                initialization_progress.progress(40)
                initialization_status.info("📊 Database connection established...")
            except Exception as e:
                initialization_status.error(f"❌ Database connection failed: {str(e)}")
                st.error(
                    "Unable to connect to the knowledge base. Please check your Neo4j configuration."
                )
                return

            try:
                llm = get_llm()
                st.session_state.llm_service = llm
                initialization_progress.progress(60)
                initialization_status.info("🤖 Language model initialized...")
            except Exception as e:
                initialization_status.error(f"❌ LLM initialization failed: {str(e)}")
                st.error(
                    "Unable to initialize the language model. Please check your API configuration."
                )
                return

            try:
                initialize_knowledge_base(graph)
                initialization_progress.progress(80)
                initialization_status.info("🛡️ Knowledge base ready...")
            except Exception as e:
                initialization_status.warning(
                    f"⚠️ Knowledge base initialization warning: {str(e)}"
                )

            initialization_progress.progress(100)
            initialization_status.success("✅ System initialized successfully!")

            import time

            time.sleep(1)
            initialization_status.empty()
            initialization_progress.empty()

            st.session_state.initialization_complete = True

        graph = st.session_state.graph_connection
        llm = st.session_state.llm_service

        tab1, tab2 = st.tabs(["💬 Chat Interface", "🔍 Knowledge Base"])

        with tab1:
            try:
                chat_tab(graph, llm)
            except Exception as e:
                st.error(f"❌ Chat interface error: {str(e)}")
                st.info("Please refresh the page or check your configuration.")

        with tab2:
            try:
                knowledge_base_tab(graph)
            except Exception as e:
                st.error(f"❌ Knowledge base interface error: {str(e)}")
                st.info("Please refresh the page or check your configuration.")

        try:
            sidebar_components(graph)
        except Exception as e:
            st.sidebar.error(f"❌ Sidebar error: {str(e)}")

    except Exception as e:
        st.error(f"❌ **Application Error:** {str(e)}")
        st.warning("Please check your configuration and try again.")
        render_error_troubleshooting()


if __name__ == "__main__":
    main()
