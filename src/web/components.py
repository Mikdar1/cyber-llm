"""
Streamlit UI Components for Cybersecurity Framework Assistant

This module provides the core user interface components for the cybersecurity
framework assistant application, including chat interfaces, knowledge base
management, statistics displays, and administrative functionality.

Components:
- Interactive chat interface with conversation history
- Dynamic statistics display with real-time data
- Knowledge base search and exploration tools
- Document management and upload functionality
- Sidebar navigation and framework status indicators
- Cache management for performance optimization

Features:
- Session state persistence for chat history
- Real-time statistics caching and invalidation
- Advanced search with filtering capabilities
- Document processing interface
- Framework status monitoring and management
- Responsive design with error boundaries
"""

import json
import os
import tempfile
from datetime import datetime
from typing import Any, Dict

import streamlit as st

from src.cybersecurity.attack_ingestion import AttackIngestion
from src.knowledge_base.graph_operations import (
    get_context_from_knowledge_base,
    get_dynamic_knowledge_base_stats,
    search_knowledge_base,
)
from src.utils.initialization import get_ingestion_status


def invalidate_statistics_cache():
    """
    Clear cached statistics to force refresh on next access.

    This function removes cached statistics data to ensure that
    updated information is displayed after data modifications
    such as new document ingestion or framework updates.
    """
    if "stats_cache" in st.session_state:
        del st.session_state.stats_cache
    if "stats_last_updated" in st.session_state:
        del st.session_state.stats_last_updated
    st.session_state.force_stats_refresh = True


def reset_ingestion_status():
    """
    Reset the framework ingestion status to initial state.

    Clears all ingestion status information and resets the tracking
    file to allow for fresh framework processing and status monitoring.
    """
    initial_status = {
        "ingested_documents": [],
        "ingested_frameworks": {
            "attack": {
                "status": "not_ingested",
                "domains": [],
                "last_updated": None,
                "node_counts": {
                    "techniques": 0,
                    "tactics": 0,
                    "groups": 0,
                    "software": 0,
                    "mitigations": 0,
                    "data_sources": 0,
                },
            }
        },
        "total_nodes": 0,
        "last_updated": datetime.now().isoformat(),
    }

    config_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config")
    status_file = os.path.join(config_dir, "ingestion_status.json")

    with open(status_file, "w") as f:
        json.dump(initial_status, f, indent=2)


def display_dynamic_statistics(graph):
    """
    Display comprehensive knowledge base statistics with intelligent caching.

    Presents real-time statistics about the cybersecurity knowledge base
    including framework counts, node distributions, and ingestion status.
    Implements intelligent caching to optimize performance while ensuring
    data freshness for user interactions.

    Args:
        graph: Neo4j database connection for statistics queries

    Features:
    - Automatic cache refresh for new sessions
    - Visual metrics with color-coded status indicators
    - Framework-specific breakdowns and summaries
    - Performance-optimized data retrieval
    """
    st.markdown("#### 📊 Knowledge Base Statistics")

    current_ingestion_status = get_ingestion_status()
    last_updated = current_ingestion_status.get("last_updated", "")

    need_refresh = (
        "stats_cache" not in st.session_state
        or "stats_last_updated" not in st.session_state
        or st.session_state.get("stats_last_updated", "") != last_updated
        or st.session_state.get("force_stats_refresh", False)
    )

    if need_refresh:
        with st.spinner("📈 Generating statistics..."):
            stats = get_dynamic_knowledge_base_stats(graph)
            st.session_state.stats_cache = stats
            st.session_state.stats_last_updated = last_updated
            st.session_state.force_stats_refresh = False
    else:
        stats = st.session_state.stats_cache

    if "error" in stats:
        st.error(f"Error loading statistics: {stats['error']}")
        return

    overview = stats.get("overview", {})
    if overview:
        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.metric("Total Nodes", f"{overview.get('total_nodes', 0):,}")

        with col2:
            st.metric(
                "Total Relationships", f"{overview.get('total_relationships', 0):,}"
            )

        with col3:
            st.metric("Frameworks", overview.get("ingested_frameworks", 0))

        with col4:
            last_updated = overview.get("last_updated")
            if last_updated:
                st.metric("Last Updated", last_updated[:10])

    frameworks = stats.get("frameworks", {})
    if frameworks:
        st.markdown("#### 🎯 Framework Breakdown")

        ingestion_status = get_ingestion_status()

        for framework, fw_stats in frameworks.items():
            if "error" not in fw_stats:
                # Create dynamic framework mapping by checking ingestion status keys
                framework_key = framework.lower().replace(" ", "_")

                # Find matching framework key in ingestion status
                framework_info = {}
                last_updated = "Unknown"

                # Check all ingested frameworks to find a match
                ingested_frameworks = ingestion_status.get("ingested_frameworks", {})
                for status_key, status_info in ingested_frameworks.items():
                    # Check if framework names match (flexible matching)
                    if (
                        status_key.lower() == framework_key
                        or status_key.lower() in framework.lower()
                        or framework.lower() in status_key.lower()
                        or any(
                            word in status_key.lower()
                            for word in framework.lower().split()
                        )
                    ):
                        framework_info = status_info
                        last_updated = status_info.get("last_updated", "Unknown")
                        break

                # Parse and format the last_updated date
                if last_updated != "Unknown" and last_updated:
                    try:
                        from datetime import datetime

                        dt = datetime.fromisoformat(last_updated.replace("Z", "+00:00"))
                        last_updated = dt.strftime("%Y-%m-%d")
                    except:
                        last_updated = (
                            last_updated[:10]
                            if len(last_updated) >= 10
                            else last_updated
                        )

                with st.expander(f"📋 {framework.upper()}"):
                    if framework == "attack":
                        display_attack_stats(fw_stats, last_updated)
                    else:
                        display_compliance_stats(fw_stats, last_updated)

    documents = stats.get("documents", {})
    if documents and documents.get("total_documents", 0) > 0:
        st.markdown("#### 📄 Document Information")
        st.metric("Total Documents", documents.get("total_documents", 0))

    relationships = stats.get("relationships", {})
    if relationships:
        st.markdown("#### 🔗 Relationship Breakdown")
        rel_cols = st.columns(min(len(relationships), 4))

        for i, (rel_type, count) in enumerate(relationships.items()):
            with rel_cols[i % 4]:
                st.metric(rel_type.replace("_", " ").title(), f"{count:,}")


def display_attack_stats(stats: Dict[str, Any], last_updated: str = "Unknown"):
    """
    Display MITRE ATT&CK framework statistics.

    Args:
        stats: Dictionary containing ATT&CK statistics
        last_updated: Last update timestamp for the framework
    """
    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric("Techniques", f"{stats.get('techniques', 0):,}")
        st.metric("Tactics", f"{stats.get('tactics', 0):,}")

    with col2:
        st.metric("Groups", f"{stats.get('groups', 0):,}")
        st.metric("Software", f"{stats.get('software', 0):,}")

    with col3:
        st.metric("Mitigations", f"{stats.get('mitigations', 0):,}")
        st.metric(
            "Last Updated",
            last_updated[:10] if last_updated != "Unknown" else "Unknown",
        )


def display_compliance_stats(stats: Dict[str, Any], last_updated: str = "Unknown"):
    """
    Display compliance framework statistics.

    Args:
        stats: Dictionary containing compliance framework statistics
        last_updated: Last update timestamp for the framework
    """
    col1, col2 = st.columns(2)

    with col1:
        st.metric("Controls", f"{stats.get('controls', 0):,}")
        st.metric("Version", stats.get("version", "N/A"))

    with col2:
        st.metric("Regulatory Body", stats.get("regulatory_body", "Unknown"))
        st.metric(
            "Last Updated",
            last_updated[:10] if last_updated != "Unknown" else "Unknown",
        )


def sidebar_components(graph):
    """
    Render enhanced sidebar with framework list and essential actions.

    Args:
        graph: Neo4j database connection for operations
    """
    st.sidebar.markdown("### 🛡️ Framework List")

    ingestion_status = get_ingestion_status()
    frameworks = ingestion_status.get("ingested_frameworks", {})

    if frameworks:
        for framework, info in frameworks.items():
            status = info.get("status", "not_ingested")
            if status == "ingested":
                st.sidebar.write(f"• {framework.upper()}")
            else:
                st.sidebar.write(f"• {framework.upper()}: Not Ingested")
    else:
        st.sidebar.info("No frameworks ingested yet")

    st.sidebar.markdown("### ⚡ Quick Actions")

    # Reset and Reingest KB
    if st.sidebar.button("🔄 Reset and Reingest KB"):
        if st.sidebar.button("⚠️ Confirm Reset", key="confirm_reset"):
            try:
                with st.spinner("Resetting knowledge base..."):
                    reset_ingestion_status()
                    invalidate_statistics_cache()

                    attack_ingester = AttackIngestion()
                    domains = ["enterprise", "ics"]
                    success, message = attack_ingester.ingest_attack_data(
                        graph, domains, clear_existing=True
                    )

                if success:
                    st.sidebar.success("✅ KB reset and reingested!")
                    invalidate_statistics_cache()
                else:
                    st.sidebar.error(f"❌ Reset failed: {message}")

            except Exception as e:
                st.sidebar.error(f"❌ Error during reset: {str(e)}")
        else:
            st.sidebar.warning(
                "⚠️ This will clear all ingested data. Click 'Confirm Reset' to proceed."
            )

    # Logout
    if st.sidebar.button("🚪 Logout", help="Logout from the application"):
        from src.auth.auth import streamlit_logout

        streamlit_logout()
        st.rerun()

    st.sidebar.markdown("### ❓ Help")
    with st.sidebar.expander("💡 Usage Tips"):
        st.write(
            """
        **Chat Interface:**
        - Ask about specific techniques (e.g., T1055)
        - Query compliance controls
        - Request framework comparisons
        
        **Document Ingestion:**
        - Upload PDF documents
        - Select appropriate framework type
        - Wait for processing completion
        
        **Search:**
        - Use specific keywords
        - Filter by node types
        - Adjust result limits
        """
        )


def chat_tab(graph, llm):
    """
    Render the interactive chat interface for cybersecurity knowledge queries.

    This function provides a conversational interface where users can ask questions
    about cybersecurity frameworks, threat intelligence, and compliance requirements.
    The chat maintains conversation history and provides contextual responses.

    Args:
        graph: Neo4j database connection for knowledge retrieval
        llm: Language model service for generating responses
    """
    # Custom CSS for better chat styling
    st.markdown(
        """
    <style>
    .chat-header {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 20px;
        border-radius: 10px;
        margin-bottom: 20px;
        text-align: center;
    }
    .feature-box {
        background: linear-gradient(45deg, #667eea, #764ba2);
        color: white;
        padding: 15px;
        border-radius: 10px;
        margin: 5px;
        text-align: center;
    }
    .chat-stats {
        background: #f8f9fa;
        padding: 15px;
        border-radius: 8px;
        border: 1px solid #e9ecef;
        margin: 10px 0;
    }
    </style>
    """,
        unsafe_allow_html=True,
    )

    # Enhanced header
    st.markdown(
        """
    <div class="chat-header">
        <h2 style="color: white; margin: 0;">🔍 Cybersecurity Knowledge Assistant</h2>
        <p style="color: rgba(255,255,255,0.9); margin: 10px 0 0 0;">Your intelligent companion for cybersecurity frameworks and threat intelligence</p>
    </div>
    """,
        unsafe_allow_html=True,
    )

    if "messages" not in st.session_state:
        st.session_state.messages = []
        st.session_state.messages.append(
            {
                "role": "assistant",
                "content": "🎯 Welcome! I'm your cybersecurity knowledge assistant, ready to help you navigate the complex world of security frameworks and threat intelligence.",
            }
        )

    # Enhanced feature showcase
    st.markdown("#### 🌟 What I Can Help You With")
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.markdown(
            """
        <div class="feature-box">
            <h4>🎯 ATT&CK Framework</h4>
            <p style="margin: 0; font-size: 0.9em;">Techniques, tactics, threat groups</p>
        </div>
        """,
            unsafe_allow_html=True,
        )

    with col2:
        st.markdown(
            """
        <div class="feature-box">
            <h4>📋 Compliance</h4>
            <p style="margin: 0; font-size: 0.9em;">Compliance & regulatory frameworks</p>
        </div>
        """,
            unsafe_allow_html=True,
        )

    with col3:
        st.markdown(
            """
        <div class="feature-box">
            <h4>🔗 Cross-Analysis</h4>
            <p style="margin: 0; font-size: 0.9em;">Framework relationships</p>
        </div>
        """,
            unsafe_allow_html=True,
        )

    with col4:
        st.markdown(
            """
        <div class="feature-box">
            <h4>💡 Best Practices</h4>
            <p style="margin: 0; font-size: 0.9em;">Implementation guidance</p>
        </div>
        """,
            unsafe_allow_html=True,
        )

    # Enhanced controls
    st.markdown("#### 💬 Chat Controls")
    col1, col2 = st.columns([2, 1])

    with col1:
        framework_scope = st.selectbox(
            "🔍 Framework Scope",
            ["All Frameworks", "ATT&CK Only", "Compliance Frameworks"],
            help="Choose which frameworks to focus on for responses",
        )

    with col2:
        if st.button(
            "🧹 Clear Chat", help="Clear conversation history", use_container_width=True
        ):
            st.session_state.messages = []
            st.session_state.messages.append(
                {
                    "role": "assistant",
                    "content": "🎯 Chat cleared! Ready for new cybersecurity questions.",
                }
            )
            st.rerun()

    # Chat statistics
    conversation_count = len(
        [msg for msg in st.session_state.messages if msg["role"] == "user"]
    )

    if conversation_count > 0:
        st.markdown(
            f"""
        <div class="chat-stats">
            <strong>📊 Session:</strong> {conversation_count} questions • Scope: {framework_scope}
        </div>
        """,
            unsafe_allow_html=True,
        )

    # Sample questions
    with st.expander("💡 Sample Questions", expanded=False):
        sample_cols = st.columns(2)
        samples = [
            "Tell me about ATT&CK technique T1055",
            "What are NIST cybersecurity controls?",
            "Show me techniques used by APT29",
            "How do HIPAA controls map to threats?",
        ]
        for i, question in enumerate(samples):
            with sample_cols[i % 2]:
                if st.button(f"🔍 {question}", key=f"sample_{i}"):
                    st.session_state.auto_question = question
                    st.rerun()

    # Enhanced chat display
    st.markdown("#### 💭 Conversation")
    chat_container = st.container()

    with chat_container:
        for i, message in enumerate(st.session_state.messages):
            if message["role"] == "assistant":
                with st.chat_message("assistant", avatar="🤖"):
                    if i == 0:
                        st.info(
                            "🛡️ **Hello!** I'm ready to help with cybersecurity frameworks, threat intelligence, and compliance questions. Try asking about specific ATT&CK techniques, compliance requirements, or security best practices!"
                        )
                    else:
                        st.markdown(message["content"])
            else:
                with st.chat_message("user", avatar="👤"):
                    st.markdown(message["content"])

    # Handle auto-filled questions
    prompt = None
    if hasattr(st.session_state, "auto_question"):
        prompt = st.session_state.auto_question
        del st.session_state.auto_question
    else:
        prompt = st.chat_input(
            "🔐 Ask about cybersecurity frameworks, threats, or compliance..."
        )

    if prompt:
        st.session_state.messages.append({"role": "user", "content": prompt})

        with st.chat_message("user", avatar="👤"):
            st.markdown(prompt)

        with st.chat_message("assistant", avatar="🤖"):
            with st.spinner("🧠 Analyzing and retrieving knowledge..."):
                try:
                    from src.api.llm_service import (
                        analyze_user_query,
                        chat_with_knowledge_base,
                    )

                    analysis = analyze_user_query(llm, prompt, framework_scope)
                    context = get_context_from_knowledge_base(
                        graph, prompt, max_results=20, framework_scope=framework_scope
                    )
                    response = chat_with_knowledge_base(
                        llm, context, prompt, framework_scope
                    )

                    st.markdown(response)

                    # Response metadata
                    st.markdown(
                        f"""
                    <div style="background: #f8f9fa; padding: 8px; border-radius: 5px; margin-top: 10px; font-size: 0.8em; color: #6c757d;">
                        📊 Generated using {framework_scope} • ⚡ Powered by Gemini AI
                    </div>
                    """,
                        unsafe_allow_html=True,
                    )

                    st.session_state.messages.append(
                        {"role": "assistant", "content": response}
                    )

                except Exception as e:
                    error_msg = f"❌ I encountered an error: {str(e)}. Please try rephrasing your question."
                    st.error(error_msg)
                    st.session_state.messages.append(
                        {"role": "assistant", "content": error_msg}
                    )


def knowledge_base_tab(graph):
    """
    Render the knowledge base management interface.

    Provides comprehensive tools for exploring, searching, and managing
    the cybersecurity knowledge base including statistics, search functionality,
    and document management capabilities.

    Args:
        graph: Neo4j database connection for data operations
    """
    st.markdown("### 🔍 Knowledge Base Management")

    kb_tab1, kb_tab2, kb_tab3 = st.tabs(["📊 Statistics", "🔍 Search", "⚙️ Management"])

    with kb_tab1:
        display_dynamic_statistics(graph)

    with kb_tab2:
        knowledge_base_search(graph)

    with kb_tab3:
        knowledge_base_management(graph)


def knowledge_base_search(graph):
    """
    Provide advanced search functionality for the knowledge base.

    Enables users to search across different node types, apply filters,
    and retrieve specific information from the cybersecurity knowledge graph.

    Args:
        graph: Neo4j database connection for search operations
    """
    st.markdown("#### 🔍 Knowledge Base Search")

    col1, col2 = st.columns([2, 1])

    with col1:
        search_query = st.text_input(
            "Search Query",
            placeholder="Enter keywords (e.g., 'credential access', 'T1055', 'encryption requirements')",
            help="Search across all frameworks for techniques, controls, and requirements",
        )

    with col2:
        # Fix the node types filter to work properly
        available_types = [
            "All",
            "Technique",
            "Control",
            "Group",
            "Software",
            "Framework",
        ]
        node_types = st.multiselect(
            "Filter by Type",
            available_types,
            default=["All"],
            help="Select which types of information to search",
        )

    with st.expander("🛠️ Advanced Options"):
        col3, col4 = st.columns(2)
        with col3:
            result_limit = st.slider("Result Limit", 5, 50, 15)
        with col4:
            exact_match = st.checkbox(
                "Exact Match for IDs", help="Use for specific technique IDs like T1055"
            )

    if search_query:
        try:
            with st.spinner("Searching knowledge base..."):
                # Determine search types based on filter
                if "All" in node_types:
                    search_types = [
                        "Technique",
                        "Control",
                        "Group",
                        "Software",
                        "Framework",
                    ]
                else:
                    search_types = [t for t in node_types if t != "All"]

                all_results = []

                for node_type in search_types:
                    if exact_match:
                        # Exact match queries
                        if node_type == "Technique":
                            query = """
                            MATCH (n:Technique)
                            WHERE n.technique_id = $search_term OR n.name = $search_term
                            RETURN n.technique_id as id, 
                                   n.name as name, n.description as description,
                                   'Technique' as type, labels(n) as labels
                            LIMIT $limit
                            """
                        elif node_type == "Control":
                            query = """
                            MATCH (n:Control)
                            WHERE n.control_id = $search_term OR n.name = $search_term
                            RETURN n.control_id as id, 
                                   n.name as name, n.description as description,
                                   'Control' as type, labels(n) as labels
                            LIMIT $limit
                            """
                        else:
                            query = f"""
                            MATCH (n:{node_type})
                            WHERE n.id = $search_term OR n.name = $search_term
                            RETURN n.id as id, 
                                   n.name as name, n.description as description,
                                   '{node_type}' as type, labels(n) as labels
                            LIMIT $limit
                            """
                    else:
                        # Partial match queries - this is the key fix
                        if node_type == "Technique":
                            query = """
                            MATCH (n:Technique)
                            WHERE toLower(n.name) CONTAINS toLower($search_term) 
                               OR toLower(n.description) CONTAINS toLower($search_term)
                               OR toLower(COALESCE(n.technique_id, '')) CONTAINS toLower($search_term)
                            RETURN n.technique_id as id, 
                                   n.name as name, n.description as description,
                                   'Technique' as type, labels(n) as labels
                            LIMIT $limit
                            """
                        elif node_type == "Control":
                            query = """
                            MATCH (n:Control)
                            WHERE toLower(n.name) CONTAINS toLower($search_term) 
                               OR toLower(n.description) CONTAINS toLower($search_term)
                               OR toLower(COALESCE(n.control_id, '')) CONTAINS toLower($search_term)
                            RETURN n.control_id as id, 
                                   n.name as name, n.description as description,
                                   'Control' as type, labels(n) as labels
                            LIMIT $limit
                            """
                        else:
                            query = f"""
                            MATCH (n:{node_type})
                            WHERE toLower(n.name) CONTAINS toLower($search_term) 
                               OR toLower(COALESCE(n.description, '')) CONTAINS toLower($search_term)
                               OR toLower(COALESCE(n.id, '')) CONTAINS toLower($search_term)
                            RETURN n.id as id, 
                                   n.name as name, n.description as description,
                                   '{node_type}' as type, labels(n) as labels
                            LIMIT $limit
                            """

                    node_results = graph.query(
                        query,
                        {
                            "search_term": search_query,
                            "limit": result_limit,
                        },
                    )
                    all_results.extend(node_results)

                # Sort results by relevance and limit to the specified number
                results = all_results[:result_limit]

            if results:
                st.success(f"🎯 Found {len(results)} results")

                for i, result in enumerate(results, 1):
                    result_id = result.get("id", "Unknown")
                    result_name = result.get("name", "Unknown")
                    display_name = (
                        f"{result_id} - {result_name}"
                        if result_id != "Unknown"
                        else result_name
                    )

                    with st.expander(f"📄 Result {i}: {display_name}"):
                        if result.get("id"):
                            st.write(f"**ID**: {result['id']}")
                        if result.get("name"):
                            st.write(f"**Name**: {result['name']}")
                        if result.get("type"):
                            st.write(f"**Type**: {result['type']}")
                        if result.get("description"):
                            description = result["description"]
                            if len(description) > 500:
                                description = description[:500] + "..."
                            st.write(f"**Description**: {description}")
            else:
                st.info(
                    "🔍 No results found. Try different keywords or check your search criteria."
                )

        except Exception as e:
            st.error(f"❌ Search error: {str(e)}")
    else:
        st.info("💡 Enter a search query to explore the knowledge base")


def knowledge_base_management(graph):
    """
    Provide document management tools for compliance framework processing.

    Allows users to upload new compliance documents and view processing guides.

    Args:
        graph: Neo4j database connection for management operations
    """
    st.markdown("#### ⚙️ Document Management")

    st.markdown("##### 📄 Document Processing")
    st.info(
        "Upload compliance framework documents for automatic processing and knowledge graph integration."
    )

    uploaded_file = st.file_uploader(
        "Choose a PDF file",
        type="pdf",
        help="Upload any compliance or regulatory framework PDF",
        key="pdf_uploader",
    )

    if uploaded_file:
        # Create a unique key for this upload session
        file_key = f"processing_{uploaded_file.name}_{uploaded_file.size}"

        # Check if we're already processing this file
        if f"processing_{file_key}" not in st.session_state:
            st.session_state[f"processing_{file_key}"] = True

            with st.spinner("🤖 Processing document..."):
                try:
                    from src.cybersecurity.compliance_ingestion import (
                        ComplianceIngestion,
                    )

                    with tempfile.NamedTemporaryFile(
                        delete=False, suffix=".pdf"
                    ) as tmp_file:
                        tmp_file.write(uploaded_file.read())
                        tmp_file_path = tmp_file.name

                    ingestion = ComplianceIngestion()
                    success, message, stats = ingestion.ingest_document_with_llm(
                        graph, tmp_file_path
                    )

                    os.unlink(tmp_file_path)

                    if success:
                        st.success(f"✅ {message}")

                        if stats:
                            col1, col2, col3 = st.columns(3)
                            with col1:
                                st.metric(
                                    "Controls Processed", stats.get("controls_count", 0)
                                )
                            with col2:
                                st.metric(
                                    "Relationships Created",
                                    stats.get("relationships_created", 0),
                                )
                            with col3:
                                st.metric(
                                    "Technique Mappings",
                                    stats.get("technique_mappings", 0),
                                )

                        # Clear the file uploader state to prevent "already ingested" message
                        if f"processing_{file_key}" in st.session_state:
                            del st.session_state[f"processing_{file_key}"]

                        invalidate_statistics_cache()

                        # Use success container with rerun button instead of automatic rerun
                        st.info(
                            "📊 Statistics updated! Switch to Statistics tab to see the changes."
                        )
                        if st.button(
                            "🔄 Refresh Page", help="Refresh to clear the uploaded file"
                        ):
                            st.rerun()
                    else:
                        st.error(f"❌ {message}")
                        if f"processing_{file_key}" in st.session_state:
                            del st.session_state[f"processing_{file_key}"]

                except Exception as e:
                    st.error(f"❌ Error processing document: {str(e)}")
                    if f"processing_{file_key}" in st.session_state:
                        del st.session_state[f"processing_{file_key}"]

    st.markdown("##### ❓ Document Processing Guide")
    with st.expander("💡 How It Works"):
        st.markdown(
            """
        **Smart Document Processing:**
        1. 📄 **Upload**: Select any compliance framework PDF document
        2. 🤖 **Analysis**: LLM automatically detects framework type and industry
        3. 🏗️ **Structure Extraction**: AI extracts controls, requirements, and metadata
        4. 🔗 **Knowledge Graph**: Creates nodes and relationships in the database
        5. 🎯 **ATT&CK Mapping**: Maps compliance controls to MITRE ATT&CK techniques
        
        **Supported Formats:**
        - Any compliance framework PDF (NIST, ISO 27001, PCI-DSS, HIPAA, etc.)
        - Regulatory guidance documents
        - Security standards and benchmarks
        - Industry-specific compliance requirements
        
        **Processing Features:**
        - Automatic framework type detection
        - Industry classification
        - Control-to-technique correlation
        - Metadata extraction and validation
        """
        )
