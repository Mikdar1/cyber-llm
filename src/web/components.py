"""
Streamlit components for the multi-framework cybersecurity application.
"""
import streamlit as st

from src.knowledge_base.graph_operations import (
    get_context_from_knowledge_base, get_selective_context_from_knowledge_base, 
    get_framework_aware_context, get_attack_statistics, get_techniques_by_tactic, 
    get_threat_group_techniques, search_by_technique_id, get_all_tactics, get_all_threat_groups
)
from src.api.llm_service import chat_with_knowledge_base, analyze_user_query
from src.utils.initialization import refresh_knowledge_base, ingest_individual_framework

def chat_tab(graph, llm):
    """Display the chat tab for interacting with the multi-framework cybersecurity AI assistant."""
    st.markdown("### 💬 Ask Your Multi-Framework Cybersecurity AI Assistant")
    
    # Add framework and search mode selection
    col1, col2 = st.columns(2)
    
    with col1:
        framework_scope = st.selectbox(
            "🎯 Framework Scope:",
            options=["All Frameworks", "ATT&CK Only", "CIS Controls", "NIST CSF", "HIPAA", "FFIEC", "PCI DSS"],
            index=0,
            help="Choose which cybersecurity frameworks to include in your search"
        )
    
    with col2:
        search_mode = st.radio(
            "🔧 Search Mode:",
            options=["Smart Selective Search", "Comprehensive Search"],
            index=0,
            horizontal=True,
            help="Smart Search analyzes your question and queries relevant object types. Comprehensive Search queries all types."
        )
    
    # Display chat messages only if there are any
    if st.session_state.messages:
        st.markdown('<div class="chat-container">', unsafe_allow_html=True)
        for message in st.session_state.messages:
            if message["role"] == "user":
                st.markdown(f'<div class="user-message">👤 {message["content"]}</div>', unsafe_allow_html=True)
            else:
                st.markdown(f'<div class="assistant-message">🤖 {message["content"]}</div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)
    else:
        st.info("💡 Start a conversation by asking about any cybersecurity framework. Examples: 'Tell me about T1055 Process Injection', 'What are CIS Control 1 safeguards?', 'Explain NIST CSF Protect function', 'What are HIPAA privacy requirements?'")
    
    # Chat input
    user_input = st.chat_input("Ask me anything about cybersecurity frameworks...")
    
    if user_input:
        # Add user message to chat history
        st.session_state.messages.append({"role": "user", "content": user_input})
        
        # Get AI response based on selected search mode and framework scope
        with st.spinner(f"Analyzing {framework_scope} cybersecurity data..."):
            if search_mode == "Smart Selective Search":
                # Step 1: Analyze the user query to determine relevant object types within framework scope
                with st.spinner(f"🔍 Analyzing your question for {framework_scope}..."):
                    query_analysis = analyze_user_query(llm, user_input, framework_scope)
                
                # Step 2: Get selective context from the knowledge base with framework filtering
                with st.spinner(f"📊 Searching {', '.join(query_analysis['relevant_types'])} in {framework_scope}..."):
                    context = get_framework_aware_context(
                        graph, 
                        query_analysis['keywords'], 
                        query_analysis['relevant_types'],
                        framework_scope
                    )
                
                # Step 3: Generate framework-specific response using LLM
                with st.spinner("🤖 Generating framework-specific response..."):
                    response = chat_with_knowledge_base(llm, context, user_input, framework_scope)
                    
                # Add analysis info to response (for transparency)
                analysis_info = f"\n\n---\n*🎯 Framework: {framework_scope}*\n*🔍 Query Focus: {query_analysis['focus']}*\n*� Searched: {', '.join(query_analysis['relevant_types'])}*\n*📝 Keywords: {', '.join(query_analysis['keywords'])}*"
                response = response + analysis_info
                
            else:  # Comprehensive Search
                # Use comprehensive search across ALL object types within framework scope
                with st.spinner(f"📊 Searching ALL {framework_scope} object types comprehensively..."):
                    # For comprehensive search, include all possible object types for the framework
                    if framework_scope == "ATT&CK Only":
                        all_types = ["techniques", "malware", "threat_groups", "tools", "mitigations", "data_sources", "campaigns"]
                    elif framework_scope == "CIS Controls":
                        all_types = ["cis_controls", "cis_safeguards", "implementation_groups"]
                    elif framework_scope == "NIST CSF":
                        all_types = ["nist_functions", "nist_categories", "nist_subcategories"]
                    elif framework_scope == "HIPAA":
                        all_types = ["hipaa_regulations", "hipaa_sections", "hipaa_requirements"]
                    elif framework_scope == "FFIEC":
                        all_types = ["ffiec_categories", "ffiec_procedures", "ffiec_guidance"]
                    elif framework_scope == "PCI DSS":
                        all_types = ["pci_requirements", "pci_procedures", "pci_controls"]
                    else:  # All Frameworks
                        all_types = ["techniques", "malware", "threat_groups", "tools", "mitigations", 
                                   "cis_controls", "cis_safeguards", "nist_functions", "nist_categories",
                                   "hipaa_regulations", "hipaa_sections", "pci_requirements"]
                    
                    # Extract keywords from user input for comprehensive search
                    keywords = [word.strip() for word in user_input.split() if len(word.strip()) > 2][:5]
                    
                    context = get_framework_aware_context(
                        graph, 
                        keywords,
                        all_types,
                        framework_scope
                    )
                
                with st.spinner("🤖 Generating comprehensive response..."):
                    response = chat_with_knowledge_base(llm, context, user_input, framework_scope)
                    
                # Add framework info to response
                framework_info = f"\n\n---\n*🎯 Framework: {framework_scope}*\n*🔍 Search Mode: Comprehensive (all {len(all_types)} object types)*\n*📊 Object Types: {', '.join(all_types)}*"
                response = response + framework_info
        
        # Add assistant response to chat history
        st.session_state.messages.append({"role": "assistant", "content": response})
        
        # Rerun to update the chat display
        st.rerun()

def knowledge_base_tab(graph):
    """Display the multi-framework knowledge base exploration tab."""
    st.markdown("""
    <div class="kb-section">
        <h2 style="color: inherit;">🔍 Explore Multi-Framework Knowledge Base</h2>
        <p style="color: inherit;">Browse and explore comprehensive cybersecurity frameworks</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Framework selection
    selected_framework = st.selectbox(
        "Select Framework to Explore:",
        ["All Frameworks", "ATT&CK", "CIS Controls", "NIST CSF", "HIPAA", "FFIEC", "PCI DSS"],
        help="Choose which cybersecurity framework to explore"
    )
    
    # Statistics section
    with st.expander("📊 Knowledge Base Statistics", expanded=True):
        try:
            if selected_framework == "All Frameworks":
                # Get comprehensive multi-framework statistics
                stats = get_attack_statistics(graph)
                
                # Add queries for other frameworks with correct labels
                try:
                    cis_stats = graph.query("MATCH (n:CIS_Control) RETURN count(n) as count")[0]['count']
                except:
                    cis_stats = 0
                try:
                    nist_stats = graph.query("MATCH (n:NIST_Function) RETURN count(n) as count")[0]['count']
                except:
                    nist_stats = 0
                try:
                    hipaa_stats = graph.query("MATCH (n:HIPAA_Regulation) RETURN count(n) as count")[0]['count']
                except:
                    hipaa_stats = 0
                
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.metric("ATT&CK Techniques", stats.get('techniques', 0))
                    st.metric("Threat Groups", stats.get('threat_groups', 0))
                
                with col2:
                    st.metric("CIS Controls", cis_stats)
                    st.metric("ATT&CK Malware", stats.get('malware', 0))
                
                with col3:
                    st.metric("NIST Functions", nist_stats)
                    st.metric("ATT&CK Tools", stats.get('tools', 0))
                
                with col4:
                    st.metric("HIPAA Regulations", hipaa_stats)
                    st.metric("ATT&CK Tactics", stats.get('tactics', 0))
                    
            elif selected_framework == "ATT&CK":
                stats = get_attack_statistics(graph)
                
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Techniques", stats.get('techniques', 0))
                    st.metric("Malware", stats.get('malware', 0))
                
                with col2:
                    st.metric("Threat Groups", stats.get('threat_groups', 0))
                    st.metric("Tools", stats.get('tools', 0))
                
                with col3:
                    st.metric("Tactics", stats.get('tactics', 0))
                    st.metric("Relationships", stats.get('relationships', 0))
                    
            elif selected_framework == "CIS Controls":
                try:
                    cis_stats = graph.query("MATCH (n:CIS_Control) RETURN count(n) as count")[0]['count']
                    safeguards_stats = graph.query("MATCH (n:CIS_Safeguard) RETURN count(n) as count")[0]['count']
                    col1, col2 = st.columns(2)
                    with col1:
                        st.metric("CIS Controls", cis_stats)
                    with col2:
                        st.metric("Safeguards", safeguards_stats)
                except:
                    st.info("CIS Controls data not available")
                    
            elif selected_framework == "NIST CSF":
                try:
                    functions_stats = graph.query("MATCH (n:NIST_Function) RETURN count(n) as count")[0]['count']
                    categories_stats = graph.query("MATCH (n:NIST_Category) RETURN count(n) as count")[0]['count']
                    col1, col2 = st.columns(2)
                    with col1:
                        st.metric("Functions", functions_stats)
                    with col2:
                        st.metric("Categories", categories_stats)
                except:
                    st.info("NIST CSF data not available")
                    
            elif selected_framework == "HIPAA":
                try:
                    regulations_stats = graph.query("MATCH (n:HIPAA_Regulation) RETURN count(n) as count")[0]['count']
                    sections_stats = graph.query("MATCH (n:HIPAA_Section) RETURN count(n) as count")[0]['count']
                    col1, col2 = st.columns(2)
                    with col1:
                        st.metric("Regulations", regulations_stats)
                    with col2:
                        st.metric("Sections", sections_stats)
                except:
                    st.info("HIPAA data not available")
                    
            else:
                st.info(f"Statistics for {selected_framework} not yet implemented")
                
        except Exception as e:
            st.error(f"Error loading statistics: {e}")
    
    # Search section
    st.markdown("### 🔎 Search Knowledge Base")
    
    if selected_framework == "ATT&CK" or selected_framework == "All Frameworks":
        search_type = st.radio(
            "Search ATT&CK by:",
            ["Technique ID", "Tactic", "Threat Group"],
            horizontal=True
        )
        
        if search_type == "Technique ID":
            technique_id = st.text_input("Enter Technique ID (e.g., T1055):")
            if technique_id and st.button("Search Technique"):
                try:
                    result = search_by_technique_id(graph, technique_id.upper())
                    if result:
                        st.markdown(f"### {result['technique_id']} - {result['name']}")
                        st.markdown(f"**Description:** {result['description']}")
                        
                        if result['platforms']:
                            st.markdown(f"**Platforms:** {', '.join(result['platforms'])}")
                        
                        if result['tactics']:
                            st.markdown(f"**Tactics:** {', '.join(result['tactics'])}")
                        
                        if result['threat_groups']:
                            threat_groups = [group for group in result['threat_groups'] if group]
                            if threat_groups:
                                st.markdown(f"**Used by Threat Groups:** {', '.join(threat_groups)}")
                        
                        if result['malware']:
                            malware_list = [malware for malware in result['malware'] if malware]
                            if malware_list:
                                st.markdown(f"**Associated Malware:** {', '.join(malware_list)}")
                    else:
                        st.warning(f"Technique {technique_id} not found.")
                except Exception as e:
                    st.error(f"Error searching technique: {e}")
        
        elif search_type == "Tactic":
            try:
                tactics = get_all_tactics(graph)
                if tactics:
                    selected_tactic = st.selectbox("Select a tactic:", tactics)
                    if selected_tactic and st.button("Show Techniques"):
                        techniques = get_techniques_by_tactic(graph, selected_tactic)
                        if techniques:
                            st.markdown(f"### Techniques for {selected_tactic.title()} Tactic")
                            for tech in techniques:
                                with st.expander(f"{tech['technique_id']} - {tech['name']}"):
                                    st.markdown(tech['description'][:500] + "...")
                        else:
                            st.info("No techniques found for this tactic.")
                else:
                    st.info("No tactics found in the knowledge base.")
            except Exception as e:
                st.error(f"Error loading tactics: {e}")
        
        elif search_type == "Threat Group":
            try:
                threat_groups = get_all_threat_groups(graph)
                if threat_groups:
                    group_names = [group['name'] for group in threat_groups if group['name']]
                    selected_group = st.selectbox("Select a threat group:", group_names)
                    if selected_group and st.button("Show Techniques"):
                        techniques = get_threat_group_techniques(graph, selected_group)
                        if techniques:
                            st.markdown(f"### Techniques used by {selected_group}")
                            for tech in techniques:
                                with st.expander(f"{tech['technique_id']} - {tech['technique_name']}"):
                                    st.markdown(f"**Relationship:** {tech['relationship_type']}")
                                    st.markdown(tech['description'][:500] + "...")
                        else:
                            st.info("No techniques found for this threat group.")
                else:
                    st.info("No threat groups found in the knowledge base.")
            except Exception as e:
                st.error(f"Error loading threat groups: {e}")
    
    else:
        st.info(f"Search functionality for {selected_framework} will be available soon.")
        st.markdown("*Currently only ATT&CK framework search is implemented.*")

def sidebar_components(graph):
    """Display the sidebar components."""
    # User info and logout at the top of sidebar
    from src.auth.auth import check_streamlit_auth, streamlit_logout
    
    if check_streamlit_auth():
        username = st.session_state.get("username", "User")
        st.sidebar.markdown("### 👤 User Session")
        st.sidebar.markdown(f"**Welcome, {username}!**")
        if st.sidebar.button("🚪 Logout", use_container_width=True):
            streamlit_logout()
            st.rerun()
        st.sidebar.markdown("---")
    
    st.sidebar.markdown("### 🛡️ Cybersecurity KB")
    st.sidebar.markdown("**Features:**")
    st.sidebar.markdown("• Chat with ATT&CK knowledge base")
    st.sidebar.markdown("• Explore techniques and tactics")
    st.sidebar.markdown("• Search threat intelligence")
    st.sidebar.markdown("• Browse threat groups and malware")

    st.sidebar.markdown("---")
    st.sidebar.markdown("### � Knowledge Base Info")
    
    try:
        stats = get_attack_statistics(graph)
        st.sidebar.markdown(f"**Techniques:** {stats.get('techniques', 0)}")
        st.sidebar.markdown(f"**Threat Groups:** {stats.get('threat_groups', 0)}")
        st.sidebar.markdown(f"**Malware:** {stats.get('malware', 0)}")
        st.sidebar.markdown(f"**Tools:** {stats.get('tools', 0)}")
    except:
        st.sidebar.error("Could not load statistics.")

    st.sidebar.markdown("---")
    
    # Multi-framework data management
    st.sidebar.subheader("🔧 Data Management")
    
    # Framework selection for individual ingestion
    selected_framework = st.sidebar.selectbox(
        "Select Framework to Re-ingest:",
        ["All Frameworks", "ATT&CK", "CIS Controls", "NIST CSF", "HIPAA", "FFIEC", "PCI DSS"],
        help="Choose which framework to re-ingest data for"
    )
    
    if st.sidebar.button("🔄 Re-ingest Framework Data"):
        if st.session_state.knowledge_base_initialized:
            if st.sidebar.button("⚠️ Confirm Re-ingest", key="confirm_reingest"):
                st.warning("Re-ingesting framework data may take some time. Please do not close the browser.")
                
                if selected_framework == "All Frameworks":
                    success, msg = refresh_knowledge_base(graph)
                else:
                    framework_map = {
                        "ATT&CK": "attack",
                        "CIS Controls": "cis", 
                        "NIST CSF": "nist",
                        "HIPAA": "hipaa",
                        "FFIEC": "ffiec",
                        "PCI DSS": "pci_dss"
                    }
                    success, msg = ingest_individual_framework(graph, framework_map[selected_framework])
                
                if success:
                    st.sidebar.success(f"🎉 Successfully re-ingested {selected_framework} data!")
                    st.rerun()
                else:
                    st.sidebar.error(f"❌ Failed to re-ingest {selected_framework} data: {msg}")
        else:
            st.sidebar.info("Knowledge base is not initialized.")

    if st.sidebar.button("🔄 Reset Complete Knowledge Base"):
        try:
            from src.knowledge_base.database import clear_knowledge_base
            clear_knowledge_base(graph)
            st.session_state.knowledge_base_initialized = False
            st.session_state.messages = []
            st.success("Knowledge base reset successfully!")
            st.rerun()
        except Exception as e:
            st.error(f"Error resetting knowledge base: {e}")

    if st.sidebar.button("💬 Clear Chat History"):
        st.session_state.messages = []
        st.rerun()
