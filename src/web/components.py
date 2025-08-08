"""
Streamlit components for the multi-framework cybersecurity application.
"""
import streamlit as st

from src.knowledge_base.graph_operations import (
    get_framework_aware_context, get_multi_framework_statistics, search_multi_framework_knowledge_base,
    get_techniques_by_tactic, get_threat_group_techniques, search_by_technique_id, 
    get_all_tactics, get_all_threat_groups
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
                    # Use multi-framework search for comprehensive results
                    if framework_scope == "All Frameworks" or len(query_analysis['relevant_types']) > 3:
                        context = search_multi_framework_knowledge_base(graph, user_input)
                    else:
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
                    # Use multi-framework search for comprehensive results across all frameworks
                    if framework_scope == "All Frameworks":
                        context = search_multi_framework_knowledge_base(graph, user_input)
                    else:
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
                if framework_scope == "All Frameworks":
                    framework_info = f"\n\n---\n*🎯 Framework: {framework_scope}*\n*🔍 Search Mode: Multi-framework comprehensive search*"
                else:
                    framework_info = f"\n\n---\n*🎯 Framework: {framework_scope}*\n*� Search Mode: Comprehensive framework search*"
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
            stats = get_multi_framework_statistics(graph)
            
            if selected_framework == "All Frameworks":
                # Overall metrics
                overall = stats.get('Overall', {})
                st.markdown("### 🌐 Overall Statistics")
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Total Nodes", overall.get('total_nodes', 0))
                with col2:
                    st.metric("Total Relationships", overall.get('total_relationships', 0))
                with col3:
                    st.metric("Citations", overall.get('citations', 0))
                
                st.markdown("---")
                
                # Framework-specific metrics in a 2x3 grid for better alignment
                st.markdown("### 📋 Framework Statistics")
                
                # Row 1: ATT&CK, NIST CSF, CIS Controls
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.markdown("#### 🎯 MITRE ATT&CK")
                    attck = stats.get('MITRE_ATTCK', {})
                    # Display ATT&CK metrics in a more compact format
                    st.metric("Techniques", attck.get('techniques', 0))
                    st.metric("Threat Groups", attck.get('threat_groups', 0))
                    
                    # Additional ATT&CK metrics in smaller format
                    col1_sub1, col1_sub2 = st.columns(2)
                    with col1_sub1:
                        st.metric("Malware", attck.get('malware', 0))
                        st.metric("Tools", attck.get('tools', 0))
                    with col1_sub2:
                        st.metric("Tactics", attck.get('tactics', 0))
                        st.metric("Mitigations", attck.get('mitigations', 0))
                
                with col2:
                    st.markdown("#### �️ NIST CSF")
                    nist = stats.get('NIST_CSF', {})
                    st.metric("Functions", nist.get('functions', 0))
                    st.metric("Categories", nist.get('categories', 0))
                    st.metric("Subcategories", nist.get('subcategories', 0))
                    # Add spacing to match ATT&CK height
                    st.write("")
                    st.write("")
                    st.write("")
                
                with col3:
                    st.markdown("#### 🔧 CIS Controls")
                    cis = stats.get('CIS_Controls', {})
                    st.metric("Controls", cis.get('controls', 0))
                    st.metric("Safeguards", cis.get('safeguards', 0))
                    st.metric("Asset Types", cis.get('asset_types', 0))
                    # Add spacing to match ATT&CK height
                    st.write("")
                    st.write("")
                    st.write("")
                
                # Row 2: HIPAA, FFIEC, PCI DSS
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.markdown("#### � HIPAA")
                    hipaa = stats.get('HIPAA', {})
                    st.metric("Regulations", hipaa.get('regulations', 0))
                    st.metric("Sections", hipaa.get('sections', 0))
                    st.metric("Requirements", hipaa.get('requirements', 0))
                
                with col2:
                    st.markdown("#### 🏦 FFIEC")
                    ffiec = stats.get('FFIEC', {})
                    st.metric("Domains", ffiec.get('domains', 0))
                    st.metric("Processes", ffiec.get('processes', 0))
                    st.metric("Activities", ffiec.get('activities', 0))
                
                with col3:
                    st.markdown("#### 💳 PCI DSS")
                    pci = stats.get('PCI_DSS', {})
                    st.metric("Requirements", pci.get('requirements', 0))
                    st.metric("Sub-requirements", pci.get('sub_requirements', 0))
                    st.metric("Testing Procedures", pci.get('testing_procedures', 0))
                    
            elif selected_framework == "ATT&CK":
                attck = stats.get('MITRE_ATTCK', {})
                st.markdown("#### 🎯 MITRE ATT&CK Framework Statistics")
                
                # Row 1: Main entities
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Techniques", attck.get('techniques', 0))
                    st.metric("Malware", attck.get('malware', 0))
                with col2:
                    st.metric("Threat Groups", attck.get('threat_groups', 0))
                    st.metric("Tools", attck.get('tools', 0))
                with col3:
                    st.metric("Tactics", attck.get('tactics', 0))
                    st.metric("Mitigations", attck.get('mitigations', 0))
                
                # Row 2: Additional metrics
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Data Sources", attck.get('data_sources', 0))
                with col2:
                    st.metric("Campaigns", attck.get('campaigns', 0))
                with col3:
                    st.write("")  # Empty for alignment
                    
            elif selected_framework == "CIS Controls":
                cis = stats.get('CIS_Controls', {})
                st.markdown("#### 🔧 CIS Controls Framework Statistics")
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Controls", cis.get('controls', 0))
                with col2:
                    st.metric("Safeguards", cis.get('safeguards', 0))
                with col3:
                    st.metric("Asset Types", cis.get('asset_types', 0))
                    
            elif selected_framework == "NIST CSF":
                nist = stats.get('NIST_CSF', {})
                st.markdown("#### 🏛️ NIST Cybersecurity Framework Statistics")
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Functions", nist.get('functions', 0))
                with col2:
                    st.metric("Categories", nist.get('categories', 0))
                with col3:
                    st.metric("Subcategories", nist.get('subcategories', 0))
                    
            elif selected_framework == "HIPAA":
                hipaa = stats.get('HIPAA', {})
                st.markdown("#### 🏥 HIPAA Security Framework Statistics")
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Regulations", hipaa.get('regulations', 0))
                with col2:
                    st.metric("Sections", hipaa.get('sections', 0))
                with col3:
                    st.metric("Requirements", hipaa.get('requirements', 0))
                    
            elif selected_framework == "FFIEC":
                ffiec = stats.get('FFIEC', {})
                st.markdown("#### 🏦 FFIEC IT Handbook Statistics")
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Domains", ffiec.get('domains', 0))
                with col2:
                    st.metric("Processes", ffiec.get('processes', 0))
                with col3:
                    st.metric("Activities", ffiec.get('activities', 0))
                    
            elif selected_framework == "PCI DSS":
                pci = stats.get('PCI_DSS', {})
                st.markdown("#### 💳 PCI DSS Framework Statistics")
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Requirements", pci.get('requirements', 0))
                with col2:
                    st.metric("Sub-requirements", pci.get('sub_requirements', 0))
                with col3:
                    st.metric("Testing Procedures", pci.get('testing_procedures', 0))
                    
        except Exception as e:
            st.error(f"Error loading statistics: {e}")
    
    # Multi-framework search section
    st.markdown("### 🔎 Search Multi-Framework Knowledge Base")
    
    # Search input with framework selection
    col1, col2 = st.columns([3, 1])
    with col1:
        search_query = st.text_input(
            "Enter search query:",
            placeholder="e.g., 'phishing', 'encryption', 'access control', 'T1055', 'NIST.ID'",
            help="Search across all cybersecurity frameworks or specific framework content"
        )
    with col2:
        search_framework = st.selectbox(
            "Framework Filter:",
            ["All Frameworks", "ATT&CK Only", "CIS Only", "NIST Only", "HIPAA Only", "FFIEC Only", "PCI DSS Only"],
            help="Filter search results by specific framework"
        )
    
    # Search button and results
    if search_query and st.button("🔍 Search Knowledge Base", use_container_width=True):
        with st.spinner(f"Searching {search_framework} for '{search_query}'..."):
            try:
                # Use the comprehensive multi-framework search
                search_results = search_multi_framework_knowledge_base(graph, search_query)
                
                if search_results and search_results != "No relevant information found across any cybersecurity frameworks.":
                    st.markdown("### 📋 Search Results")
                    st.markdown(search_results)
                else:
                    st.info(f"No results found for '{search_query}' in {search_framework}")
                    st.markdown("**Try:**")
                    st.markdown("• Different keywords or terms")
                    st.markdown("• Broader search terms")
                    st.markdown("• Specific technique IDs (e.g., T1055)")
                    st.markdown("• Control identifiers (e.g., CIS Control 1)")
                    
            except Exception as e:
                st.error(f"Error during search: {e}")
    
    # Advanced ATT&CK-specific search (for backwards compatibility)
    if selected_framework == "ATT&CK" or selected_framework == "All Frameworks":
        with st.expander("🎯 Advanced ATT&CK Search", expanded=False):
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
    
    # Framework-specific search hints
    if selected_framework != "All Frameworks":
        st.info(f"💡 **{selected_framework} Search Tips:**")
        if selected_framework == "ATT&CK":
            st.markdown("• Use technique IDs like T1055, T1059")
            st.markdown("• Search for threat groups like APT1, Carbanak")
            st.markdown("• Look for tactics like initial-access, persistence")
        elif selected_framework == "CIS Controls":
            st.markdown("• Search for control numbers like 'Control 1', 'CIS-1'")
            st.markdown("• Look for safeguards and implementation groups")
            st.markdown("• Search for asset types and security functions")
        elif selected_framework == "NIST CSF":
            st.markdown("• Search for functions like 'Identify', 'Protect', 'Detect'")
            st.markdown("• Look for categories like 'ID.AM', 'PR.AC'")
            st.markdown("• Search for subcategories and outcomes")
        elif selected_framework == "HIPAA":
            st.markdown("• Search for requirements like 'Administrative Safeguards'")
            st.markdown("• Look for sections like 'Physical Safeguards'")
            st.markdown("• Search for regulations and compliance items")
        elif selected_framework == "FFIEC":
            st.markdown("• Search for domains and processes")
            st.markdown("• Look for activities and procedures")
            st.markdown("• Search for IT examination guidance")
        elif selected_framework == "PCI DSS":
            st.markdown("• Search for requirements like 'Requirement 1', 'PCI-1'")
            st.markdown("• Look for testing procedures")
            st.markdown("• Search for payment card security controls")

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
    
    st.sidebar.markdown("### 🛡️ Multi-Framework KB")
    st.sidebar.markdown("**Features:**")
    st.sidebar.markdown("• Chat with multi-framework knowledge base")
    st.sidebar.markdown("• Explore ATT&CK, CIS, NIST, HIPAA, FFIEC, PCI DSS")
    st.sidebar.markdown("• Cross-framework analysis and mapping")
    st.sidebar.markdown("• Search threat intelligence and compliance")

    st.sidebar.markdown("---")
    st.sidebar.markdown("### 📊 Framework Statistics")
    
    try:
        stats = get_multi_framework_statistics(graph)
        
        # Display overall statistics
        overall = stats.get('Overall', {})
        st.sidebar.markdown(f"**Total Nodes:** {overall.get('total_nodes', 0)}")
        st.sidebar.markdown(f"**Total Relationships:** {overall.get('total_relationships', 0)}")
        
        # MITRE ATT&CK
        attck = stats.get('MITRE_ATTCK', {})
        if attck.get('techniques', 0) > 0:
            st.sidebar.markdown("**🎯 MITRE ATT&CK:**")
            st.sidebar.markdown(f"  • Techniques: {attck.get('techniques', 0)}")
            st.sidebar.markdown(f"  • Threat Groups: {attck.get('threat_groups', 0)}")
            st.sidebar.markdown(f"  • Malware: {attck.get('malware', 0)}")
            st.sidebar.markdown(f"  • Tools: {attck.get('tools', 0)}")
        
        # NIST CSF
        nist = stats.get('NIST_CSF', {})
        if nist.get('functions', 0) > 0:
            st.sidebar.markdown("**🏛️ NIST CSF:**")
            st.sidebar.markdown(f"  • Functions: {nist.get('functions', 0)}")
            st.sidebar.markdown(f"  • Categories: {nist.get('categories', 0)}")
            st.sidebar.markdown(f"  • Subcategories: {nist.get('subcategories', 0)}")
        
        # CIS Controls
        cis = stats.get('CIS_Controls', {})
        if cis.get('controls', 0) > 0:
            st.sidebar.markdown("**🔧 CIS Controls:**")
            st.sidebar.markdown(f"  • Controls: {cis.get('controls', 0)}")
            st.sidebar.markdown(f"  • Safeguards: {cis.get('safeguards', 0)}")
        
        # HIPAA
        hipaa = stats.get('HIPAA', {})
        if hipaa.get('requirements', 0) > 0:
            st.sidebar.markdown("**🏥 HIPAA:**")
            st.sidebar.markdown(f"  • Requirements: {hipaa.get('requirements', 0)}")
            st.sidebar.markdown(f"  • Sections: {hipaa.get('sections', 0)}")
        
        # FFIEC
        ffiec = stats.get('FFIEC', {})
        if ffiec.get('domains', 0) > 0:
            st.sidebar.markdown("**🏦 FFIEC:**")
            st.sidebar.markdown(f"  • Domains: {ffiec.get('domains', 0)}")
            st.sidebar.markdown(f"  • Processes: {ffiec.get('processes', 0)}")
        
        # PCI DSS
        pci = stats.get('PCI_DSS', {})
        if pci.get('requirements', 0) > 0:
            st.sidebar.markdown("**💳 PCI DSS:**")
            st.sidebar.markdown(f"  • Requirements: {pci.get('requirements', 0)}")
            st.sidebar.markdown(f"  • Sub-requirements: {pci.get('sub_requirements', 0)}")
            
    except Exception as e:
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
