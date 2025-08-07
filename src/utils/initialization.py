"""
Multi-Framework Knowledge Base Initialization and Setup Utilities Module

This module handles the initialization and setup of the comprehensive cybersecurity
knowledge base in Neo4j, supporting multiple frameworks including MITRE ATT&CK,
CIS Controls, NIST CSF, HIPAA, FFIEC, and PCI DSS. It manages data ingestion,
validation, and ensures the database is properly populated with the latest
framework data including complete citation tracking.

Features:
- Multi-framework automatic knowledge base initialization
- STIX-based ATT&CK data ingestion
- Document-based framework ingestion (CIS, NIST, HIPAA, FFIEC, PCI DSS)
- Data existence validation and incremental updates
- Session state management
- Progress tracking and user feedback
- Error handling and recovery
- Complete schema implementation with citations
- Cross-framework relationship mapping

Functions:
    initialize_knowledge_base: Main multi-framework initialization orchestrator
    refresh_knowledge_base: Force refresh of all framework data
    ingest_individual_framework: Single framework ingestion
"""

import streamlit as st
from src.cybersecurity.attack_ingestion import AttackIngestion
from src.cybersecurity.cis_ingestion import CISIngestion
from src.cybersecurity.nist_ingestion import NISTIngestion
from src.cybersecurity.hipaa_ingestion import HIPAAIngestion
from src.cybersecurity.ffiec_ingestion import FFIECIngestion
from src.cybersecurity.pci_dss_ingestion import PCIDSSIngestion
from src.knowledge_base.database import clear_knowledge_base


def initialize_knowledge_base(graph):
    """
    Initialize the comprehensive cybersecurity knowledge base with multi-framework support.
    
    Checks for existing data and performs initialization for all supported frameworks
    when necessary. Manages session state to prevent redundant initialization attempts
    and provides detailed progress feedback to users.
    
    Supported Frameworks:
    - MITRE ATT&CK (STIX-based ingestion)
    - CIS Controls v8.1
    - NIST Cybersecurity Framework 2.0
    - HIPAA Administrative Simplification
    - FFIEC IT Examination Handbook
    - PCI DSS v4.0.1
    
    Args:
        graph: Neo4j database connection instance
    """
    # Skip if already initialized in current session
    if st.session_state.knowledge_base_initialized:
        return
    
    with st.spinner("🔄 Initializing comprehensive cybersecurity knowledge base..."):
        try:
            # Validate existing data in Neo4j database
            check_query = "MATCH (n) RETURN count(n) as count"
            result = graph.query(check_query)
            existing_count = result[0]['count'] if result else 0
            
            if existing_count > 0:
                st.info(f"📊 Knowledge base already contains {existing_count:,} nodes. Skipping initialization.")
                st.session_state.knowledge_base_initialized = True
                return
            
            # Initialize framework ingestion systems
            st.info("🚀 Starting comprehensive multi-framework data ingestion...")
            
            total_stats = {}
            success_count = 0
            total_frameworks = 6
            
            # 1. ATT&CK Framework (STIX-based)
            st.info("📡 Ingesting MITRE ATT&CK framework...")
            attack_ingester = AttackIngestion()
            domains = ['enterprise']  # Can be expanded to include mobile, ics
            attack_stats = attack_ingester.run_full_ingestion(graph, domains)
            total_stats['ATT&CK'] = attack_stats
            success_count += 1
            
            # 2. CIS Controls v8.1
            st.info("🛡️ Ingesting CIS Controls v8.1...")
            cis_ingester = CISIngestion()
            cis_success, cis_msg = cis_ingester.ingest_cis_data(graph)
            if cis_success:
                total_stats['CIS'] = cis_ingester.ingestion_stats
                success_count += 1
            else:
                st.warning(f"CIS Controls ingestion: {cis_msg}")
            
            # 3. NIST Cybersecurity Framework 2.0
            st.info("📋 Ingesting NIST Cybersecurity Framework 2.0...")
            nist_ingester = NISTIngestion()
            nist_success, nist_msg = nist_ingester.ingest_nist_data(graph)
            if nist_success:
                total_stats['NIST'] = nist_ingester.ingestion_stats
                success_count += 1
            else:
                st.warning(f"NIST CSF ingestion: {nist_msg}")
            
            # 4. HIPAA Administrative Simplification
            st.info("🏥 Ingesting HIPAA regulatory framework...")
            hipaa_ingester = HIPAAIngestion()
            hipaa_success, hipaa_msg = hipaa_ingester.ingest_hipaa_data(graph)
            if hipaa_success:
                total_stats['HIPAA'] = hipaa_ingester.ingestion_stats
                success_count += 1
            else:
                st.warning(f"HIPAA ingestion: {hipaa_msg}")
            
            # 5. FFIEC IT Examination Handbook
            st.info("🏦 Ingesting FFIEC examination procedures...")
            ffiec_ingester = FFIECIngestion()
            ffiec_success, ffiec_msg = ffiec_ingester.ingest_ffiec_data(graph)
            if ffiec_success:
                total_stats['FFIEC'] = ffiec_ingester.ingestion_stats
                success_count += 1
            else:
                st.warning(f"FFIEC ingestion: {ffiec_msg}")
            
            # 6. PCI DSS v4.0.1
            st.info("💳 Ingesting PCI DSS security standards...")
            pci_ingester = PCIDSSIngestion()
            pci_success, pci_msg = pci_ingester.ingest_pci_dss_data(graph)
            if pci_success:
                total_stats['PCI DSS'] = pci_ingester.ingestion_stats
                success_count += 1
            else:
                st.warning(f"PCI DSS ingestion: {pci_msg}")
            
            # Display comprehensive results
            st.success(f"✅ Successfully initialized {success_count}/{total_frameworks} cybersecurity frameworks!")
            
            # Show detailed breakdown
            with st.expander("📊 Multi-Framework Ingestion Details"):
                for framework, stats in total_stats.items():
                    st.markdown(f"### {framework}")
                    if isinstance(stats, dict):
                        for stat_name, count in stats.items():
                            if count > 0:
                                st.write(f"- **{stat_name.replace('_', ' ').title()}**: {count:,}")
                    else:
                        st.write(f"- **Framework Status**: {stats}")
            
            # Create cross-framework relationships
            if success_count >= 2:
                st.info("🔗 Creating cross-framework relationships...")
                _create_cross_framework_relationships(graph)
            
            st.session_state.knowledge_base_initialized = True
            st.balloons()  # Celebrate successful initialization
                
        except Exception as e:
            st.error(f"❌ Error during knowledge base initialization: {str(e)}")
            st.info("💡 Please check your Neo4j connection and document availability, then try again.")


def _create_cross_framework_relationships(graph):
    """
    Create relationships between different cybersecurity frameworks.
    
    This function establishes connections between:
    - ATT&CK techniques and CIS Controls
    - NIST CSF categories and CIS Controls  
    - Regulatory requirements and framework controls
    
    Args:
        graph: Neo4j database connection instance
    """
    try:
        # Link ATT&CK techniques to CIS Controls (example relationships)
        graph.query("""
            MATCH (t:Technique)
            WHERE t.name CONTAINS 'Network' OR t.name CONTAINS 'Access'
            MATCH (c:CIS_Control {id: '1'})
            MERGE (t)-[:MITIGATED_BY]->(c)
        """)
        
        # Link NIST CSF categories to appropriate controls
        graph.query("""
            MATCH (cat:NIST_Category)
            WHERE cat.id STARTS WITH 'PR.AC'
            MATCH (c:CIS_Control {id: '5'})
            MERGE (cat)-[:IMPLEMENTED_BY]->(c)
        """)
        
        # Link regulatory requirements to framework functions
        graph.query("""
            MATCH (r:HIPAA_Regulation)
            WHERE r.title CONTAINS 'Security'
            MATCH (f:NIST_Function {id: 'PR'})
            MERGE (r)-[:ADDRESSES_FUNCTION]->(f)
        """)
        
        st.success("✅ Cross-framework relationships created successfully!")
        
    except Exception as e:
        st.warning(f"⚠️ Cross-framework relationship creation encountered issues: {str(e)}")


def refresh_knowledge_base(graph):
    """
    Force refresh of the comprehensive cybersecurity knowledge base with latest data.
    
    Clears existing data and performs complete re-ingestion of all supported
    cybersecurity frameworks. Use when data updates are needed across all frameworks.
    
    Args:
        graph: Neo4j database connection instance
        
    Returns:
        tuple: (success_boolean, status_message)
    """
    try:
        with st.spinner("🗑️ Clearing existing knowledge base..."):
            clear_knowledge_base(graph)
            
        with st.spinner("🔄 Ingesting latest multi-framework data..."):
            # Reset session state for fresh initialization
            st.session_state.knowledge_base_initialized = False
            
            # Perform complete multi-framework initialization
            initialize_knowledge_base(graph)
            
            return True, "Successfully refreshed comprehensive cybersecurity knowledge base with all frameworks"
                
    except Exception as e:
        return False, f"Error during knowledge base refresh: {str(e)}"


def ingest_individual_framework(graph, framework_name: str):
    """
    Ingest data for a specific cybersecurity framework.
    
    Allows selective ingestion of individual frameworks without affecting
    the rest of the knowledge base.
    
    Args:
        graph: Neo4j database connection instance
        framework_name: Name of framework to ingest ('attack', 'cis', 'nist', 'hipaa', 'ffiec', 'pci_dss')
        
    Returns:
        tuple: (success_boolean, status_message)
    """
    try:
        framework_name = framework_name.lower()
        
        if framework_name == 'attack':
            ingester = AttackIngestion()
            stats = ingester.run_full_ingestion(graph, ['enterprise'])
            return True, f"ATT&CK ingestion completed: {stats}"
            
        elif framework_name == 'cis':
            ingester = CISIngestion()
            return ingester.ingest_cis_data(graph)
            
        elif framework_name == 'nist':
            ingester = NISTIngestion()
            return ingester.ingest_nist_data(graph)
            
        elif framework_name == 'hipaa':
            ingester = HIPAAIngestion()
            return ingester.ingest_hipaa_data(graph)
            
        elif framework_name == 'ffiec':
            ingester = FFIECIngestion()
            return ingester.ingest_ffiec_data(graph)
            
        elif framework_name == 'pci_dss':
            ingester = PCIDSSIngestion()
            return ingester.ingest_pci_dss_data(graph)
            
        else:
            return False, f"Unknown framework: {framework_name}. Supported: attack, cis, nist, hipaa, ffiec, pci_dss"
            
    except Exception as e:
        return False, f"Error during {framework_name} ingestion: {str(e)}"


def reingest_attack_data(graph):
    """
    Legacy function for re-ingesting ATT&CK data.
    
    Provides backward compatibility for existing code that uses
    the older reingest function name. Delegates to refresh_knowledge_base.
    
    Args:
        graph: Neo4j database connection instance
        
    Returns:
        bool: Success status of re-ingestion operation
    """
    try:
        # Use the updated refresh function for consistency
        success, message = refresh_knowledge_base(graph)
        
        if success:
            st.success(f"✅ {message}")
            return True
        else:
            st.error(f"❌ {message}")
            return False
            
    except Exception as e:
        st.error(f"❌ Error during data re-ingestion: {str(e)}")
        return False
