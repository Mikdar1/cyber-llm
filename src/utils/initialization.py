"""
ATT&CK Knowledge Base Initialization and Setup Utilities Module

This module handles the initialization and setup of the MITRE ATT&CK cybersecurity
knowledge base in Neo4j. Compliance frameworks will be ingested on-demand through the document
ingestion feature.

Features:
- MITRE ATT&CK automatic knowledge base initialization (enterprise and ICS domains)
- STIX-based ATT&CK data ingestion from official repository
- Data existence validation and incremental updates
- Session state management
- Progress tracking and user feedback
- Error handling and recovery
- Schema implementation with citations
- Document ingestion capability for compliance frameworks

Functions:
    initialize_knowledge_base: Main ATT&CK initialization orchestrator
    setup_database_schema: Initialize database constraints and indexes
    refresh_attack_data: Force refresh of ATT&CK data
"""

import json
import os
from datetime import datetime
from typing import Any, Dict

import streamlit as st

from src.cybersecurity.attack_ingestion import AttackIngestion


def setup_database_schema(graph):
    """
    Set up database schema constraints and indexes according to unified schema.

    Args:
        graph: Neo4j database connection instance
    """
    try:
        # Load schema configuration
        schema_file = "src/config/schema.json"
        if os.path.exists(schema_file):
            with open(schema_file, "r") as f:
                schema_config = json.load(f)
        else:
            st.warning("Schema configuration file not found. Using default schema.")
            return

        # Create constraints
        constraints = schema_config.get("constraints", [])
        for constraint in constraints:
            try:
                graph.query(constraint)
            except Exception as e:
                st.warning(f"Constraint already exists or failed: {e}")

        # Create indexes
        indexes = schema_config.get("indexes", [])
        for index in indexes:
            try:
                graph.query(index)
            except Exception as e:
                st.warning(f"Index already exists or failed: {e}")

        st.success("✅ Database schema setup completed")

    except Exception as e:
        st.error(f"Error setting up database schema: {e}")


def initialize_knowledge_base(graph):
    """
        Initialize the MITRE ATT&CK knowledge base.

        Checks for existing data and performs initialization for ATT&CK framework
        when necessary. Other compliance frameworks will be ingested on-demand
        through the document ingestion feature.

        Supported Initial Framework:
        - MITRE ATT&CK (STIX-based ingestion from official repository)

        Future frameworks (document-based ingestion):
        🔄 **Available for Document Upload:**
        - Any compliance or regulatory framework document
        - Security standards and guidelines
        - Industry-specific regulations

    🎯 **Framework Support:**
        The system supports any compliance framework through document upload.

        Args:
            graph: Neo4j database connection instance
    """
    # Skip if already initialized in current session
    if st.session_state.knowledge_base_initialized:
        return

    with st.spinner("🔄 Initializing MITRE ATT&CK knowledge base..."):
        try:
            # Setup database schema first
            setup_database_schema(graph)

            # Validate existing data in Neo4j database
            check_query = "MATCH (n) RETURN count(n) as count"
            result = graph.query(check_query)
            existing_count = result[0]["count"] if result else 0

            if existing_count > 0:
                st.info(
                    f"📊 Knowledge base already contains {existing_count:,} nodes. Skipping initialization."
                )
                st.session_state.knowledge_base_initialized = True
                return

            # Initialize ATT&CK framework ingestion
            st.info("🚀 Starting MITRE ATT&CK data ingestion...")

            # ATT&CK Framework (STIX-based) - Enterprise and ICS domains
            st.info("📡 Ingesting MITRE ATT&CK framework...")
            attack_ingester = AttackIngestion()
            domains = ["enterprise", "ics"]  # Enterprise and ICS domains
            attack_stats = attack_ingester.run_full_ingestion(graph, domains)

            # Update ingestion status
            update_ingestion_status("attack", attack_stats)

            # Display completion summary
            st.success("🎉 ATT&CK Knowledge Base Initialization Complete!")
            st.info(
                """
            📋 **Initialization Summary:**
            - ✅ MITRE ATT&CK: Enterprise and ICS domains
            - 📄 Compliance frameworks: Available for document-based ingestion
            
            **Next Steps:**
            - Use the document ingestion feature to add compliance frameworks
            - Upload PDF documents for any compliance or regulatory framework
            """
            )

            st.session_state.knowledge_base_initialized = True

        except Exception as e:
            st.error(f"❌ Knowledge base initialization failed: {str(e)}")
            st.info("💡 You can still use the application with limited functionality.")


def update_ingestion_status(framework: str, stats: Dict[str, Any]):
    """
    Update the ingestion status tracking file.

    Args:
        framework: Framework name (e.g., 'attack')
        stats: Ingestion statistics
    """
    try:
        status_file = "src/config/ingestion_status.json"

        # Read current status
        if os.path.exists(status_file):
            with open(status_file, "r") as f:
                status_data = json.load(f)
        else:
            status_data = {
                "ingested_documents": [],
                "ingested_frameworks": {},
                "total_nodes": 0,
                "last_updated": None,
            }

        # Update framework status
        if framework not in status_data["ingested_frameworks"]:
            status_data["ingested_frameworks"][framework] = {
                "status": "not_ingested",
                "domains": [],
                "last_updated": None,
                "node_counts": {},
            }

        # Update ATT&CK specific data
        if framework == "attack":
            status_data["ingested_frameworks"][framework].update(
                {
                    "status": "ingested",
                    "domains": stats.get("domains", []),
                    "last_updated": datetime.now().isoformat(),
                    "node_counts": {
                        "techniques": stats.get("techniques", 0),
                        "tactics": stats.get("tactics", 0),
                        "groups": stats.get("groups", 0),
                        "software": stats.get("software", 0),
                        "mitigations": stats.get("mitigations", 0),
                        "data_sources": stats.get("data_sources", 0),
                    },
                }
            )

        # Update totals
        total_nodes = (
            sum(stats.get("node_counts", {}).values())
            if "node_counts" in stats
            else sum(stats.values())
        )
        status_data["total_nodes"] = total_nodes
        status_data["last_updated"] = datetime.now().isoformat()

        # Write updated status
        with open(status_file, "w") as f:
            json.dump(status_data, f, indent=2)

    except Exception as e:
        st.error(f"Error updating ingestion status: {e}")


def refresh_attack_data(graph):
    """
    Force refresh of ATT&CK framework data using MERGE operations.
    This is safe to run multiple times as it uses MERGE operations
    to avoid duplicate constraint violations.

    Args:
        graph: Neo4j database connection instance
    """
    with st.spinner("🔄 Refreshing ATT&CK data..."):
        try:
            # Use MERGE-based ingestion for safe refresh
            attack_ingester = AttackIngestion()
            domains = ["enterprise", "ics"]
            success, message = attack_ingester.ingest_attack_data(
                graph, domains, clear_existing=False
            )

            if success:
                st.success(f"✅ ATT&CK data refreshed: {message}")
            else:
                st.error(f"❌ ATT&CK refresh failed: {message}")

        except Exception as e:
            st.error(f"Error refreshing ATT&CK data: {e}")


def clear_attack_data(graph):
    """
    Clear ATT&CK specific data from the database using the AttackIngestion class method.

    Args:
        graph: Neo4j database connection instance
    """
    try:
        # Use the AttackIngestion class method for clearing data
        attack_ingester = AttackIngestion()
        attack_ingester.clear_attack_data(graph)
        st.info("🗑️ ATT&CK data cleared from database")

    except Exception as e:
        st.error(f"Error clearing ATT&CK data: {e}")


def get_ingestion_status() -> Dict[str, Any]:
    """
    Get current ingestion status.

    Returns:
        Dictionary containing ingestion status information
    """
    try:
        status_file = "src/config/ingestion_status.json"
        if os.path.exists(status_file):
            with open(status_file, "r") as f:
                return json.load(f)
        return {
            "ingested_documents": [],
            "ingested_frameworks": {},
            "total_nodes": 0,
            "last_updated": None,
        }
    except Exception:
        return {
            "ingested_documents": [],
            "ingested_frameworks": {},
            "total_nodes": 0,
            "last_updated": None,
        }
