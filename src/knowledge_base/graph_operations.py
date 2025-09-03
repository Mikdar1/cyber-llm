"""Graph query helpers for context retrieval, search, and stats."""

import json
import os
from typing import Any, Dict, List, Optional

from src.utils.initialization import get_ingestion_status


def get_context_from_knowledge_base(
    graph, query: str, max_results: int = 20, framework_scope: str = "All Frameworks"
) -> str:
    """Return structured context text across ATT&CK and compliance data."""
    try:
        context_parts = []
        query_lower = query.lower()

        # Get current ingestion status to determine available data
        ingestion_status = get_ingestion_status()
        available_frameworks = ingestion_status.get("ingested_frameworks", {})

        # Extract keywords from query
        keywords = extract_query_keywords(query_lower)

        context_parts.append("=== CYBERSECURITY KNOWLEDGE BASE CONTEXT ===")

        # Search ATT&CK data if available and in scope
        if framework_scope in ("All Frameworks", "ATT&CK Only"):
            if (
                "attack" in available_frameworks
                and available_frameworks["attack"].get("status") == "ingested"
            ):
                attack_context = search_attack_data(graph, keywords, max_results)
                if attack_context:
                    context_parts.append("\n=== MITRE ATT&CK FRAMEWORK ===")
                    context_parts.append(attack_context)

        # Search compliance frameworks if in scope - based on ingested documents
        if framework_scope in ("All Frameworks", "Compliance Frameworks"):
            status = get_ingestion_status()
            ingested_documents = status.get("ingested_documents", [])
            for doc in ingested_documents:
                framework_name = (doc.get("framework_type", "") or "").strip()
                if framework_name:
                    compliance_context = search_compliance_data(
                        graph, framework_name, keywords, max_results
                    )
                    if compliance_context:
                        display_name = framework_name.upper()
                        context_parts.append(
                            f"\n=== {display_name} COMPLIANCE FRAMEWORK ==="
                        )
                        context_parts.append(compliance_context)

        # Add schema context for query generation
        schema_context = get_schema_context()
        if schema_context:
            context_parts.append("\n=== KNOWLEDGE BASE SCHEMA ===")
            context_parts.append(schema_context)

        return (
            "\n".join(context_parts)
            if context_parts
            else "No relevant context found in knowledge base."
        )

    except Exception as e:
        return f"Error retrieving context: {str(e)}"


def extract_query_keywords(query: str) -> List[str]:
    """Extract ATT&CK-like IDs, cyber terms, phrases, and proper nouns."""
    # Common cybersecurity terms and patterns
    cyber_terms = [
        "attack",
        "technique",
        "tactic",
        "malware",
        "threat",
        "group",
        "apt",
        "mitigation",
        "control",
        "compliance",
        "framework",
        "security",
        "vulnerability",
        "exploit",
        "persistence",
        "lateral",
        "exfiltration",
        "credential",
        "access",
        "privilege",
        "escalation",
        "defense",
        "evasion",
    ]

    keywords = []
    words = query.split()

    # Extract technique IDs (T1234, T1234.001)
    for word in words:
        if word.upper().startswith("T") and any(c.isdigit() for c in word):
            keywords.append(word.upper())

    # Extract cyber terms
    for word in words:
        if word.lower() in cyber_terms:
            keywords.append(word.lower())

    # Extract quoted phrases
    import re

    quoted_phrases = re.findall(r'"([^"]*)"', query)
    keywords.extend(quoted_phrases)

    # Extract capitalized terms (likely proper nouns)
    for word in words:
        if word[0].isupper() and len(word) > 2:
            keywords.append(word)

    return list(set(keywords))  # Remove duplicates


def search_attack_data(graph, keywords: List[str], max_results: int) -> str:
    """Search ATT&CK techniques, groups, and software for context."""
    try:
        context_parts = []

        # Search techniques with improved query
        technique_results = []

        # First try exact ID match
        for keyword in keywords:
            exact_query = """
            MATCH (t:Technique)
            WHERE t.technique_id = $keyword
            RETURN t.technique_id as id, t.name as name, 
                   t.description as description, t.tactics as tactics
            """
            exact_results = graph.query(exact_query, {"keyword": keyword})
            technique_results.extend(exact_results)

        # Then try partial matches if we don't have enough results
        if len(technique_results) < max_results // 4:
            partial_query = """
            MATCH (t:Technique)
            WHERE ANY(keyword IN $keywords WHERE 
                toLower(t.name) CONTAINS toLower(keyword) OR
                toLower(t.description) CONTAINS toLower(keyword)
            )
            RETURN t.technique_id as id, t.name as name, 
                   t.description as description, t.tactics as tactics
            LIMIT $limit
            """
            partial_results = graph.query(
                partial_query, {"keywords": keywords, "limit": max_results // 4}
            )
            technique_results.extend(partial_results)

        if technique_results:
            context_parts.append("**TECHNIQUES:**")
            for result in technique_results:
                tactics_str = ", ".join(result.get("tactics", []))
                context_parts.append(f"- {result['id']}: {result['name']}")
                context_parts.append(f"  Tactics: {tactics_str}")
                context_parts.append(f"  Description: {result['description'][:200]}...")

        # Search groups
        group_query = """
        MATCH (g:Group)
        WHERE ANY(keyword IN $keywords WHERE 
            toLower(g.name) CONTAINS toLower(keyword) OR
            toLower(g.description) CONTAINS toLower(keyword)
        )
        RETURN g.name as name, g.description as description
        LIMIT $limit
        """

        group_results = graph.query(
            group_query, {"keywords": keywords, "limit": max_results // 4}
        )

        if group_results:
            context_parts.append("\n**THREAT GROUPS:**")
            for result in group_results:
                context_parts.append(f"- {result['name']}")
                context_parts.append(f"  Description: {result['description'][:200]}...")

        # Search software
        software_query = """
        MATCH (s:Software)
        WHERE ANY(keyword IN $keywords WHERE 
            toLower(s.name) CONTAINS toLower(keyword) OR
            toLower(s.description) CONTAINS toLower(keyword)
        )
    RETURN s.name as name, s.description as description, s.software_type as type
        LIMIT $limit
        """

        software_results = graph.query(
            software_query, {"keywords": keywords, "limit": max_results // 4}
        )

        if software_results:
            context_parts.append("\n**SOFTWARE & TOOLS:**")
            for result in software_results:
                software_type = result.get("type", "Unknown")
                context_parts.append(f"- {result['name']} ({software_type})")
                context_parts.append(f"  Description: {result['description'][:200]}...")

        return "\n".join(context_parts)

    except Exception as e:
        return f"Error searching ATT&CK data: {str(e)}"


def search_compliance_data(
    graph, framework: str, keywords: List[str], max_results: int
) -> str:
    """Search compliance controls by framework for context."""
    try:
        context_parts = []

        # Search controls
        control_query = """
        MATCH (c:Control)-[:CONTAINS]-(f:Framework)
        WHERE toLower(f.name) CONTAINS $framework AND
              (ANY(keyword IN $keywords WHERE 
                  toLower(c.name) CONTAINS toLower(keyword) OR
                  toLower(c.description) CONTAINS toLower(keyword)
              ) OR c.control_id IN $keywords)
        RETURN c.control_id as id, c.name as name, 
               c.description as description, c.control_type as type
        LIMIT $limit
        """

        control_results = graph.query(
            control_query,
            {
                "framework": framework.lower(),
                "keywords": keywords,
                "limit": max_results,
            },
        )

        if control_results:
            context_parts.append("**CONTROLS:**")
            for result in control_results:
                control_type = result.get("type", "Unknown")
                context_parts.append(
                    f"- {result['id']}: {result['name']} ({control_type})"
                )
                context_parts.append(f"  Description: {result['description'][:200]}...")

        return "\n".join(context_parts)

    except Exception as e:
        return f"Error searching {framework} data: {str(e)}"


def get_schema_context() -> str:
    """Return a brief schema overview for LLM query assistance."""
    try:
        schema_file = "src/config/schema.json"
        if os.path.exists(schema_file):
            with open(schema_file, "r") as f:
                schema_config = json.load(f)

            context_parts = [
                "**Available Node Types:**",
                "- ATT&CK: Technique, Tactic, Group, Software, Mitigation, DataSource, Campaign",
                "- Compliance: Framework, Control, RegulatoryBody, Industry",
                "- Documents: Document (tracks ingested files)",
                "",
                "**Key Relationships:**",
                "- Techniques HAS_SUBTECHNIQUE, MITIGATES, DETECTED_BY",
                "- Groups/Software USES Techniques/Software",
                "- Controls MITIGATES Techniques, APPLIES_TO Industries",
                "- Frameworks CONTAINS Controls",
                "- Documents EXTRACTED_TO Frameworks",
            ]

            return "\n".join(context_parts)
    except Exception:
        pass

    return "Schema information unavailable."


def validate_schema_compliance(graph) -> Dict[str, Any]:
    """Validate that node properties and key relationships match expected schema."""
    try:
        validation_results = {
            "overall_compliance": True,
            "node_validation": {},
            "relationship_validation": {},
            "missing_properties": [],
            "schema_violations": [],
            "summary": {},
        }

        # Define expected schema based on schema.json
        expected_node_properties = {
            "Technique": ["technique_id", "name", "description", "domain"],
            "Tactic": ["x_mitre_shortname", "name", "description", "domain"],
            "Group": ["group_id", "name", "description"],
            "Software": ["software_id", "name", "description", "software_type"],
            "Mitigation": ["mitigation_id", "name", "description"],
            "DataSource": ["data_source_id", "name", "description"],
            "DataComponent": ["component_id", "name", "description"],
            "Campaign": ["campaign_id", "name", "description"],
            "Framework": ["framework_id", "name", "version", "source_document"],
            "Control": [
                "control_id",
                "name",
                "description",
                "control_type",
                "framework_reference",
            ],
            "RegulatoryBody": ["body_id", "name"],
            "Industry": ["industry_id", "name"],
            "Document": [
                "document_id",
                "filename",
                "file_hash",
                "framework_type",
                "status",
            ],
        }

        # Validate each node type
        for node_type, required_props in expected_node_properties.items():
            node_validation = validate_node_type_properties(
                graph, node_type, required_props
            )
            validation_results["node_validation"][node_type] = node_validation

            if not node_validation["compliant"]:
                validation_results["overall_compliance"] = False
                validation_results["missing_properties"].extend(
                    node_validation["missing_properties"]
                )

        # Validate key relationships exist
        expected_relationships = [
            ("Framework", "CONTAINS", "Control"),
            ("RegulatoryBody", "PUBLISHES", "Framework"),
            ("Control", "HAS_SUBCONTROL", "Control"),
            ("Control", "APPLIES_TO", "Industry"),
            ("Technique", "HAS_SUBTECHNIQUE", "SubTechnique"),
            ("ATT&CK", "HAS_TACTIC", "Tactic"),
            ("Tactic", "HAS_TECHNIQUE", "Technique"),
            ("Group", "USES", "Technique"),
            ("Software", "USES", "Technique"),
        ]

        for source_type, rel_type, target_type in expected_relationships:
            rel_validation = validate_relationship_exists(
                graph, source_type, rel_type, target_type
            )
            validation_results["relationship_validation"][
                f"{source_type}-{rel_type}->{target_type}"
            ] = rel_validation

        # Generate summary
        total_node_types = len(expected_node_properties)
        compliant_node_types = sum(
            1
            for nv in validation_results["node_validation"].values()
            if nv["compliant"]
        )

        validation_results["summary"] = {
            "total_node_types_checked": total_node_types,
            "compliant_node_types": compliant_node_types,
            "compliance_percentage": (compliant_node_types / total_node_types) * 100,
            "total_violations": len(validation_results["missing_properties"])
            + len(validation_results["schema_violations"]),
        }

        return validation_results

    except Exception as e:
        return {"error": f"Schema validation failed: {str(e)}"}


def validate_node_type_properties(
    graph, node_type: str, required_props: List[str]
) -> Dict[str, Any]:
    """Check that a node type has required properties; return compliance info."""
    try:
        # Get sample of nodes of this type
        query = f"MATCH (n:{node_type}) RETURN n LIMIT 10"
        nodes = graph.query(query)

        if not nodes:
            return {
                "compliant": True,
                "node_count": 0,
                "missing_properties": [],
                "message": f"No {node_type} nodes found",
            }

        missing_properties = []
        sample_node = nodes[0]["n"] if nodes else None

        if sample_node:
            for prop in required_props:
                if (
                    prop not in sample_node
                    or sample_node[prop] is None
                    or sample_node[prop] == ""
                ):
                    missing_properties.append(f"{node_type}.{prop}")

        return {
            "compliant": len(missing_properties) == 0,
            "node_count": len(nodes),
            "missing_properties": missing_properties,
            "sample_properties": list(sample_node.keys()) if sample_node else [],
        }

    except Exception as e:
        return {
            "compliant": False,
            "error": f"Validation failed for {node_type}: {str(e)}",
            "missing_properties": [],
            "node_count": 0,
        }


def validate_relationship_exists(
    graph, source_type: str, rel_type: str, target_type: str
) -> Dict[str, Any]:
    """Check presence of a relationship type; return count and status."""
    try:
        query = f"""
        MATCH (s:{source_type})-[r:{rel_type}]->(t:{target_type})
        RETURN count(r) as relationship_count
        """
        result = graph.query(query)
        count = result[0]["relationship_count"] if result else 0

        return {
            "exists": count > 0,
            "count": count,
            "relationship": f"{source_type}-[{rel_type}]->{target_type}",
        }

    except Exception as e:
        return {
            "exists": False,
            "count": 0,
            "error": f"Failed to validate relationship: {str(e)}",
            "relationship": f"{source_type}-[{rel_type}]->{target_type}",
        }


def get_dynamic_knowledge_base_stats(graph) -> Dict[str, Any]:
    """Return adaptive stats for frameworks, documents, relationships, and coverage."""
    try:
        stats = {
            "overview": {},
            "frameworks": {},
            "documents": {},
            "relationships": {},
            "coverage": {},
        }

        # Get ingestion status and available frameworks from database
        ingestion_status = get_ingestion_status()

        # Query database directly for ingested frameworks using flexible matching
        frameworks_query = "MATCH (f:Framework) RETURN f.name as name, f.id as id, toLower(f.name) as name_lower"
        db_frameworks = graph.query(frameworks_query)

        # Create a mapping between database framework names and ingestion status keys
        framework_mappings = {}
        available_frameworks = ingestion_status.get("ingested_frameworks", {})

        for fw in db_frameworks:
            fw_name = fw["name"] if fw["name"] else "unknown"
            fw_name_lower = fw["name_lower"] if fw["name_lower"] else "unknown"
            fw_name_normalized = (
                fw_name_lower.replace(" ", "_")
                .replace("(", "")
                .replace(")", "")
                .replace("-", "_")
                .replace(".", "_")
                .replace(",", "")
                .replace("&", "and")
            )

            # Remove duplicate underscores and clean up
            while "__" in fw_name_normalized:
                fw_name_normalized = fw_name_normalized.replace("__", "_")
            fw_name_normalized = fw_name_normalized.strip("_")

            # Find matching status key
            matched_key = None
            for status_key in available_frameworks.keys():
                if (
                    status_key == fw_name_normalized
                    or fw_name_normalized in status_key
                    or status_key in fw_name_normalized
                    or any(
                        word in status_key
                        for word in fw_name_normalized.split("_")
                        if len(word) > 2
                    )
                ):
                    matched_key = status_key
                    break

            if matched_key:
                framework_mappings[fw_name] = {
                    "status_key": matched_key,
                    "status_info": available_frameworks[matched_key],
                }
                # Ensure it's marked as ingested
                available_frameworks[matched_key]["status"] = "ingested"
            else:
                # Framework in DB but not in status - mark as ingested
                framework_mappings[fw_name] = {
                    "status_key": fw_name_normalized,
                    "status_info": {"status": "ingested", "last_updated": "Unknown"},
                }
                available_frameworks[fw_name_normalized] = {
                    "status": "ingested",
                    "last_updated": "Unknown",
                }

        # Overall statistics
        total_nodes_query = "MATCH (n) RETURN count(n) as total"
        total_rels_query = "MATCH ()-[r]->() RETURN count(r) as total"

        total_nodes = graph.query(total_nodes_query)[0]["total"]
        total_relationships = graph.query(total_rels_query)[0]["total"]

        stats["overview"] = {
            "total_nodes": total_nodes,
            "total_relationships": total_relationships,
            "ingested_frameworks": len(
                [
                    f
                    for f in available_frameworks.values()
                    if f.get("status") == "ingested"
                ]
            ),
            "last_updated": ingestion_status.get("last_updated"),
        }

        # Framework-specific statistics using the mappings
        for db_framework_name, mapping_info in framework_mappings.items():
            status_info = mapping_info["status_info"]
            if status_info.get("status") == "ingested":
                fw_stats = get_framework_stats(graph, db_framework_name)
                stats["frameworks"][db_framework_name] = fw_stats

        # Document statistics
        doc_query = "MATCH (d:Document) RETURN count(d) as total"
        doc_result = graph.query(doc_query)
        if doc_result:
            stats["documents"]["total_documents"] = doc_result[0]["total"]
            stats["documents"]["ingested_documents"] = len(
                ingestion_status.get("ingested_documents", [])
            )

        # Relationship statistics
        rel_stats_query = """
        MATCH ()-[r]->()
        RETURN type(r) as relationship_type, count(r) as count
        ORDER BY count DESC
        """
        rel_results = graph.query(rel_stats_query)
        stats["relationships"] = {
            r["relationship_type"]: r["count"] for r in rel_results
        }

        # Coverage analysis using framework mappings
        coverage_frameworks = {}
        for db_name, mapping_info in framework_mappings.items():
            if mapping_info["status_info"].get("status") == "ingested":
                coverage_frameworks[db_name] = mapping_info["status_info"]

        stats["coverage"] = analyze_framework_coverage(graph, coverage_frameworks)

        return stats

    except Exception as e:
        return {"error": f"Error generating statistics: {str(e)}"}


def get_framework_stats(graph, framework: str) -> Dict[str, Any]:
    """Return stats for ATT&CK or a specific compliance framework."""
    try:
        if framework == "attack":
            return get_attack_stats(graph)
        else:
            return get_compliance_stats(graph, framework)
    except Exception as e:
        return {"error": f"Error getting {framework} stats: {str(e)}"}


def get_attack_stats(graph) -> Dict[str, Any]:
    """Get ATT&CK framework statistics."""
    queries = {
        "techniques": "MATCH (t:Technique) RETURN count(t) as count",
        "tactics": "MATCH (tac:Tactic) RETURN count(tac) as count",
        "groups": "MATCH (g:Group) RETURN count(g) as count",
        "software": "MATCH (s:Software) RETURN count(s) as count",
        "mitigations": "MATCH (m:Mitigation) RETURN count(m) as count",
        "data_sources": "MATCH (ds:DataSource) RETURN count(ds) as count",
        "campaigns": "MATCH (c:Campaign) RETURN count(c) as count",
    }

    stats = {}
    for category, query in queries.items():
        try:
            result = graph.query(query)
            stats[category] = result[0]["count"] if result else 0
        except Exception:
            stats[category] = 0

    return stats


def get_compliance_stats(graph, framework: str) -> Dict[str, Any]:
    """Get compliance framework statistics."""
    try:
        # Get framework and regulatory body information
        fw_query = """
        MATCH (f:Framework)
        WHERE toLower(f.name) CONTAINS $framework
        OPTIONAL MATCH (f)<-[:PUBLISHES]-(rb:RegulatoryBody)
        RETURN f.name as name, f.version as version, rb.name as regulatory_body
        """
        fw_result = graph.query(fw_query, {"framework": framework.lower()})

        if not fw_result:
            return {"error": f"Framework {framework} not found"}

        # Get control count
        control_query = """
        MATCH (f:Framework)-[:CONTAINS]->(c:Control)
        WHERE toLower(f.name) CONTAINS $framework
        RETURN count(c) as count
        """
        control_result = graph.query(control_query, {"framework": framework.lower()})

        framework_data = fw_result[0]
        return {
            "framework_name": framework_data["name"],
            "version": framework_data["version"] or "N/A",
            "regulatory_body": framework_data["regulatory_body"] or "N/A",
            "controls": control_result[0]["count"] if control_result else 0,
        }

    except Exception as e:
        return {"error": f"Error getting {framework} stats: {str(e)}"}


def analyze_framework_coverage(graph, available_frameworks: Dict) -> Dict[str, Any]:
    """Analyze ATT&CK coverage and basic cross-framework mappings."""
    try:
        coverage = {
            "attack_coverage": {},
            "cross_framework_mappings": {},
            "technique_mitigation_coverage": 0,
        }

        # ATT&CK technique coverage
        if "attack" in available_frameworks:
            technique_count_query = "MATCH (t:Technique) RETURN count(t) as count"
            covered_techniques_query = """
            MATCH (t:Technique)-[:MITIGATES]-(c:Control)
            RETURN count(DISTINCT t) as count
            """

            total_techniques = graph.query(technique_count_query)[0]["count"]
            covered_techniques = graph.query(covered_techniques_query)[0]["count"]

            if total_techniques > 0:
                coverage["technique_mitigation_coverage"] = round(
                    (covered_techniques / total_techniques) * 100, 2
                )

        return coverage

    except Exception as e:
        return {"error": f"Error analyzing coverage: {str(e)}"}


def search_knowledge_base(
    graph, query: str, node_types: Optional[List[str]] = None, limit: int = 10
) -> List[Dict]:
    """General search across node types; returns list of results."""
    try:
        if not node_types:
            node_types = ["Technique", "Control", "Group", "Software", "Framework"]

        results = []
        keywords = extract_query_keywords(query.lower())

        for node_type in node_types:
            search_query = f"""
            MATCH (n:{node_type})
            WHERE ANY(keyword IN $keywords WHERE 
                toLower(n.name) CONTAINS toLower(keyword) OR
                toLower(n.description) CONTAINS toLower(keyword)
            )
            RETURN n.name as name, n.description as description, 
                   labels(n) as types, elementId(n) as node_id
            LIMIT $limit
            """

            type_results = graph.query(
                search_query, {"keywords": keywords, "limit": limit // len(node_types)}
            )

            for result in type_results:
                result["node_type"] = node_type
                results.append(result)

        return results

    except Exception as e:
        return [{"error": f"Search error: {str(e)}"}]
