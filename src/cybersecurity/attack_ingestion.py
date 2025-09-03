"""
MITRE ATT&CK Knowledge Base Ingestion using STIX Data

This module handles the ingestion of MITRE ATT&CK data from local STIX format files
into a Neo4j graph database. The implementation loads data from local JSON files
(enterprise-attack.json and ics-attack.json) located in the documents folder and
processes it according to the unified cybersecurity knowledge base schema.

Key Features:
- STIX-based data loading from local JSON files (enterprise and ICS domains)
- Complete ATT&CK framework coverage (techniques, tactics, groups, software, mitigations)
- Schema-compliant relationship mapping according to unified schema
- Citation extraction for every node from external references
- Support for enterprise and ICS domains
- Neo4j graph database storage with optimized constraints and indexes
- Ingestion status tracking and validation
"""

import json
import re
from typing import Any, Dict, List, Optional, Tuple

import streamlit as st


class AttackIngestion:
    """
    Local STIX-based ATT&CK knowledge base ingestion system.

    Handles complete ingestion of MITRE ATT&CK data from local STIX JSON files
    into Neo4j graph database with comprehensive relationship mapping
    and citation extraction following the unified schema.
    """

    def __init__(self):
        """Initialize the ingestion system with local file configuration."""
        # File paths for local ATT&CK STIX data
        self.local_files = {
            "enterprise": "documents/enterprise-attack.json",
            "ics": "documents/ics-attack.json",
        }

        self.stix_type_mapping = {
            "attack-pattern": "Technique",
            "malware": "Software",
            "intrusion-set": "Group",
            "tool": "Software",
            "course-of-action": "Mitigation",
            "x-mitre-tactic": "Tactic",
            "x-mitre-data-source": "DataSource",
            "x-mitre-data-component": "DataComponent",
            "campaign": "Campaign",
            # Identity/Asset/CoA not modeled
        }

        # Schema-compliant property mappings
        self.schema_property_mappings = {
            "Technique": {
                "required": ["technique_id", "name", "description", "domain"],
                "optional": [
                    "x_mitre_platforms",
                    "x_mitre_detection",
                    "created",
                    "modified",
                    "citations",
                ],
            },
            "SubTechnique": {
                "required": [
                    "technique_id",
                    "name",
                    "description",
                    "parent_technique",
                ],
                "optional": ["created", "modified", "citations", "domain"],
            },
            "Tactic": {
                "required": ["x_mitre_shortname", "name", "description", "domain"],
                "optional": ["created", "modified", "citations"],
            },
            "Group": {
                "required": ["group_id", "name", "description"],
                "optional": ["aliases", "created", "modified", "citations", "domain"],
            },
            "Software": {
                "required": ["software_id", "name", "description", "software_type"],
                "optional": [
                    "x_mitre_platforms",
                    "created",
                    "modified",
                    "citations",
                    "domain",
                ],
            },
            "Mitigation": {
                "required": ["mitigation_id", "name", "description"],
                "optional": ["created", "modified", "citations", "domain"],
            },
            "DataSource": {
                "required": ["data_source_id", "name", "description"],
                "optional": [
                    "x_mitre_platforms",
                    "created",
                    "modified",
                    "citations",
                    "domain",
                ],
            },
            "DataComponent": {
                "required": ["component_id", "name", "description"],
                "optional": ["created", "modified", "citations"],
            },
            "Campaign": {
                "required": ["campaign_id", "name", "description"],
                "optional": ["created", "modified", "citations", "domain"],
            },
            # "Identity": {
            #     "required": ["identity_id", "name", "identity_class"],
            #     "optional": ["created", "modified", "citations"],
            # },
        }

    def fetch_attack_data(self, domains: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Load MITRE ATT&CK STIX data from local JSON files.

        Args:
            domains: List of domains to load (enterprise, ics)
                    Defaults to ['enterprise'] for full ATT&CK coverage

        Returns:
            Dict containing combined STIX data from all domains
        """
        import os

        if domains is None:
            domains = ["enterprise"]  # Default to enterprise domain

        all_objects = []

        st.info(
            f"📁 Loading ATT&CK STIX data from local files for {len(domains)} domain(s)..."
        )

        for domain in domains:
            # Map domain names to local file paths
            domain_file_mapping = {
                "enterprise": "documents/enterprise-attack.json",
                "ics": "documents/ics-attack.json",
            }

            domain_file = domain_file_mapping.get(domain)

            if not domain_file:
                st.warning(f"⚠️ No file mapping configured for domain: {domain}")
                continue

            file_path = os.path.join(os.getcwd(), domain_file)

            try:
                st.info(f"📄 Loading {domain} domain data from: {domain_file}")

                if not os.path.exists(file_path):
                    st.error(f"❌ File not found: {file_path}")
                    continue

                with open(file_path, "r", encoding="utf-8") as f:
                    domain_data = json.load(f)

                domain_objects = domain_data.get("objects", [])

                # Add domain metadata to objects
                for obj in domain_objects:
                    obj["x_attack_domain"] = domain

                all_objects.extend(domain_objects)
                st.success(
                    f"✅ Loaded {len(domain_objects):,} objects from {domain} domain"
                )

            except FileNotFoundError as e:
                st.error(f"❌ File not found for {domain} domain: {e}")
                continue
            except json.JSONDecodeError as e:
                st.error(f"❌ Failed to parse {domain} domain JSON: {e}")
                continue
            except Exception as e:
                st.error(f"❌ Unexpected error loading {domain} domain: {e}")
                continue

        if not all_objects:
            raise Exception("No STIX data could be loaded from any domain files")

        st.success(f"🎯 Total STIX objects loaded: {len(all_objects):,}")

        return {
            "type": "bundle",
            "id": "bundle--attack-stix-combined",
            "objects": all_objects,
        }

    def extract_citations(self, obj: Dict) -> List[str]:
        """
        Extract citation information from STIX object external references.

        Args:
            obj: STIX object with potential external references

        Returns:
            List of citation strings (flattened for Neo4j compatibility)
        """
        citations = []
        external_refs = obj.get("external_references", [])

        for ref in external_refs:
            # Create a simple string representation for Neo4j compatibility
            source_name = ref.get("source_name", "Unknown")
            url = ref.get("url", "")
            external_id = ref.get("external_id", "")
            description = ref.get("description", "")

            # Only add citations with meaningful content
            if source_name != "Unknown" or url or external_id:
                # Create a simple string format for the citation
                citation_parts = []
                if external_id:
                    citation_parts.append(f"ID: {external_id}")
                if source_name != "Unknown":
                    citation_parts.append(f"Source: {source_name}")
                if url:
                    citation_parts.append(f"URL: {url}")

                citation_string = " | ".join(citation_parts)
                if citation_string:
                    citations.append(citation_string)

        return citations

    def process_attack_objects(self, stix_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process STIX objects into graph nodes and relationships.

        Args:
            stix_data: Raw STIX bundle data

        Returns:
            Dict containing processed nodes, relationships, and statistics
        """
        objects = stix_data.get("objects", [])
        nodes = []
        relationships = []

        # Create object cache for relationship processing
        object_cache = {obj.get("id"): obj for obj in objects if obj.get("id")}

        st.info(f"⚙️ Processing {len(objects):,} STIX objects...")

        # Process each object type
        for obj in objects:
            # Skip deprecated STIX objects
            if obj.get("x_mitre_deprecated") is True or obj.get("revoked") is True:
                continue
            obj_type = obj.get("type")

            if not obj_type:
                continue

            # Map STIX type to graph node type
            node_type = self.stix_type_mapping.get(obj_type)

            if node_type:
                # Process object into node
                node = self._process_stix_object(obj, node_type)
                if node:
                    nodes.append(node)

            # Process relationships separately
            elif obj_type == "relationship":
                rels = self._process_relationship(obj, object_cache)
                if rels:
                    relationships.extend(rels)

        # Add tactic nodes and technique-tactic relationships
        tactic_nodes, tactic_relationships = self._process_tactics(nodes)
        nodes.extend(tactic_nodes)
        relationships.extend(tactic_relationships)

        # Add subtechnique relationships
        subtechnique_relationships = self._process_subtechniques(nodes)
        relationships.extend(subtechnique_relationships)

        st.success(
            f"✅ Processed {len(nodes):,} nodes and {len(relationships):,} relationships"
        )

        return {
            "nodes": nodes,
            "relationships": relationships,
            "total_objects": len(objects),
        }

    def _process_stix_object(self, obj: Dict, node_type: str) -> Optional[Dict]:
        """
        Process individual STIX object into schema-compliant graph node.

        Args:
            obj: STIX object
            node_type: Target graph node type

        Returns:
            Schema-compliant processed node dictionary or None
        """
        if not obj.get("id") or not obj.get("name"):
            return None

        # Extract citations for this object
        citations = self.extract_citations(obj)

        # Initialize node with common properties
        node = {
            "type": node_type,
            "id": obj.get("id"),
            "name": obj.get("name", ""),
            "description": obj.get("description", ""),
            "domain": obj.get("x_attack_domain", "enterprise"),
        }

        # We'll apply optional properties after determining final node type

        # Add type-specific properties according to schema
        if node_type == "Technique":
            self._enrich_technique_node_schema_compliant(node, obj)
        elif node_type == "Tactic":
            self._enrich_tactic_node_schema_compliant(node, obj)
        elif node_type == "Group":
            self._enrich_group_node_schema_compliant(node, obj)
        elif node_type == "Software":
            self._enrich_software_node_schema_compliant(node, obj)
        elif node_type == "Mitigation":
            self._enrich_mitigation_node_schema_compliant(node, obj)
        elif node_type == "DataSource":
            self._enrich_data_source_node_schema_compliant(node, obj)
        elif node_type == "DataComponent":
            self._enrich_data_component_node_schema_compliant(node, obj)
        elif node_type == "Campaign":
            self._enrich_campaign_node_schema_compliant(node, obj)

        # If technique id contains dot, convert to SubTechnique node
        if node_type == "Technique":
            tech_id = node.get("technique_id", "")
            if "." in tech_id:
                node_type = "SubTechnique"
                node["type"] = "SubTechnique"
                node["parent_technique"] = tech_id.split(".")[0]

        # Fetch schema mapping for final node_type
        schema_mapping = self.schema_property_mappings.get(node_type, {})
        required_props = schema_mapping.get("required", [])
        optional_props = schema_mapping.get("optional", [])

        # Apply optional common properties if available
        if "created" in optional_props:
            node["created"] = obj.get("created")
        if "modified" in optional_props:
            node["modified"] = obj.get("modified")
        if "citations" in optional_props:
            node["citations"] = citations

        # Validate required properties are present
        for prop in required_props:
            if prop not in node or node[prop] is None:
                if not self._fill_missing_required_property(node, prop, obj, node_type):
                    return None

        return node

    def _fill_missing_required_property(
        self, node: Dict, prop: str, obj: Dict, node_type: str
    ) -> bool:
        """Fill missing required properties with fallback values."""
        if prop == "technique_id" and node_type == "Technique":
            # Extract from external references
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    node[prop] = ref.get("external_id")
                    return True
            node[prop] = obj.get("id", "").split("--")[-1][:8].upper()  # Fallback
            return True
        elif prop == "x_mitre_shortname" and node_type == "Tactic":
            node[prop] = obj.get(
                "x_mitre_shortname", obj.get("name", "").lower().replace(" ", "-")
            )
            return True
        elif prop.endswith("_id"):
            # Generic ID property fallback
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    node[prop] = ref.get("external_id")
                    return True
            node[prop] = obj.get("id", "").split("--")[-1][:8].upper()
            return True
        elif prop == "software_type":
            # Determine software type from STIX type
            stix_type = obj.get("type", "")
            if stix_type == "malware":
                node[prop] = "Malware"
            elif stix_type == "tool":
                node[prop] = "Tool"
            else:
                node[prop] = "Software"
            return True

        return False

    def _enrich_technique_node_schema_compliant(self, node: Dict, obj: Dict):
        """Add schema-compliant technique-specific properties."""
        # Extract technique ID from external references
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                node["technique_id"] = ref.get("external_id")
                break

        # Extract platforms
        node["x_mitre_platforms"] = obj.get("x_mitre_platforms", [])

        # Extract detection information
        node["x_mitre_detection"] = obj.get("x_mitre_detection", "")

        # Collect tactic shortnames from kill chain phases for later linking
        tactics = []
        allowed_kill_chains = {
            "mitre-attack",
            "mitre-mobile-attack",
            "mitre-ics-attack",
            "enterprise-attack",
            "mobile-attack",
            "ics-attack",
        }
        for phase in obj.get("kill_chain_phases", []):
            kcn = (phase.get("kill_chain_name") or "").lower()
            if kcn in allowed_kill_chains or (
                "attack" in kcn and kcn.startswith("mitre")
            ):
                ph = phase.get("phase_name")
                if ph:
                    tactics.append(ph)
        if tactics:
            node["tactics"] = tactics

    def _enrich_tactic_node_schema_compliant(self, node: Dict, obj: Dict):
        """Add schema-compliant tactic-specific properties."""
        node["x_mitre_shortname"] = obj.get(
            "x_mitre_shortname", node["name"].lower().replace(" ", "-")
        )

    def _enrich_group_node_schema_compliant(self, node: Dict, obj: Dict):
        """Add schema-compliant group-specific properties."""
        # Extract group ID from external references
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                node["group_id"] = ref.get("external_id")
                break

        # Extract aliases
        node["aliases"] = obj.get("aliases", [])

    def _enrich_software_node_schema_compliant(self, node: Dict, obj: Dict):
        """Add schema-compliant software-specific properties."""
        # Extract software ID from external references
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                node["software_id"] = ref.get("external_id")
                break

        # Determine software type
        stix_type = obj.get("type", "")
        if stix_type == "malware":
            node["software_type"] = "Malware"
        elif stix_type == "tool":
            node["software_type"] = "Tool"
        else:
            node["software_type"] = "Software"

        # Extract platforms
        node["x_mitre_platforms"] = obj.get("x_mitre_platforms", [])

    def _enrich_mitigation_node_schema_compliant(self, node: Dict, obj: Dict):
        """Add schema-compliant mitigation-specific properties."""
        # Extract mitigation ID from external references
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                node["mitigation_id"] = ref.get("external_id")
                break

    def _enrich_data_source_node_schema_compliant(self, node: Dict, obj: Dict):
        """Add schema-compliant data source-specific properties."""
        # Extract data source ID from external references or generate
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                node["data_source_id"] = ref.get("external_id")
                break

        if "data_source_id" not in node:
            node["data_source_id"] = obj.get("id", "").split("--")[-1][:8].upper()

        # Extract platforms
        node["x_mitre_platforms"] = obj.get("x_mitre_platforms", [])

    def _enrich_data_component_node_schema_compliant(self, node: Dict, obj: Dict):
        """Add schema-compliant data component-specific properties."""
        # Extract or generate component ID
        node["component_id"] = obj.get("id", "").split("--")[-1][:8].upper()

    def _enrich_campaign_node_schema_compliant(self, node: Dict, obj: Dict):
        """Add schema-compliant campaign-specific properties."""
        # Extract campaign ID from external references or generate
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                node["campaign_id"] = ref.get("external_id")
                break

        if "campaign_id" not in node:
            node["campaign_id"] = obj.get("id", "").split("--")[-1][:8].upper()

    # Identity not modeled

    def _enrich_technique_node(self, node: Dict, obj: Dict):
        """Add technique-specific properties."""
        # Extract technique ID
        technique_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id")
                break

        # Extract tactics from kill chain phases
        tactics = []
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") == "mitre-attack":
                tactics.append(phase.get("phase_name"))

        node.update(
            {
                "technique_id": technique_id,
                "tactics": tactics,
                "platforms": obj.get("x_mitre_platforms", []),
                "data_sources": obj.get("x_mitre_data_sources", []),
                "permissions_required": obj.get("x_mitre_permissions_required", []),
                "effective_permissions": obj.get("x_mitre_effective_permissions", []),
                "system_requirements": obj.get("x_mitre_system_requirements", []),
                "defense_bypassed": obj.get("x_mitre_defense_bypassed", []),
                "detection": obj.get("x_mitre_detection", ""),
                "version": obj.get("x_mitre_version", "1.0"),
            }
        )

    def _enrich_tactic_node(self, node: Dict, obj: Dict):
        """Add tactic-specific properties."""
        node.update(
            {
                "short_name": obj.get("x_mitre_shortname", ""),
                "version": obj.get("x_mitre_version", "1.0"),
            }
        )

    # Legacy enrich helpers below are no longer used but kept for reference

    def _enrich_mitigation_node(self, node: Dict, obj: Dict):
        """Add mitigation-specific properties."""
        # Extract mitigation ID
        mitigation_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                mitigation_id = ref.get("external_id")
                break

        node.update(
            {
                "mitigation_id": mitigation_id,
                "version": obj.get("x_mitre_version", "1.0"),
            }
        )

    def _enrich_data_source_node(self, node: Dict, obj: Dict):
        """Add data source-specific properties."""
        node.update(
            {
                "platforms": obj.get("x_mitre_platforms", []),
                "collection_layers": obj.get("x_mitre_collection_layers", []),
                "version": obj.get("x_mitre_version", "1.0"),
            }
        )

    def _enrich_data_component_node(self, node: Dict, obj: Dict):
        """Add data component-specific properties."""
        node.update({"version": obj.get("x_mitre_version", "1.0")})

    def _enrich_campaign_node(self, node: Dict, obj: Dict):
        """Add campaign-specific properties."""
        node.update(
            {
                "aliases": obj.get("aliases", []),
                "first_seen": obj.get("first_seen"),
                "last_seen": obj.get("last_seen"),
                "version": obj.get("x_mitre_version", "1.0"),
            }
        )

    def _process_tactics(self, nodes: List[Dict]) -> Tuple[List[Dict], List[Dict]]:
        """
        Build Tactic->Technique (HAS_TECHNIQUE) and ATT&CK->Tactic (HAS_TACTIC) links.

        Returns a tuple of (attack_root_nodes, relationships).
        """
        attack_root_nodes: List[Dict] = []
        relationships: List[Dict] = []

        # Map (tactic shortname, domain) -> Tactic node id
        tactic_key_to_id: Dict[Tuple[str, str], str] = {}
        tactic_domains: set = set()
        for n in nodes:
            if n.get("type") == "Tactic":
                short = (
                    n.get("x_mitre_shortname") or n.get("short_name") or ""
                ).lower()
                tid = n.get("id")
                dom = n.get("domain", "enterprise")
                if short and tid:
                    tactic_key_to_id[(short, dom)] = tid
                    tactic_domains.add(dom)

        # HAS_TECHNIQUE per tactic (domain-aware)
        for node in nodes:
            if node.get("type") == "Technique":
                dom = node.get("domain", "enterprise")
                for short in node.get("tactics", []) or []:
                    key = (str(short).lower(), dom)
                    tid = tactic_key_to_id.get(key)
                    if tid:
                        relationships.append(
                            {
                                "type": "HAS_TECHNIQUE",
                                "source_id": tid,
                                "target_id": node.get("id"),
                                "source_type": "Tactic",
                                "target_type": "Technique",
                            }
                        )

        # Create a single ATT&CK root and link all tactics (domain captured on tactics)
        if tactic_key_to_id:
            root = {
                "type": "ATT&CK",
                "id": "attack--framework-root",
                "name": "ATT&CK",
                "version": "unknown",
                "domain": ",".join(sorted(tactic_domains)) or "enterprise",
            }
            attack_root_nodes.append(root)
            for tid in set(tactic_key_to_id.values()):
                relationships.append(
                    {
                        "type": "HAS_TACTIC",
                        "source_id": root["id"],
                        "target_id": tid,
                        "source_type": "ATT&CK",
                        "target_type": "Tactic",
                    }
                )

        return attack_root_nodes, relationships

    def _process_subtechniques(self, nodes: List[Dict]) -> List[Dict]:
        """
        Process parent-subtechnique relationships.

        Args:
            nodes: List of processed nodes

        Returns:
            List of subtechnique relationships
        """
        relationships: List[Dict] = []

        # Build technique ID mapping for parent techniques, keyed by (technique_id, domain)
        technique_mapping: Dict[Tuple[str, str], str] = {}
        for node in nodes:
            if node.get("type") == "Technique":
                tid = node.get("technique_id")
                nid = node.get("id")
                dom = node.get("domain", "enterprise")
                if tid and nid:
                    technique_mapping[(tid, dom)] = nid

        # Create HAS_SUBTECHNIQUE from Technique to SubTechnique
        for node in nodes:
            if node.get("type") == "SubTechnique":
                parent_id = node.get("parent_technique")
                dom = node.get("domain", "enterprise")
                parent_uuid = (
                    technique_mapping.get((parent_id, dom)) if parent_id else None
                )
                if parent_uuid:
                    relationships.append(
                        {
                            "type": "HAS_SUBTECHNIQUE",
                            "source_id": parent_uuid,
                            "target_id": node.get("id"),
                            "source_technique_id": parent_id,
                            "source_domain": dom,
                            "source_type": "Technique",
                            "target_type": "SubTechnique",
                        }
                    )

        return relationships

    def _process_relationship(
        self, obj: Dict, object_cache: Dict
    ) -> Optional[List[Dict]]:
        """
        Process STIX relationship object.

        Args:
            obj: STIX relationship object
            object_cache: Cache of all STIX objects by ID

        Returns:
            List of processed relationships or None
        """
        source_ref = obj.get("source_ref")
        target_ref = obj.get("target_ref")
        relationship_type = obj.get("relationship_type")

        if not all([source_ref, target_ref, relationship_type]):
            return None

        # Map relationship types to schema
        type_mapping = {
            "uses": "USES",
            "mitigates": "MITIGATES",
            "attributed-to": "ATTRIBUTED_TO",
            # 'targets' removed from schema
            "delivers": "DELIVERS",
            "communicates-with": "COMMUNICATES_WITH",
            "controls": "CONTROLS",
            "leverages": "LEVERAGES",
            "exploits": "EXPLOITS",
            "compromises": "COMPROMISES",
        }

        if not relationship_type:
            return None

        mapped_type = type_mapping.get(
            relationship_type, (relationship_type or "").lower()
        )

        # Get source and target objects for type information
        source_obj = object_cache.get(source_ref)
        target_obj = object_cache.get(target_ref)

        if not source_obj or not target_obj:
            return None
        # Skip if either side deprecated or revoked
        if (
            source_obj.get("x_mitre_deprecated") is True
            or target_obj.get("x_mitre_deprecated") is True
            or source_obj.get("revoked") is True
            or target_obj.get("revoked") is True
        ):
            return None

        # Skip redundant subtechnique-of (we build HAS_SUBTECHNIQUE separately)
        if relationship_type == "subtechnique-of":
            return []

        # Normalize DETECTED_BY flow from STIX "detects"
        if relationship_type == "detects":
            rels: List[Dict] = []
            source_label = self.stix_type_mapping.get(source_obj.get("type"))
            target_label = self.stix_type_mapping.get(target_obj.get("type"))

            def _detected_by_rel(tech_id: str, ds_id: str) -> Dict:
                return {
                    "type": "DETECTED_BY",
                    "source_id": tech_id,
                    "target_id": ds_id,
                    "source_type": "Technique",
                    "target_type": "DataSource",
                }

            def _has_component_rel(ds_id: str, dc_id: str) -> Dict:
                return {
                    "type": "HAS_COMPONENT",
                    "source_id": ds_id,
                    "target_id": dc_id,
                    "source_type": "DataSource",
                    "target_type": "DataComponent",
                }

            # Case A: DataComponent -> Technique/SubTechnique
            if source_label == "DataComponent" and target_label in (
                "Technique",
                "SubTechnique",
            ):
                dc_id = source_ref
                technique_id = target_ref
                ds_ref = source_obj.get("x_mitre_data_source_ref")
                if ds_ref and dc_id and technique_id:
                    rels.append(_detected_by_rel(str(technique_id), str(ds_ref)))
                    rels.append(_has_component_rel(str(ds_ref), str(dc_id)))
                return rels

            # Case B: DataSource -> Technique/SubTechnique
            if source_label == "DataSource" and target_label in (
                "Technique",
                "SubTechnique",
            ):
                ds_id = source_ref
                technique_id = target_ref
                if ds_id and technique_id:
                    rels.append(_detected_by_rel(str(technique_id), str(ds_id)))
                return rels

            # Case C: reversed direction
            if target_label == "DataComponent" and source_label in (
                "Technique",
                "SubTechnique",
            ):
                dc_id = target_ref
                technique_id = source_ref
                ds_ref = target_obj.get("x_mitre_data_source_ref")
                if ds_ref and dc_id and technique_id:
                    rels.append(_detected_by_rel(str(technique_id), str(ds_ref)))
                    rels.append(_has_component_rel(str(ds_ref), str(dc_id)))
                return rels

            if target_label == "DataSource" and source_label in (
                "Technique",
                "SubTechnique",
            ):
                ds_id = target_ref
                technique_id = source_ref
                if ds_id and technique_id:
                    return [_detected_by_rel(str(technique_id), str(ds_id))]
                return []

            return []

        # Skip relationships removed from schema
        if relationship_type == "targets" or relationship_type == "created-by":
            return []

        # Fallback: standard relationship
        source_label = self.stix_type_mapping.get(source_obj.get("type"))
        target_label = self.stix_type_mapping.get(target_obj.get("type"))
        # Drop relationships where either side isn't modeled (e.g., Identity)
        if not source_label or not target_label:
            return []
        relationship = {
            "type": mapped_type.upper(),
            "source_id": source_ref,
            "target_id": target_ref,
            "source_type": source_label,
            "target_type": target_label,
            "description": obj.get("description", ""),
            "created": obj.get("created"),
            "modified": obj.get("modified"),
        }

        return [relationship]

    def ingest_to_neo4j(self, graph, processed_data: Dict[str, Any]) -> Dict[str, int]:
        """
        Ingest processed STIX data into Neo4j database.

        Args:
            graph: Neo4j database connection
            processed_data: Processed STIX data with nodes and relationships
            Dict with ingestion statistics
        """
        nodes = processed_data["nodes"]
        relationships = processed_data["relationships"]

        # Create constraints and indexes
        self._create_database_schema(graph)

        # Ingest nodes
        progress_bar = st.progress(0)
        for i, node in enumerate(nodes):
            self._create_node(graph, node)
            progress_bar.progress((i + 1) / len(nodes))
        progress_bar.empty()
        st.success(f"✅ Ingested {len(nodes)} nodes")

        # Ingest relationships
        progress_bar = st.progress(0)
        for i, rel in enumerate(relationships):
            self._create_relationship(graph, rel)
            progress_bar.progress((i + 1) / len(relationships))
        progress_bar.empty()
        st.success(f"✅ Ingested {len(relationships)} relationships")

        # Gather stats by node type and total relationships
        stats: Dict[str, int] = {}
        for node_type in [
            "Technique",
            "SubTechnique",
            "Group",
            "Software",
            "Mitigation",
            "Tactic",
            "DataSource",
            "DataComponent",
            "Campaign",
            "ATT&CK",
        ]:
            # Escape special labels like ATT&CK
            label = (
                node_type
                if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", node_type)
                else f"`{node_type}`"
            )
            result = graph.query(f"MATCH (n:{label}) RETURN count(n) as count")
            stats[node_type.lower()] = result[0]["count"] if result else 0

        rel_result = graph.query("MATCH ()-[r]->() RETURN count(r) as count")
        stats["relationships"] = rel_result[0]["count"] if rel_result else 0

        return stats

    def _create_database_schema(self, graph):
        """Create schema-compliant database constraints and indexes based on schema.json."""
        st.info("📋 Creating schema-compliant database constraints and indexes...")

        # Schema-compliant constraints from schema.json
        constraints = [
            "CREATE CONSTRAINT technique_id_unique IF NOT EXISTS FOR (t:Technique) REQUIRE t.id IS UNIQUE",
            "CREATE CONSTRAINT subtechnique_id_unique IF NOT EXISTS FOR (st:SubTechnique) REQUIRE st.id IS UNIQUE",
            "CREATE CONSTRAINT mitigation_id_unique IF NOT EXISTS FOR (m:Mitigation) REQUIRE m.id IS UNIQUE",
            "CREATE CONSTRAINT group_id_unique IF NOT EXISTS FOR (g:Group) REQUIRE g.id IS UNIQUE",
            "CREATE CONSTRAINT software_id_unique IF NOT EXISTS FOR (s:Software) REQUIRE s.id IS UNIQUE",
            "CREATE CONSTRAINT data_source_id_unique IF NOT EXISTS FOR (ds:DataSource) REQUIRE ds.id IS UNIQUE",
            "CREATE CONSTRAINT data_component_id_unique IF NOT EXISTS FOR (dc:DataComponent) REQUIRE dc.id IS UNIQUE",
            "CREATE CONSTRAINT tactic_id_unique IF NOT EXISTS FOR (tac:Tactic) REQUIRE tac.id IS UNIQUE",
            "CREATE CONSTRAINT campaign_id_unique IF NOT EXISTS FOR (cam:Campaign) REQUIRE cam.id IS UNIQUE",
            # Identity removed
            "CREATE CONSTRAINT attack_root_unique IF NOT EXISTS FOR (a:`ATT&CK`) REQUIRE a.id IS UNIQUE",
        ]
        for constraint in constraints:
            try:
                graph.query(constraint)
            except Exception as e:
                if "already exists" not in str(e).lower():
                    st.warning(f"Constraint creation failed: {e}")
        # Schema-compliant indexes for performance
        indexes = [
            "CREATE INDEX technique_name_idx IF NOT EXISTS FOR (t:Technique) ON (t.name)",
            "CREATE INDEX technique_id_idx IF NOT EXISTS FOR (t:Technique) ON (t.technique_id)",
            "CREATE INDEX group_name_idx IF NOT EXISTS FOR (g:Group) ON (g.name)",
            "CREATE INDEX software_name_idx IF NOT EXISTS FOR (s:Software) ON (s.name)",
            "CREATE INDEX tactic_name_idx IF NOT EXISTS FOR (tac:Tactic) ON (tac.name)",
            "CREATE INDEX mitigation_name_idx IF NOT EXISTS FOR (m:Mitigation) ON (m.name)",
            "CREATE INDEX data_source_name_idx IF NOT EXISTS FOR (ds:DataSource) ON (ds.name)",
        ]

        for index in indexes:
            try:
                graph.query(index)
            except Exception as e:
                if "already exists" not in str(e).lower():
                    st.warning(f"Index creation failed: {e}")

        st.success("✅ Schema-compliant database structure created")

    def _create_node(self, graph, node: Dict):
        """Create or update a single node in Neo4j using MERGE to handle duplicates."""
        node_type = node["type"]
        node_id = node.get("id")

        if not node_id:
            st.warning(f"Node missing ID: {node.get('name', 'Unknown')}")
            return

        # Convert lists to string format for Neo4j
        for key, value in node.items():
            if isinstance(value, list):
                node[key] = value  # Neo4j handles lists natively

        # Use MERGE to handle existing nodes gracefully
        # Escape label if it contains non-identifier characters (e.g., ATT&CK)
        label = (
            node_type
            if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", node_type)
            else f"`{node_type}`"
        )
        query = f"""
        MERGE (n:{label} {{id: $node_id}})
        SET n += $properties
        """

        try:
            graph.query(query, params={"node_id": node_id, "properties": node})
        except Exception as e:
            st.warning(
                f"Failed to create/update node {node.get('name', 'Unknown')}: {e}"
            )

    def _create_relationship(self, graph, rel: Dict):
        """Create or update a single relationship in Neo4j using MERGE to handle duplicates."""
        rel_type = rel["type"]
        source_id = rel["source_id"]
        target_id = rel["target_id"]

        # Handle special relationship types
        if rel_type == "HAS_SUBTECHNIQUE":
            # Parent technique to subtechnique relationship
            query = """
            MATCH (parent:Technique {technique_id: $parent_id, domain: $domain})
            MATCH (sub:SubTechnique {id: $target_id, domain: $domain})
            MERGE (parent)-[:HAS_SUBTECHNIQUE]->(sub)
            """
            try:
                graph.query(
                    query,
                    params={
                        "parent_id": rel.get("source_technique_id"),
                        "target_id": target_id,
                        "domain": rel.get("source_domain", "enterprise"),
                    },
                )
            except Exception as e:
                st.warning(f"Failed to create subtechnique relationship: {e}")

        else:
            # Standard relationships - escape relationship types with hyphens using backticks
            escaped_rel_type = f"`{rel_type}`" if "-" in rel_type else rel_type
            query = f"""
            MATCH (source {{id: $source_id}})
            MATCH (target {{id: $target_id}})
            MERGE (source)-[:{escaped_rel_type}]->(target)
            """
            try:
                graph.query(
                    query, params={"source_id": source_id, "target_id": target_id}
                )
            except Exception as e:
                st.warning(f"Failed to create relationship {rel_type}: {e}")

    def clear_attack_data(self, graph):
        """
        Clear existing ATT&CK data from the database.

        This method removes all ATT&CK-related nodes and relationships
        to allow for a clean re-ingestion.

        Args:
            graph: Neo4j database connection
        """
        st.info("🗑️ Clearing existing ATT&CK data...")

        # List of ATT&CK node types to clear
        attack_node_types = [
            "Technique",
            "SubTechnique",
            "Tactic",
            "Software",
            "Group",
            "Mitigation",
            "DataSource",
            "DataComponent",
            "Campaign",
        ]

        try:
            # Clear relationships first to avoid constraint issues
            st.info("🔗 Removing ATT&CK relationships...")

            # Remove all relationships between ATT&CK nodes
            for node_type in attack_node_types:
                query = f"""
                MATCH (n:%LABEL%)-[r]-()
                DELETE r
                """
                label = (
                    node_type
                    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", node_type)
                    else f"`{node_type}`"
                )
                graph.query(query.replace("%LABEL%", label))

            # Clear nodes
            st.info("🗂️ Removing ATT&CK nodes...")

            for node_type in attack_node_types:
                query = f"""
                MATCH (n:%LABEL%)
                DELETE n
                """
                label = (
                    node_type
                    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", node_type)
                    else f"`{node_type}`"
                )
                result = graph.query(f"MATCH (n:{label}) RETURN count(n) as count")
                count = result[0]["count"] if result else 0

                if count > 0:
                    graph.query(query.replace("%LABEL%", label))
                    st.success(f"✅ Removed {count:,} {node_type} nodes")

            st.success("🎯 ATT&CK data cleared successfully")

        except Exception as e:
            st.error(f"❌ Error clearing ATT&CK data: {e}")
            raise

    def ingest_attack_data(
        self, graph, domains: Optional[List[str]] = None, clear_existing: bool = False
    ) -> Tuple[bool, str]:
        """
        Run complete STIX data ingestion process.

        Main entry point for ATT&CK data ingestion. Maintains compatibility
        with existing code while using new STIX-based implementation.

        Args:
            graph: Neo4j database connection
            domains: List of domains to ingest (enterprise, mobile, ics)
            clear_existing: Whether to clear existing ATT&CK data before ingestion

        Returns:
            Tuple of (success_boolean, status_message)
        """
        try:
            # Step 0: Clear existing data if requested
            if clear_existing:
                self.clear_attack_data(graph)

            # Step 1: Fetch STIX data
            stix_data = self.fetch_attack_data(domains)

            if not stix_data.get("objects"):
                return False, "No STIX data fetched"

            # Step 2: Process STIX objects
            processed_data = self.process_attack_objects(stix_data)

            # Step 3: Ingest into Neo4j
            stats = self.ingest_to_neo4j(graph, processed_data)

            # Format success message
            total_nodes = sum(stats.values()) - stats.get("relationships", 0)
            message = f"Successfully ingested {total_nodes:,} nodes and {stats.get('relationships', 0):,} relationships from STIX data"

            return True, message

        except Exception as e:
            return False, f"STIX ingestion failed: {e}"

    # Legacy method compatibility - maps to new implementation
    def run_full_ingestion(
        self, graph, domains: Optional[List[str]] = None
    ) -> Dict[str, int]:
        """
        Legacy compatibility method for full ingestion.

        Args:
            graph: Neo4j database connection
            domains: List of domains to ingest

        Returns:
            Dict with ingestion statistics
        """
        success, message = self.ingest_attack_data(graph, domains)
        if not success:
            raise Exception(message)

        # Return statistics for compatibility
        stats = {}
        for node_type in [
            "Technique",
            "SubTechnique",
            "Group",
            "Software",
            "Mitigation",
            "Tactic",
            "DataSource",
            "DataComponent",
            "Campaign",
        ]:
            result = graph.query(f"MATCH (n:{node_type}) RETURN count(n) as count")
            stats[node_type.lower()] = result[0]["count"] if result else 0

        rel_result = graph.query("MATCH ()-[r]->() RETURN count(r) as count")
        stats["relationships"] = rel_result[0]["count"] if rel_result else 0

        return stats


# Backward compatibility function for existing code
def ingest_attack_data(graph, domains: Optional[List[str]] = None) -> Tuple[bool, str]:
    """
    Backward compatibility function for existing code.

    Args:
        graph: Neo4j database connection
        domains: List of domains to ingest

    Returns:
        Tuple of (success_boolean, status_message)
    """
    ingestion = AttackIngestion()
    return ingestion.ingest_attack_data(graph, domains)
