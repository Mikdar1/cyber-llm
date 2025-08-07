"""
MITRE ATT&CK Knowledge Base Ingestion using STIX Data

This module handles the ingestion of MITRE ATT&CK data from official STIX format
into a Neo4j graph database. The implementation fetches data directly from the
official MITRE attack-stix-data repository and processes it according to the
cybersecurity knowledge base schema.

This module is focused exclusively on MITRE ATT&CK data ingestion. Other 
cybersecurity frameworks (CIS, FFIEC, HIPAA, NIST, PCI DSS) are handled 
by their respective dedicated modules coordinated through multi_source_ingestion.py.

Key Features:
- STIX-based data fetching from official MITRE repository
- Complete ATT&CK framework coverage (techniques, tactics, malware, groups, tools, mitigations)
- Schema-compliant relationship mapping (USES, MITIGATES, PART_OF_TACTIC, etc.)
- Citation extraction for every node from external references
- Support for all ATT&CK domains (enterprise, mobile, ics)
- Neo4j graph database storage with optimized constraints and indexes
- Backward compatibility with existing ingestion interfaces
"""

import streamlit as st
import requests
import json
from typing import Dict, List, Any, Optional, Tuple


class AttackIngestion:
    """
    STIX-based ATT&CK knowledge base ingestion system.
    
    Handles complete ingestion of MITRE ATT&CK data from STIX format
    into Neo4j graph database with comprehensive relationship mapping
    and citation extraction.
    """
    
    def __init__(self):
        """Initialize the ingestion system with STIX configuration."""
        self.base_url = "https://raw.githubusercontent.com/mitre/cti/master"
        self.stix_type_mapping = {
            'attack-pattern': 'Technique',
            'malware': 'Malware', 
            'intrusion-set': 'ThreatGroup',
            'tool': 'Tool',
            'course-of-action': 'Mitigation',
            'x-mitre-tactic': 'Tactic',
            'x-mitre-data-source': 'DataSource',
            'x-mitre-data-component': 'DataComponent',
            'campaign': 'Campaign'
        }

    def fetch_attack_data(self, domains: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Fetch MITRE ATT&CK STIX data from official repository.
        
        Args:
            domains: List of domains to fetch (enterprise, mobile, ics)
                    Defaults to ['enterprise'] for full ATT&CK coverage
                    
        Returns:
            Dict containing combined STIX data from all domains
        """
        if domains is None:
            domains = ['enterprise']  # Default to enterprise domain
        
        all_objects = []
        
        st.info(f"🌐 Fetching ATT&CK STIX data from {len(domains)} domain(s)...")
        
        for domain in domains:
            domain_url = f"{self.base_url}/{domain}-attack/{domain}-attack.json"
            
            try:
                st.info(f"📡 Downloading {domain} domain data...")
                response = requests.get(domain_url, timeout=30)
                response.raise_for_status()
                
                domain_data = response.json()
                domain_objects = domain_data.get('objects', [])
                
                # Add domain metadata to objects
                for obj in domain_objects:
                    obj['x_attack_domain'] = domain
                
                all_objects.extend(domain_objects)
                st.success(f"✅ Fetched {len(domain_objects):,} objects from {domain} domain")
                
            except requests.RequestException as e:
                st.error(f"❌ Failed to fetch {domain} domain data: {e}")
                continue
            except json.JSONDecodeError as e:
                st.error(f"❌ Failed to parse {domain} domain JSON: {e}")
                continue
        
        if not all_objects:
            raise Exception("No STIX data could be fetched from any domain")
        
        st.success(f"🎯 Total STIX objects fetched: {len(all_objects):,}")
        
        return {
            'type': 'bundle',
            'id': 'bundle--attack-stix-combined',
            'objects': all_objects
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
        external_refs = obj.get('external_references', [])
        
        for ref in external_refs:
            # Create a simple string representation for Neo4j compatibility
            source_name = ref.get('source_name', 'Unknown')
            url = ref.get('url', '')
            external_id = ref.get('external_id', '')
            description = ref.get('description', '')
            
            # Only add citations with meaningful content
            if source_name != 'Unknown' or url or external_id:
                # Create a simple string format for the citation
                citation_parts = []
                if external_id:
                    citation_parts.append(f"ID: {external_id}")
                if source_name != 'Unknown':
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
        objects = stix_data.get('objects', [])
        nodes = []
        relationships = []
        
        # Create object cache for relationship processing
        object_cache = {obj.get('id'): obj for obj in objects if obj.get('id')}
        
        st.info(f"⚙️ Processing {len(objects):,} STIX objects...")
        
        # Process each object type
        for obj in objects:
            obj_type = obj.get('type')
            
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
            elif obj_type == 'relationship':
                relationship = self._process_relationship(obj, object_cache)
                if relationship:
                    relationships.append(relationship)
        
        # Add tactic nodes and technique-tactic relationships
        tactic_nodes, tactic_relationships = self._process_tactics(nodes)
        nodes.extend(tactic_nodes)
        relationships.extend(tactic_relationships)
        
        # Add subtechnique relationships
        subtechnique_relationships = self._process_subtechniques(nodes)
        relationships.extend(subtechnique_relationships)
        
        st.success(f"✅ Processed {len(nodes):,} nodes and {len(relationships):,} relationships")
        
        return {
            'nodes': nodes,
            'relationships': relationships,
            'total_objects': len(objects)
        }

    def _process_stix_object(self, obj: Dict, node_type: str) -> Optional[Dict]:
        """
        Process individual STIX object into graph node.
        
        Args:
            obj: STIX object
            node_type: Target graph node type
            
        Returns:
            Processed node dictionary or None
        """
        if not obj.get('id') or not obj.get('name'):
            return None
        
        # Extract citations for this object
        citations = self.extract_citations(obj)
        
        # Base node structure
        node = {
            'type': node_type,
            'id': obj.get('id'),
            'name': obj.get('name', ''),
            'description': obj.get('description', ''),
            'created': obj.get('created'),
            'modified': obj.get('modified'),
            'citations': citations,
            'domain': obj.get('x_attack_domain', 'enterprise')
        }
        
        # Add type-specific properties
        if node_type == 'Technique':
            self._enrich_technique_node(node, obj)
        elif node_type == 'Tactic':
            self._enrich_tactic_node(node, obj)
        elif node_type == 'Malware':
            self._enrich_malware_node(node, obj)
        elif node_type == 'ThreatGroup':
            self._enrich_threat_group_node(node, obj)
        elif node_type == 'Tool':
            self._enrich_tool_node(node, obj)
        elif node_type == 'Mitigation':
            self._enrich_mitigation_node(node, obj)
        elif node_type == 'DataSource':
            self._enrich_data_source_node(node, obj)
        elif node_type == 'DataComponent':
            self._enrich_data_component_node(node, obj)
        elif node_type == 'Campaign':
            self._enrich_campaign_node(node, obj)
        
        return node

    def _enrich_technique_node(self, node: Dict, obj: Dict):
        """Add technique-specific properties."""
        # Extract technique ID
        technique_id = None
        for ref in obj.get('external_references', []):
            if ref.get('source_name') == 'mitre-attack':
                technique_id = ref.get('external_id')
                break
        
        # Extract tactics from kill chain phases
        tactics = []
        for phase in obj.get('kill_chain_phases', []):
            if phase.get('kill_chain_name') == 'mitre-attack':
                tactics.append(phase.get('phase_name'))
        
        node.update({
            'technique_id': technique_id,
            'tactics': tactics,
            'platforms': obj.get('x_mitre_platforms', []),
            'data_sources': obj.get('x_mitre_data_sources', []),
            'permissions_required': obj.get('x_mitre_permissions_required', []),
            'effective_permissions': obj.get('x_mitre_effective_permissions', []),
            'system_requirements': obj.get('x_mitre_system_requirements', []),
            'defense_bypassed': obj.get('x_mitre_defense_bypassed', []),
            'detection': obj.get('x_mitre_detection', ''),
            'is_subtechnique': '.' in (technique_id or ''),
            'version': obj.get('x_mitre_version', '1.0')
        })

    def _enrich_tactic_node(self, node: Dict, obj: Dict):
        """Add tactic-specific properties."""
        node.update({
            'short_name': obj.get('x_mitre_shortname', ''),
            'version': obj.get('x_mitre_version', '1.0')
        })

    def _enrich_malware_node(self, node: Dict, obj: Dict):
        """Add malware-specific properties."""
        node.update({
            'labels': obj.get('labels', []),
            'aliases': obj.get('x_mitre_aliases', []),
            'platforms': obj.get('x_mitre_platforms', []),
            'version': obj.get('x_mitre_version', '1.0')
        })

    def _enrich_threat_group_node(self, node: Dict, obj: Dict):
        """Add threat group-specific properties."""
        node.update({
            'aliases': obj.get('aliases', []),
            'version': obj.get('x_mitre_version', '1.0')
        })

    def _enrich_tool_node(self, node: Dict, obj: Dict):
        """Add tool-specific properties."""
        node.update({
            'labels': obj.get('labels', []),
            'aliases': obj.get('x_mitre_aliases', []),
            'platforms': obj.get('x_mitre_platforms', []),
            'version': obj.get('x_mitre_version', '1.0')
        })

    def _enrich_mitigation_node(self, node: Dict, obj: Dict):
        """Add mitigation-specific properties."""
        # Extract mitigation ID
        mitigation_id = None
        for ref in obj.get('external_references', []):
            if ref.get('source_name') == 'mitre-attack':
                mitigation_id = ref.get('external_id')
                break
        
        node.update({
            'mitigation_id': mitigation_id,
            'version': obj.get('x_mitre_version', '1.0')
        })

    def _enrich_data_source_node(self, node: Dict, obj: Dict):
        """Add data source-specific properties."""
        node.update({
            'platforms': obj.get('x_mitre_platforms', []),
            'collection_layers': obj.get('x_mitre_collection_layers', []),
            'version': obj.get('x_mitre_version', '1.0')
        })

    def _enrich_data_component_node(self, node: Dict, obj: Dict):
        """Add data component-specific properties."""
        node.update({
            'version': obj.get('x_mitre_version', '1.0')
        })

    def _enrich_campaign_node(self, node: Dict, obj: Dict):
        """Add campaign-specific properties."""
        node.update({
            'aliases': obj.get('aliases', []),
            'first_seen': obj.get('first_seen'),
            'last_seen': obj.get('last_seen'),
            'version': obj.get('x_mitre_version', '1.0')
        })

    def _process_tactics(self, nodes: List[Dict]) -> Tuple[List[Dict], List[Dict]]:
        """
        Process tactics from technique kill chain phases.
        
        Args:
            nodes: List of processed nodes
            
        Returns:
            Tuple of (tactic_nodes, tactic_relationships)
        """
        tactic_nodes = []
        tactic_relationships = []
        processed_tactics = set()
        
        for node in nodes:
            if node.get('type') == 'Technique':
                technique_id = node.get('id')
                tactics = node.get('tactics', [])
                
                for tactic_short_name in tactics:
                    if tactic_short_name and tactic_short_name not in processed_tactics:
                        # Create tactic node
                        tactic_node = {
                            'type': 'Tactic',
                            'id': f"tactic--{tactic_short_name}",
                            'name': tactic_short_name.replace('-', ' ').title(),
                            'short_name': tactic_short_name,
                            'description': f"ATT&CK tactic: {tactic_short_name}",
                            'citations': [],  # Tactics inherit from framework
                            'domain': node.get('domain', 'enterprise')
                        }
                        
                        tactic_nodes.append(tactic_node)
                        processed_tactics.add(tactic_short_name)
                    
                    # Create technique-to-tactic relationship
                    if tactic_short_name:
                        relationship = {
                            'type': 'PART_OF_TACTIC',
                            'source_id': technique_id,
                            'target_id': f"tactic--{tactic_short_name}",
                            'target_tactic': tactic_short_name,
                            'source_type': 'Technique',
                            'target_type': 'Tactic'
                        }
                        tactic_relationships.append(relationship)
        
        return tactic_nodes, tactic_relationships

    def _process_subtechniques(self, nodes: List[Dict]) -> List[Dict]:
        """
        Process parent-subtechnique relationships.
        
        Args:
            nodes: List of processed nodes
            
        Returns:
            List of subtechnique relationships
        """
        relationships = []
        
        # Build technique ID mapping
        technique_mapping = {}
        for node in nodes:
            if node.get('type') == 'Technique':
                technique_id = node.get('technique_id')
                if technique_id:
                    technique_mapping[technique_id] = node.get('id')
        
        # Find subtechniques and create relationships
        for node in nodes:
            if node.get('type') == 'Technique' and node.get('is_subtechnique'):
                technique_id = node.get('technique_id', '')
                if '.' in technique_id:
                    parent_id = technique_id.split('.')[0]
                    parent_uuid = technique_mapping.get(parent_id)
                    
                    if parent_uuid:
                        relationship = {
                            'type': 'HAS_SUBTECHNIQUE',
                            'source_id': parent_uuid,
                            'target_id': node.get('id'),
                            'source_technique_id': parent_id,
                            'source_type': 'Technique',
                            'target_type': 'Technique'
                        }
                        relationships.append(relationship)
        
        return relationships

    def _process_relationship(self, obj: Dict, object_cache: Dict) -> Optional[Dict]:
        """
        Process STIX relationship object.
        
        Args:
            obj: STIX relationship object
            object_cache: Cache of all STIX objects by ID
            
        Returns:
            Processed relationship dictionary or None
        """
        source_ref = obj.get('source_ref')
        target_ref = obj.get('target_ref')
        relationship_type = obj.get('relationship_type')
        
        if not all([source_ref, target_ref, relationship_type]):
            return None
        
        # Map relationship types to schema
        type_mapping = {
            'uses': 'USES',
            'mitigates': 'MITIGATES',
            'attributed-to': 'ATTRIBUTED_TO',
            'targets': 'TARGETS',
            'delivers': 'DELIVERS',
            'communicates-with': 'COMMUNICATES_WITH',
            'controls': 'CONTROLS',
            'leverages': 'LEVERAGES',
            'exploits': 'EXPLOITS',
            'compromises': 'COMPROMISES'
        }
        
        if not relationship_type:
            return None
            
        mapped_type = type_mapping.get(relationship_type, relationship_type.upper())
        
        # Get source and target objects for type information
        source_obj = object_cache.get(source_ref)
        target_obj = object_cache.get(target_ref)
        
        if not source_obj or not target_obj:
            return None
        
        relationship = {
            'type': mapped_type,
            'source_id': source_ref,
            'target_id': target_ref,
            'source_type': self.stix_type_mapping.get(source_obj.get('type')),
            'target_type': self.stix_type_mapping.get(target_obj.get('type')),
            'description': obj.get('description', ''),
            'created': obj.get('created'),
            'modified': obj.get('modified')
        }
        
        return relationship

    def ingest_to_neo4j(self, graph, processed_data: Dict[str, Any]) -> Dict[str, int]:
        """
        Ingest processed STIX data into Neo4j database.
        
        Args:
            graph: Neo4j database connection
            processed_data: Processed STIX data with nodes and relationships
            
        Returns:
            Dict with ingestion statistics
        """
        nodes = processed_data['nodes']
        relationships = processed_data['relationships']
        
        st.info("🗄️ Ingesting data into Neo4j...")
        
        # Clear existing data
        st.info("🧹 Clearing existing data...")
        graph.query("MATCH (n) DETACH DELETE n")
        
        # Create constraints and indexes
        self._create_database_schema(graph)
        
        # Ingest nodes
        stats = {}
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
        
        # Calculate final statistics
        for node_type in ['Technique', 'Malware', 'ThreatGroup', 'Tool', 'Mitigation', 'Tactic', 'DataSource', 'DataComponent', 'Campaign']:
            result = graph.query(f"MATCH (n:{node_type}) RETURN count(n) as count")
            stats[node_type.lower()] = result[0]['count'] if result else 0
        
        rel_result = graph.query("MATCH ()-[r]->() RETURN count(r) as count")
        stats['relationships'] = rel_result[0]['count'] if rel_result else 0
        
        return stats

    def _create_database_schema(self, graph):
        """Create database constraints and indexes."""
        st.info("📋 Creating database schema...")
        
        # Create constraints for unique IDs
        constraints = [
            "CREATE CONSTRAINT technique_id IF NOT EXISTS FOR (t:Technique) REQUIRE t.id IS UNIQUE",
            "CREATE CONSTRAINT malware_id IF NOT EXISTS FOR (m:Malware) REQUIRE m.id IS UNIQUE", 
            "CREATE CONSTRAINT tool_id IF NOT EXISTS FOR (t:Tool) REQUIRE t.id IS UNIQUE",
            "CREATE CONSTRAINT group_id IF NOT EXISTS FOR (g:ThreatGroup) REQUIRE g.id IS UNIQUE",
            "CREATE CONSTRAINT mitigation_id IF NOT EXISTS FOR (m:Mitigation) REQUIRE m.id IS UNIQUE",
            "CREATE CONSTRAINT tactic_id IF NOT EXISTS FOR (t:Tactic) REQUIRE t.id IS UNIQUE",
            "CREATE CONSTRAINT datasource_id IF NOT EXISTS FOR (d:DataSource) REQUIRE d.id IS UNIQUE",
            "CREATE CONSTRAINT datacomponent_id IF NOT EXISTS FOR (d:DataComponent) REQUIRE d.id IS UNIQUE",
            "CREATE CONSTRAINT campaign_id IF NOT EXISTS FOR (c:Campaign) REQUIRE c.id IS UNIQUE"
        ]
        
        for constraint in constraints:
            try:
                graph.query(constraint)
            except Exception as e:
                st.warning(f"Constraint creation failed: {e}")
        
        # Create indexes for performance
        indexes = [
            "CREATE INDEX technique_name IF NOT EXISTS FOR (t:Technique) ON (t.name)",
            "CREATE INDEX technique_technique_id IF NOT EXISTS FOR (t:Technique) ON (t.technique_id)",
            "CREATE INDEX malware_name IF NOT EXISTS FOR (m:Malware) ON (m.name)",
            "CREATE INDEX group_name IF NOT EXISTS FOR (g:ThreatGroup) ON (g.name)",
            "CREATE INDEX mitigation_name IF NOT EXISTS FOR (m:Mitigation) ON (m.name)"
        ]
        
        for index in indexes:
            try:
                graph.query(index)
            except Exception as e:
                st.warning(f"Index creation failed: {e}")

    def _create_node(self, graph, node: Dict):
        """Create a single node in Neo4j."""
        node_type = node['type']
        
        # Convert lists to string format for Neo4j
        for key, value in node.items():
            if isinstance(value, list):
                node[key] = value  # Neo4j handles lists natively
        
        # Create Cypher query
        query = f"""
        CREATE (n:{node_type})
        SET n += $properties
        """
        
        try:
            graph.query(query, params={'properties': node})
        except Exception as e:
            st.warning(f"Failed to create node {node.get('name', 'Unknown')}: {e}")

    def _create_relationship(self, graph, rel: Dict):
        """Create a single relationship in Neo4j."""
        rel_type = rel['type']
        source_id = rel['source_id']
        target_id = rel['target_id']
        
        # Handle special relationship types
        if rel_type == 'PART_OF_TACTIC':
            # Technique to Tactic relationship
            query = """
            MATCH (t:Technique {id: $source_id})
            MATCH (tactic:Tactic {short_name: $target_tactic})
            CREATE (t)-[:PART_OF_TACTIC]->(tactic)
            """
            try:
                graph.query(query, params={
                    'source_id': source_id,
                    'target_tactic': rel.get('target_tactic')
                })
            except Exception as e:
                st.warning(f"Failed to create tactic relationship: {e}")
        
        elif rel_type == 'HAS_SUBTECHNIQUE':
            # Parent technique to subtechnique relationship
            query = """
            MATCH (parent:Technique {technique_id: $parent_id})
            MATCH (sub:Technique {id: $target_id})
            CREATE (parent)-[:HAS_SUBTECHNIQUE]->(sub)
            """
            try:
                graph.query(query, params={
                    'parent_id': rel.get('source_technique_id'),
                    'target_id': target_id
                })
            except Exception as e:
                st.warning(f"Failed to create subtechnique relationship: {e}")
        
        else:
            # Standard relationships - escape relationship types with hyphens using backticks
            escaped_rel_type = f"`{rel_type}`" if '-' in rel_type else rel_type
            query = f"""
            MATCH (source {{id: $source_id}})
            MATCH (target {{id: $target_id}})
            CREATE (source)-[:{escaped_rel_type}]->(target)
            """
            try:
                graph.query(query, params={
                    'source_id': source_id,
                    'target_id': target_id
                })
            except Exception as e:
                st.warning(f"Failed to create relationship {rel_type}: {e}")

    def ingest_attack_data(self, graph, domains: Optional[List[str]] = None) -> Tuple[bool, str]:
        """
        Run complete STIX data ingestion process.
        
        Main entry point for ATT&CK data ingestion. Maintains compatibility
        with existing code while using new STIX-based implementation.
        
        Args:
            graph: Neo4j database connection
            domains: List of domains to ingest (enterprise, mobile, ics)
            
        Returns:
            Tuple of (success_boolean, status_message)
        """
        try:
            # Step 1: Fetch STIX data
            stix_data = self.fetch_attack_data(domains)
            
            if not stix_data.get('objects'):
                return False, "No STIX data fetched"
            
            # Step 2: Process STIX objects
            processed_data = self.process_attack_objects(stix_data)
            
            # Step 3: Ingest into Neo4j
            stats = self.ingest_to_neo4j(graph, processed_data)
            
            # Format success message
            total_nodes = sum(stats.values()) - stats.get('relationships', 0)
            message = f"Successfully ingested {total_nodes:,} nodes and {stats.get('relationships', 0):,} relationships from STIX data"
            
            return True, message
            
        except Exception as e:
            return False, f"STIX ingestion failed: {e}"

    # Legacy method compatibility - maps to new implementation
    def run_full_ingestion(self, graph, domains: Optional[List[str]] = None) -> Dict[str, int]:
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
        for node_type in ['Technique', 'Malware', 'ThreatGroup', 'Tool', 'Mitigation', 'Tactic', 'DataSource', 'DataComponent', 'Campaign']:
            result = graph.query(f"MATCH (n:{node_type}) RETURN count(n) as count")
            stats[node_type.lower()] = result[0]['count'] if result else 0
        
        rel_result = graph.query("MATCH ()-[r]->() RETURN count(r) as count")
        stats['relationships'] = rel_result[0]['count'] if rel_result else 0
        
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
