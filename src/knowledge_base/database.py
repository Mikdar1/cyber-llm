"""
Neo4j Database Connection and Management Module

This module provides connection management and basic operations for the Neo4j
graph database used to store the multi-framework cybersecurity knowledge base. 
It handles connection establishment, authentication, query execution, and database
maintenance operations for multiple cybersecurity frameworks including:

- MITRE ATT&CK: Tactics, techniques, procedures, threat groups, malware, tools
- CIS Controls v8.1: Implementation groups, controls, safeguards
- NIST CSF 2.0: Functions, categories, subcategories, implementation examples
- HIPAA Administrative Simplification: Regulations, sections, entity types
- FFIEC IT Handbook: Categories, topics, guidance sections
- PCI DSS v4.0.1: Requirements, testing procedures, guidance

Classes:
    Neo4jConnection: Wrapper class for Neo4j database operations

Functions:
    create_graph_connection: Factory function for database connections
    clear_knowledge_base: Database cleanup utility
    clear_framework_data: Framework-specific data cleanup
"""

from neo4j import GraphDatabase
from src.config.settings import NEO4J_URI, NEO4J_USERNAME, NEO4J_PASSWORD


class Neo4jConnection:
    """
    Neo4j database connection wrapper with query execution capabilities.
    
    Provides a simplified interface for Neo4j database operations including
    connection management, query execution, and transaction handling for
    multi-framework cybersecurity knowledge base operations.
    
    Supports data operations for:
    - MITRE ATT&CK framework nodes and relationships
    - CIS Controls implementation groups and safeguards
    - NIST CSF functions, categories, and subcategories
    - HIPAA regulations and compliance requirements
    - FFIEC guidance categories and topics
    - PCI DSS requirements and testing procedures
    
    Attributes:
        driver: Neo4j driver instance for database communication
    """
    
    def __init__(self, uri, username, password):
        """
        Initialize Neo4j connection with authentication.
        
        Args:
            uri (str): Neo4j database URI
            username (str): Database username
            password (str): Database password
        """
        self.driver = GraphDatabase.driver(uri, auth=(username, password))
    
    def close(self):
        """Close the database connection and release resources."""
        if self.driver:
            self.driver.close()
    
    def query(self, query, params=None, max_retries=3):
        """
        Execute a Cypher query and return results with retry logic.
        
        Args:
            query (str): Cypher query string
            params (dict, optional): Query parameters
            max_retries (int): Maximum number of retry attempts
            
        Returns:
            list: Query results as list of dictionaries
        """
        import time
        last_exception = None
        
        for attempt in range(max_retries + 1):
            try:
                with self.driver.session() as session:
                    result = session.run(query, params or {})
                    return [record.data() for record in result]
            except Exception as e:
                last_exception = e
                if attempt < max_retries:
                    # Wait before retrying (exponential backoff)
                    wait_time = 2 ** attempt
                    time.sleep(wait_time)
                    continue
                else:
                    # Re-raise the last exception if all retries failed
                    raise last_exception


def create_graph_connection():
    """
    Create and return a validated Neo4j graph connection.
    
    Establishes connection to Neo4j database using configuration settings
    and performs connection validation. The connection supports operations
    for all cybersecurity frameworks in the knowledge base.
    
    Returns:
        Neo4jConnection: Validated database connection instance
        
    Raises:
        ConnectionError: If database connection fails
    """
    try:
        connection = Neo4jConnection(NEO4J_URI, NEO4J_USERNAME, NEO4J_PASSWORD)
        
        # Validate connection with simple test query
        connection.query("RETURN 1 as test")
        return connection
    except Exception as e:
        raise ConnectionError(f"Failed to connect to Neo4j database: {e}")


def clear_knowledge_base(graph):
    """
    Clear all data from the multi-framework knowledge base.
    
    Removes all nodes and relationships from the Neo4j database across
    all cybersecurity frameworks. Use with caution as this operation 
    is irreversible and will delete:
    - All ATT&CK techniques, tactics, threat groups, malware, tools
    - All CIS Controls, implementation groups, safeguards
    - All NIST CSF functions, categories, subcategories
    - All HIPAA regulations, sections, entity types
    - All FFIEC guidance categories and topics
    - All PCI DSS requirements and testing procedures
    - All cross-framework relationships and citations
    
    Args:
        graph (Neo4jConnection): Database connection instance
        
    Returns:
        bool: True if operation successful
        
    Raises:
        Exception: If database cleanup fails
    """
    try:
        graph.query("MATCH (n) DETACH DELETE n")
        return True
    except Exception as e:
        raise Exception(f"Could not clear existing data: {e}")


def clear_framework_data(graph, framework_name):
    """
    Clear data for a specific cybersecurity framework.
    
    Removes nodes and relationships associated with a specific framework
    while preserving data from other frameworks. Supported frameworks:
    - 'attack': MITRE ATT&CK framework
    - 'cis': CIS Controls v8.1
    - 'nist': NIST CSF 2.0
    - 'hipaa': HIPAA Administrative Simplification
    - 'ffiec': FFIEC IT Handbook
    - 'pci_dss': PCI DSS v4.0.1
    
    Args:
        graph (Neo4jConnection): Database connection instance
        framework_name (str): Name of framework to clear
        
    Returns:
        bool: True if operation successful
        
    Raises:
        Exception: If framework-specific cleanup fails
    """
    try:
        framework_queries = {
            'attack': """
                MATCH (n) WHERE n.source = 'mitre_attack' OR 
                              labels(n) IN [['Technique'], ['Tactic'], ['ThreatGroup'], ['Malware'], ['Tool']]
                DETACH DELETE n
            """,
            'cis': """
                MATCH (n) WHERE n.source = 'cis_controls' OR 
                              labels(n) IN [['Control'], ['ImplementationGroup'], ['Safeguard']]
                DETACH DELETE n
            """,
            'nist': """
                MATCH (n) WHERE n.source = 'nist_csf' OR 
                              labels(n) IN [['Function'], ['Category'], ['Subcategory']]
                DETACH DELETE n
            """,
            'hipaa': """
                MATCH (n) WHERE n.source = 'hipaa' OR 
                              labels(n) IN [['Regulation'], ['Section'], ['EntityType']]
                DETACH DELETE n
            """,
            'ffiec': """
                MATCH (n) WHERE n.source = 'ffiec' OR 
                              labels(n) IN [['Category'], ['Topic'], ['GuidanceSection']]
                DETACH DELETE n
            """,
            'pci_dss': """
                MATCH (n) WHERE n.source = 'pci_dss' OR 
                              labels(n) IN [['Requirement'], ['TestingProcedure'], ['Guidance']]
                DETACH DELETE n
            """
        }
        
        if framework_name.lower() in framework_queries:
            graph.query(framework_queries[framework_name.lower()])
            return True
        else:
            raise ValueError(f"Unknown framework: {framework_name}")
            
    except Exception as e:
        raise Exception(f"Could not clear {framework_name} framework data: {e}")
