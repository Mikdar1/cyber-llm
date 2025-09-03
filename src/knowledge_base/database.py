"""Neo4j connection wrapper and helpers for the knowledge base."""

from neo4j import GraphDatabase

from src.config.settings import NEO4J_PASSWORD, NEO4J_URI, NEO4J_USERNAME


class Neo4jConnection:
    """Lightweight Neo4j driver wrapper with retrying query()."""

    def __init__(self, uri, username, password):
        """Create a driver using the given credentials."""
        self.driver = GraphDatabase.driver(uri, auth=(username, password))

    def close(self):
        """Close the database driver."""
        if self.driver:
            self.driver.close()

    def query(self, query, params=None, max_retries=3):
        """Execute a Cypher query with basic retry logic; return list of dicts."""
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
                    wait_time = 2**attempt
                    time.sleep(wait_time)
                    continue
                else:
                    # Re-raise the last exception if all retries failed
                    raise last_exception


def create_graph_connection():
    """Return a validated Neo4jConnection using configured settings."""
    try:
        connection = Neo4jConnection(NEO4J_URI, NEO4J_USERNAME, NEO4J_PASSWORD)

        # Validate connection with simple test query
        connection.query("RETURN 1 as test")
        return connection
    except Exception as e:
        raise ConnectionError(f"Failed to connect to Neo4j database: {e}")


def clear_knowledge_base(graph):
    """Delete all nodes and relationships from the knowledge base."""
    try:
        graph.query("MATCH (n) DETACH DELETE n")
        return True
    except Exception as e:
        raise Exception(f"Could not clear existing data: {e}")


def clear_framework_data(graph, framework_name):
    """Delete nodes/relationships for a given framework name."""
    try:
        if framework_name.lower() == "attack":
            # Specific cleanup for ATT&CK framework
            query = """
                MATCH (n)
                WHERE n.source = 'mitre_attack' OR labels(n) IN [
                    ['Technique'], ['SubTechnique'], ['Tactic'], ['Group'], ['Software'],
                    ['Mitigation'], ['DataSource'], ['DataComponent'], ['Campaign'], ['ATT&CK']
                ]
                DETACH DELETE n
            """
            graph.query(query)
            return True
        else:
            # Generic cleanup for compliance frameworks based on source
            query = f"""
                MATCH (n) WHERE n.source = '{framework_name.lower()}' OR 
                              n.framework = '{framework_name.lower()}'
                DETACH DELETE n
            """
            graph.query(query)
            return True
        # No additional else path; return handled above

    except Exception as e:
        raise Exception(f"Could not clear {framework_name} framework data: {e}")
