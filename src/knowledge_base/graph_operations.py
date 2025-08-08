"""
MITRE ATT&CK Knowledge Graph Operations Module

This module provides comprehensive graph database operations for querying and
analyzing the MITRE ATT&CK knowledge base stored in Neo4j. It includes functions
for context retrieval, data exploration, statistical analysis, and complex
relationship queries across all ATT&CK object types.

Functions:
    get_context_from_knowledge_base: Main context retrieval for LLM queries
    get_selective_context_from_knowledge_base: Optimized context retrieval with selective querying
    search_techniques: Search ATT&CK techniques by various criteria
    search_malware: Search malware families and variants
    search_threat_groups: Search APT groups and threat actors
    search_tools: Search tools and software used by threat actors
    search_mitigations: Search security countermeasures
    search_data_sources: Search detection data sources
    search_campaigns: Search threat campaigns
    get_knowledge_base_stats: Retrieve database statistics
    get_technique_relationships: Get technique relationship mappings
"""


def get_selective_context_from_knowledge_base(graph, keywords, relevant_types):
    """
    Retrieve targeted cybersecurity context from the ATT&CK knowledge base.
    
    Performs selective search across specified ATT&CK object types using
    optimized keywords to reduce query overhead and improve response relevance.
    
    Args:
        graph: Neo4j database connection instance
        keywords (list): List of search keywords/terms
        relevant_types (list): List of ATT&CK object types to search
        
    Returns:
        str: Structured context data organized by object type
    """
    try:
        context = []
        search_query = " OR ".join([f"'{keyword}'" for keyword in keywords])
        
        # Create a flexible search pattern for all keywords
        keyword_conditions = []
        for keyword in keywords:
            keyword_conditions.extend([
                f"toLower({{field}}) CONTAINS toLower('{keyword}')",
                f"'{keyword.upper()}' IN {{field}}"  # For technique IDs like T1055
            ])
        
        # Search ATT&CK techniques
        if 'techniques' in relevant_types:
            technique_query = """
            MATCH (t:Technique)
            WHERE """ + " OR ".join([
                cond.format(field="t.name") for cond in keyword_conditions
            ] + [
                cond.format(field="t.description") for cond in keyword_conditions
            ] + [
                cond.format(field="t.technique_id") for cond in keyword_conditions
            ]) + """
            RETURN t.technique_id as technique_id, 
                   t.name as name, 
                   t.description as description, 
                   t.tactics as tactics,
                   t.citations as citations,
                   t.platforms as platforms
            LIMIT 5
            """
            
            technique_results = graph.query(technique_query)
            
            if technique_results:
                context.append("=== ATT&CK TECHNIQUES ===")
                for result in technique_results:
                    context.append(f"\nTechnique: {result['technique_id']} - {result['name']}")
                    context.append(f"Tactics: {', '.join(result.get('tactics', []))}")
                    context.append(f"Platforms: {', '.join(result.get('platforms', []))}")
                    context.append(f"Description: {result['description'][:300]}...")
                    
                    # Add citations if available
                    citations = result.get('citations', [])
                    if citations and len(citations) > 0:
                        context.append(f"Citations: {len(citations)} references available")
        
        # Search malware families
        if 'malware' in relevant_types:
            malware_query = """
            MATCH (m:Malware)
            WHERE """ + " OR ".join([
                cond.format(field="m.name") for cond in keyword_conditions
            ] + [
                cond.format(field="m.description") for cond in keyword_conditions
            ]) + """
            RETURN m.name as name, 
                   m.description as description, 
                   m.labels as labels,
                   m.citations as citations
            LIMIT 5
            """
            
            malware_results = graph.query(malware_query)
            
            if malware_results:
                context.append("\n=== MALWARE ===")
                for result in malware_results:
                    context.append(f"\nMalware: {result['name']}")
                    context.append(f"Labels: {', '.join(result.get('labels', []))}")
                    context.append(f"Description: {result['description'][:300]}...")
                    
                    # Add citations if available
                    citations = result.get('citations', [])
                    if citations and len(citations) > 0:
                        context.append(f"Citations: {len(citations)} references available")
        
        # Search threat groups
        if 'threat_groups' in relevant_types:
            group_query = """
            MATCH (g:ThreatGroup)
            WHERE """ + " OR ".join([
                cond.format(field="g.name") for cond in keyword_conditions
            ] + [
                cond.format(field="g.description") for cond in keyword_conditions
            ] + [
                f"ANY(alias IN g.aliases WHERE toLower(alias) CONTAINS toLower('{keyword}'))" 
                for keyword in keywords
            ]) + """
            RETURN g.name as name, 
                   g.description as description, 
                   g.aliases as aliases,
                   g.citations as citations
            LIMIT 5
            """
            
            group_results = graph.query(group_query)
            
            if group_results:
                context.append("\n=== THREAT GROUPS ===")
                for result in group_results:
                    context.append(f"\nThreat Group: {result['name']}")
                    if result.get('aliases'):
                        context.append(f"Aliases: {', '.join(result['aliases'])}")
                    context.append(f"Description: {result['description'][:300]}...")
                    
                    # Add citations if available
                    citations = result.get('citations', [])
                    if citations and len(citations) > 0:
                        context.append(f"Citations: {len(citations)} references available")
        
        # Search tools
        if 'tools' in relevant_types:
            tool_query = """
            MATCH (t:Tool)
            WHERE """ + " OR ".join([
                cond.format(field="t.name") for cond in keyword_conditions
            ] + [
                cond.format(field="t.description") for cond in keyword_conditions
            ]) + """
            RETURN t.name as name, 
                   t.description as description, 
                   t.labels as labels,
                   t.citations as citations
            LIMIT 5
            """
            
            tool_results = graph.query(tool_query)
            
            if tool_results:
                context.append("\n=== TOOLS ===")
                for result in tool_results:
                    context.append(f"\nTool: {result['name']}")
                    context.append(f"Labels: {', '.join(result.get('labels', []))}")
                    context.append(f"Description: {result['description'][:300]}...")
                    
                    # Add citations if available
                    citations = result.get('citations', [])
                    if citations and len(citations) > 0:
                        context.append(f"Citations: {len(citations)} references available")
        
        # Search mitigations
        if 'mitigations' in relevant_types:
            mitigation_query = """
            MATCH (m:Mitigation)
            WHERE """ + " OR ".join([
                cond.format(field="m.name") for cond in keyword_conditions
            ] + [
                cond.format(field="m.description") for cond in keyword_conditions
            ] + [
                cond.format(field="m.mitigation_id") for cond in keyword_conditions
            ]) + """
            RETURN m.mitigation_id as mitigation_id, m.name as name, m.description as description, m.citations as citations
            LIMIT 5
            """
            
            mitigation_results = graph.query(mitigation_query)
            
            if mitigation_results:
                context.append("\n=== MITIGATIONS ===")
                for result in mitigation_results:
                    context.append(f"\nMitigation: {result['mitigation_id']} - {result['name']}")
                    context.append(f"Description: {result['description'][:300]}...")
                    
                    # Add citations if available
                    citations = result.get('citations', [])
                    if citations and len(citations) > 0:
                        context.append(f"Citations: {len(citations)} references available")
        
        # Search data sources
        if 'data_sources' in relevant_types:
            data_source_query = """
            MATCH (ds:DataSource)
            WHERE """ + " OR ".join([
                cond.format(field="ds.name") for cond in keyword_conditions
            ] + [
                cond.format(field="ds.description") for cond in keyword_conditions
            ]) + """
            RETURN ds.name as name, ds.description as description, ds.platforms as platforms
            LIMIT 5
            """
            
            data_source_results = graph.query(data_source_query)
            
            if data_source_results:
                context.append("\n=== DATA SOURCES ===")
                for result in data_source_results:
                    context.append(f"\nData Source: {result['name']}")
                    context.append(f"Platforms: {', '.join(result.get('platforms', []))}")
                    context.append(f"Description: {result['description'][:300]}...")
        
        # Search campaigns
        if 'campaigns' in relevant_types:
            campaign_query = """
            MATCH (c:Campaign)
            WHERE """ + " OR ".join([
                cond.format(field="c.name") for cond in keyword_conditions
            ] + [
                cond.format(field="c.description") for cond in keyword_conditions
            ] + [
                f"ANY(alias IN c.aliases WHERE toLower(alias) CONTAINS toLower('{keyword}'))" 
                for keyword in keywords
            ]) + """
            RETURN c.name as name, c.description as description, c.aliases as aliases, c.first_seen as first_seen
            LIMIT 5
            """
            
            campaign_results = graph.query(campaign_query)
            
            if campaign_results:
                context.append("\n=== CAMPAIGNS ===")
                for result in campaign_results:
                    context.append(f"\nCampaign: {result['name']}")
                    if result.get('aliases'):
                        context.append(f"Aliases: {', '.join(result['aliases'])}")
                    context.append(f"Description: {result['description'][:300]}...")
        
        # If no results found with selective search, fall back to broader search
        if not context:
            context.append("=== BROADER SEARCH RESULTS ===")
            broad_query = """
            MATCH (n)
            WHERE """ + " OR ".join([
                cond.format(field="n.name") for cond in keyword_conditions[:2]  # Limit to avoid complexity
            ] + [
                cond.format(field="n.description") for cond in keyword_conditions[:2]
            ]) + """
            RETURN labels(n) as type, n.name as name, n.description as description
            LIMIT 10
            """
            
            broad_results = graph.query(broad_query)
            
            for result in broad_results:
                entity_type = result.get('type', ['Unknown'])[0] if result.get('type') else 'Unknown'
                context.append(f"\n{entity_type}: {result.get('name', 'N/A')}")
                if result.get('description'):
                    context.append(f"Description: {result['description'][:200]}...")
        
        return "\n".join(context) if context else "No relevant information found in the knowledge base."
    
    except Exception as e:
        raise Exception(f"Error in selective knowledge base query: {e}")


def get_context_from_knowledge_base(graph, query):
    """
    Retrieve relevant cybersecurity context from the ATT&CK knowledge base.
    
    Performs comprehensive search across all ATT&CK object types to find
    relevant context for the given query. Uses fuzzy matching on names,
    descriptions, and identifiers.
    
    Args:
        graph: Neo4j database connection instance
        query (str): Search query string
        
    Returns:
        dict: Structured context data organized by object type
    """
    try:
        # Search ATT&CK techniques by name, description, or ID
        technique_query = """
        MATCH (t:Technique)
        WHERE t.name CONTAINS $query 
           OR t.description CONTAINS $query 
           OR t.technique_id CONTAINS $query
        RETURN t.technique_id as technique_id, 
               t.name as name, 
               t.description as description, 
               t.tactics as tactics,
               t.citations as citations
        LIMIT 10
        """
        technique_results = graph.query(technique_query, params={"query": query})
        
        # Search malware families and variants
        malware_query = """
        MATCH (m:Malware)
        WHERE m.name CONTAINS $query OR m.description CONTAINS $query
        RETURN m.name as name, 
               m.description as description, 
               m.labels as labels,
               m.citations as citations
        LIMIT 10
        """
        malware_results = graph.query(malware_query, params={"query": query})
        
        # Search threat groups and APTs
        group_query = """
        MATCH (g:ThreatGroup)
        WHERE g.name CONTAINS $query 
           OR g.description CONTAINS $query 
           OR ANY(alias IN g.aliases WHERE alias CONTAINS $query)
        RETURN g.name as name, 
               g.description as description, 
               g.aliases as aliases,
               g.citations as citations
        LIMIT 10
        """
        group_results = graph.query(group_query, params={"query": query})
        
        # Search tools and software
        tool_query = """
        MATCH (t:Tool)
        WHERE t.name CONTAINS $query OR t.description CONTAINS $query
        RETURN t.name as name, 
               t.description as description, 
               t.labels as labels
        LIMIT 10
        """
        tool_results = graph.query(tool_query, params={"query": query})
        
        # Search for mitigations
        mitigation_query = """
        MATCH (m:Mitigation)
        WHERE m.name CONTAINS $query OR m.description CONTAINS $query OR m.mitigation_id CONTAINS $query
        RETURN m.mitigation_id as mitigation_id, m.name as name, m.description as description
        LIMIT 10
        """
        
        mitigation_results = graph.query(mitigation_query, params={"query": query})
        
        # Search for data sources
        data_source_query = """
        MATCH (ds:DataSource)
        WHERE ds.name CONTAINS $query OR ds.description CONTAINS $query
        RETURN ds.name as name, ds.description as description, ds.platforms as platforms
        LIMIT 10
        """
        
        data_source_results = graph.query(data_source_query, params={"query": query})
        
        # Search for campaigns
        campaign_query = """
        MATCH (c:Campaign)
        WHERE c.name CONTAINS $query OR c.description CONTAINS $query OR ANY(alias IN c.aliases WHERE alias CONTAINS $query)
        RETURN c.name as name, c.description as description, c.aliases as aliases, c.first_seen as first_seen
        LIMIT 10
        """
        
        campaign_results = graph.query(campaign_query, params={"query": query})
        
        # If no specific results, try a broader search
        if not technique_results and not malware_results and not group_results and not tool_results and not mitigation_results and not data_source_results and not campaign_results:
            broad_query = """
            MATCH (n)
            WHERE n.name CONTAINS $query OR n.description CONTAINS $query
            RETURN labels(n) as type, n.name as name, n.description as description
            LIMIT 20
            """
            broad_results = graph.query(broad_query, params={"query": query})
        else:
            broad_results = []
        
        context = []
        
        # Process technique results
        if technique_results:
            context.append("=== ATT&CK TECHNIQUES ===")
            for result in technique_results:
                context.append(f"\nTechnique: {result['technique_id']} - {result['name']}")
                context.append(f"Tactics: {', '.join(result.get('tactics', []))}")
                context.append(f"Description: {result['description'][:300]}...")
        
        # Process malware results
        if malware_results:
            context.append("\n=== MALWARE ===")
            for result in malware_results:
                context.append(f"\nMalware: {result['name']}")
                context.append(f"Labels: {', '.join(result.get('labels', []))}")
                context.append(f"Description: {result['description'][:300]}...")
        
        # Process threat group results
        if group_results:
            context.append("\n=== THREAT GROUPS ===")
            for result in group_results:
                context.append(f"\nThreat Group: {result['name']}")
                if result.get('aliases'):
                    context.append(f"Aliases: {', '.join(result['aliases'])}")
                context.append(f"Description: {result['description'][:300]}...")
        
        # Process tool results
        if tool_results:
            context.append("\n=== TOOLS ===")
            for result in tool_results:
                context.append(f"\nTool: {result['name']}")
                context.append(f"Labels: {', '.join(result.get('labels', []))}")
                context.append(f"Description: {result['description'][:300]}...")
        
        # Process mitigation results
        if mitigation_results:
            context.append("\n=== MITIGATIONS ===")
            for result in mitigation_results:
                context.append(f"\nMitigation: {result['name']}")
                context.append(f"Description: {result['description'][:300]}...")
        
        # Process data source results
        if data_source_results:
            context.append("\n=== DATA SOURCES ===")
            for result in data_source_results:
                context.append(f"\nData Source: {result['name']}")
                context.append(f"Platforms: {', '.join(result.get('platforms', []))}")
                context.append(f"Description: {result['description'][:300]}...")
        
        # Process campaign results
        if campaign_results:
            context.append("\n=== CAMPAIGNS ===")
            for result in campaign_results:
                context.append(f"\nCampaign: {result['name']}")
                context.append(f"Aliases: {', '.join(result.get('aliases', []))}")
                context.append(f"Description: {result['description'][:300]}...")
        
        # Process broad results if needed
        if broad_results:
            context.append("\n=== ADDITIONAL RESULTS ===")
            for result in broad_results:
                entity_type = result.get('type', ['Unknown'])[0] if result.get('type') else 'Unknown'
                context.append(f"\n{entity_type}: {result.get('name', 'N/A')}")
                if result.get('description'):
                    context.append(f"Description: {result['description'][:300]}...")
        
        return "\n".join(context)
    
    except Exception as e:
        raise Exception(f"Error querying knowledge base: {e}")

def get_attack_statistics(graph):
    """Get statistics about the ATT&CK knowledge base."""
    try:
        stats = {}
        
        # Count techniques
        technique_count = graph.query("MATCH (t:Technique) RETURN count(t) as count")[0]['count']
        stats['techniques'] = technique_count
        
        # Count malware
        malware_count = graph.query("MATCH (m:Malware) RETURN count(m) as count")[0]['count']
        stats['malware'] = malware_count
        
        # Count threat groups
        group_count = graph.query("MATCH (g:ThreatGroup) RETURN count(g) as count")[0]['count']
        stats['threat_groups'] = group_count
        
        # Count tools
        tool_count = graph.query("MATCH (t:Tool) RETURN count(t) as count")[0]['count']
        stats['tools'] = tool_count
        
        # Count tactics
        tactic_count = graph.query("MATCH (t:Tactic) RETURN count(t) as count")[0]['count']
        stats['tactics'] = tactic_count
        
        # Count relationships
        relationship_count = graph.query("MATCH ()-[r]->() RETURN count(r) as count")[0]['count']
        stats['relationships'] = relationship_count
        
        # Count mitigations
        mitigation_count = graph.query("MATCH (m:Mitigation) RETURN count(m) as count")[0]['count']
        stats['mitigations'] = mitigation_count
        
        # Count data sources
        data_source_count = graph.query("MATCH (ds:DataSource) RETURN count(ds) as count")[0]['count']
        stats['data_sources'] = data_source_count
        
        # Count campaigns
        campaign_count = graph.query("MATCH (c:Campaign) RETURN count(c) as count")[0]['count']
        stats['campaigns'] = campaign_count
        
        return stats
        
    except Exception as e:
        raise Exception(f"Error getting statistics: {e}")


def get_multi_framework_statistics(graph):
    """Get comprehensive statistics about all cybersecurity frameworks in the knowledge base."""
    try:
        stats = {}
        
        # MITRE ATT&CK Framework
        attck_stats = {}
        attck_stats['techniques'] = graph.query("MATCH (t:Technique) RETURN count(t) as count")[0]['count']
        attck_stats['malware'] = graph.query("MATCH (m:Malware) RETURN count(m) as count")[0]['count']
        attck_stats['threat_groups'] = graph.query("MATCH (g:ThreatGroup) RETURN count(g) as count")[0]['count']
        attck_stats['tools'] = graph.query("MATCH (t:Tool) RETURN count(t) as count")[0]['count']
        attck_stats['tactics'] = graph.query("MATCH (t:Tactic) RETURN count(t) as count")[0]['count']
        attck_stats['mitigations'] = graph.query("MATCH (m:Mitigation) RETURN count(m) as count")[0]['count']
        attck_stats['data_sources'] = graph.query("MATCH (ds:DataSource) RETURN count(ds) as count")[0]['count']
        attck_stats['campaigns'] = graph.query("MATCH (c:Campaign) RETURN count(c) as count")[0]['count']
        stats['MITRE_ATTCK'] = attck_stats
        
        # NIST Cybersecurity Framework
        nist_stats = {}
        nist_stats['functions'] = graph.query("MATCH (f:NIST_Function) RETURN count(f) as count")[0]['count']
        nist_stats['categories'] = graph.query("MATCH (c:NIST_Category) RETURN count(c) as count")[0]['count']
        nist_stats['subcategories'] = graph.query("MATCH (s:NIST_Subcategory) RETURN count(s) as count")[0]['count']
        stats['NIST_CSF'] = nist_stats
        
        # CIS Controls
        cis_stats = {}
        cis_stats['controls'] = graph.query("MATCH (c:CIS_Control) RETURN count(c) as count")[0]['count']
        cis_stats['safeguards'] = graph.query("MATCH (s:CIS_Safeguard) RETURN count(s) as count")[0]['count']
        cis_stats['asset_types'] = graph.query("MATCH (a:CIS_AssetType) RETURN count(a) as count")[0]['count']
        cis_stats['security_functions'] = graph.query("MATCH (sf:CIS_SecurityFunction) RETURN count(sf) as count")[0]['count']
        stats['CIS_Controls'] = cis_stats
        
        # HIPAA Security
        hipaa_stats = {}
        hipaa_stats['regulations'] = graph.query("MATCH (r:HIPAA_Regulation) RETURN count(r) as count")[0]['count']
        hipaa_stats['sections'] = graph.query("MATCH (s:HIPAA_Section) RETURN count(s) as count")[0]['count']
        hipaa_stats['requirements'] = graph.query("MATCH (req:HIPAA_Requirement) RETURN count(req) as count")[0]['count']
        stats['HIPAA'] = hipaa_stats
        
        # FFIEC IT Handbook
        ffiec_stats = {}
        ffiec_stats['domains'] = graph.query("MATCH (d:FFIEC_Domain) RETURN count(d) as count")[0]['count']
        ffiec_stats['processes'] = graph.query("MATCH (p:FFIEC_Process) RETURN count(p) as count")[0]['count']
        ffiec_stats['activities'] = graph.query("MATCH (a:FFIEC_Activity) RETURN count(a) as count")[0]['count']
        stats['FFIEC'] = ffiec_stats
        
        # PCI DSS
        pci_stats = {}
        pci_stats['requirements'] = graph.query("MATCH (r:PCI_DSS_Requirement) RETURN count(r) as count")[0]['count']
        pci_stats['sub_requirements'] = graph.query("MATCH (sr:PCI_DSS_SubRequirement) RETURN count(sr) as count")[0]['count']
        pci_stats['testing_procedures'] = graph.query("MATCH (tp:PCI_DSS_TestingProcedure) RETURN count(tp) as count")[0]['count']
        stats['PCI_DSS'] = pci_stats
        
        # Overall statistics
        overall_stats = {}
        overall_stats['total_nodes'] = graph.query("MATCH (n) RETURN count(n) as count")[0]['count']
        overall_stats['total_relationships'] = graph.query("MATCH ()-[r]->() RETURN count(r) as count")[0]['count']
        overall_stats['citations'] = graph.query("MATCH (c:Citation) RETURN count(c) as count")[0]['count']
        stats['Overall'] = overall_stats
        
        return stats
        
    except Exception as e:
        raise Exception(f"Error getting multi-framework statistics: {e}")


def search_multi_framework_knowledge_base(graph, query):
    """
    Comprehensive search across all cybersecurity frameworks in the knowledge base.
    
    Searches through MITRE ATT&CK, NIST CSF, CIS Controls, HIPAA, FFIEC, and PCI DSS frameworks
    to find relevant cybersecurity information based on the query.
    
    Args:
        graph: Neo4j database connection instance
        query (str): Search query string
        
    Returns:
        str: Formatted search results from all frameworks
    """
    try:
        query = query.lower()
        context = []
        
        # MITRE ATT&CK Framework Search
        # Search techniques
        attck_technique_query = """
        MATCH (t:Technique)
        WHERE toLower(t.name) CONTAINS $query 
           OR toLower(t.description) CONTAINS $query 
           OR toLower(t.technique_id) CONTAINS $query
        RETURN t.technique_id as id, t.name as name, t.description as description, t.tactics as tactics
        LIMIT 5
        """
        attck_techniques = graph.query(attck_technique_query, params={"query": query})
        
        # Search threat groups
        attck_groups_query = """
        MATCH (g:ThreatGroup)
        WHERE toLower(g.name) CONTAINS $query 
           OR toLower(g.description) CONTAINS $query 
           OR ANY(alias IN g.aliases WHERE toLower(alias) CONTAINS $query)
        RETURN g.name as name, g.description as description, g.aliases as aliases
        LIMIT 3
        """
        attck_groups = graph.query(attck_groups_query, params={"query": query})
        
        # Search malware
        attck_malware_query = """
        MATCH (m:Malware)
        WHERE toLower(m.name) CONTAINS $query OR toLower(m.description) CONTAINS $query
        RETURN m.name as name, m.description as description, m.labels as labels
        LIMIT 3
        """
        attck_malware = graph.query(attck_malware_query, params={"query": query})
        
        # Search mitigations
        attck_mitigations_query = """
        MATCH (m:Mitigation)
        WHERE toLower(m.name) CONTAINS $query 
           OR toLower(m.description) CONTAINS $query 
           OR toLower(m.mitigation_id) CONTAINS $query
        RETURN m.mitigation_id as id, m.name as name, m.description as description
        LIMIT 3
        """
        attck_mitigations = graph.query(attck_mitigations_query, params={"query": query})
        
        # NIST CSF Search
        nist_functions_query = """
        MATCH (f:NIST_Function)
        WHERE toLower(f.name) CONTAINS $query OR toLower(f.description) CONTAINS $query
        RETURN f.function_id as id, f.name as name, f.description as description
        LIMIT 3
        """
        nist_functions = graph.query(nist_functions_query, params={"query": query})
        
        nist_categories_query = """
        MATCH (c:NIST_Category)
        WHERE toLower(c.name) CONTAINS $query OR toLower(c.description) CONTAINS $query
        RETURN c.category_id as id, c.name as name, c.description as description
        LIMIT 3
        """
        nist_categories = graph.query(nist_categories_query, params={"query": query})
        
        nist_subcategories_query = """
        MATCH (s:NIST_Subcategory)
        WHERE toLower(s.name) CONTAINS $query OR toLower(s.description) CONTAINS $query
        RETURN s.subcategory_id as id, s.name as name, s.description as description
        LIMIT 3
        """
        nist_subcategories = graph.query(nist_subcategories_query, params={"query": query})
        
        # CIS Controls Search
        cis_controls_query = """
        MATCH (c:CIS_Control)
        WHERE toLower(c.title) CONTAINS $query OR toLower(c.description) CONTAINS $query
        RETURN c.control_id as id, c.title as name, c.description as description
        LIMIT 3
        """
        cis_controls = graph.query(cis_controls_query, params={"query": query})
        
        cis_safeguards_query = """
        MATCH (s:CIS_Safeguard)
        WHERE toLower(s.title) CONTAINS $query OR toLower(s.description) CONTAINS $query
        RETURN s.safeguard_id as id, s.title as name, s.description as description
        LIMIT 3
        """
        cis_safeguards = graph.query(cis_safeguards_query, params={"query": query})
        
        # HIPAA Search
        hipaa_requirements_query = """
        MATCH (r:HIPAA_Requirement)
        WHERE toLower(r.title) CONTAINS $query OR toLower(r.description) CONTAINS $query
        RETURN r.requirement_id as id, r.title as name, r.description as description
        LIMIT 3
        """
        hipaa_requirements = graph.query(hipaa_requirements_query, params={"query": query})
        
        # FFIEC Search
        ffiec_domains_query = """
        MATCH (d:FFIEC_Domain)
        WHERE toLower(d.name) CONTAINS $query OR toLower(d.description) CONTAINS $query
        RETURN d.domain_id as id, d.name as name, d.description as description
        LIMIT 3
        """
        ffiec_domains = graph.query(ffiec_domains_query, params={"query": query})
        
        ffiec_activities_query = """
        MATCH (a:FFIEC_Activity)
        WHERE toLower(a.name) CONTAINS $query OR toLower(a.description) CONTAINS $query
        RETURN a.activity_id as id, a.name as name, a.description as description
        LIMIT 3
        """
        ffiec_activities = graph.query(ffiec_activities_query, params={"query": query})
        
        # PCI DSS Search
        pci_requirements_query = """
        MATCH (r:PCI_DSS_Requirement)
        WHERE toLower(r.title) CONTAINS $query OR toLower(r.description) CONTAINS $query
        RETURN r.requirement_id as id, r.title as name, r.description as description
        LIMIT 3
        """
        pci_requirements = graph.query(pci_requirements_query, params={"query": query})
        
        # Format results
        if attck_techniques or attck_groups or attck_malware or attck_mitigations:
            context.append("=== MITRE ATT&CK FRAMEWORK ===")
            
            if attck_techniques:
                context.append("\n--- ATT&CK Techniques ---")
                for result in attck_techniques:
                    context.append(f"• {result['id']} - {result['name']}")
                    context.append(f"  Tactics: {', '.join(result.get('tactics', []))}")
                    context.append(f"  {result['description'][:200]}...")
            
            if attck_groups:
                context.append("\n--- Threat Groups ---")
                for result in attck_groups:
                    context.append(f"• {result['name']}")
                    if result.get('aliases'):
                        context.append(f"  Aliases: {', '.join(result['aliases'])}")
                    context.append(f"  {result['description'][:200]}...")
            
            if attck_malware:
                context.append("\n--- Malware ---")
                for result in attck_malware:
                    context.append(f"• {result['name']}")
                    context.append(f"  {result['description'][:200]}...")
            
            if attck_mitigations:
                context.append("\n--- Mitigations ---")
                for result in attck_mitigations:
                    context.append(f"• {result['id']} - {result['name']}")
                    context.append(f"  {result['description'][:200]}...")
        
        if nist_functions or nist_categories or nist_subcategories:
            context.append("\n=== NIST CYBERSECURITY FRAMEWORK ===")
            
            if nist_functions:
                context.append("\n--- Functions ---")
                for result in nist_functions:
                    context.append(f"• {result['id']} - {result['name']}")
                    context.append(f"  {result['description'][:200]}...")
            
            if nist_categories:
                context.append("\n--- Categories ---")
                for result in nist_categories:
                    context.append(f"• {result['id']} - {result['name']}")
                    context.append(f"  {result['description'][:200]}...")
            
            if nist_subcategories:
                context.append("\n--- Subcategories ---")
                for result in nist_subcategories:
                    context.append(f"• {result['id']} - {result['name']}")
                    context.append(f"  {result['description'][:200]}...")
        
        if cis_controls or cis_safeguards:
            context.append("\n=== CIS CONTROLS ===")
            
            if cis_controls:
                context.append("\n--- Controls ---")
                for result in cis_controls:
                    context.append(f"• {result['id']} - {result['name']}")
                    context.append(f"  {result['description'][:200]}...")
            
            if cis_safeguards:
                context.append("\n--- Safeguards ---")
                for result in cis_safeguards:
                    context.append(f"• {result['id']} - {result['name']}")
                    context.append(f"  {result['description'][:200]}...")
        
        if hipaa_requirements:
            context.append("\n=== HIPAA SECURITY ===")
            context.append("\n--- Requirements ---")
            for result in hipaa_requirements:
                context.append(f"• {result['id']} - {result['name']}")
                context.append(f"  {result['description'][:200]}...")
        
        if ffiec_domains or ffiec_activities:
            context.append("\n=== FFIEC IT HANDBOOK ===")
            
            if ffiec_domains:
                context.append("\n--- Domains ---")
                for result in ffiec_domains:
                    context.append(f"• {result['id']} - {result['name']}")
                    context.append(f"  {result['description'][:200]}...")
            
            if ffiec_activities:
                context.append("\n--- Activities ---")
                for result in ffiec_activities:
                    context.append(f"• {result['id']} - {result['name']}")
                    context.append(f"  {result['description'][:200]}...")
        
        if pci_requirements:
            context.append("\n=== PCI DSS ===")
            context.append("\n--- Requirements ---")
            for result in pci_requirements:
                context.append(f"• {result['id']} - {result['name']}")
                context.append(f"  {result['description'][:200]}...")
        
        if not context:
            # If no specific results, try a broader search
            broad_query = """
            MATCH (n)
            WHERE toLower(n.name) CONTAINS $query OR toLower(n.description) CONTAINS $query
            RETURN labels(n) as type, n.name as name, 
                   COALESCE(n.description, n.title, '') as description
            LIMIT 10
            """
            broad_results = graph.query(broad_query, params={"query": query})
            
            if broad_results:
                context.append("=== BROADER SEARCH RESULTS ===")
                for result in broad_results:
                    entity_type = result.get('type', ['Unknown'])[0] if result.get('type') else 'Unknown'
                    context.append(f"\n{entity_type}: {result.get('name', 'N/A')}")
                    if result.get('description'):
                        context.append(f"  {result['description'][:200]}...")
        
        return "\n".join(context) if context else "No relevant information found across any cybersecurity frameworks."
    
    except Exception as e:
        raise Exception(f"Error in multi-framework search: {e}")


def get_techniques_by_tactic(graph, tactic_name=None):
    """Get techniques grouped by tactic."""
    try:
        if tactic_name:
            query = """
            MATCH (t:Technique)-[:BELONGS_TO_TACTIC]->(tactic:Tactic {name: $tactic_name})
            RETURN t.technique_id as technique_id, t.name as name, t.description as description
            ORDER BY t.technique_id
            """
            results = graph.query(query, params={"tactic_name": tactic_name})
        else:
            query = """
            MATCH (t:Technique)-[:BELONGS_TO_TACTIC]->(tactic:Tactic)
            RETURN tactic.name as tactic, t.technique_id as technique_id, t.name as name, t.description as description
            ORDER BY tactic.name, t.technique_id
            """
            results = graph.query(query)
        
        return results
        
    except Exception as e:
        raise Exception(f"Error getting techniques by tactic: {e}")

def get_threat_group_techniques(graph, group_name):
    """Get techniques used by a specific threat group."""
    try:
        query = """
        MATCH (g:ThreatGroup)-[r]->(t:Technique)
        WHERE g.name CONTAINS $group_name
        RETURN g.name as group_name, t.technique_id as technique_id, t.name as technique_name, 
               t.description as description, type(r) as relationship_type
        ORDER BY t.technique_id
        """
        
        results = graph.query(query, params={"group_name": group_name})
        return results
        
    except Exception as e:
        raise Exception(f"Error getting threat group techniques: {e}")

def search_by_technique_id(graph, technique_id):
    """Search for a specific technique by ID."""
    try:
        query = """
        MATCH (t:Technique {technique_id: $technique_id})
        OPTIONAL MATCH (t)-[:BELONGS_TO_TACTIC]->(tactic:Tactic)
        OPTIONAL MATCH (g:ThreatGroup)-[r]->(t)
        OPTIONAL MATCH (m:Malware)-[r2]->(t)
        RETURN t.technique_id as technique_id, t.name as name, t.description as description,
               t.platforms as platforms, collect(DISTINCT tactic.name) as tactics,
               collect(DISTINCT g.name) as threat_groups, collect(DISTINCT m.name) as malware
        """
        
        results = graph.query(query, params={"technique_id": technique_id})
        return results[0] if results else None
        
    except Exception as e:
        raise Exception(f"Error searching technique: {e}")

def get_all_tactics(graph):
    """Get all tactics in the knowledge base."""
    try:
        query = """
        MATCH (t:Tactic)
        RETURN t.name as name
        ORDER BY t.name
        """
        
        results = graph.query(query)
        return [result['name'] for result in results if result['name']]
        
    except Exception as e:
        raise Exception(f"Error getting tactics: {e}")

def get_all_threat_groups(graph):
    """Get all threat groups in the knowledge base."""
    try:
        query = """
        MATCH (g:ThreatGroup)
        RETURN g.name as name, g.aliases as aliases
        ORDER BY g.name
        """
        
        results = graph.query(query)
        return results
        
    except Exception as e:
        raise Exception(f"Error getting threat groups: {e}")

def get_all_mitigations(graph):
    """Get all mitigations in the knowledge base."""
    try:
        query = """
        MATCH (m:Mitigation)
        RETURN m.mitigation_id as mitigation_id, m.name as name, m.description as description
        ORDER BY m.mitigation_id
        """
        
        results = graph.query(query)
        return results
        
    except Exception as e:
        raise Exception(f"Error getting mitigations: {e}")

def get_all_data_sources(graph):
    """Get all data sources in the knowledge base."""
    try:
        query = """
        MATCH (ds:DataSource)
        RETURN ds.name as name, ds.description as description, ds.platforms as platforms
        ORDER BY ds.name
        """
        
        results = graph.query(query)
        return results
        
    except Exception as e:
        raise Exception(f"Error getting data sources: {e}")

def get_all_campaigns(graph):
    """Get all campaigns in the knowledge base."""
    try:
        query = """
        MATCH (c:Campaign)
        RETURN c.name as name, c.description as description, c.aliases as aliases, 
               c.first_seen as first_seen, c.last_seen as last_seen
        ORDER BY c.name
        """
        
        results = graph.query(query)
        return results
        
    except Exception as e:
        raise Exception(f"Error getting campaigns: {e}")

def get_technique_mitigations(graph, technique_id):
    """Get mitigations for a specific technique."""
    try:
        query = """
        MATCH (t:Technique {technique_id: $technique_id})-[:MITIGATED_BY]->(m:Mitigation)
        RETURN m.mitigation_id as mitigation_id, m.name as name, m.description as description
        ORDER BY m.mitigation_id
        """
        
        results = graph.query(query, params={"technique_id": technique_id})
        return results
        
    except Exception as e:
        raise Exception(f"Error getting technique mitigations: {e}")

def get_technique_data_sources(graph, technique_id):
    """Get data sources for a specific technique."""
    try:
        query = """
        MATCH (t:Technique {technique_id: $technique_id})-[:DETECTED_BY]->(ds:DataSource)
        RETURN ds.name as name, ds.description as description, ds.platforms as platforms
        ORDER BY ds.name
        """
        
        results = graph.query(query, params={"technique_id": technique_id})
        return results
        
    except Exception as e:
        raise Exception(f"Error getting technique data sources: {e}")

# Framework to node type mapping
FRAMEWORK_NODE_MAPPING = {
    "ATT&CK Only": {
        "techniques": "Technique",
        "malware": "Malware", 
        "threat_groups": "ThreatGroup",
        "tools": "Tool",
        "mitigations": "Mitigation",
        "data_sources": "DataSource",
        "campaigns": "Campaign"
    },
    "CIS Controls": {
        "cis_controls": "CIS_Control",
        "cis_safeguards": "CIS_Safeguard",
        "implementation_groups": "CIS_ImplementationGroup"
    },
    "NIST CSF": {
        "nist_functions": "NIST_Function",
        "nist_categories": "NIST_Category", 
        "nist_subcategories": "NIST_Subcategory"
    },
    "HIPAA": {
        "hipaa_regulations": "HIPAA_Regulation",
        "hipaa_sections": "HIPAA_Section",
        "hipaa_requirements": "HIPAA_Requirement"
    },
    "FFIEC": {
        "ffiec_categories": "FFIEC_Category",
        "ffiec_procedures": "FFIEC_Procedure",
        "ffiec_guidance": "FFIEC_Guidance"
    },
    "PCI DSS": {
        "pci_requirements": "PCI_Requirement",
        "pci_procedures": "PCI_Procedure", 
        "pci_controls": "PCI_Control"
    }
}


def get_framework_aware_context(graph, keywords, relevant_types, framework_scope="All Frameworks"):
    """
    Retrieve framework-specific context from the knowledge base.
    
    Args:
        graph: Neo4j database connection instance
        keywords (list): List of search keywords/terms
        relevant_types (list): List of object types to search
        framework_scope (str): Framework scope for filtering
        
    Returns:
        str: Structured context data organized by framework and object type
    """
    try:
        context = []
        
        # Create keyword search conditions
        keyword_conditions = []
        for keyword in keywords:
            keyword_conditions.extend([
                f"toLower({{field}}) CONTAINS toLower('{keyword}')",
                f"'{keyword.upper()}' IN {{field}}"
            ])
        
        # Determine which frameworks to search
        if framework_scope == "All Frameworks":
            frameworks_to_search = FRAMEWORK_NODE_MAPPING.keys()
        else:
            frameworks_to_search = [framework_scope]
        
        for framework in frameworks_to_search:
            if framework not in FRAMEWORK_NODE_MAPPING:
                continue
                
            framework_mapping = FRAMEWORK_NODE_MAPPING[framework]
            framework_context = []
            
            for obj_type in relevant_types:
                if obj_type in framework_mapping:
                    node_label = framework_mapping[obj_type]
                    
                    # Build dynamic query based on node type
                    if framework == "ATT&CK Only":
                        results = _search_attack_objects(graph, node_label, keyword_conditions, obj_type)
                    elif framework == "CIS Controls":
                        results = _search_cis_objects(graph, node_label, keyword_conditions, obj_type)
                    elif framework == "NIST CSF":
                        results = _search_nist_objects(graph, node_label, keyword_conditions, obj_type)
                    elif framework == "HIPAA":
                        results = _search_hipaa_objects(graph, node_label, keyword_conditions, obj_type)
                    else:
                        results = _search_generic_objects(graph, node_label, keyword_conditions, obj_type)
                    
                    if results:
                        framework_context.extend(results)
            
            if framework_context:
                context.append(f"\n=== {framework.upper()} FRAMEWORK ===")
                context.extend(framework_context)
        
        return "\n".join(context) if context else f"No relevant information found for '{', '.join(keywords)}' in {framework_scope}."
        
    except Exception as e:
        return f"Error retrieving context: {e}"


def _search_attack_objects(graph, node_label, keyword_conditions, obj_type):
    """Search ATT&CK objects with specific formatting."""
    results = []
    
    if obj_type == "techniques":
        query = f"""
        MATCH (n:{node_label})
        WHERE """ + " OR ".join([
            cond.format(field="n.name") for cond in keyword_conditions
        ] + [
            cond.format(field="n.description") for cond in keyword_conditions
        ] + [
            cond.format(field="n.technique_id") for cond in keyword_conditions
        ]) + """
        RETURN n.technique_id as id, n.name as name, n.description as description, 
               n.tactics as tactics, n.platforms as platforms
        LIMIT 3
        """
        
        technique_results = graph.query(query)
        for result in technique_results:
            results.append(f"\n🎯 Technique: {result['id']} - {result['name']}")
            results.append(f"   Tactics: {', '.join(result.get('tactics', []))}")
            results.append(f"   Description: {result['description'][:200]}...")
    
    elif obj_type == "malware":
        query = f"""
        MATCH (n:{node_label})
        WHERE """ + " OR ".join([
            cond.format(field="n.name") for cond in keyword_conditions
        ] + [
            cond.format(field="n.description") for cond in keyword_conditions
        ]) + """
        RETURN n.name as name, n.description as description, n.labels as labels
        LIMIT 3
        """
        
        malware_results = graph.query(query)
        for result in malware_results:
            results.append(f"\n🦠 Malware: {result['name']}")
            results.append(f"   Type: {', '.join(result.get('labels', []))}")
            results.append(f"   Description: {result['description'][:200]}...")
    
    # Add similar patterns for other ATT&CK object types...
    
    return results


def _search_cis_objects(graph, node_label, keyword_conditions, obj_type):
    """Search CIS Controls objects with specific formatting."""
    results = []
    
    if obj_type == "cis_controls":
        query = f"""
        MATCH (n:{node_label})
        WHERE """ + " OR ".join([
            cond.format(field="n.title") for cond in keyword_conditions
        ] + [
            cond.format(field="n.description") for cond in keyword_conditions
        ] + [
            cond.format(field="n.control_id") for cond in keyword_conditions
        ]) + """
        RETURN n.control_id as id, n.title as title, n.description as description,
               n.asset_type as asset_type, n.security_function as security_function
        LIMIT 3
        """
        
        control_results = graph.query(query)
        for result in control_results:
            results.append(f"\n🛡️ CIS Control {result['id']}: {result['title']}")
            results.append(f"   Asset Type: {result.get('asset_type', 'N/A')}")
            results.append(f"   Security Function: {result.get('security_function', 'N/A')}")
            results.append(f"   Description: {result['description'][:200]}...")
    
    return results


def _search_nist_objects(graph, node_label, keyword_conditions, obj_type):
    """Search NIST CSF objects with specific formatting."""
    results = []
    
    if obj_type == "nist_functions":
        query = f"""
        MATCH (n:{node_label})
        WHERE """ + " OR ".join([
            cond.format(field="n.name") for cond in keyword_conditions
        ] + [
            cond.format(field="n.description") for cond in keyword_conditions
        ] + [
            cond.format(field="n.id") for cond in keyword_conditions
        ]) + """
        RETURN n.id as id, n.name as name, n.description as description
        LIMIT 3
        """
        
        function_results = graph.query(query)
        for result in function_results:
            results.append(f"\n📋 NIST Function {result['id']}: {result['name']}")
            results.append(f"   Description: {result['description'][:200]}...")
    
    elif obj_type == "nist_categories":
        query = f"""
        MATCH (n:{node_label})
        WHERE """ + " OR ".join([
            cond.format(field="n.name") for cond in keyword_conditions
        ] + [
            cond.format(field="n.description") for cond in keyword_conditions
        ] + [
            cond.format(field="n.id") for cond in keyword_conditions
        ]) + """
        RETURN n.id as id, n.name as name, n.description as description
        LIMIT 3
        """
        
        category_results = graph.query(query)
        for result in category_results:
            results.append(f"\n📂 NIST Category {result['id']}: {result['name']}")
            results.append(f"   Description: {result['description'][:200]}...")
    
    return results


def _search_hipaa_objects(graph, node_label, keyword_conditions, obj_type):
    """Search HIPAA objects with specific formatting."""
    results = []
    
    if obj_type == "hipaa_regulations":
        query = f"""
        MATCH (n:{node_label})
        WHERE """ + " OR ".join([
            cond.format(field="n.title") for cond in keyword_conditions
        ] + [
            cond.format(field="n.description") for cond in keyword_conditions
        ] + [
            cond.format(field="n.regulation_id") for cond in keyword_conditions
        ]) + """
        RETURN n.regulation_id as id, n.title as title, n.description as description,
               n.category as category
        LIMIT 3
        """
        
        regulation_results = graph.query(query)
        for result in regulation_results:
            results.append(f"\n🏥 HIPAA Regulation {result['id']}: {result['title']}")
            results.append(f"   Category: {result.get('category', 'N/A')}")
            results.append(f"   Description: {result['description'][:200]}...")
    
    return results


def _search_generic_objects(graph, node_label, keyword_conditions, obj_type):
    """Generic search for other framework objects."""
    results = []
    
    try:
        query = f"""
        MATCH (n:{node_label})
        WHERE """ + " OR ".join([
            cond.format(field="n.name") for cond in keyword_conditions[:2]  # Limit conditions for safety
        ]) + """
        RETURN n.id as id, n.name as name, n.description as description
        LIMIT 3
        """
        
        generic_results = graph.query(query)
        for result in generic_results:
            results.append(f"\n📋 {obj_type}: {result.get('name', result.get('id', 'Unknown'))}")
            if result.get('description'):
                results.append(f"   Description: {result['description'][:200]}...")
    
    except Exception:
        # Fallback for objects with different property names
        pass
    
    return results
