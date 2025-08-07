"""
Large Language Model Integration Service Module

This module provides integration with Google's Gemini LLM for cybersecurity
intelligence analysis and chatbot functionality. It handles LLM initialization,
prompt templating, and context-aware response generation using the MITRE ATT&CK
knowledge base.

Features:
- Google Gemini LLM integration via LangChain
- Cybersecurity-specialized prompt templates
- Context-aware response generation
- ATT&CK knowledge base integration
- Document parsing and extraction services

Functions:
    get_llm: LLM factory and configuration
    chat_with_knowledge_base: Main chat interface with context injection
    
Classes:
    LLMService: Main service class for document extraction and analysis
"""

from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import ChatPromptTemplate
from src.config.settings import MODEL_NAME, GEMINI_API_KEY
import logging

# Suppress LangChain warnings
import os
os.environ['LANGCHAIN_TRACING_V2'] = 'false'


class LLMService:
    """
    Service class for LLM-based document parsing and analysis.
    
    Provides methods for extracting structured data from cybersecurity
    framework documents using Google Gemini LLM.
    """
    
    def __init__(self):
        """Initialize the LLM service."""
        self.llm = self._get_llm()
    
    def _get_llm(self):
        """Initialize and configure the Google Gemini LLM instance."""
        return ChatGoogleGenerativeAI(
            model=MODEL_NAME,
            temperature=0.1,  # Low temperature for consistent extraction
            google_api_key=GEMINI_API_KEY
        )
    
    def generate_response(self, prompt: str) -> str:
        """
        Generate a response from the LLM based on the given prompt.
        
        Args:
            prompt (str): The input prompt for the LLM
            
        Returns:
            str: The LLM's response
        """
        try:
            response = self.llm.invoke(prompt)
            if hasattr(response, 'content'):
                content = response.content
                if isinstance(content, str):
                    return content
                elif isinstance(content, list):
                    return str(content)
                else:
                    return str(content)
            else:
                return str(response)
        except Exception as e:
            logging.error(f"LLM generation failed: {e}")
            raise


def get_llm():
    """
    Initialize and configure the Google Gemini LLM instance.
    
    Creates a ChatGoogleGenerativeAI instance with cybersecurity-optimized
    settings including temperature control for consistent responses.
    
    Returns:
        ChatGoogleGenerativeAI: Configured LLM instance for chat operations
    """
    return ChatGoogleGenerativeAI(
        model=MODEL_NAME,
        temperature=0,  # Deterministic responses for cybersecurity accuracy
        google_api_key=GEMINI_API_KEY
    )


# Framework-specific chat prompt templates
framework_templates = {
    "All Frameworks": ChatPromptTemplate.from_template("""
You are a cybersecurity expert assistant with deep knowledge of multiple cybersecurity frameworks. 
You have access to comprehensive cybersecurity intelligence from:

🎯 **MITRE ATT&CK**: Techniques, tactics, threat actors, malware, tools, and mitigations
🛡️ **CIS Controls v8.1**: Critical security controls and implementation safeguards
📋 **NIST CSF 2.0**: Functions, categories, subcategories, and implementation guidance
🏥 **HIPAA**: Healthcare regulatory compliance requirements and privacy rules
🏦 **FFIEC**: Financial institution examination procedures and guidance
💳 **PCI DSS v4.0.1**: Payment card industry security standards and requirements

**Context from Multi-Framework Knowledge Base:**
{context}

**User Question:** {question}

**Instructions:**
- Provide accurate, detailed responses based on ALL available cybersecurity frameworks
- Reference specific framework codes when applicable (T#### for ATT&CK, CIS Control numbers, NIST function IDs, etc.)
- Cross-reference between frameworks when relevant (e.g., how NIST CSF relates to CIS Controls)
- If information spans multiple frameworks, provide a comprehensive view
- Clearly indicate which framework(s) your information comes from
- If information is not available in the knowledge base, clearly state this limitation
"""),

    "ATT&CK Only": ChatPromptTemplate.from_template("""
You are a MITRE ATT&CK expert assistant with deep knowledge of the ATT&CK framework.
You have access to comprehensive ATT&CK intelligence including:

🎯 **ATT&CK Techniques & Tactics**: Complete technique library with T-codes and tactic mappings
🦠 **Malware Intelligence**: Families, variants, and behavioral analysis
👥 **Threat Actor Profiles**: APT groups, their TTPs, and attribution data
🔧 **Tools & Software**: Attack tools, legitimate software abuse, and capabilities
🛡️ **Security Mitigations**: Countermeasures, detection methods, and M-codes
📊 **Data Sources**: Detection data sources and monitoring capabilities

**Context from ATT&CK Knowledge Base:**
{context}

**User Question:** {question}

**Instructions:**
- Focus exclusively on MITRE ATT&CK framework information
- Include relevant technique IDs (T####), mitigation codes (M####), and tactic information
- Reference specific threat groups, malware families, or tools when applicable
- Provide detailed ATT&CK-specific analysis and intelligence
- If information is not available in the ATT&CK knowledge base, clearly state this limitation
"""),

    "CIS Controls": ChatPromptTemplate.from_template("""
You are a CIS Controls expert assistant with deep knowledge of CIS Controls v8.1.
You have access to comprehensive CIS Controls information including:

🛡️ **CIS Controls**: 18 critical security controls organized by implementation groups
⚙️ **Safeguards**: Specific implementation safeguards for each control
📊 **Implementation Groups**: IG1, IG2, and IG3 organizational maturity levels
🎯 **Asset Types**: Controls organized by asset type and security functions

**Context from CIS Controls Knowledge Base:**
{context}

**User Question:** {question}

**Instructions:**
- Focus exclusively on CIS Controls v8.1 framework information
- Reference specific control numbers (Control 1, Control 2, etc.) and safeguard IDs
- Explain implementation groups (IG1, IG2, IG3) when relevant
- Provide practical implementation guidance and best practices
- If information is not available in the CIS Controls knowledge base, clearly state this limitation
"""),

    "NIST CSF": ChatPromptTemplate.from_template("""
You are a NIST Cybersecurity Framework expert assistant with deep knowledge of NIST CSF 2.0.
You have access to comprehensive NIST CSF information including:

📋 **Functions**: Govern (GV), Identify (ID), Protect (PR), Detect (DE), Respond (RS), Recover (RC)
📂 **Categories**: Organizational categories within each function
📋 **Subcategories**: Specific cybersecurity outcomes and activities
💡 **Implementation Examples**: Practical guidance for implementation

**Context from NIST CSF Knowledge Base:**
{context}

**User Question:** {question}

**Instructions:**
- Focus exclusively on NIST Cybersecurity Framework 2.0 information
- Reference specific function IDs (GV, ID, PR, DE, RS, RC), category IDs, and subcategory codes
- Explain the hierarchical relationship between functions, categories, and subcategories
- Provide implementation guidance and organizational context
- If information is not available in the NIST CSF knowledge base, clearly state this limitation
"""),

    "HIPAA": ChatPromptTemplate.from_template("""
You are a HIPAA compliance expert assistant with deep knowledge of HIPAA Administrative Simplification.
You have access to comprehensive HIPAA regulatory information including:

🏥 **Privacy Rules**: Protected health information (PHI) requirements and safeguards
🔒 **Security Rules**: Administrative, physical, and technical safeguards
📋 **Administrative Simplification**: Regulatory compliance requirements
⚖️ **Enforcement**: Violation categories and penalty structures

**Context from HIPAA Knowledge Base:**
{context}

**User Question:** {question}

**Instructions:**
- Focus exclusively on HIPAA regulatory framework information
- Reference specific HIPAA sections, rules, and compliance requirements
- Explain privacy and security rule requirements in detail
- Provide compliance guidance and regulatory interpretation
- If information is not available in the HIPAA knowledge base, clearly state this limitation
"""),

    "FFIEC": ChatPromptTemplate.from_template("""
You are an FFIEC examination expert assistant with deep knowledge of FFIEC IT examination procedures.
You have access to comprehensive FFIEC guidance including:

🏦 **IT Examination Handbook**: Information technology examination procedures
🔍 **Examination Categories**: Risk assessment and examination focus areas
📋 **Procedures**: Detailed examination procedures and controls assessment
⚖️ **Regulatory Guidance**: Financial institution compliance requirements

**Context from FFIEC Knowledge Base:**
{context}

**User Question:** {question}

**Instructions:**
- Focus exclusively on FFIEC examination procedures and guidance
- Reference specific FFIEC categories, procedures, and examination focus areas
- Explain financial institution regulatory requirements and examination processes
- Provide examination and compliance guidance
- If information is not available in the FFIEC knowledge base, clearly state this limitation
"""),

    "PCI DSS": ChatPromptTemplate.from_template("""
You are a PCI DSS compliance expert assistant with deep knowledge of PCI DSS v4.0.1.
You have access to comprehensive PCI DSS information including:

💳 **Requirements**: 12 high-level security requirements for cardholder data protection
🔍 **Testing Procedures**: Detailed testing and validation procedures
📋 **Guidance**: Implementation guidance and best practices
🛡️ **Controls**: Technical and procedural security controls

**Context from PCI DSS Knowledge Base:**
{context}

**User Question:** {question}

**Instructions:**
- Focus exclusively on PCI DSS v4.0.1 framework information
- Reference specific requirement numbers, testing procedures, and guidance sections
- Explain cardholder data protection requirements and implementation
- Provide compliance guidance and security control recommendations
- If information is not available in the PCI DSS knowledge base, clearly state this limitation
""")
}

# Legacy template for backward compatibility
chat_template = framework_templates["All Frameworks"]


# Framework-aware query analysis prompt template
query_analysis_template = ChatPromptTemplate.from_template("""
You are a cybersecurity query analyzer. Your task is to analyze user questions and determine which cybersecurity object types are most relevant within the specified framework scope.

**Framework Scope:** {framework_scope}

**Available Object Types by Framework:**
- ATT&CK: techniques, malware, threat_groups, tools, mitigations, data_sources, campaigns
- CIS Controls: cis_controls, cis_safeguards, implementation_groups
- NIST CSF: nist_functions, nist_categories, nist_subcategories
- HIPAA: hipaa_regulations, hipaa_sections, hipaa_requirements
- FFIEC: ffiec_categories, ffiec_procedures, ffiec_guidance
- PCI DSS: pci_requirements, pci_procedures, pci_controls

**User Question:** {question}

**Instructions:**
Analyze the question within the {framework_scope} context and return ONLY a JSON object:
{{
    "relevant_types": ["type1", "type2", ...],
    "keywords": ["keyword1", "keyword2", ...],
    "focus": "primary_focus_description",
    "framework_filter": "{framework_scope}"
}}

**Rules:**
- Only include object types relevant to the specified framework scope
- If framework_scope is "All Frameworks", include types from all relevant frameworks
- Extract 3-5 key terms specific to the framework context
- Focus should describe what the user wants to know within the framework scope

**Examples:**
Framework: "ATT&CK Only", Question: "Tell me about APT28 techniques"
Response: {{"relevant_types": ["threat_groups", "techniques"], "keywords": ["APT28", "Fancy Bear"], "focus": "ATT&CK threat group techniques", "framework_filter": "ATT&CK Only"}}

Framework: "CIS Controls", Question: "What is Control 1?"
Response: {{"relevant_types": ["cis_controls", "cis_safeguards"], "keywords": ["Control 1", "asset management"], "focus": "CIS Control implementation", "framework_filter": "CIS Controls"}}

Framework: "NIST CSF", Question: "Explain the Protect function"
Response: {{"relevant_types": ["nist_functions", "nist_categories"], "keywords": ["Protect", "PR"], "focus": "NIST CSF Protect function", "framework_filter": "NIST CSF"}}
""")


def analyze_user_query(llm, user_question, framework_scope="All Frameworks"):
    """
    Analyze user question to determine relevant object types and keywords within framework scope.
    
    Uses LLM to intelligently parse the user's question and identify which
    specific object types should be queried based on the selected framework.
    
    Args:
        llm: Configured language model instance
        user_question (str): User's cybersecurity question
        framework_scope (str): Selected framework scope
        
    Returns:
        dict: Analysis results with relevant_types, keywords, focus, and framework_filter
    """
    try:
        response = llm.invoke(query_analysis_template.format(
            question=user_question,
            framework_scope=framework_scope
        ))
        
        # Parse the JSON response
        import json
        analysis = json.loads(response.content.strip())
        
        # Validate the response structure
        if not isinstance(analysis.get('relevant_types'), list):
            # Provide framework-specific defaults
            if framework_scope == "ATT&CK Only":
                analysis['relevant_types'] = ['techniques', 'malware', 'threat_groups']
            elif framework_scope == "CIS Controls":
                analysis['relevant_types'] = ['cis_controls', 'cis_safeguards']
            elif framework_scope == "NIST CSF":
                analysis['relevant_types'] = ['nist_functions', 'nist_categories']
            elif framework_scope == "HIPAA":
                analysis['relevant_types'] = ['hipaa_regulations', 'hipaa_sections']
            elif framework_scope == "FFIEC":
                analysis['relevant_types'] = ['ffiec_categories', 'ffiec_procedures']
            elif framework_scope == "PCI DSS":
                analysis['relevant_types'] = ['pci_requirements', 'pci_procedures']
            else:
                analysis['relevant_types'] = ['techniques', 'cis_controls', 'nist_functions']
                
        if not isinstance(analysis.get('keywords'), list):
            analysis['keywords'] = [user_question]
        if not analysis.get('focus'):
            analysis['focus'] = f"cybersecurity inquiry within {framework_scope}"
        if not analysis.get('framework_filter'):
            analysis['framework_filter'] = framework_scope
            
        return analysis
        
    except Exception as e:
        # Fallback to framework-specific analysis if LLM fails
        if framework_scope == "ATT&CK Only":
            return {
                'relevant_types': ['techniques', 'malware', 'threat_groups'],
                'keywords': [user_question],
                'focus': 'ATT&CK framework inquiry',
                'framework_filter': framework_scope
            }
        elif framework_scope == "CIS Controls":
            return {
                'relevant_types': ['cis_controls', 'cis_safeguards'],
                'keywords': [user_question],
                'focus': 'CIS Controls inquiry',
                'framework_filter': framework_scope
            }
        else:
            return {
                'relevant_types': ['techniques', 'cis_controls', 'nist_functions'],
                'keywords': [user_question],
                'focus': 'multi-framework cybersecurity inquiry',
                'framework_filter': framework_scope
            }


def chat_with_knowledge_base(llm, context, user_question, framework_scope="All Frameworks"):
    """
    Generate context-aware responses using the specified cybersecurity framework scope.
    
    Processes user questions with relevant context to provide framework-specific
    cybersecurity intelligence responses.
    
    Args:
        llm: Configured language model instance
        context (str): Relevant knowledge base context
        user_question (str): User's cybersecurity question
        framework_scope (str): Selected framework scope for response
        
    Returns:
        str: Generated response with framework-specific cybersecurity intelligence
    """
    try:
        # Select the appropriate template based on framework scope
        template = framework_templates.get(framework_scope, framework_templates["All Frameworks"])
        
        response = llm.invoke(template.format(
            context=context, 
            question=user_question
        ))
        return response.content
    except Exception as e:
        return f"❌ Error generating response: {e}"
