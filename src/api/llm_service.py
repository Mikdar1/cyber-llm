"""LLM integration utilities (Gemini) and prompt templates for chat and analysis."""

import json
import logging
import os

from langchain_core.prompts import ChatPromptTemplate
from langchain_google_genai import ChatGoogleGenerativeAI

from src.config.settings import GEMINI_API_KEY, MODEL_NAME

# Suppress LangChain warnings
os.environ["LANGCHAIN_TRACING_V2"] = "false"


def get_ingestion_status():
    """Return current ingestion status (frameworks, documents, totals)."""
    try:
        with open("src/config/ingestion_status.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {
            "ingested_documents": [],
            "ingested_frameworks": {
                "attack": {
                    "status": "not_ingested",
                    "domains": [],
                    "last_updated": None,
                    "node_counts": {},
                }
            },
            "total_nodes": 0,
            "last_updated": None,
        }


def get_available_compliance_frameworks():
    """Return names of compliance frameworks detected from ingested documents."""
    status = get_ingestion_status()
    compliance_frameworks = []

    # Get frameworks from ingested documents
    for doc in status.get("ingested_documents", []):
        if (
            doc.get("framework_type")
            and doc["framework_type"] not in compliance_frameworks
        ):
            compliance_frameworks.append(doc["framework_type"])

    return compliance_frameworks


def generate_compliance_framework_description():
    """Return a short description of available compliance frameworks."""
    available_frameworks = get_available_compliance_frameworks()

    if not available_frameworks:
        return """📋 **Compliance Frameworks**: No compliance framework documents have been uploaded yet.
    - Upload PDF documents through the web interface to add compliance frameworks
    - Supported formats: Any compliance or regulatory framework document"""

    framework_list = ", ".join(available_frameworks)
    return f"""📋 **Compliance Frameworks**: Currently available frameworks based on uploaded documents:
    - Active frameworks: {framework_list}
    - Content extracted and processed via LLM-based document analysis
    - Additional frameworks can be added by uploading more documents"""


class LLMService:
    """LLM-based document parsing and analysis helper."""

    def __init__(self):
        """Initialize the LLM service."""
        self.llm = self._get_llm()

    def _get_llm(self):
        """Return a configured Gemini LLM instance."""
        return ChatGoogleGenerativeAI(
            model=MODEL_NAME,
            temperature=0.1,  # Low temperature for consistent extraction
            google_api_key=GEMINI_API_KEY,
        )

    def generate_response(self, prompt: str) -> str:
        """Generate a response string for a prompt."""
        try:
            response = self.llm.invoke(prompt)
            if hasattr(response, "content"):
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
    """Return a configured Gemini LLM instance for chat operations."""
    return ChatGoogleGenerativeAI(
        model=MODEL_NAME,
        temperature=0,  # Deterministic responses for cybersecurity accuracy
        google_api_key=GEMINI_API_KEY,
    )


def get_dynamic_framework_templates():
    """Build prompt templates based on current ingestion status."""
    status = get_ingestion_status()
    available_frameworks = get_available_compliance_frameworks()
    compliance_description = generate_compliance_framework_description()

    # Check if ATT&CK is available
    attack_available = (
        status.get("ingested_frameworks", {}).get("attack", {}).get("status")
        == "ingested"
    )
    attack_info = (
        "🎯 **MITRE ATT&CK**: Techniques, tactics, threat actors, malware, tools, and mitigations"
        if attack_available
        else "🎯 **MITRE ATT&CK**: Not yet loaded (run initialization to load ATT&CK data)"
    )

    templates = {
        "All Frameworks": ChatPromptTemplate.from_template(
            f"""
You are a cybersecurity expert assistant with access to cybersecurity intelligence from available frameworks.

**Currently Available Frameworks:**
{attack_info}
{compliance_description}

**Context from Cybersecurity Knowledge Base:**
{{context}}

**User Question:** {{question}}

**Instructions:**
- Provide accurate, detailed responses based on currently available frameworks only
- Reference specific framework codes when applicable (T#### for ATT&CK, control numbers for compliance frameworks)
- Cross-reference between frameworks when relevant and data is available
- If information spans multiple frameworks, provide a comprehensive view
- Clearly indicate which framework(s) your information comes from
- If information is not available in the knowledge base, clearly state this limitation
- If a framework hasn't been loaded yet, inform the user how to load it
"""
        ),
        "ATT&CK Only": ChatPromptTemplate.from_template(
            """
You are a MITRE ATT&CK expert assistant with deep knowledge of the ATT&CK framework.
You have access to comprehensive ATT&CK intelligence including:

🎯 **ATT&CK Techniques & Tactics**: Complete technique library with T-codes and tactic mappings
🦠 **Malware Intelligence**: Families, variants, and behavioral analysis
👥 **Threat Actor Profiles**: APT groups, their TTPs, and attribution data
🔧 **Tools & Software**: Attack tools, legitimate software abuse, and capabilities
🛡️ **Security Mitigations**: Countermeasures, detection methods, and M-codes
📊 **Data Sources**: Detection data sources and monitoring capabilities

**Context from ATT&CK Knowledge Base:**
{{context}}

**User Question:** {{question}}

**Instructions:**
- Focus exclusively on MITRE ATT&CK framework information
- Include relevant technique IDs (T####), mitigation codes (M####), and tactic information
- Reference specific threat groups, malware families, or tools when applicable
- Provide detailed ATT&CK-specific analysis and intelligence
- If information is not available in the ATT&CK knowledge base, clearly state this limitation
"""
        ),
    }

    # Add compliance framework template only if compliance frameworks are available
    if available_frameworks:
        framework_list = ", ".join(available_frameworks)
        templates["Compliance Frameworks"] = ChatPromptTemplate.from_template(
            f"""
You are a compliance framework expert assistant with knowledge of uploaded cybersecurity and regulatory frameworks.

**Currently Available Compliance Frameworks:** {framework_list}

**Framework Information Available:**
📋 **Controls and Requirements**: Specific controls, requirements, and implementation guidance
📂 **Organizational Structure**: Categories, subcategories, and hierarchical organization  
💡 **Implementation Guidance**: Practical implementation examples and best practices
🔍 **Document-Based Content**: Information extracted from uploaded framework documents

**Context from Compliance Framework Knowledge Base:**
{{context}}

**User Question:** {{question}}

**Instructions:**
- Focus on compliance framework information available in the knowledge base
- Reference specific control numbers, requirement IDs, or framework codes when available
- Explain hierarchical relationships within frameworks when relevant
- Provide implementation guidance and compliance recommendations
- Clearly indicate which specific framework(s) your information comes from
- Available frameworks: {framework_list}
- If information is not available for a specific framework, clearly state this limitation
 - Do not reference MITRE ATT&CK techniques (e.g., T####) or ATT&CK content in this scope. If the question is about ATT&CK, explain it's out of scope and suggest switching to "All Frameworks" or "ATT&CK Only".
"""
        )
    else:
        templates["Compliance Frameworks"] = ChatPromptTemplate.from_template(
            """
You are a compliance framework expert assistant.

**Status:** No compliance framework documents have been uploaded yet.

**Context from Knowledge Base:**
{context}

**User Question:** {question}

**Instructions:**
- Inform the user that no compliance framework documents are currently available
- Explain that they can upload PDF documents through the web interface to add compliance frameworks
- Suggest using the document upload feature to add any compliance frameworks
- If the question is about a specific compliance framework, explain how to upload the relevant documents
"""
        )

    return templates


# Get dynamic framework templates based on current ingestion status
framework_templates = get_dynamic_framework_templates()

# Legacy template for backward compatibility
chat_template = framework_templates["All Frameworks"]


# Framework-aware query analysis prompt template
def get_dynamic_query_analysis_template():
    """Return a query-analysis template tailored to available frameworks."""
    status = get_ingestion_status()
    available_compliance_frameworks = get_available_compliance_frameworks()

    # Build dynamic object types description
    object_types_desc = "- ATT&CK: techniques, malware, threat_groups, tools, mitigations, data_sources, campaigns"

    if available_compliance_frameworks:
        object_types_desc += "\n- Compliance Frameworks: compliance_controls, compliance_requirements, compliance_categories, compliance_documents"
        examples_section = """
**Examples:**
Framework: "ATT&CK Only", Question: "Tell me about APT28 techniques"
Response: {"relevant_types": ["threat_groups", "techniques"], "keywords": ["APT28", "Fancy Bear"], "focus": "ATT&CK threat group techniques", "framework_filter": "ATT&CK Only"}

Framework: "Compliance Frameworks", Question: "What are the data encryption requirements?"
Response: {"relevant_types": ["compliance_controls", "compliance_requirements"], "keywords": ["data encryption", "cryptography"], "focus": "Compliance encryption requirements", "framework_filter": "Compliance Frameworks"}"""
    else:
        object_types_desc += "\n- Compliance Frameworks: No compliance frameworks currently available (upload documents to add frameworks)"
        examples_section = """
**Examples:**
Framework: "ATT&CK Only", Question: "Tell me about APT28 techniques"
Response: {"relevant_types": ["threat_groups", "techniques"], "keywords": ["APT28", "Fancy Bear"], "focus": "ATT&CK threat group techniques", "framework_filter": "ATT&CK Only"}

Framework: "Compliance Frameworks", Question: "What are data encryption requirements?"
Response: {"relevant_types": [], "keywords": ["data encryption"], "focus": "No compliance frameworks available", "framework_filter": "Compliance Frameworks"}"""

    return ChatPromptTemplate.from_template(
        f"""
You are a cybersecurity query analyzer. Your task is to analyze user questions and determine which cybersecurity object types are most relevant within the specified framework scope.

**Framework Scope:** {{framework_scope}}

**Available Object Types by Framework:**
{object_types_desc}

**User Question:** {{question}}

**Instructions:**
Analyze the question within the {{framework_scope}} context and return ONLY a JSON object:
{{{{
    "relevant_types": ["type1", "type2", ...],
    "keywords": ["keyword1", "keyword2", ...],
    "focus": "primary_focus_description",
    "framework_filter": "{{framework_scope}}"
}}}}

**Rules:**
- Only include object types relevant to the specified framework scope
- If framework_scope is "All Frameworks", include types from all available frameworks
- Extract 3-5 key terms specific to the framework context
- Focus should describe what the user wants to know within the framework scope
- If no frameworks are available for a scope, return empty relevant_types

{examples_section}
"""
    )


# Get dynamic query analysis template
query_analysis_template = get_dynamic_query_analysis_template()


def analyze_user_query(llm, user_question, framework_scope="All Frameworks"):
    """Analyze a question and return relevant_types, keywords, focus, and filter."""
    try:
        response = llm.invoke(
            query_analysis_template.format(
                question=user_question, framework_scope=framework_scope
            )
        )

        # Parse the JSON response
        import json

        analysis = json.loads(response.content.strip())

        # Validate the response structure
        if not isinstance(analysis.get("relevant_types"), list):
            # Provide framework-specific defaults based on available frameworks
            if framework_scope == "ATT&CK Only":
                analysis["relevant_types"] = ["techniques", "malware", "threat_groups"]
            elif framework_scope == "Compliance Frameworks":
                # Use generic compliance types since we don't know which specific frameworks
                analysis["relevant_types"] = [
                    "compliance_controls",
                    "compliance_requirements",
                    "compliance_categories",
                ]
            else:
                # All Frameworks - combine ATT&CK with generic compliance types
                base_types = ["techniques", "malware", "threat_groups"]
                available_frameworks = get_available_compliance_frameworks()
                if available_frameworks:
                    base_types.extend(
                        ["compliance_controls", "compliance_requirements"]
                    )
                analysis["relevant_types"] = base_types

        if not isinstance(analysis.get("keywords"), list):
            analysis["keywords"] = [user_question]
        if not analysis.get("focus"):
            analysis["focus"] = f"cybersecurity inquiry within {framework_scope}"
        if not analysis.get("framework_filter"):
            analysis["framework_filter"] = framework_scope

        return analysis

    except Exception as e:
        # Fallback to framework-specific analysis if LLM fails
        available_frameworks = get_available_compliance_frameworks()

        if framework_scope == "ATT&CK Only":
            return {
                "relevant_types": ["techniques", "malware", "threat_groups"],
                "keywords": [user_question],
                "focus": "ATT&CK framework inquiry",
                "framework_filter": framework_scope,
            }
        elif framework_scope == "Compliance Frameworks":
            if available_frameworks:
                return {
                    "relevant_types": [
                        "compliance_controls",
                        "compliance_requirements",
                    ],
                    "keywords": [user_question],
                    "focus": "Compliance framework inquiry",
                    "framework_filter": framework_scope,
                }
            else:
                return {
                    "relevant_types": [],
                    "keywords": [user_question],
                    "focus": "No compliance frameworks available",
                    "framework_filter": framework_scope,
                }
        else:
            # All Frameworks fallback
            base_types = ["techniques", "malware", "threat_groups"]
            if available_frameworks:
                base_types.extend(["compliance_controls", "compliance_requirements"])

            return {
                "relevant_types": base_types,
                "keywords": [user_question],
                "focus": "multi-framework cybersecurity inquiry",
                "framework_filter": framework_scope,
            }


def chat_with_knowledge_base(
    llm, context, user_question, framework_scope="All Frameworks"
):
    """Generate a framework-scoped response using provided context and question."""
    try:
        # Hard guard: if scope is Compliance and the question is about ATT&CK T-codes, inform out-of-scope
        if framework_scope == "Compliance Frameworks":
            import re

            if re.search(r"\bT\d{4}(?:\.\d{3})?\b", user_question, flags=re.IGNORECASE):
                return (
                    "This question references a MITRE ATT&CK technique (e.g., T-code), which is out of scope for 'Compliance Frameworks'. "
                    "Switch scope to 'ATT&CK Only' or 'All Frameworks' to get ATT&CK-specific answers."
                )

        # Refresh framework templates to get latest ingestion status
        current_templates = get_dynamic_framework_templates()

        # Select the appropriate template based on framework scope
        template = current_templates.get(
            framework_scope, current_templates["All Frameworks"]
        )

        response = llm.invoke(template.format(context=context, question=user_question))
        return response.content
    except Exception as e:
        return f"❌ Error generating response: {e}"
