"""
Cybersecurity Security Event Analysis API

A FastAPI-based web service that analyzes security events using the 
cybersecurity knowledge base and provides threat intelligence recommendations.

This API processes security events and provides automated responses based on
threat intelligence from multiple cybersecurity frameworks (MITRE ATT&CK, 
CIS Controls, NIST CSF, HIPAA, FFIEC, PCI DSS).

Features:
- RESTful API for security event analysis
- Multi-framework threat intelligence analysis
- Automated response recommendations
- Process tree analysis
- Risk-based decision making

Usage:
    uvicorn api_service:app --host 0.0.0.0 --port 8000
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, List, Any, Optional
from datetime import datetime
import logging
import json

# Import application modules
from src.knowledge_base.database import create_graph_connection
from src.api.llm_service import get_llm
from src.cybersecurity.attack_ingestion import ingest_attack_data

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# FastAPI app instance
app = FastAPI(
    title="Cybersecurity Security Event Analysis API",
    description="API for analyzing security events using cybersecurity threat intelligence",
    version="1.0.0"
)

# Global variables for services
graph = None
llm = None

def initialize_api_knowledge_base(graph_connection):
    """
    Initialize knowledge base for API service without Streamlit dependencies.
    
    Args:
        graph_connection: Neo4j database connection instance
    """
    try:
        # Check if database already has data
        check_query = "MATCH (n) RETURN count(n) as count"
        result = graph_connection.query(check_query)
        existing_count = result[0]['count'] if result else 0
        
        logger.info(f"Knowledge base contains {existing_count:,} nodes")
        
        # If empty, initialize with basic ATT&CK data
        if existing_count == 0:
            logger.info("Initializing knowledge base with ATT&CK data...")
            success, message = ingest_attack_data(graph_connection, domains=['enterprise'])
            if success:
                logger.info("ATT&CK data ingestion completed successfully")
            else:
                logger.warning(f"ATT&CK data ingestion failed: {message}")
        else:
            logger.info("Knowledge base already initialized")
            
    except Exception as e:
        logger.error(f"Error initializing knowledge base: {e}")
        # Continue anyway - the API can work without the full knowledge base


@app.on_event("startup")
async def startup_event():
    """Initialize services on startup."""
    global graph, llm
    try:
        logger.info("Initializing cybersecurity knowledge base...")
        graph = create_graph_connection()
        llm = get_llm()
        initialize_api_knowledge_base(graph)
        logger.info("API services initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize services: {e}")
        # Don't raise - allow API to start even if knowledge base fails
        logger.warning("API starting with limited functionality")


# Pydantic models for request/response
class ProcessInfo(BaseModel):
    """Process information in the parent tree."""
    prcsCreationTime: str
    prcsHash: str
    prcsPID: int
    prcsPath: str
    prcsUserDomain: str
    prcsUserName: str
    prcsVerdict: str


class SecurityEventRequest(BaseModel):
    """Security event analysis request model."""
    adaptive_event_type: str
    base_event_type: str
    component: str
    device_name: str
    event_group: str
    event_time: str
    process_creation_time: str
    logged_on_user: str
    process_hash: str
    process_parent_tree: Dict[str, ProcessInfo]
    process_path: str
    process_user_domain: str
    process_user_name: str
    process_verdict: str


class AlertOnlyResponse(BaseModel):
    """Alert only response model."""
    action: str = "Alert Only"


class TerminateAndExecuteResponse(BaseModel):
    """Terminate and execute command response model."""
    action: str = "Terminate and Execute Command"
    auto: str  # "yes" or "no"
    command: str


def analyze_threat_level(event_data: SecurityEventRequest, threat_intel: str) -> str:
    """
    Analyze the threat level based on event characteristics and threat intelligence.
    
    Args:
        event_data: Security event data
        threat_intel: MITRE ATT&CK threat intelligence context
        
    Returns:
        Threat level (LOW, MEDIUM, HIGH, CRITICAL)
    """
    if not llm:
        # Fallback to basic analysis if LLM unavailable
        threat_indicators = 0
        high_risk_events = [
            "credential stealing", "mimikatz", "password dumping",
            "privilege escalation", "lateral movement", "persistence",
            "command and control", "data exfiltration"
        ]
        
        if any(risk_event in event_data.adaptive_event_type.lower() for risk_event in high_risk_events):
            threat_indicators += 3
        
        if event_data.process_verdict.lower() == "malicious":
            threat_indicators += 3
        elif event_data.process_verdict.lower() == "unknown":
            threat_indicators += 1
        
        for process_info in event_data.process_parent_tree.values():
            if process_info.prcsVerdict.lower() == "malicious":
                threat_indicators += 2
            elif process_info.prcsVerdict.lower() == "unknown":
                threat_indicators += 1
        
        if "system32" not in event_data.process_path.lower():
            threat_indicators += 1
        
        if threat_indicators >= 6:
            return "CRITICAL"
        elif threat_indicators >= 4:
            return "HIGH"
        elif threat_indicators >= 2:
            return "MEDIUM"
        else:
            return "LOW"
    
    # Use LLM for intelligent threat assessment
    try:
        assessment_prompt = f"""
        You are a cybersecurity threat analyst. Analyze this security event and determine the threat level.

        Security Event:
        - Event Type: {event_data.adaptive_event_type}
        - Base Event: {event_data.base_event_type}
        - Process Path: {event_data.process_path}
        - Process Verdict: {event_data.process_verdict}
        - User Context: {event_data.logged_on_user}
        - Component: {event_data.component}

        Process Tree Context:
        {json.dumps({k: v.dict() for k, v in event_data.process_parent_tree.items()}, indent=2)}

        MITRE ATT&CK Intelligence:
        {threat_intel}

        Based on this comprehensive analysis, what is the threat level?

        Consider:
        1. Known attack techniques and their severity
        2. Process chain analysis and parent-child relationships
        3. User context and privileges
        4. Process verdicts and reputation
        5. MITRE ATT&CK technique mappings

        Respond with ONLY one of: LOW, MEDIUM, HIGH, CRITICAL
        """
        
        response = llm.invoke(assessment_prompt)
        threat_level = str(response.content).strip().upper()
        
        # Validate response
        if threat_level in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            return threat_level
        else:
            logger.warning(f"Invalid threat level from LLM: {threat_level}, defaulting to MEDIUM")
            return "MEDIUM"
            
    except Exception as e:
        logger.error(f"Error in LLM threat assessment: {e}")
        return "MEDIUM"  # Safe fallback


def get_comprehensive_threat_intelligence(event_data: SecurityEventRequest) -> Dict[str, Any]:
    """
    Gather comprehensive threat intelligence from the cybersecurity knowledge base.
    
    Args:
        event_data: Security event data
        
    Returns:
        Comprehensive threat intelligence context
    """
    if not graph:
        return {
            "status": "unavailable",
            "message": "Knowledge base unavailable",
            "techniques": [],
            "tactics": [],
            "mitigations": [],
            "groups": [],
            "summary": "Threat intelligence unavailable."
        }
    
    try:
        intelligence = {
            "techniques": [],
            "tactics": [],
            "mitigations": [],
            "groups": [],
            "data_sources": []
        }
        
        # 1. Find related MITRE ATT&CK techniques
        technique_query = """
        MATCH (t:Technique)
        WHERE toLower(t.name) CONTAINS toLower($event_type)
           OR toLower(t.description) CONTAINS toLower($event_type)
           OR ANY(platform IN t.platforms WHERE toLower(platform) CONTAINS 'windows')
        RETURN t.technique_id, t.name, t.description, t.tactics, t.data_sources, 
               t.permissions_required, t.defense_bypassed, t.detection
        LIMIT 10
        """
        
        technique_results = graph.query(technique_query, {"event_type": event_data.adaptive_event_type})
        if technique_results:
            for record in technique_results:
                intelligence["techniques"].append({
                    "id": record.get("t.technique_id"),
                    "name": record.get("t.name"),
                    "description": record.get("t.description"),
                    "tactics": record.get("t.tactics", []),
                    "data_sources": record.get("t.data_sources", []),
                    "permissions_required": record.get("t.permissions_required", []),
                    "defense_bypassed": record.get("t.defense_bypassed", []),
                    "detection": record.get("t.detection")
                })
        
        # 2. Find related tactics
        if intelligence["techniques"]:
            all_tactics = set()
            for tech in intelligence["techniques"]:
                if tech["tactics"]:
                    all_tactics.update(tech["tactics"])
            
            if all_tactics:
                tactic_query = """
                MATCH (tactic:Tactic)
                WHERE tactic.name IN $tactic_names
                RETURN tactic.name, tactic.description, tactic.tactic_id
                """
                
                tactic_results = graph.query(tactic_query, {"tactic_names": list(all_tactics)})
                if tactic_results:
                    intelligence["tactics"] = [{
                        "id": record.get("tactic.tactic_id"),
                        "name": record.get("tactic.name"),
                        "description": record.get("tactic.description")
                    } for record in tactic_results]
        
        # 3. Find related threat groups that use similar techniques
        if intelligence["techniques"]:
            technique_ids = [t["id"] for t in intelligence["techniques"] if t["id"]]
            if technique_ids:
                group_query = """
                MATCH (g:ThreatGroup)-[:USES]->(t:Technique)
                WHERE t.technique_id IN $technique_ids
                RETURN DISTINCT g.name, g.description, g.aliases
                LIMIT 5
                """
                
                group_results = graph.query(group_query, {"technique_ids": technique_ids})
                if group_results:
                    intelligence["groups"] = [{
                        "name": record.get("g.name"),
                        "description": record.get("g.description"),
                        "aliases": record.get("g.aliases", [])
                    } for record in group_results]
        
        # 4. Find related mitigations
        if intelligence["techniques"]:
            technique_ids = [t["id"] for t in intelligence["techniques"] if t["id"]]
            if technique_ids:
                mitigation_query = """
                MATCH (m:Mitigation)-[:MITIGATES]->(t:Technique)
                WHERE t.technique_id IN $technique_ids
                RETURN DISTINCT m.name, m.description, m.mitigation_id
                LIMIT 5
                """
                
                mitigation_results = graph.query(mitigation_query, {"technique_ids": technique_ids})
                if mitigation_results:
                    intelligence["mitigations"] = [{
                        "id": record.get("m.mitigation_id"),
                        "name": record.get("m.name"),
                        "description": record.get("m.description")
                    } for record in mitigation_results]
        
        # 5. Process-specific intelligence
        process_name = event_data.process_path.split("\\")[-1] if "\\" in event_data.process_path else event_data.process_path.split("/")[-1]
        
        process_query = """
        MATCH (t:Technique)
        WHERE toLower(t.description) CONTAINS toLower($process_name)
           OR toLower(t.name) CONTAINS toLower($process_name)
        RETURN t.technique_id, t.name, t.description
        LIMIT 5
        """
        
        process_results = graph.query(process_query, {"process_name": process_name})
        if process_results:
            for record in process_results:
                # Add process-specific techniques if not already present
                existing_ids = [t["id"] for t in intelligence["techniques"]]
                if record.get("t.technique_id") not in existing_ids:
                    intelligence["techniques"].append({
                        "id": record.get("t.technique_id"),
                        "name": record.get("t.name"),
                        "description": record.get("t.description"),
                        "context": "process-specific"
                    })
        
        # Generate summary
        summary_parts = []
        if intelligence["techniques"]:
            summary_parts.append(f"Found {len(intelligence['techniques'])} related MITRE ATT&CK techniques")
        if intelligence["tactics"]:
            summary_parts.append(f"{len(intelligence['tactics'])} tactics")
        if intelligence["groups"]:
            summary_parts.append(f"{len(intelligence['groups'])} known threat groups")
        if intelligence["mitigations"]:
            summary_parts.append(f"{len(intelligence['mitigations'])} applicable mitigations")
        
        summary = "; ".join(summary_parts) if summary_parts else "No specific threat intelligence found"
        
        # Create final result dictionary
        result = {
            "status": "success",
            "summary": summary,
            "techniques": intelligence["techniques"],
            "tactics": intelligence["tactics"],
            "mitigations": intelligence["mitigations"],
            "groups": intelligence["groups"],
            "data_sources": intelligence["data_sources"]
        }
        
        return result
        
    except Exception as e:
        logger.error(f"Error gathering comprehensive threat intelligence: {e}")
        return {
            "status": "error",
            "message": f"Error gathering threat intelligence: {str(e)}",
            "techniques": [],
            "tactics": [],
            "mitigations": [],
            "groups": [],
            "summary": "Threat intelligence gathering failed."
        }


def generate_response_recommendation(event_data: SecurityEventRequest) -> Dict[str, Any]:
    """
    Generate comprehensive response recommendation using KB and LLM analysis.
    
    Args:
        event_data: Security event data
        
    Returns:
        Response recommendation with detailed analysis
    """
    try:
        logger.info("Gathering comprehensive threat intelligence...")
        
        # 1. Gather comprehensive threat intelligence from knowledge base
        threat_intel = get_comprehensive_threat_intelligence(event_data)
        
        # 2. Create formatted threat intelligence summary for LLM
        intel_summary = threat_intel["summary"]
        if threat_intel["techniques"]:
            intel_summary += "\n\nKey Techniques:"
            for tech in threat_intel["techniques"][:3]:  # Top 3 techniques
                intel_summary += f"\n- {tech['id']}: {tech['name']}"
                if tech.get('tactics'):
                    intel_summary += f" (Tactics: {', '.join(tech['tactics'][:2])})"
        
        if threat_intel["groups"]:
            intel_summary += f"\n\nKnown Threat Groups: {', '.join([g['name'] for g in threat_intel['groups'][:3]])}"
        
        if threat_intel["mitigations"]:
            intel_summary += f"\n\nRecommended Mitigations: {', '.join([m['name'] for m in threat_intel['mitigations'][:2]])}"
        
        # 3. Use LLM for intelligent threat level assessment
        threat_level = analyze_threat_level(event_data, intel_summary)
        
        logger.info(f"Threat level assessed as: {threat_level}")
        
        # 4. Use LLM for comprehensive response recommendation
        if llm:
            # Create comprehensive analysis prompt
            prompt = f"""
            You are an expert cybersecurity incident response analyst with access to comprehensive threat intelligence. 
            Analyze this security event and provide a specific response recommendation.

            SECURITY EVENT ANALYSIS:
            ========================
            Event Type: {event_data.adaptive_event_type}
            Base Event: {event_data.base_event_type}
            Process: {event_data.process_path}
            Process Verdict: {event_data.process_verdict}
            User Context: {event_data.logged_on_user}
            Component: {event_data.component}
            Device: {event_data.device_name}
            
            PROCESS TREE ANALYSIS:
            =====================
            {json.dumps({k: v.dict() for k, v in event_data.process_parent_tree.items()}, indent=2)}

            THREAT INTELLIGENCE (MITRE ATT&CK):
            ===================================
            {intel_summary}

            THREAT LEVEL ASSESSMENT: {threat_level}

            RESPONSE ANALYSIS:
            ==================
            Based on your expertise and the comprehensive threat intelligence above, analyze:

            1. Attack Vector: How is this attack being executed?
            2. Potential Impact: What could happen if this continues?
            3. Urgency Level: How quickly must we respond?
            4. Containment Strategy: What's the best way to contain this?

            Recommend ONE of these specific actions:

            A) "Alert Only" - For events that need monitoring but no immediate action
               Use when: Low confidence threat, requires human analysis, or false positive likely

            B) "Terminate and Execute Command" with auto="yes" - For high-confidence threats requiring immediate automated response
               Use when: Known malicious activity, high confidence, standard response available

            C) "Terminate and Execute Command" with auto="no" - For critical threats requiring manual approval before action
               Use when: Potentially destructive response needed, high business impact, or complex scenario

            For B or C, suggest a specific command appropriate for this Windows environment.
            Consider: process termination, network isolation, system shutdown, or custom security commands.

            Respond with your analysis and final recommendation. Be specific about WHY you chose this action.
            """
            
            # Get LLM recommendation
            try:
                response = llm.invoke(prompt)
                analysis_text = str(response.content).lower()
                logger.info(f"LLM Analysis completed. Response length: {len(analysis_text)} chars")
                
                # Extract process name for targeted commands
                process_name = event_data.process_path.split("\\")[-1] if "\\" in event_data.process_path else event_data.process_path.split("/")[-1]
                
                # Intelligent response determination based on LLM analysis and threat level
                if threat_level == "CRITICAL":
                    if any(keyword in analysis_text for keyword in ["manual", "approval", "human", "careful", "review"]):
                        command = "shutdown /r /f /t 300"  # 5-minute delayed restart for review
                        if "immediate" in analysis_text or "urgent" in analysis_text:
                            command = "shutdown /r /f /t 60"  # 1-minute delay for critical
                        return {
                            "action": "Terminate and Execute Command",
                            "auto": "no",
                            "command": command,
                            "reason": "Critical threat requiring manual approval",
                            "threat_level": threat_level,
                            "intelligence_summary": threat_intel["summary"]
                        }
                    else:
                        # Determine best automated response
                        if "network" in analysis_text or "lateral" in analysis_text:
                            command = "netsh advfirewall set allprofiles state on"  # Enable firewall
                        elif process_name and process_name.lower() != "system":
                            command = f"taskkill /F /IM {process_name}"
                        else:
                            command = "shutdown /r /f /t 60"
                        
                        return {
                            "action": "Terminate and Execute Command",
                            "auto": "yes",
                            "command": command,
                            "reason": "Critical automated response required",
                            "threat_level": threat_level,
                            "intelligence_summary": threat_intel["summary"]
                        }
                
                elif threat_level == "HIGH":
                    if any(keyword in analysis_text for keyword in ["terminate", "kill", "stop", "block"]):
                        if process_name and process_name.lower() != "system":
                            command = f"taskkill /F /IM {process_name}"
                        else:
                            command = "net stop \"suspicious service\""
                        
                        return {
                            "action": "Terminate and Execute Command",
                            "auto": "yes",
                            "command": command,
                            "reason": "High threat requiring immediate process termination",
                            "threat_level": threat_level,
                            "intelligence_summary": threat_intel["summary"]
                        }
                    else:
                        return {
                            "action": "Terminate and Execute Command",
                            "auto": "no",
                            "command": f"taskkill /F /IM {process_name}" if process_name else "echo 'Review required'",
                            "reason": "High threat requiring manual review",
                            "threat_level": threat_level,
                            "intelligence_summary": threat_intel["summary"]
                        }
                
                elif threat_level == "MEDIUM":
                    if any(keyword in analysis_text for keyword in ["monitor", "alert", "watch", "observe"]):
                        return {
                            "action": "Alert Only",
                            "reason": "Medium threat requiring monitoring and analysis",
                            "threat_level": threat_level,
                            "intelligence_summary": threat_intel["summary"]
                        }
                    else:
                        return {
                            "action": "Terminate and Execute Command",
                            "auto": "no",
                            "command": f"taskkill /F /IM {process_name}" if process_name else "echo 'Manual review required'",
                            "reason": "Medium threat requiring careful manual assessment",
                            "threat_level": threat_level,
                            "intelligence_summary": threat_intel["summary"]
                        }
                
                else:  # LOW
                    return {
                        "action": "Alert Only",
                        "reason": "Low threat level - monitoring recommended",
                        "threat_level": threat_level,
                        "intelligence_summary": threat_intel["summary"]
                    }
                
            except Exception as e:
                logger.error(f"Error getting LLM response: {e}")
                # Fallback to rule-based decision
                
        # Fallback rule-based decision if LLM unavailable
        if threat_level == "CRITICAL":
            return {
                "action": "Terminate and Execute Command",
                "auto": "no",
                "command": "shutdown /r /f /t 300",
                "reason": "Critical threat detected - manual approval required",
                "threat_level": threat_level,
                "intelligence_summary": threat_intel["summary"]
            }
        elif threat_level == "HIGH":
            process_name = event_data.process_path.split("\\")[-1] if "\\" in event_data.process_path else event_data.process_path.split("/")[-1]
            return {
                "action": "Terminate and Execute Command",
                "auto": "yes",
                "command": f"taskkill /F /IM {process_name}" if process_name else "echo 'Process termination required'",
                "reason": "High threat requiring immediate response",
                "threat_level": threat_level,
                "intelligence_summary": threat_intel["summary"]
            }
        else:
            return {
                "action": "Alert Only",
                "reason": "Threat level does not require immediate action",
                "threat_level": threat_level,
                "intelligence_summary": threat_intel["summary"]
            }
            
    except Exception as e:
        logger.error(f"Error generating response recommendation: {e}")
        # Safe fallback
        return {
            "action": "Alert Only",
            "reason": f"Error in analysis: {str(e)}",
            "threat_level": "UNKNOWN",
            "intelligence_summary": "Analysis failed"
        }


@app.post("/analyze", response_model=Dict[str, Any])
async def analyze_security_event(event: SecurityEventRequest):
    """
    Analyze a security event and provide response recommendation.
    
    Args:
        event: Security event data
        
    Returns:
        Response recommendation (Alert Only or Terminate and Execute Command)
    """
    try:
        logger.info(f"Analyzing security event: {event.adaptive_event_type}")
        
        # Generate response recommendation
        recommendation = generate_response_recommendation(event)
        
        logger.info(f"Generated recommendation: {recommendation}")
        return recommendation
        
    except Exception as e:
        logger.error(f"Error analyzing security event: {e}")
        raise HTTPException(status_code=500, detail="Internal server error during event analysis")

@app.get("/ci_cd_test")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "ok",
        "timestamp": datetime.now().isoformat(),
        "services": {
            "knowledge_base": "connected" if graph else "disconnected",
            "llm": "ready" if llm else "not_ready"
        }
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "services": {
            "knowledge_base": "connected" if graph else "disconnected",
            "llm": "ready" if llm else "not_ready"
        }
    }


@app.get("/")
async def root():
    """Root endpoint with API information."""
    return {
        "service": "Cybersecurity Security Event Analysis API",
        "version": "1.0.0",
        "endpoints": {
            "analyze": "POST /analyze - Analyze security events",
            "health": "GET /health - Health check",
            "docs": "GET /docs - API documentation"
        }
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
