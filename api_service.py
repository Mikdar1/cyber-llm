"""
Security Event Analysis API using FastAPI.

Provides a protected /analyze endpoint that maps events to ATT&CK techniques
with LLM-backed context and a deterministic fallback. Includes /login for JWT
issuance and /health for service status. Initializes a minimal knowledge base
on startup if empty.
"""

import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from src.api.llm_service import get_llm
from src.auth.auth import auth_manager, get_current_user_from_token
from src.cybersecurity.attack_ingestion import AttackIngestion
from src.knowledge_base.database import create_graph_connection
from src.knowledge_base.graph_operations import get_context_from_knowledge_base

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

security = HTTPBearer(auto_error=False)

graph = None
llm = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize services on startup; log status on shutdown."""
    global graph, llm
    # Startup
    try:
        logger.info("Initializing enhanced cybersecurity API...")
        graph = create_graph_connection()
        llm = get_llm()
        initialize_api_knowledge_base(graph)
        logger.info("Enhanced API services initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize services: {e}")
        logger.warning("API starting with limited functionality")

    yield

    # Shutdown (cleanup if needed)
    logger.info("Shutting down API services...")


app = FastAPI(
    title="Enhanced Cybersecurity Security Event Analysis API",
    description="API for analyzing security events using unified cybersecurity threat intelligence",
    version="2.0.0",
    lifespan=lifespan,
)


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
):
    """Validate JWT from Authorization header and return username."""
    # Return a clear 401 instead of default 403 when header is missing
    if credentials is None or not getattr(credentials, "credentials", None):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated. Use /login, then click Authorize in /docs.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    username = get_current_user_from_token(token)

    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return username


def initialize_api_knowledge_base(graph_connection):
    """Load ATT&CK data if the database is empty."""
    try:
        check_query = "MATCH (n) RETURN count(n) as count"
        result = graph_connection.query(check_query)
        existing_count = result[0]["count"] if result else 0

        logger.info(f"Knowledge base contains {existing_count:,} nodes")

        if existing_count == 0:
            logger.info("Initializing ATT&CK data for API...")
            attack_ingester = AttackIngestion()
            domains = ["enterprise"]
            attack_ingester.run_full_ingestion(graph_connection, domains)
            logger.info("ATT&CK data ingestion completed for API")
        else:
            logger.info("Knowledge base already initialized")

    except Exception as e:
        logger.error(f"Error initializing knowledge base: {e}")
        # Continue: API can still operate with limited functionality


# Enhanced Pydantic models
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
    # Accept both a list of process dicts or a dict keyed by numeric strings
    process_parent_tree: Union[List[Dict[str, Any]], Dict[str, Any]]
    process_path: str
    process_user_domain: str
    process_user_name: str
    process_verdict: str


class TechniqueInfo(BaseModel):
    """ATT&CK technique details."""

    id: str
    name: str
    description: str
    tactic: str


class ProcessOfInterest(BaseModel):
    """Process of interest."""

    name: str
    path: str
    pid: int
    hash: str


class ContextInfo(BaseModel):
    """Context for the event."""

    associated_software: List[str]
    associated_groups: List[str]
    process_of_interest: ProcessOfInterest


class CountermeasureAction(BaseModel):
    """Countermeasure action and command."""

    category: str
    action: str
    command: str


class SecurityEventResponse(BaseModel):
    """Structured analysis response."""

    incident_id: str
    technique_info: TechniqueInfo
    context: ContextInfo
    countermeasures: List[CountermeasureAction]


# Authentication models
class LoginRequest(BaseModel):
    """Login request."""

    username: str
    password: str


class LoginResponse(BaseModel):
    """Login response."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int


class UserInfo(BaseModel):
    """Authenticated user info."""

    username: str
    authenticated: bool


def analyze_security_event_with_kb(event_data: SecurityEventRequest) -> Dict[str, Any]:
    """Analyze the event using the knowledge base and LLM; return structured result."""
    # Generate incident ID
    incident_id = f"{event_data.event_group}-{event_data.device_name}-{int(datetime.now().timestamp())}"

    try:
        analysis_query = f"""
        Analyze this security event:
        
        Event Type: {event_data.adaptive_event_type}
        Process: {event_data.process_path}
        User: {event_data.logged_on_user}
        Component: {event_data.component}
        
        Process Tree:
        {json.dumps(event_data.process_parent_tree, indent=2)}
        
        What ATT&CK techniques are relevant to this event?
        """

        kb_context = (
            get_context_from_knowledge_base(graph, analysis_query)
            if graph
            else "Knowledge base unavailable"
        )

        # Resolve process of interest robustly from provided tree
        def _extract_processes(
            tree: Union[List[Any], Dict[str, Any]],
        ) -> List[Dict[str, Any]]:
            items: List[Dict[str, Any]] = []
            if isinstance(tree, list):
                for elem in tree:
                    if isinstance(elem, dict) and all(
                        k in elem for k in ["prcsPath", "prcsPID", "prcsHash"]
                    ):
                        items.append(elem)
                    elif isinstance(elem, dict):
                        for v in elem.values():
                            if isinstance(v, dict) and "prcsPID" in v:
                                items.append(v)
            elif isinstance(tree, dict):
                # Handle dict-of-indexed-objects like {"0": {...}, "1": {...}}
                def _key_sort(k: Any) -> Any:
                    try:
                        return int(k)
                    except Exception:
                        return str(k)

                for k in sorted(list(tree.keys()), key=_key_sort):
                    v = tree[k]
                    if isinstance(v, dict) and "prcsPID" in v:
                        items.append(v)
            return items

        proc_items = _extract_processes(event_data.process_parent_tree)
        poi = None
        if proc_items:
            # Try exact path match first
            for it in proc_items:
                if (
                    str(it.get("prcsPath", "")).lower()
                    == str(event_data.process_path).lower()
                ):
                    poi = it
                    break
            if poi is None:
                poi = proc_items[-1]
        pid = int(poi.get("prcsPID", 0)) if poi else 0

        analysis_prompt = f"""
        You are a cybersecurity threat analyst. Analyze this security event and provide a structured response.

        Security Event Details:
        - Event Type: {event_data.adaptive_event_type}
        - Base Event: {event_data.base_event_type}
        - Process Path: {event_data.process_path}
        - Process Verdict: {event_data.process_verdict}
        - User Context: {event_data.logged_on_user}
        - Component: {event_data.component}
        - Device: {event_data.device_name}

        Process Tree:
        {json.dumps(event_data.process_parent_tree, indent=2)}

        Knowledge Base Context:
        {kb_context}

        Based on this analysis, provide a JSON response with the following structure:
        {{
            "technique_info": {{
                "id": "ATT&CK technique ID (e.g., T1003.001)",
                "name": "Technique name",
                "description": "Detailed description",
                "tactic": "Primary tactic"
            }},
            "context": {{
                "associated_software": ["List of relevant malware/tools"],
                "associated_groups": ["List of threat groups that use this technique"],
                "process_of_interest": {{
                    "name": "Process filename",
                    "path": "{event_data.process_path}",
                    "pid": {pid},
                    "hash": "{event_data.process_hash}"
                }}
            }},
            "countermeasures": [
                {{
                    "category": "Containment",
                    "action": "Detailed action description",
                    "command": "Specific PowerShell/CMD command"
                }},
                {{
                    "category": "Eradication", 
                    "action": "Detailed action description",
                    "command": "Specific PowerShell/CMD command"
                }}
            ]
        }}

        Ensure:
        1. Technique ID is accurate based on the event type
        2. Commands are Windows-compatible (PowerShell/CMD)
        3. Actions are specific and actionable
        4. Software and groups are real from ATT&CK framework

        Return only valid JSON without additional text.
        """

        if not llm:
            return create_fallback_response(event_data, incident_id, "LLM unavailable")

        llm_response = llm.invoke(analysis_prompt)
        response_text = (
            llm_response.content
            if hasattr(llm_response, "content")
            else str(llm_response)
        )

        try:
            if isinstance(response_text, list):
                response_text = str(response_text[0]) if response_text else "{}"
            elif not isinstance(response_text, str):
                response_text = str(response_text)

            analysis_result = json.loads(response_text)
            required_keys = {"technique_info", "context", "countermeasures"}
            if not isinstance(analysis_result, dict) or not required_keys.issubset(
                analysis_result.keys()
            ):
                return create_fallback_response(
                    event_data, incident_id, "Incomplete LLM response"
                )

            analysis_result["incident_id"] = incident_id
            return analysis_result

        except json.JSONDecodeError:
            return create_fallback_response(event_data, incident_id)

    except Exception as e:
        logger.error(f"Error in security event analysis: {e}")
        return create_fallback_response(event_data, incident_id, str(e))


def create_fallback_response(
    event_data: SecurityEventRequest, incident_id: str, error: Optional[str] = None
) -> Dict[str, Any]:
    """Create a deterministic response when LLM or parsing fails."""
    # Map common event types to techniques
    technique_mapping = {
        "credential stealing": {
            "id": "T1003.001",
            "name": "OS Credential Dumping: LSASS Memory",
            "tactic": "Credential Access",
        },
        "mimikatz": {
            "id": "T1003.001",
            "name": "OS Credential Dumping: LSASS Memory",
            "tactic": "Credential Access",
        },
        "privilege escalation": {
            "id": "T1055",
            "name": "Process Injection",
            "tactic": "Privilege Escalation",
        },
    }

    event_type_lower = event_data.adaptive_event_type.lower()
    technique = None

    for key, tech in technique_mapping.items():
        if key in event_type_lower:
            technique = tech
            break

    if not technique:
        technique = {
            "id": "T1059",
            "name": "Command and Scripting Interpreter",
            "tactic": "Execution",
        }

    # Derive pid from provided process tree (list or dict)
    pid = 0
    try:

        def _collect(tree: Union[List[Any], Dict[str, Any]]) -> List[Dict[str, Any]]:
            out: List[Dict[str, Any]] = []
            if isinstance(tree, list):
                for e in tree:
                    if isinstance(e, dict):
                        out.append(e)
                        for v in e.values():
                            if isinstance(v, dict):
                                out.append(v)
            elif isinstance(tree, dict):
                for v in tree.values():
                    if isinstance(v, dict):
                        out.append(v)
            return out

        procs = _collect(event_data.process_parent_tree)
        if procs:
            pid = int(procs[-1].get("prcsPID", 0))
    except Exception:
        pid = 0

    fallback_response = {
        "incident_id": incident_id,
        "technique_info": {
            "id": technique["id"],
            "name": technique["name"],
            "description": f"Potential {technique['name']} activity detected based on event type: {event_data.adaptive_event_type}",
            "tactic": technique["tactic"],
        },
        "context": {
            "associated_software": ["Unknown"],
            "associated_groups": ["Unknown"],
            "process_of_interest": {
                "name": (
                    event_data.process_path.split("\\")[-1]
                    if "\\" in event_data.process_path
                    else event_data.process_path
                ),
                "path": event_data.process_path,
                "pid": pid,
                "hash": event_data.process_hash,
            },
        },
        "countermeasures": [
            {
                "category": "Containment",
                "action": f"Isolate the device {event_data.device_name} from the network to prevent lateral movement.",
                "command": 'netsh advfirewall firewall add rule name="IsolateDevice" dir=in action=block',
            },
            {
                "category": "Eradication",
                "action": f"Terminate the suspicious process (PID: {pid}) to stop the malicious activity.",
                "command": f"taskkill /PID {pid} /F",
            },
        ],
    }

    if error:
        fallback_response["analysis_note"] = f"Fallback analysis used due to: {error}"

    return fallback_response


@app.post("/login", response_model=LoginResponse)
async def login(credentials: LoginRequest):
    """Authenticate user and return JWT token."""
    try:
        if auth_manager.authenticate_user(credentials.username, credentials.password):
            token_data = auth_manager.create_access_token({"sub": credentials.username})
            return LoginResponse(access_token=token_data, expires_in=3600)
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password",
            )
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication service error",
        )


@app.post("/analyze", response_model=SecurityEventResponse)
async def analyze_security_event(
    event: SecurityEventRequest, current_user: str = Depends(get_current_user)
):
    """Analyze the event and return technique mapping, context, and countermeasures."""
    try:
        logger.info(f"Analyzing security event for user: {current_user}")
        logger.info(f"Event type: {event.adaptive_event_type}")

        # Perform comprehensive analysis
        analysis_result = analyze_security_event_with_kb(event)

        # Convert to response model
        response = SecurityEventResponse(
            incident_id=analysis_result["incident_id"],
            technique_info=TechniqueInfo(**analysis_result["technique_info"]),
            context=ContextInfo(**analysis_result["context"]),
            countermeasures=[
                CountermeasureAction(**cm) for cm in analysis_result["countermeasures"]
            ],
        )

        logger.info(f"Analysis completed for incident: {response.incident_id}")
        return response

    except Exception as e:
        logger.error(f"Error analyzing security event: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis failed: {str(e)}",
        )


@app.get("/health")
async def health_check():
    """Return service and dependency status."""
    try:
        health_status = {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "version": "2.0.0",
            "components": {},
        }

        if graph:
            try:
                result = graph.query("MATCH (n) RETURN count(n) as count LIMIT 1")
                health_status["components"]["database"] = {
                    "status": "healthy",
                    "nodes": result[0]["count"] if result else 0,
                }
            except Exception as e:
                health_status["components"]["database"] = {
                    "status": "unhealthy",
                    "error": str(e),
                }
        else:
            health_status["components"]["database"] = {"status": "not_initialized"}

        if llm:
            health_status["components"]["llm"] = {"status": "healthy"}
        else:
            health_status["components"]["llm"] = {"status": "not_initialized"}

        return health_status

    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.now().isoformat(),
        }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
