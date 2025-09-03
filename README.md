# 🛡️ Cybersecurity Framework Assistant

A comprehensive, AI-powered cybersecurity platform that unifies threat intelligence with compliance frameworks through an intelligent knowledge graph. The system provides both interactive chat interfaces and REST API services for advanced cybersecurity analysis and decision-making.

[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-green.svg)](https://fastapi.tiangolo.com/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.28+-red.svg)](https://streamlit.io/)
[![Neo4j](https://img.shields.io/badge/Neo4j-5.0+-yellow.svg)](https://neo4j.com/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## 🚀 Key Features

### 🎯 **Unified Knowledge Graph**

- **MITRE ATT&CK Framework**: Complete enterprise and ICS threat landscape with 1000+ techniques
- **Compliance Processing**: Intelligent document analysis for any compliance standard
- **Cross-Framework Intelligence**: Direct mappings between compliance controls and ATT&CK techniques
- **Real-time Knowledge Synthesis**: Dynamic relationships and correlation discovery

### 🤖 **Advanced Processing**

- **Smart Document Ingestion**: LLM-based extraction from compliance PDFs with auto-detection
- **Intelligent Framework Recognition**: Automatic identification of framework types and industries
- **Contextual Query Analysis**: Natural language understanding for cybersecurity questions
- **Adaptive Response Generation**: Framework-aware responses with cross-referencing

### 🏗️ **Production-Ready Architecture**

- **Neo4j Graph Database**: Scalable graph storage with optimized queries and indexing
- **Google Gemini Integration**: Advanced LLM capabilities for document understanding
- **FastAPI REST Services**: High-performance API with automatic documentation
- **Streamlit Web Interface**: Intuitive UI with real-time statistics and management
- **JWT Authentication**: Secure access control for both web and API interfaces

### 📊 **Comprehensive Framework Support**

#### Pre-loaded Intelligence

- ✅ **MITRE ATT&CK Enterprise**: Complete enterprise threat landscape (tactics, techniques, groups, software)
- ✅ **MITRE ATT&CK ICS**: Industrial control systems security framework

#### Processed Compliance Frameworks

- 🏥 **HIPAA**: Healthcare compliance and privacy protection requirements
- 💳 **PCI-DSS**: Payment card industry data security standards
- 🏛️ **NIST Cybersecurity Framework**: National cybersecurity guidelines
- 🔒 **CIS Controls**: Critical security controls implementation guide
- 📋 **ISO 27001**: Information security management standards
- 🔐 **SOC 2**: Service organization control requirements
- 🇺🇸 **FedRAMP**: Federal cloud security authorization
- 📄 **Custom Frameworks**: Upload any compliance document for processing

## 🛠️ Installation & Setup

### Prerequisites

- **Python 3.8+** with pip package manager
- **Neo4j Database** (Community or Enterprise Edition)
- **Google Gemini API Key** for LLM functionality
- **Git** for repository cloning

### 1. Clone Repository

```bash
git clone https://github.com/your-username/cyber-llm.git
cd cyber-llm
```

### 2. Install Dependencies

```bash
# Create virtual environment
python -m venv cyber_env
source cyber_env/bin/activate  # On Windows: cyber_env\Scripts\activate

# Install required packages
pip install -r requirements.txt
```

### 3. Environment Configuration

Create a `.env` file in the project root:

```env
# Neo4j Database Configuration
NEO4J_URI=bolt://localhost:7687
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=your_neo4j_password

# Google Gemini API Configuration
GEMINI_API_KEY=your_gemini_api_key
MODEL_NAME=gemini-1.5-flash

# Authentication Configuration
JWT_SECRET_KEY=your_jwt_secret_key
JWT_ALGORITHM=HS256
JWT_EXPIRATION_HOURS=24

# Application Configuration
USERNAME=admin
PASSWORD=secure_password
```

### 4. Neo4j Database Setup

```bash
# Install Neo4j Desktop or use Docker
docker run -d \
  --name neo4j \
  -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/your_password \
  neo4j:latest

# Or start local Neo4j instance
neo4j start
```

### 5. Initialize Knowledge Base

```bash
# Start the application to auto-initialize ATT&CK data
streamlit run app.py
```

## 🎮 Usage Guide

### Web Interface (Streamlit)

```bash
streamlit run app.py
```

**Features:**

- **💬 Interactive Chat**: Natural language queries about threats and compliance
- **📊 Knowledge Base Statistics**: Real-time framework metrics and node counts
- **🔍 Advanced Search**: Multi-criteria search across all frameworks
- **⚙️ Document Management**: Upload and process compliance documents
- **🛡️ Framework List**: View ingested frameworks and their status
- **⚡ Quick Actions**: Reset knowledge base and logout functionality

### REST API Service (FastAPI)

```bash
uvicorn api_service:app --host 0.0.0.0 --port 8000
```

**Endpoints:**

- POST `/login` – Authenticate and obtain JWT token
- POST `/analyze` – Analyze security events
- GET `/health` – Service health check
- GET `/docs` – Interactive API documentation (Swagger UI)

### Run with Docker

```bash
docker build -t cyber-llm .
docker run -p 8000:8000 -p 8501:8501 --env-file .env cyber-llm
```

Or using Compose:

```bash
docker compose up --build
```

## 📈 AI Processing Capabilities

### Intelligent Document Analysis

The system uses advanced LLM techniques to extract structured information from compliance documents:

**Automated Extraction:**

- **Regulatory Bodies**: Identifying publishing organizations and authorities
- **Framework Metadata**: Versions, publication dates, scope, and applicability
- **Control Structures**: Individual requirements with implementation guidance
- **Industry Classifications**: Target sectors and regulatory environments
- **Threat Correlations**: Mapping controls to relevant ATT&CK techniques

**Example Processing Output:**

```json
{
  "regulatory_body": {
    "name": "Department of Health and Human Services",
    "description": "Federal agency responsible for HIPAA enforcement"
  },
  "framework": {
    "name": "Health Insurance Portability and Accountability Act",
    "version": "Administrative Simplification Rules 2013"
  },
  "controls": [
    {
      "control_id": "§164.308(a)(1)",
      "name": "Security Officer Assignment",
      "description": "Assign responsibility for security functions",
      "potential_attack_techniques": ["T1078.001", "T1098.001"],
      "implementation_guidance": "Designate a security officer responsible for developing and implementing security policies"
    }
  ]
}
```

## 🔍 Query Examples & Use Cases

### Cross-Framework Intelligence Queries

```
"What HIPAA controls help mitigate credential access techniques?"
"Show me PCI-DSS requirements related to T1055 Process Injection"
"Which compliance frameworks address privilege escalation attacks?"
"Map ISO 27001 controls to lateral movement techniques"
```

### Threat Analysis Questions

```
"Explain the ATT&CK technique T1566.001 Spearphishing Attachment"
"What techniques does APT29 commonly use for initial access?"
"Show me mitigations for T1059 Command and Scripting Interpreter"
"List all techniques in the Defense Evasion tactic"
```

### Compliance Guidance Requests

```
"What are the key requirements for data encryption in healthcare?"
"How should financial institutions implement access controls?"
"What monitoring capabilities are required for cloud compliance?"
"Explain the differences between SOC 2 Type I and Type II"
```

## 🏗️ System Architecture

### Core Components

```
├── Frontend Layer (Streamlit)
│   ├── Interactive Chat Interface
│   ├── Knowledge Base Management
│   ├── Real-time Statistics Dashboard
│   └── Document Processing Interface
├── API Layer (FastAPI)
│   ├── Security Event Analysis
│   ├── JWT Authentication Service
│   ├── RESTful Endpoints
│   └── Interactive Documentation
├── AI Processing Engine
│   ├── Google Gemini Integration
│   ├── Document Understanding
│   ├── Structured Data Extraction
│   └── Cross-framework Correlation
├── Graph Database (Neo4j)
│   ├── ATT&CK Data Model
│   ├── Compliance Schema
│   ├── Relationship Management
│   └── Performance Optimization
└── Data Ingestion Pipeline
    ├── ATT&CK STIX Processing
    ├── Smart PDF Analysis
    ├── Schema Validation
    └── Automated Mapping
```

### Data Flow Architecture

1. **📄 Document Upload** → Secure file handling and validation
2. **🤖 LLM Analysis** → Framework detection and content extraction
3. **🏗️ Node Creation** → Structured data transformation
4. **🔗 Relationship Building** → Cross-framework correlation mapping
5. **🎯 Query Processing** → Intelligent response generation

## 📊 Performance & Scalability

### Database Optimization

- **Indexed Properties**: Optimized for fast text and property searches
- **Unique Constraints**: Data integrity enforcement and duplicate prevention
- **Relationship Indexing**: Fast traversal for complex graph queries
- **Query Optimization**: Efficient Cypher patterns for large datasets

### Processing Efficiency

- **Asynchronous Operations**: Non-blocking document processing
- **Caching Strategies**: Statistics and query result caching
- **Batch Processing**: Efficient handling of large document sets
- **Error Recovery**: Graceful handling of processing failures

### Scalability Features

- **Horizontal Scaling**: Support for Neo4j clustering
- **API Rate Limiting**: Configurable request throttling
- **Connection Pooling**: Efficient database connection management
- **Resource Monitoring**: Performance metrics and health checks

## 🔧 Development & Testing

### Running Tests

```bash
# Install development dependencies
pip install pytest pytest-asyncio pytest-cov

# Run test suite
pytest tests/ -v

# Run with coverage reporting
pytest --cov=src tests/ --cov-report=html
```

### Code Quality Tools

```bash
# Format code with Black
black src/ *.py

# Type checking with MyPy
mypy src/

# Linting with Flake8
flake8 src/ --max-line-length=88

# Security scanning
bandit -r src/
```

### Development Server

```bash
# Chat interface with auto-reload
streamlit run app.py --server.runOnSave=true

# API service with auto-reload
uvicorn api_service:app --reload --host 0.0.0.0 --port 8000
```

## 🚀 Deployment Options

### Local Development

```bash
# Start chat interface
streamlit run app.py

# Start API service
python api_service.py
```

### Docker Deployment

```bash
# Build production image
docker build -t cyber-llm:latest .

# Run chat interface
docker run -p 8501:8501 --env-file .env cyber-llm:latest

# Run API service
docker run -p 8000:8000 --env-file .env cyber-llm:latest python api_service.py
```

### Production Deployment

```bash
# Using Docker Compose
docker-compose up -d

# Using Kubernetes
kubectl apply -f k8s/

# Manual deployment with Gunicorn
gunicorn api_service:app -w 4 -k uvicorn.workers.UvicornWorker
```

## 🔐 Security Considerations

### Authentication & Authorization

- **JWT-based Authentication**: Secure token-based access control
- **Session Management**: Secure state handling with expiration
- **Role-based Access**: Configurable user permissions
- **API Key Management**: Secure external service integration

### Data Protection

- **Encrypted Connections**: TLS/SSL for all network communications
- **Environment Variables**: Secure configuration management
- **Input Validation**: Comprehensive sanitization and validation
- **Error Handling**: Secure error messages without information leakage

### Security Best Practices

- **Parameter Binding**: SQL injection prevention in Neo4j queries
- **Rate Limiting**: Protection against abuse and DoS attacks
- **CORS Configuration**: Secure cross-origin resource sharing
- **Audit Logging**: Comprehensive security event logging

## 📚 API Reference

### Authentication Endpoints

- **POST `/login`**: User authentication with credentials
- **GET `/user-info`**: Current user profile and permissions

### Analysis Endpoints

- **POST `/analyze`**: Comprehensive security event analysis
- **GET `/health`**: Service health check and status information

### Security Event Analysis Request Format

```json
{
  "adaptive_event_type": "Credential Stealing with Mimikatz",
  "base_event_type": "Virtual Memory Access",
  "component": "EDR",
  "device_name": "desktop-tqja799",
  "event_group": "DEFENSEPLUS",
  "event_time": "2025-07-03 17:27:45.710+07:00",
  "process_creation_time": "2025-07-03 16:34:21.960+07:00",
  "logged_on_user": "SYSTEM@NT AUTHORITY",
  "process_hash": "3fd857449ab04f2293985d1d770e0520466bd65c",
  "process_parent_tree": [
    {
      "prcsCreationTime": "2025-07-03 16:34:19.728+07:00",
      "prcsHash": "26d9650e827f35cb38c4560ad925d2bd4a7e6f43",
      "prcsPID": 1400,
      "prcsPath": "C:\\Windows\\System32\\wininit.exe",
      "prcsUserDomain": "NT AUTHORITY",
      "prcsUserName": "SYSTEM@NT AUTHORITY",
      "prcsVerdict": "Safe"
    },
    {
      "prcsCreationTime": "2025-07-03 16:34:19.809+07:00",
      "prcsHash": "2598905e5b093aa6116175a4a970a7cb21ab3231",
      "prcsPID": 1540,
      "prcsPath": "C:\\Windows\\System32\\services.exe",
      "prcsUserDomain": "NT AUTHORITY",
      "prcsUserName": "SYSTEM@NT AUTHORITY",
      "prcsVerdict": "Safe"
    },
    {
      "prcsCreationTime": "2025-07-03 16:34:21.079+07:00",
      "prcsHash": "3fd857449ab04f2293985d1d770e0520466bd65c",
      "prcsPID": 4288,
      "prcsPath": "C:\\Program Files\\RustDesk\\RustDesk.exe",
      "prcsUserDomain": "NT AUTHORITY",
      "prcsUserName": "SYSTEM@NT AUTHORITY",
      "prcsVerdict": "Unknown"
    }
  ],
  "process_path": "C:\\Program Files\\RustDesk\\RustDesk.exe",
  "process_user_domain": "NT AUTHORITY",
  "process_user_name": "SYSTEM@NT AUTHORITY",
  "process_verdict": "Unknown"
}
```

### Security Event Analysis Response Format

```json
{
  "incident_id": "DEFENSEPLUS-desktop-tqja799-1720002465",
  "technique_info": {
    "id": "T1003.001",
    "name": "OS Credential Dumping: LSASS Memory",
    "description": "Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS).",
    "tactic": "Credential Access"
  },
  "context": {
    "associated_software": ["Mimikatz", "Pypykatz", "Cobalt Strike"],
    "associated_groups": ["APT28", "FIN6", "Lazarus Group"],
    "process_of_interest": {
      "name": "RustDesk.exe",
      "path": "C:\\Program Files\\RustDesk\\RustDesk.exe",
      "pid": 4288,
      "hash": "3fd857449ab04f2293985d1d770e0520466bd65c"
    }
  },
  "countermeasures": [
    {
      "category": "Containment",
      "action": "Isolate the device from the network to prevent lateral movement.",
      "command": "netsh advfirewall firewall add rule name=\"IsolateDevice\" dir=in action=block"
    },
    {
      "category": "Eradication",
      "action": "Terminate the suspicious process immediately to stop the credential dumping activity.",
      "command": "taskkill /PID 4288 /F"
    }
  ]
}
```

**Note**: All response data is fetched from the knowledge base, while countermeasures are generated by the LLM.

## 🤝 Contributing

We welcome contributions to improve the Cybersecurity Framework Assistant!

### Development Setup

1. Fork the repository and clone your fork
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Install development dependencies: `pip install -r requirements-dev.txt`
4. Make your changes and add tests
5. Run the test suite and ensure all tests pass
6. Submit a pull request with a clear description

### Contribution Guidelines

- Follow PEP 8 style guide for Python code
- Add comprehensive docstrings for all functions and classes
- Include unit tests for new functionality
- Update documentation for significant changes
- Ensure compatibility with existing API interfaces

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📞 Support & Contact

For questions, issues, or contributions:

- **🐛 Bug Reports**: [Create an issue](https://github.com/your-username/cyber-llm/issues)
- **💡 Feature Requests**: [Open a discussion](https://github.com/your-username/cyber-llm/discussions)
- **📖 Documentation**: Comprehensive guides in the `/docs` folder
- **💬 Community**: Join our discussions for support and collaboration

## 🔗 Related Resources

- **MITRE ATT&CK**: [Official Framework Documentation](https://attack.mitre.org/)
- **Neo4j**: [Graph Database Documentation](https://neo4j.com/docs/)
- **FastAPI**: [Modern Python Web Framework](https://fastapi.tiangolo.com/)
- **Streamlit**: [Interactive Web Applications](https://streamlit.io/)
- **Google Gemini**: [Advanced AI Language Models](https://cloud.google.com/ai)

---

**Built with ❤️ for the cybersecurity community**

_Empowering security professionals with AI-driven threat intelligence and compliance automation_
