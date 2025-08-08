# 🛡️ Cybersecurity Multi-Framework Assistant

A comprehensive cybersecurity platform that provides both an interactive chat interface and a REST API for threat intelligence analysis across multiple cybersecurity frameworks.

## 🚀 Features

### 🎯 Multi-Framework Support

- **MITRE ATT&CK**: Threat tactics, techniques, and procedures
- **CIS Controls v8.1**: Critical security controls and safeguards
- **NIST Cybersecurity Framework 2.0**: Core functions and categories
- **HIPAA Administrative Simplification**: Healthcare regulatory compliance
- **FFIEC IT Handbook**: Financial institution examination procedures
- **PCI DSS v4.0.1**: Payment card industry security standards

### 🤖 Intelligence Capabilities

- **Interactive Chat Interface**: Ask questions across all supported frameworks
- **REST API Service**: Automated security event analysis and response recommendations
- **Cross-Framework Analysis**: Explore relationships between different standards
- **Threat Intelligence**: Real-time threat analysis and risk assessment
- **Citation Tracking**: Complete source attribution for all framework elements

### 🏗️ Technical Architecture

- **Neo4j Graph Database**: Complex relationship modeling across frameworks
- **AI-Powered Responses**: Google Gemini LLM for intelligent cybersecurity insights
- **FastAPI REST Service**: High-performance API for security event analysis
- **Streamlit Chat Interface**: Interactive web-based exploration
- **Document Processing**: PDF parsing and structured data extraction
- **JWT Authentication**: Secure token-based authentication for both chat and API services
- **Session Management**: Streamlit session state handling for user authentication
- **Environment Configuration**: Configurable credentials and API keys via environment variables

## 📋 Prerequisites

- Python 3.8+
- Neo4j Database (local or cloud instance)
- Google Gemini API key
- Internet connection for framework data fetching
- Framework documents (PDF files in `documents/` folder)

## 🛠️ Installation

1. **Clone the repository**:

   ```bash
   git clone <repository-url>
   cd cybersecurity-multi-framework-assistant
   ```

2. **Install dependencies**:

   ```bash
   pip install -r requirements.txt
   ```

3. **Set up environment variables**:
   Copy `.env.example` to `.env` and configure:

   ```env
   # Core Configuration
   GEMINI_API_KEY=your_gemini_api_key_here
   MODEL_NAME=gemini-2.5-flash-preview-05-20
   NEO4J_URI=your_neo4j_uri_here
   NEO4J_USERNAME=your_neo4j_username
   NEO4J_PASSWORD=your_neo4j_password
   NEO4J_DATABASE=neo4j

   # Authentication Settings
   APP_USERNAME=admin
   APP_PASSWORD=cybersec2025
   JWT_SECRET_KEY=your_jwt_secret_key_change_this_in_production
   JWT_ALGORITHM=HS256
   JWT_ACCESS_TOKEN_EXPIRE_MINUTES=1440
   ```

4. **Add framework documents**:
   Place the following PDF documents in the `documents/` folder:

   - `CIS_Controls__v8.1_Guide__2024_06.pdf`
   - `NIST.CSWP.29.pdf`
   - `hipaa-simplification-201303.pdf`
   - `2016- it-handbook-information-security-booklet.pdf`
   - `PCI-DSS-v4_0_1.pdf`

5. **Run the chat application**:

   ```bash
   streamlit run app.py
   ```

6. **Run the API service** (optional):

   ```bash
   # Using uvicorn directly (if installed globally)
   uvicorn api_service:app --host 0.0.0.0 --port 8000

   # Or using Python module (recommended)
   python -m uvicorn api_service:app --host 0.0.0.0 --port 8000
   ```

The chat interface will be available at `http://localhost:8501` and the API at `http://localhost:8000`.

## 🐳 Docker Deployment

### Chat Application

1. **Build the Docker image**:

   ```bash
   docker build -t cybersecurity-platform .
   ```

2. **Run the chat application**:
   ```bash
   docker run -p 8501:8501 --env-file .env cybersecurity-platform
   ```

### API Service

1. **Run the API service**:
   ```bash
   docker run -p 8000:8000 --env-file .env cybersecurity-platform uvicorn api_service:app --host 0.0.0.0 --port 8000
   ```

### Multi-Service Deployment

Use Docker Compose to run both services:

```yaml
# docker-compose.yml
version: "3.8"
services:
  chat-app:
    build: .
    ports:
      - "8501:8501"
    env_file: .env

  api-service:
    build: .
    ports:
      - "8000:8000"
    env_file: .env
    command: uvicorn api_service:app --host 0.0.0.0 --port 8000
```

Run with: `docker-compose up`

## 💡 Usage

### 🔐 Authentication

Both the Streamlit chat application and FastAPI service require authentication:

**Default Credentials:**

- **Username**: `admin`
- **Password**: `cybersec2025`

> ⚠️ **Important**: Change these credentials in production by updating the environment variables.

### 🤖 REST API Service

The API provides automated security event analysis for integration with security tools.

#### Authentication

**1. Get Access Token:**

```bash
curl -X POST "http://localhost:8000/login" \
     -H "Content-Type: application/json" \
     -d '{"username": "admin", "password": "cybersec2025"}'
```

**Response:**

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
```

**2. Use Token in Requests:**

```bash
TOKEN="your_jwt_token_here"
curl -X POST "http://localhost:8000/analyze" \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{...event_data...}'
```

#### Endpoint: `POST /analyze` (Authentication Required)

**Event Data Format:**

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
  "process_parent_tree": {
    "0": {
      "prcsCreationTime": "2025-07-03 16:34:19.728+07:00",
      "prcsHash": "26d9650e827f35cb38c4560ad925d2bd4a7e6f43",
      "prcsPID": 1400,
      "prcsPath": "C:\\Windows\\System32\\wininit.exe",
      "prcsUserDomain": "NT AUTHORITY",
      "prcsUserName": "SYSTEM@NT AUTHORITY",
      "prcsVerdict": "Safe"
    }
  },
  "process_path": "C:\\Program Files\\RustDesk\\RustDesk.exe",
  "process_user_domain": "NT AUTHORITY",
  "process_user_name": "SYSTEM@NT AUTHORITY",
  "process_verdict": "Unknown"
}
```

**Response Formats:**

```json
{ "action": "Alert Only" }
```

```json
{
  "action": "Terminate and Execute Command",
  "auto": "yes",
  "command": "shutdown /r /f /t 0"
}
```

```json
{
  "action": "Terminate and Execute Command",
  "auto": "no",
  "command": "shutdown /r /f /t 0"
}
```

### 💬 Interactive Chat Interface

- **ATT&CK Questions**: "Tell me about T1055 Process Injection"
- **CIS Controls**: "What are the CIS Controls for network security?"
- **NIST Framework**: "Explain the NIST Cybersecurity Framework Protect function"
- **HIPAA Compliance**: "What are HIPAA requirements for data encryption?"
- **Cross-Framework**: "How do CIS Controls relate to NIST CSF categories?"
- **PCI DSS**: "What are the PCI DSS requirements for cardholder data?"

### Knowledge Base Exploration

- **Multi-Framework Statistics**: View counts across all supported frameworks
- **Framework-Specific Browsing**: Explore controls, techniques, and requirements by framework
- **Cross-Framework Relationships**: Discover connections between different standards
- **Citation Tracking**: Access source documents and references
- **Compliance Mapping**: Map requirements across regulatory frameworks

## 🏗️ Architecture

```
├── src/
│   ├── cybersecurity/              # Multi-framework data ingestion
│   │   ├── __init__.py
│   │   ├── attack_ingestion.py     # MITRE ATT&CK ingestion
│   │   ├── cis_ingestion.py        # CIS Controls ingestion
│   │   ├── nist_ingestion.py       # NIST CSF ingestion
│   │   ├── hipaa_ingestion.py      # HIPAA regulatory ingestion
│   │   ├── ffiec_ingestion.py      # FFIEC examination procedures
│   │   └── pci_dss_ingestion.py    # PCI DSS security standards
│   ├── knowledge_base/             # Graph database operations
│   │   ├── database.py             # Neo4j connection
│   │   └── graph_operations.py     # Multi-framework queries
│   ├── api/                        # LLM integration
│   │   └── llm_service.py          # Gemini API wrapper
│   ├── auth/                       # Authentication
│   │   └── auth.py                 # Authentication logic
│   ├── web/                        # UI components
│   │   ├── components.py           # Streamlit components
│   │   └── ui.py                  # CSS styles
│   ├── utils/                      # Utilities
│   │   └── initialization.py   # App initialization
│   └── config/                  # Configuration
│       └── settings.py          # Environment settings
├── api_service.py               # REST API service
├── app.py                       # Chat application
├── test_api.py                  # API testing script
├── docker-compose.yml           # Multi-service deployment
├── requirements.txt             # Dependencies
├── Dockerfile                   # Container configuration
└── README.md                    # This file
```

## 🔧 Configuration

### Neo4j Setup

The application requires a Neo4j database instance. You can use:

- Neo4j Desktop (local development)
- Neo4j Aura (cloud service)
- Self-hosted Neo4j instance

### Environment Variables

- `GEMINI_API_KEY`: Your Google Gemini API key
- `NEO4J_URI`: Neo4j connection URI
- `NEO4J_USERNAME`: Database username
- `NEO4J_PASSWORD`: Database password
- `NEO4J_DATABASE`: Database name (usually 'neo4j')

## 🔍 Data Sources

The application automatically ingests data from multiple cybersecurity frameworks:

- **NIST Cybersecurity Framework**: Core framework controls and guidelines
- **CIS Controls**: Critical security controls and implementation guidance
- **MITRE ATT&CK Framework**: Latest techniques, tactics, and procedures
- **FFIEC IT Handbook**: Financial sector cybersecurity requirements
- **HIPAA Security**: Healthcare data protection requirements
- **PCI DSS**: Payment card industry security standards

## 🚨 Security Considerations

- Store API keys securely in environment variables
- Use HTTPS in production deployments
- Change default authentication credentials for production use
- Use strong JWT secret keys in production
- Regularly update dependencies for security patches
- Consider network security for Neo4j database access
- Implement proper session management for multi-user environments

## 🔄 Data Updates

The application fetches the latest framework data on initialization. To update:

1. Use the "Re-ingest Framework Data" button in the sidebar
2. Or restart the application to fetch fresh data

## 🔗 API Integration

The REST API service can be integrated with security tools and SIEM systems:

1. **Start the API service**: `python -m uvicorn api_service:app --host 0.0.0.0 --port 8000`
2. **Send security events**: POST to `/analyze` endpoint
3. **Receive recommendations**: Get automated response actions
4. **Health monitoring**: Use `/health` endpoint for service status

## 📚 API Documentation

### Endpoints

- **POST /analyze** - Analyze security events and get response recommendations
- **GET /health** - Service health check
- **GET /** - API information and available endpoints
- **GET /docs** - Interactive API documentation (Swagger UI)
- **GET /redoc** - Alternative API documentation

### Testing the API

1. **Start the API service**:

   ```bash
   python -m uvicorn api_service:app --host 0.0.0.0 --port 8000
   ```

2. **Test with the provided script**:

   ```bash
   python test_api.py
   ```

3. **Access interactive documentation**:
   - Swagger UI: http://localhost:8000/docs
   - ReDoc: http://localhost:8000/redoc

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📝 License

[Add your license information here]

## 🆘 Support

For issues and questions:

1. Check the troubleshooting section in the app
2. Verify your environment configuration
3. Ensure Neo4j connectivity
4. Check API key validity

## 🔮 Future Enhancements

- Support for additional cybersecurity frameworks (ISO 27001)
- Real-time threat intelligence feeds
- Custom threat modeling capabilities
- Integration with SIEM systems
- Advanced visualization of attack paths
- Export capabilities for reports and analysis
