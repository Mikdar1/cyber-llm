"""
Cybersecurity module for managing cybersecurity framework data ingestion and processing.

This module provides ingestion capabilities for cybersecurity frameworks:
- MITRE ATT&CK: Tactics, techniques, and procedures
- Compliance: LLM-powered document processing for any compliance framework

The module includes:
- attack_ingestion: MITRE ATT&CK STIX data processing
- compliance_ingestion: AI-powered PDF document processing for compliance frameworks

Each ingestion module provides standardized interfaces for data processing
and graph database integration.
"""

from .attack_ingestion import AttackIngestion
from .compliance_ingestion import ComplianceIngestion

__all__ = ["AttackIngestion", "ComplianceIngestion"]
