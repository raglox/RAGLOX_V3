# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Intel/CTI Module
# Breach Data and Threat Intelligence Integration
# ═══════════════════════════════════════════════════════════════

"""
Intel Module - Breach Data and Threat Intelligence Integration.

This module provides integration with leaked/breached data sources
for credential intelligence gathering.

Components:
- BreachDataProvider: Abstract interface for breach data sources
- MockBreachProvider: Test provider with simulated data
- FileSearchProvider: Provider that searches local files
- IntelCredential: Credential with source metadata and reliability

Architecture:
┌────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│ IntelSpecialist│────▶│ BreachDataProvider│────▶│ Data Sources    │
│                │     │ (Interface)       │     │ - Mock          │
│                │     └──────────────────┘     │ - File Search   │
│                │              │               │ - External APIs │
└────────────────┘              │               └─────────────────┘
                                ▼
                    ┌──────────────────────┐
                    │ IntelCredential      │
                    │ - username/password  │
                    │ - source metadata    │
                    │ - reliability_score  │
                    └──────────────────────┘

Data Flow:
1. IntelSpecialist receives NewTargetEvent
2. Queries BreachDataProvider with domain/IP
3. Returns IntelCredentials with source metadata
4. Credentials stored in Blackboard with reliability_score
5. AttackSpecialist prioritizes high-reliability credentials
"""

from .base import (
    BreachDataProvider,
    IntelCredential,
    IntelSearchResult,
    BreachSource,
)
from .mock_provider import MockBreachProvider
from .file_provider import FileSearchProvider

__all__ = [
    # Base types
    "BreachDataProvider",
    "IntelCredential",
    "IntelSearchResult",
    "BreachSource",
    # Providers
    "MockBreachProvider",
    "FileSearchProvider",
]

__version__ = "3.0.0"
