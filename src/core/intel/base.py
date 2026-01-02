# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Breach Data Provider Base
# Abstract interface for breach/leaked data sources
# ═══════════════════════════════════════════════════════════════

from abc import ABC, abstractmethod
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from uuid import UUID, uuid4
import hashlib
import re


class BreachSource(str, Enum):
    """Source types for breached data."""
    
    UNKNOWN = "unknown"
    ARTHOUSE = "arthouse"              # ArtHouse leaks
    FATETRAFFIC = "fatetraffic"        # Fatetraffic dumps
    COMBOLIST = "combolist"            # Combined credential lists
    DATABASE_DUMP = "database_dump"    # Direct database dumps
    STEALER_LOG = "stealer_log"        # Info stealer logs
    PASTE_SITE = "paste_site"          # Pastebin/similar
    DARKWEB_MARKET = "darkweb_market"  # Darkweb marketplace
    RANSOMWARE_LEAK = "ransomware"     # Ransomware group leaks
    LOCAL_FILE = "local_file"          # Local file search


class IntelCredential(BaseModel):
    """
    Credential found from intelligence/breach sources.
    
    Contains additional metadata about source and reliability
    compared to regular Credential model.
    """
    
    id: UUID = Field(default_factory=uuid4)
    
    # Credential data
    username: Optional[str] = None
    email: Optional[str] = None
    password: Optional[str] = None  # Plaintext if available
    password_hash: Optional[str] = None  # Hash if plaintext not available
    hash_type: Optional[str] = None  # md5, sha1, bcrypt, etc.
    domain: Optional[str] = None
    
    # Target association
    target_domain: Optional[str] = None
    target_ip: Optional[str] = None
    
    # Source metadata
    source: BreachSource = BreachSource.UNKNOWN
    source_name: Optional[str] = None  # Specific source name (e.g., "ArtHouse_2024")
    source_date: Optional[datetime] = None  # When the breach occurred
    raw_log: Optional[str] = None  # Raw log line (masked for sensitive data)
    
    # Reliability
    reliability_score: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Reliability score 0-1 (1.0 = verified, 0.5 = unverified leak)"
    )
    
    # Status
    verified: bool = False
    verified_at: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    
    # Additional metadata
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow)
    
    def get_masked_password(self, show_chars: int = 2) -> str:
        """Get masked password for safe logging."""
        if not self.password:
            return "***"
        if len(self.password) <= show_chars * 2:
            return "*" * len(self.password)
        return self.password[:show_chars] + "*" * (len(self.password) - show_chars * 2) + self.password[-show_chars:]
    
    def get_masked_email(self) -> str:
        """Get masked email for safe logging."""
        if not self.email:
            return "***"
        parts = self.email.split("@")
        if len(parts) != 2:
            return "***@***"
        local = parts[0]
        domain = parts[1]
        if len(local) <= 2:
            masked_local = "*" * len(local)
        else:
            masked_local = local[0] + "*" * (len(local) - 2) + local[-1]
        return f"{masked_local}@{domain}"
    
    def to_credential_dict(self, mission_id: UUID, target_id: UUID) -> Dict[str, Any]:
        """
        Convert to a dictionary suitable for creating a Credential entity.
        
        Args:
            mission_id: Mission ID
            target_id: Target ID
            
        Returns:
            Dictionary with credential data and intel metadata
        """
        return {
            "mission_id": mission_id,
            "target_id": target_id,
            "type": "password" if self.password else "hash",
            "username": self.username or self.email,
            "domain": self.domain,
            "source": f"intel:{self.source.value}:{self.source_name or 'unknown'}",
            "discovered_by": "IntelSpecialist",
            "verified": self.verified,
            "metadata": {
                "intel_source": self.source.value,
                "source_name": self.source_name,
                "source_date": self.source_date.isoformat() if self.source_date else None,
                "reliability_score": self.reliability_score,
                "raw_log_hash": hashlib.sha256(self.raw_log.encode()).hexdigest()[:16] if self.raw_log else None,
                "email": self.email,
                "has_plaintext": bool(self.password),
                "hash_type": self.hash_type,
            }
        }
    
    def __repr__(self) -> str:
        return f"IntelCredential(email={self.get_masked_email()}, source={self.source.value}, reliability={self.reliability_score})"


class IntelSearchResult(BaseModel):
    """Result from a breach data search."""
    
    query: str
    query_type: str = "domain"  # domain, email, ip, username
    credentials: List[IntelCredential] = Field(default_factory=list)
    total_found: int = 0
    
    # Search metadata
    provider: str = "unknown"
    search_time_ms: float = 0.0
    searched_at: datetime = Field(default_factory=datetime.utcnow)
    
    # Status
    success: bool = True
    error: Optional[str] = None
    
    @property
    def has_results(self) -> bool:
        return len(self.credentials) > 0
    
    def get_by_reliability(self, min_score: float = 0.0) -> List[IntelCredential]:
        """Get credentials filtered and sorted by reliability score."""
        filtered = [c for c in self.credentials if c.reliability_score >= min_score]
        return sorted(filtered, key=lambda c: c.reliability_score, reverse=True)


class BreachDataProvider(ABC):
    """
    Abstract interface for breach/leaked data providers.
    
    Implementations:
    - MockBreachProvider: For testing with simulated data
    - FileSearchProvider: Search local files (simulating grep on large files)
    - ExternalAPIProvider: Future - Integration with external CTI APIs
    
    Usage:
        provider = MockBreachProvider()
        result = await provider.search("example.com")
        for cred in result.credentials:
            print(f"Found: {cred.get_masked_email()}")
    """
    
    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Return the provider name."""
        pass
    
    @property
    def supported_query_types(self) -> List[str]:
        """Return supported query types."""
        return ["domain", "email", "ip", "username"]
    
    @abstractmethod
    async def search(
        self,
        query: str,
        query_type: str = "domain",
        limit: int = 100
    ) -> IntelSearchResult:
        """
        Search for credentials in the breach data source.
        
        Args:
            query: Search query (domain, email, IP, or username)
            query_type: Type of query ("domain", "email", "ip", "username")
            limit: Maximum number of results
            
        Returns:
            IntelSearchResult with found credentials
        """
        pass
    
    @abstractmethod
    async def health_check(self) -> bool:
        """Check if the provider is available and working."""
        pass
    
    def _detect_query_type(self, query: str) -> str:
        """
        Auto-detect query type from the query string.
        
        Args:
            query: Search query
            
        Returns:
            Detected query type
        """
        # Email pattern
        if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', query):
            return "email"
        
        # IP pattern (IPv4)
        if re.match(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$', query):
            return "ip"
        
        # Domain pattern
        if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9-]*\.[a-zA-Z]{2,}$', query):
            return "domain"
        
        # Default to username
        return "username"
    
    def _mask_sensitive_data(self, data: str, show_chars: int = 2) -> str:
        """Mask sensitive data for logging."""
        if not data or len(data) <= show_chars * 2:
            return "*" * (len(data) if data else 3)
        return data[:show_chars] + "*" * (len(data) - show_chars * 2) + data[-show_chars:]
    
    def _calculate_reliability(
        self,
        source: BreachSource,
        source_date: Optional[datetime] = None,
        verified: bool = False
    ) -> float:
        """
        Calculate reliability score based on source and age.
        
        Factors:
        - Verified credentials get 1.0
        - Source type affects base score
        - Age reduces score (older = less reliable)
        
        Returns:
            Reliability score 0.0 - 1.0
        """
        if verified:
            return 1.0
        
        # Base scores by source type
        base_scores = {
            BreachSource.STEALER_LOG: 0.9,      # Recent stealer logs are reliable
            BreachSource.DATABASE_DUMP: 0.85,   # Direct dumps are good
            BreachSource.RANSOMWARE_LEAK: 0.85, # Ransomware leaks are recent
            BreachSource.ARTHOUSE: 0.8,
            BreachSource.FATETRAFFIC: 0.8,
            BreachSource.COMBOLIST: 0.6,        # Combo lists may have duplicates
            BreachSource.PASTE_SITE: 0.5,       # Paste sites may be unreliable
            BreachSource.DARKWEB_MARKET: 0.7,
            BreachSource.LOCAL_FILE: 0.75,
            BreachSource.UNKNOWN: 0.5,
        }
        
        base_score = base_scores.get(source, 0.5)
        
        # Age penalty (reduce score for older data)
        if source_date:
            age_days = (datetime.utcnow() - source_date).days
            if age_days > 365 * 3:  # > 3 years
                age_penalty = 0.3
            elif age_days > 365 * 2:  # > 2 years
                age_penalty = 0.2
            elif age_days > 365:  # > 1 year
                age_penalty = 0.1
            elif age_days > 180:  # > 6 months
                age_penalty = 0.05
            else:
                age_penalty = 0.0
            
            base_score = max(0.1, base_score - age_penalty)
        
        return round(base_score, 2)
