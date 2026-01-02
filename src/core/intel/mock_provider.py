# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Mock Breach Data Provider
# Test provider with simulated leaked credentials
# ═══════════════════════════════════════════════════════════════

import asyncio
import random
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
import logging

from .base import BreachDataProvider, BreachSource, IntelCredential, IntelSearchResult


class MockBreachProvider(BreachDataProvider):
    """
    Mock breach data provider for testing.
    
    Contains simulated leaked credentials for known test targets
    like "vulnerable-target" and common test domains.
    
    This provider is useful for:
    - Unit tests
    - Integration tests
    - Development without real breach data
    - Demos and presentations
    """
    
    def __init__(
        self,
        delay_ms: int = 50,
        failure_rate: float = 0.0,
        include_hashes: bool = True
    ):
        """
        Initialize mock provider.
        
        Args:
            delay_ms: Simulated search delay in milliseconds
            failure_rate: Rate of simulated failures (0.0 - 1.0)
            include_hashes: Include password hashes in results
        """
        self._delay_ms = delay_ms
        self._failure_rate = failure_rate
        self._include_hashes = include_hashes
        self.logger = logging.getLogger("raglox.intel.mock_provider")
        
        # Pre-populated mock data
        self._mock_data = self._build_mock_database()
    
    @property
    def provider_name(self) -> str:
        return "mock"
    
    def _build_mock_database(self) -> Dict[str, List[Dict[str, Any]]]:
        """Build mock database with test credentials."""
        
        # Base date for calculating ages
        now = datetime.utcnow()
        
        return {
            # Test target - vulnerable-target
            "vulnerable-target": [
                {
                    "email": "admin@vulnerable-target.local",
                    "username": "admin",
                    "password": "admin123!",
                    "source": BreachSource.ARTHOUSE,
                    "source_name": "ArtHouse_2024",
                    "source_date": now - timedelta(days=60),
                    "raw_log": "admin@vulnerable-target.local:admin123! [ArtHouse 2024-01]",
                },
                {
                    "email": "root@vulnerable-target.local",
                    "username": "root",
                    "password": "toor",
                    "source": BreachSource.DATABASE_DUMP,
                    "source_name": "VulnTarget_DB_2023",
                    "source_date": now - timedelta(days=365),
                    "raw_log": "root:toor [DB dump 2023]",
                },
                {
                    "email": "test@vulnerable-target.local",
                    "username": "test",
                    "password": "test123",
                    "source": BreachSource.COMBOLIST,
                    "source_name": "Mega_Combo_2024",
                    "source_date": now - timedelta(days=30),
                    "raw_log": "test@vulnerable-target.local:test123",
                },
                {
                    "email": "backup@vulnerable-target.local",
                    "username": "backup",
                    "password": "backup2023!",
                    "source": BreachSource.STEALER_LOG,
                    "source_name": "RedLine_2024",
                    "source_date": now - timedelta(days=14),
                    "raw_log": "URL: ssh://vulnerable-target.local\nUser: backup\nPass: backup2023!",
                },
                {
                    "email": "developer@vulnerable-target.local",
                    "username": "dev",
                    "password_hash": "5f4dcc3b5aa765d61d8327deb882cf99",  # "password" in MD5
                    "hash_type": "md5",
                    "source": BreachSource.FATETRAFFIC,
                    "source_name": "Fatetraffic_2024Q1",
                    "source_date": now - timedelta(days=90),
                    "raw_log": "dev:5f4dcc3b5aa765d61d8327deb882cf99 [Fatetraffic]",
                },
            ],
            
            # Standard test IP
            "172.28.0.100": [
                {
                    "username": "admin",
                    "password": "admin123!",
                    "source": BreachSource.ARTHOUSE,
                    "source_name": "ArtHouse_2024",
                    "source_date": now - timedelta(days=45),
                    "raw_log": "172.28.0.100 admin:admin123!",
                },
                {
                    "username": "operator",
                    "password": "Operator2024!",
                    "source": BreachSource.STEALER_LOG,
                    "source_name": "Raccoon_2024",
                    "source_date": now - timedelta(days=7),
                    "raw_log": "SSH 172.28.0.100:22 operator:Operator2024!",
                },
            ],
            
            # Example corporate domain
            "example.com": [
                {
                    "email": "john.smith@example.com",
                    "username": "jsmith",
                    "password": "Summer2024!",
                    "source": BreachSource.COMBOLIST,
                    "source_name": "Collection_5",
                    "source_date": now - timedelta(days=180),
                    "raw_log": "john.smith@example.com:Summer2024!",
                },
                {
                    "email": "admin@example.com",
                    "username": "admin",
                    "password_hash": "e99a18c428cb38d5f260853678922e03",  # "abc123"
                    "hash_type": "md5",
                    "source": BreachSource.DATABASE_DUMP,
                    "source_name": "ExampleCorp_2022",
                    "source_date": now - timedelta(days=730),
                    "raw_log": "admin:e99a18c428cb38d5f260853678922e03 [Example Corp DB]",
                },
                {
                    "email": "ceo@example.com",
                    "username": "ceo",
                    "password": "Executive123!",
                    "source": BreachSource.RANSOMWARE_LEAK,
                    "source_name": "LockBit_Example_2023",
                    "source_date": now - timedelta(days=300),
                    "raw_log": "ceo@example.com:Executive123! [LockBit leak]",
                },
            ],
            
            # Test domain
            "testcorp.local": [
                {
                    "email": "sysadmin@testcorp.local",
                    "username": "sysadmin",
                    "domain": "TESTCORP",
                    "password": "SysAdmin2024!",
                    "source": BreachSource.STEALER_LOG,
                    "source_name": "Vidar_2024",
                    "source_date": now - timedelta(days=21),
                    "raw_log": "TESTCORP\\sysadmin:SysAdmin2024!",
                },
                {
                    "email": "helpdesk@testcorp.local",
                    "username": "helpdesk",
                    "domain": "TESTCORP",
                    "password": "Help123!",
                    "source": BreachSource.PASTE_SITE,
                    "source_name": "Pastebin_2024",
                    "source_date": now - timedelta(days=120),
                    "raw_log": "helpdesk@testcorp.local:Help123!",
                },
            ],
        }
    
    async def search(
        self,
        query: str,
        query_type: str = "domain",
        limit: int = 100
    ) -> IntelSearchResult:
        """
        Search mock database for credentials.
        
        Args:
            query: Search query (domain, email, IP)
            query_type: Type of query (auto-detected if not specified)
            limit: Maximum results to return
            
        Returns:
            IntelSearchResult with found credentials
        """
        start_time = datetime.utcnow()
        
        # Simulate network delay
        if self._delay_ms > 0:
            await asyncio.sleep(self._delay_ms / 1000)
        
        # Simulate random failures
        if random.random() < self._failure_rate:
            return IntelSearchResult(
                query=query,
                query_type=query_type,
                success=False,
                error="Simulated provider failure",
                provider=self.provider_name,
                search_time_ms=(datetime.utcnow() - start_time).total_seconds() * 1000
            )
        
        # Auto-detect query type if needed
        if query_type == "auto":
            query_type = self._detect_query_type(query)
        
        # Normalize query
        query_lower = query.lower().strip()
        
        # Search for matching entries
        found_credentials: List[IntelCredential] = []
        
        for key, entries in self._mock_data.items():
            # Check if query matches this key or entries
            if self._matches_query(key, query_lower, query_type):
                for entry in entries:
                    cred = self._entry_to_credential(entry, key)
                    found_credentials.append(cred)
        
        # Apply limit
        found_credentials = found_credentials[:limit]
        
        search_time = (datetime.utcnow() - start_time).total_seconds() * 1000
        
        self.logger.info(
            f"Mock search for '{self._mask_sensitive_data(query)}' "
            f"found {len(found_credentials)} credentials in {search_time:.1f}ms"
        )
        
        return IntelSearchResult(
            query=query,
            query_type=query_type,
            credentials=found_credentials,
            total_found=len(found_credentials),
            provider=self.provider_name,
            search_time_ms=search_time,
            success=True
        )
    
    def _matches_query(self, key: str, query: str, query_type: str) -> bool:
        """Check if a key matches the search query."""
        key_lower = key.lower()
        
        # Direct match
        if query in key_lower or key_lower in query:
            return True
        
        # Domain matching - check if query is subdomain or parent domain
        if query_type == "domain":
            # Check if query is part of key or vice versa
            if query.endswith(key_lower) or key_lower.endswith(query):
                return True
            # Remove common prefixes
            query_clean = query.replace("www.", "").replace("mail.", "")
            if query_clean in key_lower or key_lower in query_clean:
                return True
        
        # IP matching
        if query_type == "ip":
            # Exact match for IP
            if query == key_lower:
                return True
            # Subnet matching (simple)
            if query.rsplit(".", 1)[0] == key_lower.rsplit(".", 1)[0]:
                return True
        
        return False
    
    def _entry_to_credential(self, entry: Dict[str, Any], target_key: str) -> IntelCredential:
        """Convert a mock entry to IntelCredential."""
        source = entry.get("source", BreachSource.UNKNOWN)
        source_date = entry.get("source_date")
        
        return IntelCredential(
            username=entry.get("username"),
            email=entry.get("email"),
            password=entry.get("password"),
            password_hash=entry.get("password_hash") if self._include_hashes else None,
            hash_type=entry.get("hash_type"),
            domain=entry.get("domain"),
            target_domain=target_key if not target_key.replace(".", "").isdigit() else None,
            target_ip=target_key if target_key.replace(".", "").isdigit() else None,
            source=source,
            source_name=entry.get("source_name"),
            source_date=source_date,
            raw_log=entry.get("raw_log"),
            reliability_score=self._calculate_reliability(source, source_date),
        )
    
    async def health_check(self) -> bool:
        """Mock provider is always healthy."""
        return True
    
    def add_mock_entry(
        self,
        target: str,
        username: str = None,
        email: str = None,
        password: str = None,
        source: BreachSource = BreachSource.UNKNOWN,
        source_name: str = "Custom_Mock"
    ) -> None:
        """
        Add a custom entry to the mock database.
        
        Useful for testing specific scenarios.
        """
        if target not in self._mock_data:
            self._mock_data[target] = []
        
        self._mock_data[target].append({
            "username": username,
            "email": email,
            "password": password,
            "source": source,
            "source_name": source_name,
            "source_date": datetime.utcnow(),
            "raw_log": f"{email or username}:{password}",
        })
        
        self.logger.debug(f"Added mock entry for target: {target}")
    
    def clear_mock_data(self) -> None:
        """Clear all mock data."""
        self._mock_data = {}
    
    def reset_mock_data(self) -> None:
        """Reset to default mock data."""
        self._mock_data = self._build_mock_database()
