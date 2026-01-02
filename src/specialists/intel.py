# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Intel Specialist
# OSINT and leaked data reconnaissance specialist
# ═══════════════════════════════════════════════════════════════

"""
IntelSpecialist - Handles OSINT lookups and leaked credential searches.

This specialist listens for NewTargetEvent and creates OSINT_LOOKUP tasks
to search breach data for credentials associated with the target.

Design:
- Listens for new targets (domain or IP)
- Searches breach data providers for matching credentials
- Outputs Credential objects with reliability_score and metadata
- Prioritizes credentials for AttackSpecialist to use before brute force

Data Sources:
- MockBreachProvider: For testing
- FileSearchProvider: Search local breach data files
- Future: External CTI APIs
"""

import asyncio
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, TYPE_CHECKING
from uuid import UUID

from .base import BaseSpecialist
from ..core.models import (
    TaskType, SpecialistType, TargetStatus, Priority,
    CredentialType, PrivilegeLevel,
    NewTargetEvent, NewCredEvent
)
from ..core.blackboard import Blackboard
from ..core.config import Settings
from ..core.knowledge import EmbeddedKnowledge

# Intel data layer imports
from ..core.intel import (
    BreachDataProvider,
    IntelCredential,
    IntelSearchResult,
    BreachSource
)
from ..core.intel.mock_provider import MockBreachProvider
from ..core.intel.file_provider import FileSearchProvider

if TYPE_CHECKING:
    from ..executors import RXModuleRunner, ExecutorFactory


class IntelSpecialist(BaseSpecialist):
    """
    Intel Specialist - Handles OSINT and leaked credential reconnaissance.
    
    Responsibilities:
    - Searching breach data for target credentials
    - Processing NewTargetEvent to create OSINT_LOOKUP tasks
    - Converting IntelCredential to Credential with reliability scoring
    - Masking sensitive data in logs
    
    Task Types Handled:
    - OSINT_LOOKUP: Search for leaked credentials associated with a target
    
    Reads From Blackboard:
    - New targets (via Pub/Sub)
    - Target information (IP, hostname, domain)
    
    Writes To Blackboard:
    - New credentials (with source_metadata and reliability_score)
    - Creates follow-up tasks for AttackSpecialist
    
    Data Sources:
    - ArtHouse: Leaked credential database
    - Fatetraffic: Traffic analysis dumps
    - Local files: Combo lists, stealer logs, database dumps
    """
    
    # Reliability scores by source type
    RELIABILITY_SCORES = {
        BreachSource.STEALER_LOG: 0.9,
        BreachSource.DATABASE_DUMP: 0.85,
        BreachSource.RANSOMWARE_LEAK: 0.85,
        BreachSource.ARTHOUSE: 0.8,
        BreachSource.FATETRAFFIC: 0.8,
        BreachSource.COMBOLIST: 0.6,
        BreachSource.PASTE_SITE: 0.5,
        BreachSource.DARKWEB_MARKET: 0.7,
        BreachSource.LOCAL_FILE: 0.75,
        BreachSource.UNKNOWN: 0.5,
    }
    
    def __init__(
        self,
        blackboard: Optional[Blackboard] = None,
        settings: Optional[Settings] = None,
        worker_id: Optional[str] = None,
        knowledge: Optional[EmbeddedKnowledge] = None,
        runner: Optional['RXModuleRunner'] = None,
        executor_factory: Optional['ExecutorFactory'] = None,
        providers: Optional[List[BreachDataProvider]] = None,
        use_mock: bool = False,
        data_dir: str = "./data/breach_data"
    ):
        """
        Initialize the Intel Specialist.
        
        Args:
            blackboard: Blackboard instance
            settings: Application settings
            worker_id: Unique worker identifier
            knowledge: Embedded knowledge base
            runner: RXModuleRunner (not used by Intel)
            executor_factory: ExecutorFactory (not used by Intel)
            providers: List of breach data providers (auto-created if not provided)
            use_mock: Whether to use mock provider for testing
            data_dir: Directory for FileSearchProvider
        """
        super().__init__(
            specialist_type=SpecialistType.INTEL,
            blackboard=blackboard,
            settings=settings,
            worker_id=worker_id,
            knowledge=knowledge,
            runner=runner,
            executor_factory=executor_factory
        )
        
        # Task types this specialist handles
        self._supported_task_types = {
            TaskType.OSINT_LOOKUP
        }
        
        # Setup logging with sensitive data masking
        self.logger = logging.getLogger("raglox.specialist.intel")
        
        # Initialize breach data providers
        self._providers: List[BreachDataProvider] = []
        self._use_mock = use_mock
        self._data_dir = data_dir
        
        if providers:
            self._providers = providers
        else:
            self._init_default_providers()
        
        # Statistics
        self._stats = {
            "total_searches": 0,
            "credentials_found": 0,
            "targets_processed": 0,
            "search_failures": 0
        }
    
    def _init_default_providers(self) -> None:
        """Initialize default breach data providers."""
        if self._use_mock:
            # Use mock provider for testing
            self._providers.append(MockBreachProvider())
            self.logger.info("Initialized MockBreachProvider for testing")
        else:
            # Use file provider for production
            self._providers.append(FileSearchProvider(data_dir=self._data_dir))
            self.logger.info(f"Initialized FileSearchProvider with data_dir: {self._data_dir}")
    
    # ═══════════════════════════════════════════════════════════
    # Task Execution
    # ═══════════════════════════════════════════════════════════
    
    async def execute_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Execute an intel task."""
        task_type = task.get("type")
        
        handlers = {
            TaskType.OSINT_LOOKUP.value: self._execute_osint_lookup,
        }
        
        handler = handlers.get(task_type)
        if not handler:
            raise ValueError(f"Unsupported task type: {task_type}")
        
        return await handler(task)
    
    async def _execute_osint_lookup(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute OSINT lookup for a target.
        
        Searches breach data providers for credentials associated with:
        - Target domain
        - Target IP
        - Email addresses in the target domain
        
        Args:
            task: Task data with target_id
            
        Returns:
            Result dictionary with found credentials
        """
        target_id = task.get("target_id")
        task_id = task.get("id")
        
        if not target_id:
            return {"error": "No target_id specified", "credentials_found": 0}
        
        # Clean target_id
        if isinstance(target_id, str) and target_id.startswith("target:"):
            target_id = target_id.replace("target:", "")
        
        # Get target details
        target = await self.blackboard.get_target(target_id)
        if not target:
            return {"error": f"Target {target_id} not found", "credentials_found": 0}
        
        target_ip = target.get("ip")
        target_hostname = target.get("hostname")
        
        self.logger.info(
            f"Starting OSINT lookup for target {target_id} "
            f"(IP: {self._mask_ip(target_ip)}, hostname: {self._mask_hostname(target_hostname)})"
        )
        
        self._stats["targets_processed"] += 1
        
        all_credentials: List[IntelCredential] = []
        search_queries = []
        
        # Build search queries
        if target_hostname:
            # Extract domain from hostname
            domain = self._extract_domain(target_hostname)
            if domain:
                search_queries.append(("domain", domain))
        
        if target_ip:
            search_queries.append(("ip", target_ip))
        
        # Search each provider
        for provider in self._providers:
            for query_type, query in search_queries:
                try:
                    self._stats["total_searches"] += 1
                    
                    result = await provider.search(
                        query=query,
                        query_type=query_type,
                        limit=50
                    )
                    
                    if result.success and result.has_results:
                        all_credentials.extend(result.credentials)
                        self.logger.info(
                            f"Found {len(result.credentials)} credentials from "
                            f"{provider.provider_name} for {self._mask_sensitive(query)}"
                        )
                    
                except Exception as e:
                    self._stats["search_failures"] += 1
                    self.logger.error(
                        f"Error searching {provider.provider_name}: "
                        f"{self._mask_error(str(e))}"
                    )
        
        # Deduplicate credentials
        unique_credentials = self._deduplicate_credentials(all_credentials)
        
        # Convert to Credential and save to Blackboard
        saved_credentials = []
        for intel_cred in unique_credentials:
            try:
                cred_id = await self._save_intel_credential(
                    target_id=target_id,
                    intel_cred=intel_cred
                )
                
                saved_credentials.append({
                    "cred_id": cred_id,
                    "username": self._mask_username(intel_cred.username),
                    "email": intel_cred.get_masked_email(),
                    "source": intel_cred.source.value,
                    "reliability_score": intel_cred.reliability_score
                })
                
                self._stats["credentials_found"] += 1
                
            except Exception as e:
                self.logger.error(f"Error saving credential: {e}")
        
        # Create exploit task if high-reliability credentials found
        high_reliability_creds = [
            c for c in saved_credentials 
            if c["reliability_score"] >= 0.7
        ]
        
        if high_reliability_creds:
            self.logger.info(
                f"Found {len(high_reliability_creds)} high-reliability credentials, "
                "creating exploit task"
            )
            
            # Get the cred_id and ensure it's a valid UUID string
            cred_id = high_reliability_creds[0]["cred_id"]
            # Clean cred_id if it has prefix
            if isinstance(cred_id, str) and cred_id.startswith("cred:"):
                cred_id = cred_id.replace("cred:", "")
            
            # Create EXPLOIT task to use the credentials
            await self.create_task(
                task_type=TaskType.EXPLOIT,
                target_specialist=SpecialistType.ATTACK,
                priority=8,  # High priority for intel-backed exploit
                target_id=target_id,
                cred_id=cred_id,
                intel_source="intel_lookup",
                reliability=high_reliability_creds[0]["reliability_score"]
            )
        
        return {
            "credentials_found": len(saved_credentials),
            "credentials": saved_credentials,
            "queries_executed": len(search_queries) * len(self._providers),
            "target_ip": self._mask_ip(target_ip),
            "target_hostname": self._mask_hostname(target_hostname)
        }
    
    async def _save_intel_credential(
        self,
        target_id: str,
        intel_cred: IntelCredential
    ) -> str:
        """
        Save an IntelCredential to the Blackboard as a Credential.
        
        Args:
            target_id: Target ID
            intel_cred: IntelCredential from provider
            
        Returns:
            Credential ID
        """
        from uuid import UUID
        from ..core.models import Credential
        
        # Determine credential type
        if intel_cred.password:
            cred_type = CredentialType.PASSWORD
        elif intel_cred.password_hash:
            cred_type = CredentialType.HASH
        else:
            cred_type = CredentialType.PASSWORD
        
        # Build source metadata
        source_metadata = {
            "intel_source": intel_cred.source.value,
            "source_name": intel_cred.source_name,
            "source_date": intel_cred.source_date.isoformat() if intel_cred.source_date else None,
            "raw_log_hash": intel_cred._get_raw_log_hash() if hasattr(intel_cred, '_get_raw_log_hash') else None,
            "email": intel_cred.email,
            "has_plaintext": bool(intel_cred.password),
            "hash_type": intel_cred.hash_type,
        }
        
        # Add raw_log hash if available (masked for security)
        if intel_cred.raw_log:
            import hashlib
            source_metadata["raw_log_hash"] = hashlib.sha256(
                intel_cred.raw_log.encode()
            ).hexdigest()[:16]
        
        # Build source string
        source = f"intel:{intel_cred.source.value}:{intel_cred.source_name or 'unknown'}"
        
        # Encrypt password if available (simulated for now)
        value_encrypted = None
        if intel_cred.password:
            value_encrypted = intel_cred.password.encode()  # In production, would encrypt
        elif intel_cred.password_hash:
            value_encrypted = intel_cred.password_hash.encode()
        
        # Create Credential
        cred = Credential(
            mission_id=UUID(self._current_mission_id),
            target_id=UUID(target_id),
            type=cred_type,
            username=intel_cred.username or intel_cred.email,
            domain=intel_cred.domain,
            value_encrypted=value_encrypted,
            source=source,
            discovered_by=self.worker_id,
            verified=intel_cred.verified,
            privilege_level=PrivilegeLevel.UNKNOWN,  # Unknown until verified
            reliability_score=intel_cred.reliability_score,
            source_metadata=source_metadata
        )
        
        cred_id = await self.blackboard.add_credential(cred)
        
        # Publish event
        event = NewCredEvent(
            mission_id=UUID(self._current_mission_id),
            cred_id=cred.id,
            target_id=UUID(target_id),
            type=cred_type,
            privilege_level=PrivilegeLevel.UNKNOWN
        )
        await self.publish_event(event)
        
        self.logger.info(
            f"Added Intel credential: {self._mask_username(cred.username)} "
            f"(reliability: {intel_cred.reliability_score}, source: {intel_cred.source.value})"
        )
        
        return cred_id
    
    def _deduplicate_credentials(
        self,
        credentials: List[IntelCredential]
    ) -> List[IntelCredential]:
        """
        Remove duplicate credentials, keeping highest reliability.
        
        Args:
            credentials: List of IntelCredentials
            
        Returns:
            Deduplicated list sorted by reliability
        """
        seen: Dict[str, IntelCredential] = {}
        
        for cred in credentials:
            # Create unique key
            key = f"{cred.email or cred.username}:{cred.password or cred.password_hash}"
            
            if key not in seen or cred.reliability_score > seen[key].reliability_score:
                seen[key] = cred
        
        # Sort by reliability
        return sorted(seen.values(), key=lambda c: c.reliability_score, reverse=True)
    
    def _extract_domain(self, hostname: str) -> Optional[str]:
        """Extract domain from hostname."""
        if not hostname:
            return None
        
        # Simple domain extraction (could be improved with TLD library)
        parts = hostname.lower().split(".")
        
        if len(parts) >= 2:
            # Return last two parts (e.g., example.com)
            return ".".join(parts[-2:])
        
        return hostname.lower()
    
    # ═══════════════════════════════════════════════════════════
    # Sensitive Data Masking
    # ═══════════════════════════════════════════════════════════
    
    def _mask_sensitive(self, data: str, show_chars: int = 2) -> str:
        """Mask sensitive data for logging."""
        if not data or len(data) <= show_chars * 2:
            return "*" * (len(data) if data else 3)
        return data[:show_chars] + "*" * (len(data) - show_chars * 2) + data[-show_chars:]
    
    def _mask_ip(self, ip: Optional[str]) -> str:
        """Mask IP address for logging."""
        if not ip:
            return "***"
        parts = ip.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.*.*"
        return self._mask_sensitive(ip)
    
    def _mask_hostname(self, hostname: Optional[str]) -> str:
        """Mask hostname for logging."""
        if not hostname:
            return "***"
        parts = hostname.split(".")
        if len(parts) >= 2:
            return f"***.{'.'.join(parts[-2:])}"
        return self._mask_sensitive(hostname)
    
    def _mask_username(self, username: Optional[str]) -> str:
        """Mask username for logging."""
        if not username:
            return "***"
        if len(username) <= 3:
            return "*" * len(username)
        return username[0] + "*" * (len(username) - 2) + username[-1]
    
    def _mask_error(self, error: str) -> str:
        """Mask potentially sensitive info in error messages."""
        # Remove potential passwords, keys, etc.
        import re
        masked = re.sub(r'(password|secret|key|token)[=:]\s*\S+', r'\1=***', error, flags=re.I)
        return masked
    
    # ═══════════════════════════════════════════════════════════
    # Event Handling
    # ═══════════════════════════════════════════════════════════
    
    async def on_event(self, event: Dict[str, Any]) -> None:
        """Handle Pub/Sub events."""
        event_type = event.get("event")
        
        if event_type == "new_target":
            # New target discovered - create OSINT_LOOKUP task
            target_id = event.get("target_id")
            ip = event.get("ip")
            
            self.logger.info(
                f"New target detected: {self._mask_ip(ip)}, creating OSINT lookup task"
            )
            
            # Create OSINT_LOOKUP task
            await self.create_task(
                task_type=TaskType.OSINT_LOOKUP,
                target_specialist=SpecialistType.INTEL,
                priority=7,  # High priority for intel gathering
                target_id=str(target_id) if target_id else None
            )
        
        elif event_type == "control":
            command = event.get("command")
            if command == "pause":
                await self.pause()
            elif command == "resume":
                await self.resume()
            elif command == "stop":
                await self.stop()
    
    # ═══════════════════════════════════════════════════════════
    # Channel Subscriptions
    # ═══════════════════════════════════════════════════════════
    
    def _get_channels_to_subscribe(self, mission_id: str) -> List[str]:
        """Get channels for Intel specialist."""
        return [
            self.blackboard.get_channel(mission_id, "tasks"),
            self.blackboard.get_channel(mission_id, "targets"),  # Listen for new targets
            self.blackboard.get_channel(mission_id, "control"),
        ]
    
    # ═══════════════════════════════════════════════════════════
    # Provider Management
    # ═══════════════════════════════════════════════════════════
    
    def add_provider(self, provider: BreachDataProvider) -> None:
        """Add a breach data provider."""
        self._providers.append(provider)
        self.logger.info(f"Added provider: {provider.provider_name}")
    
    def get_providers(self) -> List[BreachDataProvider]:
        """Get all configured providers."""
        return self._providers.copy()
    
    async def health_check_providers(self) -> Dict[str, bool]:
        """Check health of all providers."""
        results = {}
        for provider in self._providers:
            try:
                results[provider.provider_name] = await provider.health_check()
            except Exception as e:
                self.logger.error(f"Health check failed for {provider.provider_name}: {e}")
                results[provider.provider_name] = False
        return results
    
    # ═══════════════════════════════════════════════════════════
    # Statistics
    # ═══════════════════════════════════════════════════════════
    
    def get_stats(self) -> Dict[str, Any]:
        """Get Intel specialist statistics."""
        return {
            **self._stats,
            "providers_count": len(self._providers),
            "provider_names": [p.provider_name for p in self._providers]
        }
