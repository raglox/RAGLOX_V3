# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Analysis Specialist
# Reflexion Logic specialist for failure analysis and adaptive learning
# With LLM Integration for intelligent decision making
# Enhanced with Operational Memory for adaptive learning
# ═══════════════════════════════════════════════════════════════

import asyncio
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, TYPE_CHECKING
from uuid import UUID, uuid4

from .base import BaseSpecialist
from ..core.models import (
    TaskType, SpecialistType, TaskStatus, Severity, Priority,
    Task, ErrorContext, ExecutionLog,
    TaskFailedEvent, TaskAnalysisRequestEvent, TaskAnalysisResultEvent,
    BlackboardEvent,
    # HITL Models
    ApprovalAction, ApprovalStatus, ApprovalRequestEvent,
    ActionType, RiskLevel
)
from ..core.blackboard import Blackboard
from ..core.config import Settings, get_settings
from ..core.knowledge import EmbeddedKnowledge, NucleiTemplate

# Hybrid Intelligence Layer imports
from ..core.operational_memory import (
    OperationalMemory,
    DecisionRecord,
    DecisionOutcome,
    OperationalContext,
)

# LLM imports
if TYPE_CHECKING:
    from ..core.llm.service import LLMService
    from ..core.llm.base import LLMProvider


class AnalysisSpecialist(BaseSpecialist):
    """
    Analysis Specialist - Handles failure analysis and reflexion logic.
    
    This specialist implements the Reflexion Logic pattern:
    1. Receives failed task events with full error context
    2. Analyzes the failure to understand root cause
    3. Determines appropriate next action (retry, skip, escalate, modify)
    4. Creates modified retry tasks or escalates to human/LLM
    
    Responsibilities:
    - Analyzing failed exploitation attempts
    - Understanding why attacks failed (AV detection, firewall, etc.)
    - Suggesting alternative techniques or modules
    - Learning from failures to improve future attempts
    - Preparing context for LLM decision-making
    
    Task Types Handled:
    - ANALYSIS: Analyze a failed task and determine next steps
    
    Reads From Blackboard:
    - Failed tasks with error_context
    - Execution logs
    - Target information (for context)
    - Vulnerability details
    
    Writes To Blackboard:
    - Analysis results
    - Modified retry tasks
    - Escalation events
    - Learning insights
    
    Reflexion Logic Flow:
    ┌────────────────┐     ┌───────────────────┐     ┌─────────────────┐
    │  Task Failed   │────▶│ AnalysisSpecialist│────▶│   Decision      │
    │  (with context)│     │   (Reflexion)     │     │ retry/skip/mod  │
    └────────────────┘     └───────────────────┘     └─────────────────┘
                                    │
                                    ▼
                           ┌─────────────────┐
                           │  Knowledge Base │
                           │  (alternatives) │
                           └─────────────────┘
    """
    
    # Error type mappings for analysis
    ERROR_CATEGORIES = {
        "connection_refused": "network",
        "connection_timeout": "network",
        "port_closed": "network",
        "firewall_blocked": "network",
        "av_detected": "defense",
        "edr_blocked": "defense",
        "sandbox_detected": "defense",
        "credential_mismatch": "defense",
        "auth_failed": "authentication",
        "access_denied": "authentication",
        "permission_denied": "authentication",
        "target_patched": "vulnerability",
        "exploit_failed": "vulnerability",
        "module_error": "technical",
        "timeout": "technical",
        "crash": "technical",
        "unknown": "unknown"
    }
    
    # Retry strategies based on error category
    RETRY_STRATEGIES = {
        "network": {
            "max_retries": 3,
            "retry_delay": 60,  # seconds
            "recommendations": [
                "Try alternative ports",
                "Use proxy/tunnel",
                "Wait and retry (network transient)",
            ]
        },
        "defense": {
            "max_retries": 1,
            "retry_delay": 300,  # 5 minutes
            "recommendations": [
                "Use evasion techniques",
                "Try living-off-the-land binaries",
                "Use encoded payloads",
                "Try alternative exploit chain"
            ]
        },
        "authentication": {
            "max_retries": 2,
            "retry_delay": 30,
            "recommendations": [
                "Try credential spraying",
                "Harvest more credentials",
                "Try kerberoasting"
            ]
        },
        "vulnerability": {
            "max_retries": 0,
            "retry_delay": 0,
            "recommendations": [
                "Target may be patched - skip",
                "Try different vulnerability",
                "Enumerate for new vulns"
            ]
        },
        "technical": {
            "max_retries": 2,
            "retry_delay": 10,
            "recommendations": [
                "Check module configuration",
                "Try alternative module",
                "Verify target availability"
            ]
        },
        "unknown": {
            "max_retries": 1,
            "retry_delay": 30,
            "recommendations": [
                "Collect more information",
                "Escalate for manual review"
            ]
        }
    }
    
    def __init__(
        self,
        blackboard: Optional[Blackboard] = None,
        settings: Optional[Settings] = None,
        worker_id: Optional[str] = None,
        knowledge: Optional[EmbeddedKnowledge] = None,
        llm_enabled: Optional[bool] = None,
        llm_service: Optional["LLMService"] = None,
        operational_memory: Optional[OperationalMemory] = None,
    ):
        super().__init__(
            specialist_type=SpecialistType.ANALYSIS,
            blackboard=blackboard,
            settings=settings,
            worker_id=worker_id,
            knowledge=knowledge
        )
        
        # Load settings if not provided
        self._settings = settings or get_settings()
        
        # LLM configuration from settings or explicit parameter
        self.llm_enabled = llm_enabled if llm_enabled is not None else self._settings.llm_enabled
        self._llm_service = llm_service
        self._llm_initialized = False
        
        # ═══════════════════════════════════════════════════════════
        # Hybrid Intelligence: Operational Memory Integration
        # ═══════════════════════════════════════════════════════════
        self._operational_memory = operational_memory or OperationalMemory(
            blackboard=blackboard,
            logger=self.logger
        )
        
        # Analysis history for learning (local cache, syncs with OperationalMemory)
        self._analysis_history: List[Dict[str, Any]] = []
        
        # Currently no specific task types - analysis works on events
        self._supported_task_types = set()
        
        # Statistics
        self._stats = {
            "analyses_performed": 0,
            "retries_recommended": 0,
            "skips_recommended": 0,
            "escalations": 0,
            "modifications_recommended": 0,
            "llm_analyses": 0,
            "llm_failures": 0,
            "rule_based_fallbacks": 0,
            "safety_limit_breaches": 0,
            # New: Memory-assisted stats
            "memory_consultations": 0,
            "memory_guided_decisions": 0,
            "historical_insights_applied": 0,
        }
        
        # Safety limits tracking (per mission)
        self._mission_llm_requests = 0
        self._mission_tokens_used = 0
        self._mission_estimated_cost = 0.0
        self._daily_llm_requests = 0
        self._daily_reset_date = datetime.utcnow().date()
        
        self.logger.info("AnalysisSpecialist initialized with Operational Memory integration")
    
    def _check_safety_limits(self) -> tuple[bool, str]:
        """
        Check if safety limits have been reached.
        
        Returns:
            Tuple of (is_safe, reason_if_not_safe)
        """
        if not self._settings.llm_safety_mode:
            return True, ""
        
        # Reset daily counter if new day
        today = datetime.utcnow().date()
        if today > self._daily_reset_date:
            self._daily_llm_requests = 0
            self._daily_reset_date = today
        
        # Check mission request limit
        if self._mission_llm_requests >= self._settings.llm_mission_requests_limit:
            return False, f"Mission LLM request limit reached ({self._settings.llm_mission_requests_limit})"
        
        # Check daily request limit
        if self._daily_llm_requests >= self._settings.llm_daily_requests_limit:
            return False, f"Daily LLM request limit reached ({self._settings.llm_daily_requests_limit})"
        
        # Check cost limit
        if self._mission_estimated_cost >= self._settings.llm_max_cost_limit:
            return False, f"Mission cost limit reached (${self._settings.llm_max_cost_limit:.2f})"
        
        return True, ""
    
    def _update_usage_tracking(self, tokens_used: int = 0) -> None:
        """Update usage tracking after an LLM call."""
        self._mission_llm_requests += 1
        self._daily_llm_requests += 1
        self._mission_tokens_used += tokens_used
        
        # Estimate cost
        cost_per_token = self._settings.llm_cost_per_1k_tokens / 1000
        self._mission_estimated_cost += tokens_used * cost_per_token
    
    def reset_mission_limits(self) -> None:
        """Reset mission-specific limits (call when starting new mission)."""
        self._mission_llm_requests = 0
        self._mission_tokens_used = 0
        self._mission_estimated_cost = 0.0
    
    def get_usage_stats(self) -> Dict[str, Any]:
        """Get current usage statistics."""
        return {
            "mission_llm_requests": self._mission_llm_requests,
            "mission_tokens_used": self._mission_tokens_used,
            "mission_estimated_cost_usd": round(self._mission_estimated_cost, 4),
            "daily_llm_requests": self._daily_llm_requests,
            "limits": {
                "mission_requests_limit": self._settings.llm_mission_requests_limit,
                "daily_requests_limit": self._settings.llm_daily_requests_limit,
                "max_cost_limit_usd": self._settings.llm_max_cost_limit,
            }
        }
    
    def _safe_uuid(self, value: str) -> UUID:
        """Safely convert a string to UUID, generating new one if invalid."""
        try:
            return UUID(value) if value and len(value) == 36 else uuid4()
        except (ValueError, TypeError):
            return uuid4()
    
    async def _ensure_llm_service(self) -> Optional["LLMService"]:
        """
        Ensure LLM service is initialized.
        
        Lazily initializes the LLM service if not already done.
        
        Returns:
            LLMService instance or None if LLM is disabled
        """
        if not self.llm_enabled:
            return None
        
        if self._llm_service is not None:
            return self._llm_service
        
        if self._llm_initialized:
            return self._llm_service
        
        self._llm_initialized = True
        
        try:
            from ..core.llm.service import LLMService, get_llm_service
            from ..core.llm.base import LLMConfig, ProviderType
            
            # Try to get global service first
            service = get_llm_service()
            
            # If no providers registered, try to set up from config
            if not service.providers:
                await self._setup_llm_from_config(service)
            
            self._llm_service = service
            self.logger.info(f"LLM service initialized with providers: {list(service.providers.keys())}")
            return service
            
        except Exception as e:
            self.logger.warning(f"Failed to initialize LLM service: {e}")
            self.llm_enabled = False
            return None
    
    async def _setup_llm_from_config(self, service: "LLMService") -> None:
        """Setup LLM providers from configuration."""
        from ..core.llm.base import LLMConfig, ProviderType
        
        provider_type = self._settings.llm_provider.lower()
        
        if provider_type == "openai" and self._settings.effective_llm_api_key:
            from ..core.llm.openai_provider import OpenAIProvider
            config = LLMConfig(
                provider_type=ProviderType.OPENAI,
                api_key=self._settings.effective_llm_api_key,
                api_base=self._settings.llm_api_base,
                model=self._settings.llm_model,
                temperature=self._settings.llm_temperature,
                max_tokens=self._settings.llm_max_tokens,
                timeout=self._settings.llm_timeout,
                max_retries=self._settings.llm_max_retries,
            )
            service.register_provider("openai", OpenAIProvider(config), set_as_default=True)
            self.logger.info("✅ OpenAI provider configured")
        
        elif provider_type == "blackbox" and self._settings.effective_llm_api_key:
            from ..core.llm.blackbox_provider import BlackboxAIProvider
            api_base = self._settings.llm_api_base or "https://api.blackbox.ai"
            config = LLMConfig(
                api_key=self._settings.effective_llm_api_key,
                api_base=api_base,
                model=self._settings.llm_model,
                temperature=self._settings.llm_temperature,
                max_tokens=self._settings.llm_max_tokens,
                timeout=self._settings.llm_timeout,
                max_retries=self._settings.llm_max_retries,
            )
            service.register_provider("blackbox", BlackboxAIProvider(config), set_as_default=True)
            self.logger.info("✅ BlackboxAI provider configured")
            
        elif provider_type == "local" and self._settings.llm_api_base:
            from ..core.llm.local_provider import LocalLLMProvider
            config = LLMConfig(
                provider_type=ProviderType.LOCAL,
                api_base=self._settings.llm_api_base,
                api_key=self._settings.effective_llm_api_key,  # Optional for some local servers
                model=self._settings.llm_model,
                temperature=self._settings.llm_temperature,
                max_tokens=self._settings.llm_max_tokens,
                timeout=self._settings.llm_timeout,
                max_retries=self._settings.llm_max_retries,
            )
            service.register_provider("local", LocalLLMProvider(config), set_as_default=True)
            self.logger.info("✅ Local LLM provider configured")
            
        elif provider_type == "mock":
            from ..core.llm.mock_provider import MockLLMProvider
            mock = MockLLMProvider()
            mock.setup_analysis_responses()
            service.register_provider("mock", mock, set_as_default=True)
            self.logger.info("✅ Mock LLM provider configured (for testing)")
        
        else:
            self.logger.warning(
                f"⚠️ LLM provider '{provider_type}' requires additional configuration. "
                "Set LLM_API_KEY for OpenAI/BlackboxAI or LLM_API_BASE for local providers."
            )
    
    # ═══════════════════════════════════════════════════════════
    # Task Execution (for analysis tasks)
    # ═══════════════════════════════════════════════════════════
    
    async def execute_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute an analysis task.
        
        Analysis tasks contain the failed task data and require
        determining the next course of action.
        """
        self.logger.info(f"Executing analysis task: {task.get('id')}")
        
        # Extract the original failed task information
        failed_task_id = task.get("result_data", {}).get("original_task_id")
        error_context = task.get("result_data", {}).get("error_context", {})
        execution_logs = task.get("result_data", {}).get("execution_logs", [])
        
        if not failed_task_id:
            return {"error": "No original task ID provided", "decision": "skip"}
        
        # Perform analysis
        analysis_result = await self.analyze_failure(
            task_id=failed_task_id,
            error_context=error_context,
            execution_logs=execution_logs
        )
        
        return analysis_result
    
    # ═══════════════════════════════════════════════════════════
    # Core Analysis Methods
    # ═══════════════════════════════════════════════════════════
    
    async def analyze_failure(
        self,
        task_id: str,
        error_context: Dict[str, Any],
        execution_logs: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Analyze a failed task and determine next steps.
        
        This is the core Reflexion Logic implementation.
        Enhanced with Operational Memory for adaptive learning.
        
        Args:
            task_id: ID of the failed task
            error_context: ErrorContext data from the failed task
            execution_logs: Execution logs from the task
            
        Returns:
            Analysis result with decision and reasoning
        """
        self.logger.info(f"Analyzing failure for task {task_id}")
        self._stats["analyses_performed"] += 1
        
        # Get the original task
        original_task = await self.blackboard.get_task(task_id)
        if not original_task:
            return {
                "decision": "skip",
                "reasoning": "Original task not found",
                "task_id": task_id
            }
        
        # Categorize the error
        error_type = error_context.get("error_type", "unknown")
        category = self._categorize_error(error_type)
        
        # Get retry strategy for this category
        strategy = self.RETRY_STRATEGIES.get(category, self.RETRY_STRATEGIES["unknown"])
        
        # Check retry count
        retry_count = original_task.get("retry_count", 0)
        max_retries = original_task.get("max_retries", strategy["max_retries"])
        
        # Gather context for decision
        context = await self._gather_analysis_context(original_task, error_context)
        
        # ═══════════════════════════════════════════════════════════
        # Hybrid Intelligence: Consult Operational Memory
        # ═══════════════════════════════════════════════════════════
        historical_insight = await self._get_historical_insight(
            original_task, error_context, context
        )
        if historical_insight:
            context["historical_insight"] = historical_insight
            self._stats["memory_consultations"] += 1
        
        # Record decision start time for tracking
        decision_start_time = datetime.utcnow()
        
        # Make decision
        decision = await self._make_decision(
            original_task=original_task,
            error_context=error_context,
            execution_logs=execution_logs,
            category=category,
            strategy=strategy,
            context=context,
            retry_count=retry_count,
            max_retries=max_retries
        )
        
        # Calculate decision duration
        decision_duration_ms = int((datetime.utcnow() - decision_start_time).total_seconds() * 1000)
        
        # Record analysis in local history
        analysis_record = {
            "task_id": task_id,
            "error_type": error_type,
            "category": category,
            "decision": decision["decision"],
            "timestamp": datetime.utcnow().isoformat(),
            "used_historical_insight": historical_insight is not None,
            "duration_ms": decision_duration_ms,
        }
        self._analysis_history.append(analysis_record)
        
        # ═══════════════════════════════════════════════════════════
        # Hybrid Intelligence: Record Decision in Operational Memory
        # ═══════════════════════════════════════════════════════════
        await self._record_decision_to_memory(
            original_task, error_context, context, decision, decision_duration_ms
        )
        
        # Publish analysis result event
        await self._publish_analysis_result(task_id, original_task, decision)
        
        return decision
    
    # ═══════════════════════════════════════════════════════════
    # Hybrid Intelligence: Operational Memory Integration Methods
    # ═══════════════════════════════════════════════════════════
    
    async def _get_historical_insight(
        self,
        task: Dict[str, Any],
        error_context: Dict[str, Any],
        context: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Query Operational Memory for historical insights.
        
        This is the key to adaptive learning - we learn from past failures!
        
        Args:
            task: The original failed task
            error_context: Error context from the failure
            context: Gathered analysis context
            
        Returns:
            Historical insight dict or None if no relevant data
        """
        if not self._operational_memory:
            return None
        
        try:
            # Determine context type
            task_type = task.get("type", "").lower()
            if "exploit" in task_type:
                op_context = OperationalContext.EXPLOIT
            elif "privesc" in task_type:
                op_context = OperationalContext.PRIVESC
            elif "lateral" in task_type:
                op_context = OperationalContext.LATERAL
            elif "cred" in task_type:
                op_context = OperationalContext.CRED_HARVEST
            else:
                op_context = OperationalContext.ANALYSIS
            
            # Get target OS from context
            target_info = context.get("target_info") or {}
            target_os = target_info.get("os")
            
            # Get vulnerability type from context
            vuln_info = context.get("vuln_info") or {}
            vuln_type = vuln_info.get("type") or error_context.get("technique_id")
            
            # Search for similar experiences
            experiences = await self._operational_memory.get_similar_experiences(
                context=op_context,
                target_os=target_os,
                vuln_type=vuln_type,
                limit=10
            )
            
            if not experiences:
                self.logger.debug("No historical experiences found for this context")
                return None
            
            # Get best approach recommendation
            best_approach = await self._operational_memory.get_best_approach_for_context(
                context=op_context,
                target_os=target_os,
                vuln_type=vuln_type,
                available_modules=[m.get("rx_module_id") for m in context.get("alternative_modules", [])]
            )
            
            # Get success rate
            success_rate, sample_count = await self._operational_memory.get_success_rate_for_context(
                context=op_context,
                target_os=target_os,
                vuln_type=vuln_type
            )
            
            insight = {
                "experiences_found": len(experiences),
                "success_rate": success_rate,
                "sample_count": sample_count,
                "best_approach": best_approach,
                "common_failure_factors": self._extract_common_failures(experiences),
                "recommended_modifications": self._extract_successful_modifications(experiences),
            }
            
            self.logger.info(
                f"Historical insight found: {len(experiences)} experiences, "
                f"success rate: {success_rate:.1%} (n={sample_count})"
            )
            
            return insight
            
        except Exception as e:
            self.logger.warning(f"Failed to get historical insight: {e}")
            return None
    
    def _extract_common_failures(self, experiences: List[DecisionRecord]) -> List[str]:
        """Extract common failure factors from experiences."""
        from collections import Counter
        
        all_factors = []
        for exp in experiences:
            if exp.outcome == DecisionOutcome.FAILURE:
                all_factors.extend(exp.failure_factors)
        
        if not all_factors:
            return []
        
        # Return top 5 most common
        counter = Counter(all_factors)
        return [factor for factor, _ in counter.most_common(5)]
    
    def _extract_successful_modifications(
        self,
        experiences: List[DecisionRecord]
    ) -> List[Dict[str, Any]]:
        """Extract successful modifications from past experiences."""
        modifications = []
        
        for exp in experiences:
            if exp.outcome == DecisionOutcome.SUCCESS and exp.decision_type == "modify_approach":
                modifications.append({
                    "parameters": exp.parameters_used,
                    "success_factors": exp.success_factors,
                    "module": exp.parameters_used.get("module"),
                })
        
        return modifications[:5]  # Top 5
    
    async def _record_decision_to_memory(
        self,
        original_task: Dict[str, Any],
        error_context: Dict[str, Any],
        context: Dict[str, Any],
        decision: Dict[str, Any],
        duration_ms: int
    ) -> None:
        """
        Record the analysis decision in Operational Memory.
        
        This enables future learning from this decision!
        """
        if not self._operational_memory:
            return
        
        try:
            # Determine context type
            task_type = original_task.get("type", "").lower()
            if "exploit" in task_type:
                op_context = OperationalContext.EXPLOIT
            elif "privesc" in task_type:
                op_context = OperationalContext.PRIVESC
            elif "lateral" in task_type:
                op_context = OperationalContext.LATERAL
            elif "cred" in task_type:
                op_context = OperationalContext.CRED_HARVEST
            else:
                op_context = OperationalContext.ANALYSIS
            
            # Get mission ID
            mission_id = None
            if self._current_mission_id:
                try:
                    mission_id = UUID(self._current_mission_id)
                except (ValueError, TypeError):
                    pass
            
            # Prepare target and vuln info
            target_info = context.get("target_info")
            vuln_info = context.get("vuln_info")
            
            # Build parameters
            parameters = {
                "decision": decision.get("decision"),
                "error_category": self._categorize_error(error_context.get("error_type", "unknown")),
                "module": decision.get("new_module") or original_task.get("rx_module"),
                **decision.get("modified_parameters", {})
            }
            
            # Record the decision
            decision_id = await self._operational_memory.record_decision(
                mission_id=mission_id,
                context=op_context,
                decision_type=decision.get("decision", "unknown"),
                decision_source="llm" if decision.get("llm_analysis") else "rules",
                parameters=parameters,
                target_info=target_info,
                vuln_info=vuln_info
            )
            
            # Note: The outcome will be updated when we get feedback
            # For now, we mark it as pending (default is FAILURE, will be updated)
            
            self.logger.debug(f"Recorded decision {decision_id} to Operational Memory")
            
        except Exception as e:
            self.logger.warning(f"Failed to record decision to memory: {e}")
    
    async def update_decision_outcome(
        self,
        decision_id: UUID,
        success: bool,
        details: Dict[str, Any],
        lessons: Optional[List[str]] = None
    ) -> None:
        """
        Update the outcome of a previously recorded decision.
        
        Call this when we know if the decision led to success or failure.
        This completes the learning loop!
        
        Args:
            decision_id: ID of the decision to update
            success: Whether the decision led to success
            details: Additional details about the outcome
            lessons: Lessons learned from this experience
        """
        if not self._operational_memory:
            return
        
        try:
            outcome = DecisionOutcome.SUCCESS if success else DecisionOutcome.FAILURE
            
            await self._operational_memory.update_outcome(
                decision_id=decision_id,
                outcome=outcome,
                details=details,
                lessons=lessons
            )
            
            self.logger.info(f"Updated decision {decision_id} outcome: {outcome.value}")
            
        except Exception as e:
            self.logger.warning(f"Failed to update decision outcome: {e}")
    
    def _categorize_error(self, error_type: str) -> str:
        """Categorize an error type into a broader category."""
        return self.ERROR_CATEGORIES.get(error_type.lower(), "unknown")
    
    async def _gather_analysis_context(
        self,
        task: Dict[str, Any],
        error_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Gather additional context for analysis.
        
        This includes target information, vulnerability details,
        and knowledge base recommendations.
        """
        context = {
            "target_info": None,
            "vuln_info": None,
            "alternative_modules": [],
            "alternative_techniques": [],
            "detected_defenses": error_context.get("detected_defenses", [])
        }
        
        # Get target info
        target_id = task.get("target_id")
        if target_id:
            if isinstance(target_id, str) and target_id.startswith("target:"):
                target_id = target_id.replace("target:", "")
            context["target_info"] = await self.blackboard.get_target(target_id)
        
        # Get vulnerability info
        vuln_id = task.get("vuln_id")
        if vuln_id:
            if isinstance(vuln_id, str) and vuln_id.startswith("vuln:"):
                vuln_id = vuln_id.replace("vuln:", "")
            context["vuln_info"] = await self.blackboard.get_vulnerability(vuln_id)
        
        # Query knowledge base for alternatives
        if self.knowledge and self.knowledge.is_loaded():
            # Get alternative modules for the same technique
            technique_id = error_context.get("technique_id")
            if technique_id:
                alt_modules = self.get_technique_modules(
                    technique_id=technique_id,
                    platform=self._get_target_platform(context["target_info"])
                )
                # Exclude the one that failed
                failed_module = error_context.get("module_used")
                context["alternative_modules"] = [
                    m for m in alt_modules 
                    if m.get("rx_module_id") != failed_module
                ][:5]  # Limit to top 5
            
            # Get alternative techniques if defenses detected
            if context["detected_defenses"]:
                # Search for evasion modules
                evasion_modules = self.search_modules(
                    query="evasion bypass defense",
                    platform=self._get_target_platform(context["target_info"]),
                    limit=5
                )
                context["alternative_techniques"] = [
                    m.get("technique_id") for m in evasion_modules if m.get("technique_id")
                ]
            
            # ═══════════════════════════════════════════════════════════
            # AI-PLAN: Query Nuclei CVE API for alternative exploitation paths
            # If vulnerability is High severity and exploit failed, search for
            # related Nuclei templates that might provide alternative approaches
            # ═══════════════════════════════════════════════════════════
            vuln_info = context.get("vuln_info")
            if vuln_info:
                vuln_severity = vuln_info.get("severity", "").lower()
                vuln_type = vuln_info.get("type", "")
                cve_id = vuln_info.get("cve_id") or vuln_type  # Use CVE ID or vuln type
                
                # Search for alternative Nuclei templates if High severity exploit failed
                if vuln_severity in ["high", "critical"]:
                    nuclei_alternatives = await self._search_nuclei_alternatives(
                        cve_id=cve_id,
                        vuln_type=vuln_type,
                        error_context=error_context
                    )
                    context["nuclei_alternatives"] = nuclei_alternatives
        
        return context
    
    async def _search_nuclei_alternatives(
        self,
        cve_id: str,
        vuln_type: str,
        error_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        AI-Driven Nuclei Template Search for Alternative Exploitation Paths.
        
        When a High severity vulnerability exploit fails, this method searches
        the Nuclei Knowledge Base for alternative approaches:
        
        1. First, try to find the exact CVE in Nuclei templates
        2. If found, look for related templates (same technology/protocol)
        3. Extract alternative exploitation techniques from template info
        
        This implements the AI-to-Nuclei Logic Wiring for failed exploit analysis.
        
        Args:
            cve_id: CVE ID or vulnerability identifier
            vuln_type: Vulnerability type/name
            error_context: Context from the failed task
            
        Returns:
            Dict containing alternative approaches from Nuclei knowledge base
        """
        if not self.knowledge or not self.knowledge.is_loaded():
            return {"available": False, "reason": "Knowledge base not loaded"}
        
        alternatives = {
            "available": True,
            "cve_template": None,
            "related_templates": [],
            "alternative_approaches": [],
            "ai_plan_messages": []
        }
        
        # Step 1: Try to find exact CVE template
        if cve_id and cve_id.upper().startswith("CVE-"):
            ai_plan_msg = (
                f"[AI-PLAN] Exploit failed for {cve_id}. "
                f"Searching Nuclei Knowledge Base for alternative approaches..."
            )
            alternatives["ai_plan_messages"].append(ai_plan_msg)
            self.logger.info(ai_plan_msg)
            
            cve_template = self.knowledge.get_nuclei_template_by_cve(cve_id)
            if cve_template:
                alternatives["cve_template"] = cve_template
                
                # Extract tags and references for finding related templates
                template_tags = cve_template.get("tags", [])
                template_protocol = cve_template.get("protocol", [])
                
                ai_plan_msg = (
                    f"[AI-PLAN] Found Nuclei template for {cve_id}: "
                    f"{cve_template.get('name')}. Tags: {template_tags[:5]}..."
                )
                alternatives["ai_plan_messages"].append(ai_plan_msg)
                self.logger.info(ai_plan_msg)
                
                # Step 2: Search for related templates by tags
                for tag in template_tags[:3]:  # Top 3 tags
                    related = self.knowledge.get_nuclei_templates_by_tag(
                        tag=tag,
                        limit=10
                    )
                    for rt in related:
                        if rt.get("template_id") != cve_template.get("template_id"):
                            if rt not in alternatives["related_templates"]:
                                alternatives["related_templates"].append(rt)
                
                # Step 3: Generate alternative approaches
                alternatives["alternative_approaches"] = self._generate_alternative_approaches(
                    cve_template=cve_template,
                    related_templates=alternatives["related_templates"],
                    error_context=error_context
                )
        
        # If no CVE template found, search by vuln type
        if not alternatives["cve_template"] and vuln_type:
            ai_plan_msg = (
                f"[AI-PLAN] No direct CVE template found. "
                f"Searching by vulnerability type: {vuln_type}..."
            )
            alternatives["ai_plan_messages"].append(ai_plan_msg)
            self.logger.info(ai_plan_msg)
            
            # Search Nuclei templates by vulnerability type
            search_results = self.knowledge.search_nuclei_templates(
                query=vuln_type,
                limit=20
            )
            
            if search_results:
                alternatives["related_templates"] = search_results
                ai_plan_msg = (
                    f"[AI-PLAN] Found {len(search_results)} related Nuclei templates "
                    f"for vulnerability type: {vuln_type}"
                )
                alternatives["ai_plan_messages"].append(ai_plan_msg)
                self.logger.info(ai_plan_msg)
                
                # Generate approaches from search results
                alternatives["alternative_approaches"] = self._generate_alternative_approaches(
                    cve_template=None,
                    related_templates=search_results,
                    error_context=error_context
                )
        
        # Log to Blackboard for Execution Stream visibility
        if self.blackboard and self._current_mission_id:
            await self.blackboard.log_result(
                self._current_mission_id,
                "ai_plan",
                {
                    "event": "nuclei_alternative_search",
                    "cve_id": cve_id,
                    "vuln_type": vuln_type,
                    "found_cve_template": alternatives["cve_template"] is not None,
                    "related_templates_count": len(alternatives["related_templates"]),
                    "alternative_approaches_count": len(alternatives["alternative_approaches"]),
                    "messages": alternatives["ai_plan_messages"]
                }
            )
        
        return alternatives
    
    def _generate_alternative_approaches(
        self,
        cve_template: Optional[Dict[str, Any]],
        related_templates: List[Dict[str, Any]],
        error_context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Generate alternative exploitation approaches based on Nuclei templates.
        
        Analyzes the templates to suggest different attack vectors,
        evasion techniques, or alternative exploitation paths.
        
        Args:
            cve_template: Direct CVE template if found
            related_templates: Related templates from search
            error_context: Original error context
            
        Returns:
            List of alternative approach suggestions
        """
        approaches = []
        error_type = error_context.get("error_type", "unknown").lower()
        
        # Approach 1: If defense detected, suggest templates with evasion
        if "defense" in error_type or "blocked" in error_type:
            evasion_templates = [
                t for t in related_templates
                if any(tag in ["evasion", "bypass", "waf-bypass"] 
                       for tag in t.get("tags", []))
            ]
            if evasion_templates:
                approaches.append({
                    "type": "evasion",
                    "description": "Defense detected. Try templates with evasion capabilities.",
                    "suggested_templates": [t.get("template_id") for t in evasion_templates[:5]],
                    "reasoning": "These templates include WAF bypass or evasion techniques."
                })
        
        # Approach 2: Try different protocols/methods
        if cve_template:
            template_protocol = cve_template.get("protocol", [])
            alt_protocol_templates = [
                t for t in related_templates
                if t.get("protocol") and t.get("protocol") != template_protocol
            ]
            if alt_protocol_templates:
                approaches.append({
                    "type": "protocol_switch",
                    "description": f"Try alternative protocol. Original: {template_protocol}",
                    "suggested_templates": [t.get("template_id") for t in alt_protocol_templates[:5]],
                    "reasoning": "Different protocols may bypass current defenses."
                })
        
        # Approach 3: Look for exploit chain templates
        chain_templates = [
            t for t in related_templates
            if any(tag in ["chain", "multi-step", "exploit-chain"] 
                   for tag in t.get("tags", []))
        ]
        if chain_templates:
            approaches.append({
                "type": "exploit_chain",
                "description": "Consider multi-step exploitation.",
                "suggested_templates": [t.get("template_id") for t in chain_templates[:5]],
                "reasoning": "Chained exploits may succeed where single exploits fail."
            })
        
        # Approach 4: Lower severity reconnaissance
        if not approaches:
            info_templates = [
                t for t in related_templates
                if t.get("severity", "").lower() in ["info", "low"]
            ]
            if info_templates:
                approaches.append({
                    "type": "reconnaissance",
                    "description": "Gather more information before retrying exploit.",
                    "suggested_templates": [t.get("template_id") for t in info_templates[:5]],
                    "reasoning": "Additional recon may reveal better attack vectors."
                })
        
        return approaches
    
    def _get_target_platform(self, target_info: Optional[Dict[str, Any]]) -> Optional[str]:
        """Extract platform from target info."""
        if not target_info:
            return None
        
        os_info = (target_info.get("os") or "").lower()
        if "windows" in os_info:
            return "windows"
        elif "linux" in os_info:
            return "linux"
        elif "macos" in os_info or "darwin" in os_info:
            return "macos"
        return None
    
    async def _make_decision(
        self,
        original_task: Dict[str, Any],
        error_context: Dict[str, Any],
        execution_logs: List[Dict[str, Any]],
        category: str,
        strategy: Dict[str, Any],
        context: Dict[str, Any],
        retry_count: int,
        max_retries: int
    ) -> Dict[str, Any]:
        """
        Make a decision about how to handle the failed task.
        
        Decision options:
        - retry: Retry the same task
        - modify_approach: Retry with different parameters/module
        - skip: Skip this task and move on
        - escalate: Escalate for human/LLM review
        - ask_approval: HITL - Request user approval for high-risk action
        """
        # ═══════════════════════════════════════════════════════════
        # HITL: Check if this is a high-risk action requiring approval
        # ═══════════════════════════════════════════════════════════
        is_high_risk, risk_reason, risk_level = self._is_high_risk_action(original_task, context)
        if is_high_risk:
            self.logger.warning(f"⚠️ High-risk action detected: {risk_reason}")
            return await self._create_approval_request(
                original_task, context, risk_reason, risk_level
            )
        
        # ═══════════════════════════════════════════════════════════
        # Hybrid Intelligence: Apply Historical Insight First
        # ═══════════════════════════════════════════════════════════
        historical_insight = context.get("historical_insight")
        if historical_insight:
            memory_decision = self._apply_historical_insight(
                historical_insight, category, strategy, context
            )
            if memory_decision:
                self._stats["memory_guided_decisions"] += 1
                self._stats["historical_insights_applied"] += 1
                return memory_decision
        
        # Check if LLM analysis is available and needed
        if self.llm_enabled and self._needs_llm_analysis(category, context):
            return await self._llm_decision(
                original_task, error_context, execution_logs, context
            )
        
        # Rule-based decision making
        detected_defenses = context.get("detected_defenses", [])
        
        # Defense detected - try alternatives or skip
        if category == "defense":
            # ═══════════════════════════════════════════════════════════
            # AI-PLAN: Check Nuclei alternatives for High severity vulns
            # ═══════════════════════════════════════════════════════════
            nuclei_alts = context.get("nuclei_alternatives", {})
            if nuclei_alts.get("alternative_approaches"):
                best_approach = nuclei_alts["alternative_approaches"][0]
                self._stats["modifications_recommended"] += 1
                
                ai_plan_msg = (
                    f"[AI-PLAN] Defense blocked exploit. Found Nuclei alternative: "
                    f"{best_approach.get('type')} - {best_approach.get('description')}"
                )
                self.logger.info(ai_plan_msg)
                
                return {
                    "decision": "modify_approach",
                    "reasoning": (
                        f"Defense detected ({detected_defenses}). "
                        f"AI-PLAN suggests: {best_approach.get('description')}"
                    ),
                    "nuclei_approach": best_approach,
                    "nuclei_templates": best_approach.get("suggested_templates", []),
                    "modified_parameters": {
                        "use_evasion": True,
                        "encode_payload": True,
                        "nuclei_guided": True
                    },
                    "recommendations": [
                        best_approach.get("reasoning"),
                        *strategy["recommendations"]
                    ],
                    "ai_plan_messages": nuclei_alts.get("ai_plan_messages", [])
                }
            elif context["alternative_modules"]:
                self._stats["modifications_recommended"] += 1
                return {
                    "decision": "modify_approach",
                    "reasoning": f"Defense detected ({detected_defenses}). Trying alternative module.",
                    "new_module": context["alternative_modules"][0].get("rx_module_id"),
                    "modified_parameters": {
                        "use_evasion": True,
                        "encode_payload": True
                    },
                    "recommendations": strategy["recommendations"]
                }
            else:
                self._stats["skips_recommended"] += 1
                return {
                    "decision": "skip",
                    "reasoning": f"Defense detected ({detected_defenses}) and no alternatives available.",
                    "recommendations": strategy["recommendations"]
                }
        
        # Vulnerability patched - check Nuclei for reconnaissance or skip
        if category == "vulnerability":
            # ═══════════════════════════════════════════════════════════
            # AI-PLAN: Before skipping, check if Nuclei suggests recon
            # ═══════════════════════════════════════════════════════════
            nuclei_alts = context.get("nuclei_alternatives", {})
            recon_approaches = [
                a for a in nuclei_alts.get("alternative_approaches", [])
                if a.get("type") == "reconnaissance"
            ]
            
            if recon_approaches:
                recon_approach = recon_approaches[0]
                ai_plan_msg = (
                    f"[AI-PLAN] Vulnerability appears patched. "
                    f"Suggesting additional reconnaissance via Nuclei templates."
                )
                self.logger.info(ai_plan_msg)
                
                self._stats["modifications_recommended"] += 1
                return {
                    "decision": "modify_approach",
                    "reasoning": (
                        "Target may be patched. AI-PLAN suggests gathering more "
                        "information before giving up."
                    ),
                    "nuclei_approach": recon_approach,
                    "nuclei_templates": recon_approach.get("suggested_templates", []),
                    "modified_parameters": {
                        "perform_recon": True,
                        "nuclei_guided": True
                    },
                    "recommendations": [
                        recon_approach.get("reasoning"),
                        "Run additional Nuclei scans before skipping this target",
                        *strategy["recommendations"]
                    ],
                    "ai_plan_messages": nuclei_alts.get("ai_plan_messages", [])
                }
            
            self._stats["skips_recommended"] += 1
            return {
                "decision": "skip",
                "reasoning": "Target appears to be patched or not vulnerable.",
                "recommendations": strategy["recommendations"]
            }
        
        # Network issues - retry if within limits
        if category == "network" and retry_count < max_retries:
            self._stats["retries_recommended"] += 1
            return {
                "decision": "retry",
                "reasoning": f"Network issue - retry attempt {retry_count + 1}/{max_retries}",
                "delay_seconds": strategy["retry_delay"],
                "recommendations": strategy["recommendations"]
            }
        
        # Authentication failed - try different approach
        if category == "authentication":
            if retry_count < max_retries:
                self._stats["retries_recommended"] += 1
                return {
                    "decision": "retry",
                    "reasoning": "Authentication failed - may be transient",
                    "delay_seconds": strategy["retry_delay"],
                    "recommendations": strategy["recommendations"]
                }
            else:
                self._stats["modifications_recommended"] += 1
                return {
                    "decision": "modify_approach",
                    "reasoning": "Authentication persistently failing - need different credentials",
                    "modified_parameters": {
                        "harvest_more_creds": True
                    },
                    "recommendations": strategy["recommendations"]
                }
        
        # Technical error - retry or escalate
        if category == "technical":
            if retry_count < max_retries:
                self._stats["retries_recommended"] += 1
                return {
                    "decision": "retry",
                    "reasoning": "Technical error - may be transient",
                    "delay_seconds": strategy["retry_delay"],
                    "recommendations": strategy["recommendations"]
                }
            else:
                self._stats["escalations"] += 1
                return {
                    "decision": "escalate",
                    "reasoning": "Persistent technical error - needs manual review",
                    "escalation_reason": error_context.get("error_message", "Unknown error"),
                    "recommendations": strategy["recommendations"]
                }
        
        # Unknown error - escalate
        self._stats["escalations"] += 1
        return {
            "decision": "escalate",
            "reasoning": "Unknown error type - needs investigation",
            "escalation_reason": error_context.get("error_message", "Unknown error"),
            "recommendations": strategy["recommendations"]
        }
    
    def _needs_llm_analysis(self, category: str, context: Dict[str, Any]) -> bool:
        """Determine if this failure needs LLM analysis."""
        # If we have good historical insight with high confidence, skip LLM
        historical_insight = context.get("historical_insight")
        if historical_insight:
            best_approach = historical_insight.get("best_approach", {})
            if best_approach.get("confidence") == "high":
                self.logger.debug("High-confidence historical insight available, skipping LLM")
                return False
        
        # Complex defense scenarios benefit from LLM reasoning
        if category == "defense" and len(context.get("detected_defenses", [])) > 1:
            return True
        
        # Multiple alternatives need intelligent selection
        if len(context.get("alternative_modules", [])) > 3:
            return True
        
        return False
    
    def _apply_historical_insight(
        self,
        insight: Dict[str, Any],
        category: str,
        strategy: Dict[str, Any],
        context: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Apply historical insight to make a decision.
        
        This is where we actually USE the memory to guide decisions!
        
        Args:
            insight: Historical insight from Operational Memory
            category: Error category
            strategy: Retry strategy for this category
            context: Full analysis context
            
        Returns:
            Decision dict if insight is actionable, None otherwise
        """
        best_approach = insight.get("best_approach")
        if not best_approach:
            return None
        
        confidence = best_approach.get("confidence", "low")
        success_rate = insight.get("success_rate", 0.5)
        sample_count = insight.get("sample_count", 0)
        
        # Only apply if we have enough data and reasonable success rate
        if sample_count < 3:
            self.logger.debug(f"Insufficient samples ({sample_count}) for memory-guided decision")
            return None
        
        # If success rate is very low, don't recommend retrying
        if success_rate < 0.1:
            self.logger.info(
                f"Historical success rate very low ({success_rate:.1%}), recommending skip"
            )
            return {
                "decision": "skip",
                "reasoning": (
                    f"Operational Memory indicates very low success rate ({success_rate:.1%}) "
                    f"for this scenario based on {sample_count} similar experiences. "
                    "Recommending skip to avoid wasted effort."
                ),
                "recommendations": [
                    *strategy.get("recommendations", []),
                    "Consider different attack vector",
                    "Target may be well-defended against this approach"
                ],
                "memory_guided": True,
                "historical_success_rate": success_rate,
                "sample_count": sample_count,
            }
        
        # If we have a recommended approach with medium+ confidence
        recommended_approach = best_approach.get("recommended_approach")
        if recommended_approach and confidence in ["medium", "high"]:
            module = recommended_approach.get("module")
            params = recommended_approach.get("recommended_parameters", {})
            
            # Check if module is in available alternatives
            alternative_modules = context.get("alternative_modules", [])
            module_available = any(
                m.get("rx_module_id") == module or m.get("name") == module
                for m in alternative_modules
            ) if alternative_modules else True  # Assume available if no list
            
            if module_available:
                avoid_factors = best_approach.get("avoid_factors", [])
                
                self.logger.info(
                    f"Memory-guided decision: Use approach with {success_rate:.1%} success rate"
                )
                
                return {
                    "decision": "modify_approach",
                    "reasoning": (
                        f"Operational Memory recommends this approach based on {sample_count} "
                        f"similar experiences with {success_rate:.1%} success rate. "
                        f"Confidence: {confidence}."
                    ),
                    "new_module": module,
                    "modified_parameters": {
                        **params,
                        "avoid_patterns": avoid_factors,
                    },
                    "recommendations": [
                        f"Approach selected based on {sample_count} historical experiences",
                        f"Avoid these patterns: {', '.join(avoid_factors[:3])}" if avoid_factors else "No specific patterns to avoid",
                        *strategy.get("recommendations", [])[:2],
                    ],
                    "memory_guided": True,
                    "historical_success_rate": success_rate,
                    "sample_count": sample_count,
                    "confidence": confidence,
                }
        
        # No actionable insight
        return None
    
    def _is_high_risk_action(self, task: Dict[str, Any], context: Dict[str, Any]) -> tuple[bool, str, RiskLevel]:
        """
        Determine if an action is high-risk and requires user approval.
        
        HITL: This is used to identify actions that should trigger ASK_APPROVAL.
        
        Returns:
            Tuple of (is_high_risk, reason, risk_level)
        """
        task_type = task.get("type", "")
        module = task.get("rx_module", "") or ""
        
        # Critical risk: Destructive operations
        destructive_modules = [
            "delete", "wipe", "destroy", "format", "ransom",
            "rm -rf", "diskpart", "fdisk"
        ]
        if any(d in module.lower() for d in destructive_modules):
            return True, "Potentially destructive operation", RiskLevel.CRITICAL
        
        # High risk: Persistence mechanisms
        persistence_modules = [
            "persistence", "backdoor", "rootkit", "scheduled_task",
            "registry", "startup", "service"
        ]
        if any(p in module.lower() for p in persistence_modules):
            return True, "Installing persistence mechanism", RiskLevel.HIGH
        
        # High risk: Privilege escalation to SYSTEM/root
        if task_type == "privesc":
            return True, "Privilege escalation attempt", RiskLevel.HIGH
        
        # High risk: Data exfiltration
        exfil_modules = [
            "exfil", "upload", "transfer", "extract", "dump",
            "copy_data", "steal"
        ]
        if any(e in module.lower() for e in exfil_modules):
            return True, "Data extraction/exfiltration", RiskLevel.HIGH
        
        # Medium risk: Lateral movement
        if task_type == "lateral":
            return True, "Lateral movement to new target", RiskLevel.MEDIUM
        
        # Medium risk: Write operations on target
        write_modules = [
            "write", "create", "modify", "change", "edit",
            "append", "patch"
        ]
        if any(w in module.lower() for w in write_modules):
            return True, "Write operation on target system", RiskLevel.MEDIUM
        
        # Not high-risk
        return False, "", RiskLevel.LOW
    
    async def _create_approval_request(
        self,
        original_task: Dict[str, Any],
        context: Dict[str, Any],
        risk_reason: str,
        risk_level: RiskLevel
    ) -> Dict[str, Any]:
        """
        Create an approval request for a high-risk action.
        
        This is the HITL integration point where we pause execution
        and wait for user consent.
        """
        self.logger.info(f"🔐 Creating approval request: {risk_reason}")
        
        # Determine action type from task
        task_type = original_task.get("type", "")
        if "exploit" in task_type.lower():
            action_type = ActionType.EXPLOIT
        elif "lateral" in task_type.lower():
            action_type = ActionType.LATERAL_MOVEMENT
        elif "privesc" in task_type.lower():
            action_type = ActionType.PRIVILEGE_ESCALATION
        elif "persistence" in task_type.lower():
            action_type = ActionType.PERSISTENCE
        else:
            action_type = ActionType.WRITE_OPERATION
        
        # Get target info
        target_info = context.get("target_info") or {}
        
        # Create approval action
        approval_action = ApprovalAction(
            mission_id=self._safe_uuid(self._current_mission_id) if self._current_mission_id else uuid4(),
            task_id=self._safe_uuid(original_task["id"].replace("task:", "")) if original_task.get("id") else None,
            action_type=action_type,
            action_description=f"{task_type}: {risk_reason}",
            target_ip=target_info.get("ip"),
            target_hostname=target_info.get("hostname"),
            risk_level=risk_level,
            risk_reasons=[risk_reason],
            potential_impact=f"This action may {risk_reason.lower()}. Please review before proceeding.",
            module_to_execute=original_task.get("rx_module"),
            command_preview=original_task.get("result_data", {}).get("command_preview"),
            parameters=original_task.get("result_data", {})
        )
        
        # Publish approval request event
        if self.blackboard and self._current_mission_id:
            event = ApprovalRequestEvent(
                mission_id=self._safe_uuid(self._current_mission_id),
                action_id=approval_action.id,
                action_type=action_type,
                action_description=approval_action.action_description,
                target_ip=approval_action.target_ip,
                target_hostname=approval_action.target_hostname,
                risk_level=risk_level,
                risk_reasons=approval_action.risk_reasons,
                potential_impact=approval_action.potential_impact,
                command_preview=approval_action.command_preview
            )
            
            channel = self.blackboard.get_channel(self._current_mission_id, "approvals")
            await self.blackboard.publish_event(channel, event)
            
            self.logger.info(f"📡 Published approval request: {approval_action.id}")
        
        # Return decision to wait for approval
        return {
            "decision": "ask_approval",
            "reasoning": f"High-risk action detected: {risk_reason}. Waiting for user approval.",
            "requires_approval": True,
            "approval_action_id": str(approval_action.id),
            "risk_level": risk_level.value,
            "risk_reason": risk_reason,
            "recommendations": [
                "Review the proposed action carefully",
                "Consider the potential impact on the target system",
                "Approve only if the action aligns with mission objectives"
            ]
        }
    
    async def _llm_decision(
        self,
        original_task: Dict[str, Any],
        error_context: Dict[str, Any],
        execution_logs: List[Dict[str, Any]],
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Make decision using LLM analysis.
        
        Uses the LLM service to analyze the failure and recommend
        the best course of action.
        
        Includes safety checks to prevent runaway API costs.
        """
        self.logger.info("🧠 Performing LLM-assisted analysis...")
        
        # ═══════════════════════════════════════════════════════════
        # SAFETY CHECK - Verify limits before calling LLM API
        # ═══════════════════════════════════════════════════════════
        is_safe, reason = self._check_safety_limits()
        if not is_safe:
            self.logger.warning(f"⚠️ Safety limit reached: {reason}")
            self.logger.warning("⚠️ Falling back to rule-based analysis to prevent cost overrun")
            self._stats["safety_limit_breaches"] += 1
            self._stats["rule_based_fallbacks"] += 1
            return self._rule_based_fallback(original_task, error_context, context)
        
        # Get LLM service
        llm_service = await self._ensure_llm_service()
        if not llm_service or not llm_service.providers:
            self.logger.warning("LLM service not available, falling back to rule-based")
            self._stats["rule_based_fallbacks"] += 1
            return self._rule_based_fallback(original_task, error_context, context)
        
        try:
            # Build analysis request
            from ..core.llm.models import (
                AnalysisRequest,
                TaskContext,
                ExecutionContext,
                ErrorDetails,
                AvailableModule,
            )
            
            # Extract target info
            target_info = context.get("target_info") or {}
            
            # Build request
            request = AnalysisRequest(
                task=TaskContext(
                    task_id=original_task.get("id", "unknown"),
                    task_type=original_task.get("type", "UNKNOWN"),
                    target_ip=target_info.get("ip"),
                    target_hostname=target_info.get("hostname"),
                    target_os=target_info.get("os"),
                    target_platform=self._get_target_platform(target_info),
                ),
                execution=ExecutionContext(
                    module_used=error_context.get("module_used"),
                    technique_id=error_context.get("technique_id"),
                    command_executed=error_context.get("command"),
                    exit_code=error_context.get("exit_code"),
                    duration_ms=error_context.get("duration_ms"),
                ),
                error=ErrorDetails(
                    error_type=error_context.get("error_type", "unknown"),
                    error_message=error_context.get("error_message", ""),
                    stderr=error_context.get("stderr"),
                    stdout=error_context.get("stdout"),
                    detected_defenses=context.get("detected_defenses", []),
                ),
                retry_count=original_task.get("retry_count", 0),
                max_retries=original_task.get("max_retries", 3),
                available_modules=[
                    AvailableModule(
                        rx_module_id=m.get("rx_module_id", m.get("id", "")),
                        name=m.get("name", ""),
                        description=m.get("description"),
                        technique_id=m.get("technique_id"),
                        supports_evasion=m.get("supports_evasion", False),
                        success_rate=m.get("success_rate"),
                    )
                    for m in context.get("alternative_modules", [])
                ],
                mission_goals=self._get_mission_goals(),
            )
            
            # Call LLM service
            self.logger.info(f"📡 Calling LLM API (request #{self._mission_llm_requests + 1})...")
            response = await llm_service.analyze_failure(request)
            
            # Update usage tracking AFTER successful call
            tokens_used = response.tokens_used if response.tokens_used else 0
            self._update_usage_tracking(tokens_used)
            
            # Log usage info
            self.logger.info(
                f"🧠 LLM Response received: "
                f"tokens={tokens_used}, "
                f"latency={response.latency_ms:.0f}ms, "
                f"model={response.model_used}"
            )
            self.logger.info(
                f"💰 Usage: requests={self._mission_llm_requests}/{self._settings.llm_mission_requests_limit}, "
                f"est_cost=${self._mission_estimated_cost:.4f}/${self._settings.llm_max_cost_limit:.2f}"
            )
            
            if response.success and response.analysis:
                self._stats["llm_analyses"] += 1
                
                # Convert LLM response to decision dict
                analysis = response.analysis
                action = analysis.recommended_action
                
                decision = {
                    "decision": action.decision.value,
                    "reasoning": action.reasoning,
                    "delay_seconds": action.delay_seconds,
                    "recommendations": analysis.additional_recommendations,
                    "lessons_learned": analysis.lessons_learned,
                    "llm_analysis": True,
                    "model_used": response.model_used,
                    "tokens_used": tokens_used,
                    "latency_ms": response.latency_ms,
                    "estimated_cost_usd": round(self._mission_estimated_cost, 4),
                    "root_cause": {
                        "category": analysis.analysis.category.value,
                        "cause": analysis.analysis.root_cause,
                        "confidence": analysis.analysis.confidence.value,
                        "detected_defenses": [d.value for d in analysis.analysis.detected_defenses],
                    }
                }
                
                # Add decision-specific fields
                if action.decision.value == "modify_approach" and action.alternative_module:
                    decision["new_module"] = action.alternative_module.rx_module_id
                    decision["modified_parameters"] = action.modified_parameters
                    decision["evasion_techniques"] = action.alternative_module.evasion_techniques
                    self._stats["modifications_recommended"] += 1
                    
                elif action.decision.value == "retry":
                    self._stats["retries_recommended"] += 1
                    
                elif action.decision.value == "skip":
                    self._stats["skips_recommended"] += 1
                    
                elif action.decision.value == "escalate":
                    decision["escalation_reason"] = action.escalation_reason
                    decision["human_guidance_needed"] = action.human_guidance_needed
                    self._stats["escalations"] += 1
                    
                elif action.decision.value == "pivot":
                    decision["new_attack_vector"] = action.new_attack_vector
                    decision["new_technique_id"] = action.new_technique_id
                
                # Handle knowledge update if recommended
                if analysis.should_update_knowledge and analysis.knowledge_update:
                    await self._update_knowledge(analysis.knowledge_update)
                
                return decision
            
            else:
                # LLM failed, fall back to rules
                self.logger.warning(f"LLM analysis failed: {response.error}")
                self._stats["llm_failures"] += 1
                self._stats["rule_based_fallbacks"] += 1
                return self._rule_based_fallback(original_task, error_context, context)
            
        except Exception as e:
            self.logger.error(f"LLM analysis error: {e}")
            self._stats["llm_failures"] += 1
            self._stats["rule_based_fallbacks"] += 1
            return self._rule_based_fallback(original_task, error_context, context)
    
    def _rule_based_fallback(
        self,
        original_task: Dict[str, Any],
        error_context: Dict[str, Any],
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Rule-based fallback when LLM is unavailable or fails.
        """
        category = self._categorize_error(error_context.get("error_type", "unknown"))
        strategy = self.RETRY_STRATEGIES.get(category, self.RETRY_STRATEGIES["unknown"])
        
        # Simple rule-based decision
        if context.get("alternative_modules"):
            self._stats["modifications_recommended"] += 1
            return {
                "decision": "modify_approach",
                "reasoning": f"LLM unavailable. Rule-based: trying alternative module for {category} error.",
                "new_module": context["alternative_modules"][0].get("rx_module_id"),
                "recommendations": strategy["recommendations"],
                "llm_analysis": False,
            }
        
        retry_count = original_task.get("retry_count", 0)
        max_retries = strategy["max_retries"]
        
        if retry_count < max_retries:
            self._stats["retries_recommended"] += 1
            return {
                "decision": "retry",
                "reasoning": f"LLM unavailable. Rule-based: retry {retry_count + 1}/{max_retries}",
                "delay_seconds": strategy["retry_delay"],
                "recommendations": strategy["recommendations"],
                "llm_analysis": False,
            }
        
        self._stats["escalations"] += 1
        return {
            "decision": "escalate",
            "reasoning": "LLM unavailable and retries exhausted. Escalating for review.",
            "escalation_reason": error_context.get("error_message", "Unknown error"),
            "recommendations": strategy["recommendations"],
            "llm_analysis": False,
        }
    
    def _get_mission_goals(self) -> List[str]:
        """Get current mission goals."""
        # This would be fetched from the blackboard in production
        return [
            "Gain initial access to target network",
            "Achieve persistence on compromised hosts",
            "Harvest credentials for lateral movement",
        ]
    
    async def _update_knowledge(self, knowledge_update: str) -> None:
        """Update knowledge base with learned information."""
        self.logger.info(f"Knowledge update: {knowledge_update}")
        # In production, this would update the knowledge base
        # For now, just log it
        if self.blackboard and self._current_mission_id:
            await self.blackboard.log_result(
                self._current_mission_id,
                "knowledge_update",
                {"update": knowledge_update}
            )
    
    async def _publish_analysis_result(
        self,
        original_task_id: str,
        original_task: Dict[str, Any],
        decision: Dict[str, Any]
    ) -> None:
        """Publish analysis result event."""
        if not self._current_mission_id:
            return
        
        event = TaskAnalysisResultEvent(
            mission_id=UUID(self._current_mission_id),
            original_task_id=UUID(original_task_id.replace("task:", "")),
            decision=decision["decision"],
            reasoning=decision["reasoning"],
            modified_parameters=decision.get("modified_parameters", {}),
            escalation_reason=decision.get("escalation_reason")
        )
        
        await self.publish_event(event)
    
    # ═══════════════════════════════════════════════════════════
    # Event Handling
    # ═══════════════════════════════════════════════════════════
    
    async def on_event(self, event: Dict[str, Any]) -> None:
        """Handle Pub/Sub events."""
        event_type = event.get("event")
        
        if event_type == "task_failed":
            # Task failed - analyze it
            await self._handle_task_failed(event)
        
        elif event_type == "analysis_request":
            # Explicit analysis request
            await self._handle_analysis_request(event)
        
        elif event_type == "control":
            command = event.get("command")
            if command == "pause":
                await self.pause()
            elif command == "resume":
                await self.resume()
            elif command == "stop":
                await self.stop()
    
    async def _handle_task_failed(self, event: Dict[str, Any]) -> None:
        """Handle a TaskFailedEvent."""
        task_id = event.get("task_id")
        if not task_id:
            return
        
        self.logger.info(f"Received task_failed event for task {task_id}")
        
        # Extract error context from event
        error_context = {
            "error_type": event.get("error_type", "unknown"),
            "error_message": event.get("error_message", ""),
            "technique_id": event.get("technique_id"),
            "module_used": event.get("module_used"),
            "detected_defenses": event.get("detected_defenses", [])
        }
        
        # Perform analysis
        result = await self.analyze_failure(
            task_id=str(task_id),
            error_context=error_context,
            execution_logs=[]  # Would be fetched from task
        )
        
        self.logger.info(f"Analysis complete for task {task_id}: {result['decision']}")
        
        # Handle the decision
        await self._execute_decision(task_id, result)
    
    async def _handle_analysis_request(self, event: Dict[str, Any]) -> None:
        """Handle a TaskAnalysisRequestEvent."""
        task_id = event.get("task_id")
        if not task_id:
            return
        
        self.logger.info(f"Received analysis_request for task {task_id}")
        
        # Perform analysis
        result = await self.analyze_failure(
            task_id=str(task_id),
            error_context=event.get("error_context", {}),
            execution_logs=event.get("execution_logs", [])
        )
        
        # Handle the decision
        await self._execute_decision(task_id, result)
    
    async def _execute_decision(
        self,
        original_task_id: str,
        decision: Dict[str, Any]
    ) -> None:
        """
        Execute the analysis decision.
        
        This creates retry tasks, updates task status, etc.
        """
        decision_type = decision["decision"]
        
        if decision_type == "retry":
            await self._create_retry_task(original_task_id, decision)
        
        elif decision_type == "modify_approach":
            await self._create_modified_task(original_task_id, decision)
        
        elif decision_type == "skip":
            self.logger.info(f"Skipping task {original_task_id}: {decision['reasoning']}")
        
        elif decision_type == "escalate":
            await self._escalate_task(original_task_id, decision)
        
        elif decision_type == "ask_approval":
            # HITL: Waiting for user approval - no action needed here
            # The approval request has already been published
            self.logger.info(
                f"🔐 Task {original_task_id} awaiting user approval: "
                f"{decision.get('risk_reason', 'High-risk action')}"
            )
    
    async def _create_retry_task(
        self,
        original_task_id: str,
        decision: Dict[str, Any]
    ) -> None:
        """Create a retry task."""
        original_task = await self.blackboard.get_task(original_task_id)
        if not original_task:
            return
        
        # Schedule retry with delay
        delay = decision.get("delay_seconds", 30)
        
        self.logger.info(
            f"Scheduling retry for task {original_task_id} in {delay}s"
        )
        
        # Create new task with incremented retry count
        retry_count = original_task.get("retry_count", 0) + 1
        
        await self.create_task(
            task_type=TaskType(original_task["type"]),
            target_specialist=SpecialistType(original_task["specialist"]),
            priority=original_task.get("priority", 5),
            target_id=original_task.get("target_id"),
            vuln_id=original_task.get("vuln_id"),
            cred_id=original_task.get("cred_id"),
            rx_module=original_task.get("rx_module"),
            retry_count=retry_count,
            parent_task_id=original_task_id
        )
    
    async def _create_modified_task(
        self,
        original_task_id: str,
        decision: Dict[str, Any]
    ) -> None:
        """Create a modified retry task with different parameters."""
        original_task = await self.blackboard.get_task(original_task_id)
        if not original_task:
            return
        
        # Get modifications
        new_module = decision.get("new_module")
        modified_params = decision.get("modified_parameters", {})
        
        self.logger.info(
            f"Creating modified task for {original_task_id} with module {new_module}"
        )
        
        await self.create_task(
            task_type=TaskType(original_task["type"]),
            target_specialist=SpecialistType(original_task["specialist"]),
            priority=original_task.get("priority", 5) + 1,  # Slight priority boost
            target_id=original_task.get("target_id"),
            vuln_id=original_task.get("vuln_id"),
            cred_id=original_task.get("cred_id"),
            rx_module=new_module or original_task.get("rx_module"),
            parent_task_id=original_task_id,
            **modified_params
        )
    
    async def _escalate_task(
        self,
        original_task_id: str,
        decision: Dict[str, Any]
    ) -> None:
        """Escalate a task for manual/LLM review."""
        self.logger.warning(
            f"Escalating task {original_task_id}: {decision.get('escalation_reason')}"
        )
        
        # Log the escalation
        await self.blackboard.log_result(
            self._current_mission_id,
            "task_escalated",
            {
                "task_id": original_task_id,
                "reason": decision.get("escalation_reason"),
                "reasoning": decision["reasoning"],
                "recommendations": decision.get("recommendations", [])
            }
        )
    
    # ═══════════════════════════════════════════════════════════
    # Channel Subscriptions
    # ═══════════════════════════════════════════════════════════
    
    def _get_channels_to_subscribe(self, mission_id: str) -> List[str]:
        """Get channels for Analysis specialist."""
        return [
            self.blackboard.get_channel(mission_id, "tasks"),
            self.blackboard.get_channel(mission_id, "failures"),  # Task failures
            self.blackboard.get_channel(mission_id, "analysis"),  # Analysis requests
            self.blackboard.get_channel(mission_id, "control"),
        ]
    
    # ═══════════════════════════════════════════════════════════
    # Statistics and Reporting
    # ═══════════════════════════════════════════════════════════
    
    def get_stats(self) -> Dict[str, Any]:
        """Get analysis statistics."""
        memory_stats = {}
        if self._operational_memory:
            memory_stats = self._operational_memory.get_stats()
        
        return {
            **self._stats,
            "analysis_history_size": len(self._analysis_history),
            "operational_memory": memory_stats,
        }
    
    def get_recent_analyses(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent analysis records."""
        return self._analysis_history[-limit:]
    
    def clear_history(self) -> None:
        """Clear analysis history."""
        self._analysis_history.clear()
