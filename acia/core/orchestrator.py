"""
ACIA Orchestrator - The heart of the autonomous improvement system.

This module contains the main orchestration loop that NEVER STOPS.
It coordinates all components and manages the improvement cycle.
"""

from __future__ import annotations

import asyncio
import signal
import sys
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

import structlog

from acia.core.models import CycleResult, SystemState

if TYPE_CHECKING:
    from acia.core.config import ACIAConfig
    from acia.analyzers.log_analyzer import LogAnalyzer
    from acia.analyzers.code_analyzer import CodeAnalyzer
    from acia.engine.improvement_engine import ImprovementEngine
    from acia.git.change_manager import ChangeManager
    from acia.notifications.notification_service import NotificationService
    from acia.storage.state_store import StateStore


logger = structlog.get_logger(__name__)


class Orchestrator:
    """
    Main orchestrator for ACIA.
    
    This class manages the infinite loop that:
    1. Analyzes logs for errors and patterns
    2. Analyzes code for issues and improvements
    3. Generates fixes using AI
    4. Creates PRs with improvements
    5. Sends notifications
    6. Repeats forever
    """
    
    def __init__(self, config: ACIAConfig):
        self.config = config
        self.state = SystemState()
        self._shutdown_event = asyncio.Event()
        self._components_initialized = False
        
        # Components (lazily initialized)
        self._log_analyzer: LogAnalyzer | None = None
        self._code_analyzer: CodeAnalyzer | None = None
        self._improvement_engine: ImprovementEngine | None = None
        self._change_manager: ChangeManager | None = None
        self._notification_service: NotificationService | None = None
        self._state_store: StateStore | None = None
    
    async def initialize(self) -> None:
        """Initialize all components."""
        if self._components_initialized:
            return
        
        logger.info("Initializing ACIA components...")
        
        # Import here to avoid circular imports
        from acia.analyzers.log_analyzer import LogAnalyzer
        from acia.analyzers.code_analyzer import CodeAnalyzer
        from acia.engine.improvement_engine import ImprovementEngine
        from acia.git.change_manager import ChangeManager
        from acia.notifications.notification_service import NotificationService
        from acia.storage.state_store import create_state_store
        
        # Initialize components
        self._state_store = create_state_store(self.config.storage)
        await self._state_store.initialize()
        
        self._log_analyzer = LogAnalyzer(self.config.logs)
        self._code_analyzer = CodeAnalyzer(self.config.analysis, self.config.codebase)
        self._improvement_engine = ImprovementEngine(self.config.improvement_engine)
        self._change_manager = ChangeManager(self.config.git, self.config.codebase)
        self._notification_service = NotificationService(self.config.notifications)
        
        # Load previous state
        stored_state = await self._state_store.load_state()
        if stored_state:
            self.state = stored_state
        
        self._components_initialized = True
        logger.info("All components initialized successfully")
    
    async def run(self) -> None:
        """
        Main entry point - starts the infinite improvement loop.
        
        THIS NEVER STOPS (unless shutdown is requested).
        """
        import sys
        
        print("=" * 60, flush=True)
        print("  ACIA - Autonomous Code Improvement Agent", flush=True)
        print("=" * 60, flush=True)
        print(f"  Initializing...", flush=True)
        
        await self.initialize()
        
        # Setup signal handlers for graceful shutdown
        self._setup_signal_handlers()
        
        self.state.is_running = True
        self.state.started_at = datetime.utcnow()
        
        print(f"  ✓ Components initialized", flush=True)
        print(f"  ✓ Repository: {self.config.codebase.repository_url}", flush=True)
        print(f"  ✓ Analyzers: {', '.join(self.config.orchestrator.enabled_analyzers)}", flush=True)
        print(f"  ✓ Cycle interval: {self.config.orchestrator.cycle_interval}s", flush=True)
        print(f"  ✓ Dry run mode: {self.config.safety.dry_run}", flush=True)
        print("=" * 60, flush=True)
        print("  Starting first cycle NOW...", flush=True)
        print("=" * 60, flush=True)
        sys.stdout.flush()
        
        logger.info(
            "ACIA Orchestrator starting infinite loop",
            cycle_interval=self.config.orchestrator.cycle_interval,
        )
        
        cycle_count = 0
        try:
            while not self._shutdown_event.is_set():
                cycle_count += 1
                print(f"\n[Cycle {cycle_count}] Starting at {datetime.utcnow().isoformat()}...", flush=True)
                
                await self._run_cycle()
                
                if self._shutdown_event.is_set():
                    break
                
                print(f"[Cycle {cycle_count}] Complete. Next cycle in {self.config.orchestrator.cycle_interval}s", flush=True)
                print(f"  (Press Ctrl+C to stop)", flush=True)
                
                # Wait for next cycle or shutdown - check every second
                wait_time = self.config.orchestrator.cycle_interval
                while wait_time > 0 and not self._shutdown_event.is_set():
                    await asyncio.sleep(min(1, wait_time))
                    wait_time -= 1
        
        except asyncio.CancelledError:
            logger.info("Orchestrator cancelled")
        
        except KeyboardInterrupt:
            print("\n\n⚠️  Interrupted!", flush=True)
        
        finally:
            await self._cleanup()
    
    async def _run_cycle(self) -> CycleResult:
        """
        Run a single improvement cycle.
        
        This is where the magic happens:
        1. Analyze logs (optional)
        2. Analyze code
        3. Correlate findings
        4. Generate improvements
        5. Create PRs
        6. Send notifications
        """
        cycle = CycleResult(started_at=datetime.utcnow())
        self.state.current_cycle_id = cycle.id
        
        print(f"  → Cycle ID: {cycle.id[:8]}...", flush=True)
        logger.info("Starting improvement cycle", cycle_id=cycle.id)
        
        try:
            # Check daily PR limit
            if self.state.prs_today >= self.config.safety.max_prs_per_day:
                print(f"  ⚠ Daily PR limit reached ({self.state.prs_today}/{self.config.safety.max_prs_per_day})", flush=True)
                logger.warning(
                    "Daily PR limit reached, skipping cycle",
                    prs_today=self.state.prs_today,
                    limit=self.config.safety.max_prs_per_day,
                )
                return cycle
            
            # Step 1: Analyze logs (optional - skip if no sources configured)
            if (
                "log_analyzer" in self.config.orchestrator.enabled_analyzers
                and self.config.logs.sources  # Only if log sources are configured
            ):
                try:
                    print("  → Step 1/4: Analyzing production logs...", flush=True)
                    logger.info("Analyzing production logs...")
                    log_result = await self._log_analyzer.analyze()
                    cycle.log_analysis = log_result
                    cycle.logs_analyzed = log_result.entries_analyzed
                    print(f"    ✓ Logs: {log_result.entries_analyzed} entries, {len(log_result.patterns_detected)} patterns", flush=True)
                    logger.info(
                        "Log analysis complete",
                        entries=log_result.entries_analyzed,
                        patterns=len(log_result.patterns_detected),
                    )
                except Exception as e:
                    print(f"    ⚠ Log analysis failed: {e}", flush=True)
                    logger.warning("Log analysis failed, continuing with code analysis", error=str(e))
            else:
                print("  → Step 1/4: Skipping log analysis (not configured)", flush=True)
                logger.info("Skipping log analysis (no sources configured or disabled)")
            
            # Step 2: Analyze code
            if "code_analyzer" in self.config.orchestrator.enabled_analyzers:
                print("  → Step 2/4: Analyzing codebase...", flush=True)
                logger.info("Analyzing codebase...")
                code_result = await self._code_analyzer.analyze()
                cycle.code_analysis = code_result
                cycle.files_analyzed = code_result.files_analyzed
                cycle.issues_found = code_result.total_issues
                print(f"    ✓ Code: {code_result.files_analyzed} files, {code_result.total_issues} issues found", flush=True)
                logger.info(
                    "Code analysis complete",
                    files=code_result.files_analyzed,
                    issues=code_result.total_issues,
                )
            
            # Step 3: Generate improvements
            if cycle.log_analysis or cycle.code_analysis:
                print("  → Step 3/4: Generating AI improvements...", flush=True)
                logger.info("Generating improvements...")
                improvement_plans = await self._improvement_engine.generate_improvements(
                    log_analysis=cycle.log_analysis,
                    code_analysis=cycle.code_analysis,
                )
                cycle.improvement_plans = improvement_plans
                cycle.improvements_made = len(improvement_plans)
                print(f"    ✓ Generated {len(improvement_plans)} improvement plans", flush=True)
                logger.info(
                    "Improvements generated",
                    plans=len(improvement_plans),
                )
            
            # Step 4: Create PRs (if not dry run)
            print("  → Step 4/4: Creating PRs...", flush=True)
            if cycle.improvement_plans and not self.config.safety.dry_run:
                logger.info("Creating pull requests...")
                for plan in cycle.improvement_plans:
                    # Check PR limit again
                    if self.state.prs_today >= self.config.safety.max_prs_per_day:
                        print(f"    ⚠ Daily PR limit reached", flush=True)
                        logger.warning("Daily PR limit reached during PR creation")
                        break
                    
                    try:
                        pr = await self._change_manager.create_pr(plan)
                        cycle.pull_requests.append(pr)
                        cycle.prs_created += 1
                        self.state.prs_today += 1
                        self.state.total_prs_created += 1
                        print(f"    ✓ PR created: {pr.branch_name}", flush=True)
                        
                        logger.info(
                            "PR created",
                            pr_number=pr.pr_number,
                            branch=pr.branch_name,
                        )
                    except Exception as e:
                        print(f"    ✗ PR failed: {e}", flush=True)
                        logger.error("Failed to create PR", error=str(e))
                        cycle.errors.append(f"PR creation failed: {e}")
                print(f"    ✓ Created {cycle.prs_created} PRs", flush=True)
            elif self.config.safety.dry_run:
                print(f"    ℹ Dry run mode - no PRs created", flush=True)
            else:
                print(f"    ℹ No improvements to submit", flush=True)
            
            # Step 5: Send notifications
            if cycle.pull_requests or cycle.issues_found > 0:
                logger.info("Sending notifications...")
                notifications = await self._notification_service.notify_cycle_complete(
                    cycle=cycle
                )
                cycle.notifications_sent = notifications
            
            # Update state
            self.state.total_cycles += 1
            self.state.last_cycle_at = datetime.utcnow()
            self.state.consecutive_failures = 0
            self.state.last_error = None
            
            # Persist state
            await self._state_store.save_state(self.state)
            await self._state_store.save_cycle(cycle)
            
            # Print summary
            print(f"\n  ════════════════════════════════════════", flush=True)
            print(f"  CYCLE SUMMARY:", flush=True)
            print(f"    Files analyzed: {cycle.files_analyzed}", flush=True)
            print(f"    Issues found: {cycle.issues_found}", flush=True)
            print(f"    Improvements: {cycle.improvements_made}", flush=True)
            print(f"    PRs created: {cycle.prs_created}", flush=True)
            print(f"  ════════════════════════════════════════", flush=True)
        
        except Exception as e:
            print(f"\n  ✗ CYCLE FAILED: {e}", flush=True)
            logger.exception("Cycle failed", error=str(e))
            cycle.errors.append(str(e))
            self.state.consecutive_failures += 1
            self.state.last_error = str(e)
            
            # Notify on failures
            if self._notification_service:
                await self._notification_service.notify_error(
                    error=str(e),
                    cycle_id=cycle.id,
                )
        
        finally:
            cycle.completed_at = datetime.utcnow()
            self.state.current_cycle_id = None
            
            logger.info(
                "Cycle complete",
                cycle_id=cycle.id,
                duration=cycle.duration_seconds,
                prs_created=cycle.prs_created,
                errors=len(cycle.errors),
            )
        
        return cycle
    
    def _setup_signal_handlers(self) -> None:
        """Setup handlers for graceful shutdown."""
        
        def handle_signal(signum, frame):
            """Synchronous signal handler."""
            sig_name = signal.Signals(signum).name if hasattr(signal, 'Signals') else f"signal {signum}"
            print(f"\n\n⚠️  Received {sig_name}, shutting down gracefully...", flush=True)
            print("  (Press Ctrl+C again to force quit)\n", flush=True)
            self._shutdown_event.set()
        
        def force_quit(signum, frame):
            """Force quit on second signal."""
            print("\n\n🛑 Force quitting...\n", flush=True)
            import sys
            sys.exit(1)
        
        # First Ctrl+C = graceful shutdown
        signal.signal(signal.SIGINT, handle_signal)
        signal.signal(signal.SIGTERM, handle_signal)
        
        print("  ✓ Signal handlers registered (Ctrl+C to stop)", flush=True)
    
    async def _handle_shutdown(self, sig: signal.Signals) -> None:
        """Handle shutdown signal."""
        print(f"\n⚠️  Shutting down...", flush=True)
        logger.info("Received shutdown signal")
        self._shutdown_event.set()
    
    async def _cleanup(self) -> None:
        """Cleanup resources on shutdown."""
        print("  → Cleaning up resources...", flush=True)
        logger.info("Cleaning up resources...")
        
        self.state.is_running = False
        
        try:
            if self._state_store:
                await self._state_store.save_state(self.state)
                await self._state_store.close()
        except Exception as e:
            logger.warning(f"Error during cleanup: {e}")
        
        print("  ✓ Cleanup complete. Goodbye!", flush=True)
        logger.info("Cleanup complete")
    
    async def request_shutdown(self) -> None:
        """Request a graceful shutdown."""
        logger.info("Shutdown requested")
        self._shutdown_event.set()
    
    def is_running(self) -> bool:
        """Check if the orchestrator is running."""
        return self.state.is_running and not self._shutdown_event.is_set()
    
    async def get_status(self) -> dict:
        """Get current status of the orchestrator."""
        return {
            "is_running": self.is_running(),
            "started_at": self.state.started_at.isoformat() if self.state.started_at else None,
            "total_cycles": self.state.total_cycles,
            "total_prs_created": self.state.total_prs_created,
            "prs_today": self.state.prs_today,
            "last_cycle_at": self.state.last_cycle_at.isoformat() if self.state.last_cycle_at else None,
            "current_cycle": self.state.current_cycle_id,
            "consecutive_failures": self.state.consecutive_failures,
            "last_error": self.state.last_error,
        }
    
    async def trigger_cycle(self) -> CycleResult:
        """Manually trigger an improvement cycle."""
        if not self._components_initialized:
            await self.initialize()
        return await self._run_cycle()


class OrchestratorFactory:
    """Factory for creating orchestrators."""
    
    @staticmethod
    def create(config: ACIAConfig) -> Orchestrator:
        """Create an orchestrator instance."""
        return Orchestrator(config)
    
    @staticmethod
    async def create_and_run(config: ACIAConfig) -> None:
        """Create and run an orchestrator."""
        orchestrator = OrchestratorFactory.create(config)
        await orchestrator.run()