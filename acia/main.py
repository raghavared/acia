"""
ACIA - Autonomous Code Improvement Agent

Main entry point for running ACIA.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import click
import structlog

from acia.core.config import ACIAConfig
from acia.core.orchestrator import Orchestrator, OrchestratorFactory


# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.dev.ConsoleRenderer() if sys.stdout.isatty() else structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger(__name__)


@click.group()
@click.version_option(version="0.1.0")
def cli():
    """ACIA - Autonomous Code Improvement Agent
    
    A foundation model for autonomous code analysis, improvement, and deployment.
    It continuously monitors codebases and production logs, identifies issues,
    generates fixes, creates PRs, and notifies stakeholders.
    """
    pass


@cli.command()
@click.option(
    "--config", "-c",
    type=click.Path(exists=True, path_type=Path),
    default="config.yaml",
    help="Path to configuration file",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Run in dry-run mode (no actual changes)",
)
def run(config: Path, dry_run: bool):
    """Start the autonomous improvement loop.
    
    This command starts ACIA and runs indefinitely, continuously analyzing
    code and logs, generating improvements, and creating PRs.
    
    Use Ctrl+C to stop gracefully.
    """
    logger.info("Starting ACIA", config=str(config), dry_run=dry_run)
    
    try:
        # Load configuration
        acia_config = ACIAConfig.from_yaml(config)
        
        if dry_run:
            acia_config.safety.dry_run = True
            logger.info("Running in dry-run mode - no changes will be made")
        
        # Create and run orchestrator
        asyncio.run(OrchestratorFactory.create_and_run(acia_config))
    
    except KeyboardInterrupt:
        print("\n\n👋 ACIA stopped by user. Goodbye!", flush=True)
        sys.exit(0)
    except Exception as e:
        logger.exception("ACIA failed", error=str(e))
        sys.exit(1)


@cli.command()
@click.option(
    "--config", "-c",
    type=click.Path(exists=True, path_type=Path),
    default="config.yaml",
    help="Path to configuration file",
)
def cycle(config: Path):
    """Run a single improvement cycle.
    
    This command runs one complete improvement cycle and then exits.
    Useful for testing or manual triggering.
    """
    logger.info("Running single cycle", config=str(config))
    
    async def run_single_cycle():
        acia_config = ACIAConfig.from_yaml(config)
        orchestrator = Orchestrator(acia_config)
        result = await orchestrator.trigger_cycle()
        
        click.echo(f"\nCycle completed:")
        click.echo(f"  Files analyzed: {result.files_analyzed}")
        click.echo(f"  Logs analyzed: {result.logs_analyzed}")
        click.echo(f"  Issues found: {result.issues_found}")
        click.echo(f"  Improvements made: {result.improvements_made}")
        click.echo(f"  PRs created: {result.prs_created}")
        click.echo(f"  Duration: {result.duration_seconds:.2f}s")
        
        if result.errors:
            click.echo(f"\nErrors: {len(result.errors)}")
            for error in result.errors:
                click.echo(f"  - {error}")
    
    asyncio.run(run_single_cycle())


@cli.command()
@click.option(
    "--config", "-c",
    type=click.Path(exists=True, path_type=Path),
    default="config.yaml",
    help="Path to configuration file",
)
def analyze(config: Path):
    """Run analysis only (no improvements).
    
    This command runs only the analysis phase (logs + code) and shows
    the results without generating or applying any improvements.
    """
    logger.info("Running analysis only", config=str(config))
    
    async def run_analysis():
        from acia.analyzers.log_analyzer import LogAnalyzer
        from acia.analyzers.code_analyzer import CodeAnalyzer
        
        acia_config = ACIAConfig.from_yaml(config)
        
        # Analyze logs
        click.echo("\n=== Log Analysis ===")
        if acia_config.logs.sources:
            log_analyzer = LogAnalyzer(acia_config.logs)
            log_result = await log_analyzer.analyze()
            
            click.echo(f"Entries analyzed: {log_result.entries_analyzed}")
            click.echo(f"Errors found: {log_result.errors_found}")
            click.echo(f"Patterns detected: {len(log_result.patterns_detected)}")
            
            for pattern in log_result.patterns_detected[:5]:
                click.echo(f"\n  Pattern: {pattern.description[:80]}")
                click.echo(f"    Occurrences: {pattern.occurrences}")
                click.echo(f"    Severity: {pattern.severity.value}")
                click.echo(f"    Files: {', '.join(pattern.suspected_files[:3])}")
        else:
            click.echo("No log sources configured")
        
        # Analyze code
        click.echo("\n=== Code Analysis ===")
        code_analyzer = CodeAnalyzer(acia_config.analysis, acia_config.codebase)
        code_result = await code_analyzer.analyze()
        
        click.echo(f"Files analyzed: {code_result.files_analyzed}")
        click.echo(f"Total issues: {code_result.total_issues}")
        click.echo(f"Average complexity: {code_result.average_complexity:.2f}")
        click.echo(f"Average maintainability: {code_result.average_maintainability:.2f}")
        
        click.echo("\nIssues by severity:")
        for severity, count in code_result.issues_by_severity.items():
            click.echo(f"  {severity}: {count}")
        
        click.echo("\nIssues by type:")
        for issue_type, count in code_result.issues_by_type.items():
            click.echo(f"  {issue_type}: {count}")
    
    asyncio.run(run_analysis())


@cli.command()
@click.option(
    "--config", "-c",
    type=click.Path(exists=True, path_type=Path),
    default="config.yaml",
    help="Path to configuration file",
)
def status(config: Path):
    """Show the current status of ACIA.
    
    Displays information about the stored state, including
    total cycles run, PRs created, and recent activity.
    """
    async def show_status():
        from acia.storage.state_store import create_state_store
        
        acia_config = ACIAConfig.from_yaml(config)
        store = create_state_store(acia_config.storage)
        await store.initialize()
        
        state = await store.load_state()
        
        if not state:
            click.echo("No state found. ACIA has not been run yet.")
            return
        
        click.echo("\n=== ACIA Status ===")
        click.echo(f"Running: {state.is_running}")
        click.echo(f"Started at: {state.started_at}")
        click.echo(f"Total cycles: {state.total_cycles}")
        click.echo(f"Total PRs created: {state.total_prs_created}")
        click.echo(f"Total issues fixed: {state.total_issues_fixed}")
        click.echo(f"PRs today: {state.prs_today}")
        click.echo(f"Last cycle: {state.last_cycle_at}")
        
        if state.last_error:
            click.echo(f"\nLast error: {state.last_error}")
            click.echo(f"Consecutive failures: {state.consecutive_failures}")
        
        # Show recent cycles
        cycles = await store.get_recent_cycles(limit=5)
        if cycles:
            click.echo("\n=== Recent Cycles ===")
            for cycle in cycles:
                click.echo(f"\n  {cycle.id[:8]} ({cycle.started_at})")
                click.echo(f"    Duration: {cycle.duration_seconds:.2f}s")
                click.echo(f"    Files: {cycle.files_analyzed}, Issues: {cycle.issues_found}")
                click.echo(f"    PRs: {cycle.prs_created}, Errors: {len(cycle.errors)}")
        
        await store.close()
    
    asyncio.run(show_status())


@cli.command()
@click.argument("output", type=click.Path(path_type=Path), default="config.yaml")
def init(output: Path):
    """Initialize a new configuration file.
    
    Creates a new config.yaml with default settings that you can
    customize for your project.
    """
    import shutil
    
    # Find the example config
    example_config = Path(__file__).parent.parent / "config.example.yaml"
    
    if output.exists():
        if not click.confirm(f"{output} already exists. Overwrite?"):
            return
    
    if example_config.exists():
        shutil.copy(example_config, output)
    else:
        # Create minimal config
        minimal_config = """
# ACIA Configuration
# See documentation for full options

orchestrator:
  cycle_interval: 3600  # 1 hour
  max_workers: 4
  enabled_analyzers:
    - log_analyzer
    - code_analyzer

codebase:
  repository_url: "https://github.com/your-org/your-repo.git"
  target_branch: "main"
  local_path: "/var/acia/repos/your-repo"
  auth:
    type: "token"
    token_env_var: "GITHUB_TOKEN"
  include_patterns:
    - "**/*.py"
    - "**/*.js"
  exclude_patterns:
    - "**/node_modules/**"
    - "**/venv/**"

improvement_engine:
  provider: "anthropic"
  anthropic:
    model: "claude-sonnet-4-20250514"
    api_key_env_var: "ANTHROPIC_API_KEY"

git:
  user:
    name: "ACIA Bot"
    email: "acia-bot@example.com"
  pull_request:
    platform: "github"
    labels:
      - "automated"
      - "acia-bot"

notifications:
  email:
    enabled: true
    smtp:
      host: "smtp.example.com"
      port: 587
      use_tls: true
    from_address: "acia-bot@example.com"
    recipients:
      pr_created:
        - "dev-team@example.com"

safety:
  dry_run: true  # Start in dry-run mode
  max_prs_per_day: 10
"""
        output.write_text(minimal_config)
    
    click.echo(f"Created configuration file: {output}")
    click.echo("\nNext steps:")
    click.echo("1. Edit the configuration with your repository and credentials")
    click.echo("2. Set environment variables (GITHUB_TOKEN, ANTHROPIC_API_KEY, etc.)")
    click.echo("3. Run: acia run --config config.yaml")


def main():
    """Main entry point."""
    cli()


if __name__ == "__main__":
    main()