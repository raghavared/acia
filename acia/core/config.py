"""
Configuration models for ACIA.

Uses Pydantic for validation and type safety.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Literal
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings
import yaml


# =============================================================================
# SUB-MODELS
# =============================================================================


class OrchestratorConfig(BaseModel):
    """Orchestrator settings."""

    cycle_interval: int = Field(default=3600, ge=60, description="Cycle interval in seconds")
    max_workers: int = Field(default=4, ge=1, le=32)
    enabled_analyzers: list[str] = Field(default_factory=lambda: ["log_analyzer", "code_analyzer"])
    shutdown_timeout: int = Field(default=300, ge=30)


class AuthConfig(BaseModel):
    """Authentication configuration."""

    type: Literal["token", "ssh", "basic"] = "token"
    token: str | None = None  # Direct token value
    token_env_var: str | None = None  # Or environment variable name
    ssh_key_path: str | None = None
    username_env_var: str | None = None
    password_env_var: str | None = None

    def get_token(self) -> str | None:
        # First check direct token
        if self.token:
            return self.token
        # Then check environment variable
        if self.token_env_var:
            token = self.token_env_var
            if token:
                return token
        # Fallback to common env var names
        for env_var in ["GITHUB_TOKEN", "GH_TOKEN", "GITLAB_TOKEN"]:
            token = os.getenv(env_var)
            if token:
                return token
        return None


class CodebaseConfig(BaseModel):
    """Codebase configuration."""

    repository_url: str
    target_branch: str = "main"
    local_path: str = "/var/acia/repos"
    auth: AuthConfig = Field(default_factory=AuthConfig)
    include_patterns: list[str] = Field(default_factory=lambda: ["**/*.py", "**/*.js"])
    exclude_patterns: list[str] = Field(
        default_factory=lambda: ["**/node_modules/**", "**/venv/**"]
    )


class LogSourceConfig(BaseModel):
    """Individual log source configuration."""

    name: str
    type: Literal["file", "elasticsearch", "cloudwatch", "datadog", "splunk"]
    path: str | None = None
    host: str | None = None
    index: str | None = None
    log_group: str | None = None
    region: str | None = None
    format: Literal["json", "plain", "structured"] = "json"
    auth_env_var: str | None = None


class LogsConfig(BaseModel):
    """Log analysis configuration."""

    sources: list[LogSourceConfig] = Field(default_factory=list)
    lookback_period: str = "24h"
    error_threshold: int = 5
    ignore_patterns: list[str] = Field(default_factory=list)


class StaticAnalyzerConfig(BaseModel):
    """Static analyzer configuration."""

    tool: str
    config: str | None = None
    min_score: float | None = None
    strict: bool = False


class ComplexityConfig(BaseModel):
    """Code complexity thresholds."""

    max_cyclomatic: int = 10
    max_cognitive: int = 15
    max_function_length: int = 50
    max_file_length: int = 500


class SecurityConfig(BaseModel):
    """Security scanning configuration."""

    enabled: bool = True
    tools: list[str] = Field(default_factory=lambda: ["bandit", "semgrep"])
    severity_threshold: Literal["low", "medium", "high", "critical"] = "medium"


class DependencyConfig(BaseModel):
    """Dependency analysis configuration."""

    check_outdated: bool = True
    check_vulnerabilities: bool = True
    auto_update_patch: bool = True
    auto_update_minor: bool = False


class AnalysisConfig(BaseModel):
    """Code analysis configuration."""

    static_analyzers: dict[str, list[StaticAnalyzerConfig]] = Field(default_factory=dict)
    complexity: ComplexityConfig = Field(default_factory=ComplexityConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    dependencies: DependencyConfig = Field(default_factory=DependencyConfig)


class LLMProviderConfig(BaseModel):
    """LLM provider configuration."""

    model: str
    api_key: str | None = None  # Direct API key
    api_key_env_var: str | None = None  # Or environment variable name
    endpoint: str | None = None
    max_tokens: int = 4096

    def get_api_key(self) -> str | None:
        # First check for direct api_key
        if self.api_key:
            return self.api_key
        # Then check environment variable
        if self.api_key_env_var:
            return os.getenv(self.api_key_env_var)
        return None


class ImprovementStrategy(BaseModel):
    """Improvement strategy configuration."""

    name: str
    priority: int = 1
    enabled: bool = True


class ImprovementConstraints(BaseModel):
    """Constraints for code improvements."""

    max_changes_per_file: int = 10
    max_files_per_pr: int = 5
    require_tests: bool = True
    require_type_hints: bool = True


class ImprovementEngineConfig(BaseModel):
    """AI/LLM improvement engine configuration."""

    provider: Literal["anthropic", "openai", "local"] = "anthropic"
    anthropic: LLMProviderConfig | None = None
    openai: LLMProviderConfig | None = None
    local: LLMProviderConfig | None = None
    strategies: list[ImprovementStrategy] = Field(default_factory=list)
    constraints: ImprovementConstraints = Field(default_factory=ImprovementConstraints)

    def get_active_provider(self) -> LLMProviderConfig:
        providers = {
            "anthropic": self.anthropic,
            "openai": self.openai,
            "local": self.local,
        }
        provider = providers.get(self.provider)
        if not provider:
            raise ValueError(f"Provider {self.provider} not configured")
        return provider


class GitUserConfig(BaseModel):
    """Git user configuration."""

    name: str = "ACIA Bot"
    email: str = "acia-bot@example.com"


class PRConfig(BaseModel):
    """Pull request configuration."""

    platform: Literal["github", "gitlab", "bitbucket", "azure"] = "github"
    title_format: str = "[ACIA] {type}: {summary}"
    labels: list[str] = Field(default_factory=lambda: ["automated", "acia-bot"])
    reviewers: list[str] = Field(default_factory=list)
    auto_merge: dict[str, Any] = Field(default_factory=dict)


class GitConfig(BaseModel):
    """Git configuration."""

    user: GitUserConfig = Field(default_factory=GitUserConfig)
    branch_prefix: str = "acia/"
    branch_format: str = "{type}/{timestamp}-{short_description}"
    commit_format: str = "[ACIA] {type}: {description}"
    pull_request: PRConfig = Field(default_factory=PRConfig)


class SMTPConfig(BaseModel):
    """SMTP configuration."""

    host: str
    port: int = 587
    use_tls: bool = True
    username_env_var: str | None = None
    password_env_var: str | None = None

    def get_credentials(self) -> tuple[str | None, str | None]:
        username = os.getenv(self.username_env_var) if self.username_env_var else None
        password = os.getenv(self.password_env_var) if self.password_env_var else None
        return username, password


class EmailConfig(BaseModel):
    """Email notification configuration."""

    enabled: bool = True
    smtp: SMTPConfig | None = None
    from_address: str = "acia-bot@example.com"
    recipients: dict[str, list[str]] = Field(default_factory=dict)


class SlackConfig(BaseModel):
    """Slack notification configuration."""

    enabled: bool = False
    webhook_url_env_var: str | None = None
    channel: str = "#acia-notifications"

    def get_webhook_url(self) -> str | None:
        if self.webhook_url_env_var:
            return os.getenv(self.webhook_url_env_var)
        return None


class WebhookEndpoint(BaseModel):
    """Webhook endpoint configuration."""

    url: str
    events: list[str] = Field(default_factory=list)
    auth_header_env_var: str | None = None


class WebhookConfig(BaseModel):
    """Webhook notification configuration."""

    enabled: bool = False
    endpoints: list[WebhookEndpoint] = Field(default_factory=list)


class NotificationsConfig(BaseModel):
    """Notifications configuration."""

    email: EmailConfig = Field(default_factory=EmailConfig)
    slack: SlackConfig = Field(default_factory=SlackConfig)
    webhook: WebhookConfig = Field(default_factory=WebhookConfig)


class StorageConfig(BaseModel):
    """Storage configuration."""

    type: Literal["sqlite", "postgres", "mongodb"] = "sqlite"
    sqlite: dict[str, Any] = Field(default_factory=lambda: {"path": "/var/acia/acia.db"})
    postgres: dict[str, Any] = Field(default_factory=dict)
    mongodb: dict[str, Any] = Field(default_factory=dict)
    retention: dict[str, str] = Field(default_factory=dict)


class SafetyConfig(BaseModel):
    """Safety and limits configuration."""

    dry_run: bool = False
    max_prs_per_day: int = 10
    require_approval: list[str] = Field(default_factory=list)
    protected_files: list[str] = Field(default_factory=list)
    rollback: dict[str, Any] = Field(default_factory=dict)


# =============================================================================
# MAIN CONFIG
# =============================================================================


class ACIAConfig(BaseModel):
    """Main ACIA configuration."""

    orchestrator: OrchestratorConfig = Field(default_factory=OrchestratorConfig)
    codebase: CodebaseConfig
    logs: LogsConfig = Field(default_factory=LogsConfig)
    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)
    improvement_engine: ImprovementEngineConfig = Field(default_factory=ImprovementEngineConfig)
    git: GitConfig = Field(default_factory=GitConfig)
    notifications: NotificationsConfig = Field(default_factory=NotificationsConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    safety: SafetyConfig = Field(default_factory=SafetyConfig)

    @classmethod
    def from_yaml(cls, path: str | Path) -> ACIAConfig:
        """Load configuration from YAML file."""
        with open(path) as f:
            data = yaml.safe_load(f)
        return cls(**data)

    @classmethod
    def from_env(cls) -> ACIAConfig:
        """Load configuration from environment variables."""
        config_path = os.getenv("ACIA_CONFIG", "config.yaml")
        return cls.from_yaml(config_path)

    def to_yaml(self, path: str | Path) -> None:
        """Save configuration to YAML file."""
        with open(path, "w") as f:
            yaml.dump(self.model_dump(), f, default_flow_style=False)
