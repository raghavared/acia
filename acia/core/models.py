"""
Core data models for ACIA.

These models represent the data flowing through the system.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any
from pydantic import BaseModel, Field
from uuid import uuid4


class Severity(str, Enum):
    """Issue severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IssueType(str, Enum):
    """Types of issues detected."""
    BUG = "bug"
    SECURITY = "security"
    PERFORMANCE = "performance"
    COMPLEXITY = "complexity"
    STYLE = "style"
    DEPRECATION = "deprecation"
    DEPENDENCY = "dependency"
    ERROR_PATTERN = "error_pattern"


class ChangeType(str, Enum):
    """Types of code changes."""
    BUG_FIX = "bug_fix"
    SECURITY_FIX = "security_fix"
    PERFORMANCE = "performance"
    REFACTOR = "refactor"
    CLEANUP = "cleanup"
    DEPENDENCY_UPDATE = "dependency_update"
    DOCUMENTATION = "documentation"


class PRStatus(str, Enum):
    """Pull request status."""
    DRAFT = "draft"
    OPEN = "open"
    MERGED = "merged"
    CLOSED = "closed"
    FAILED = "failed"


# =============================================================================
# LOG MODELS
# =============================================================================

class LogEntry(BaseModel):
    """Represents a single log entry."""
    id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime
    level: str
    message: str
    source: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    
    # Extracted information
    error_type: str | None = None
    stack_trace: str | None = None
    file_path: str | None = None
    line_number: int | None = None
    function_name: str | None = None


class LogPattern(BaseModel):
    """Represents a detected pattern in logs."""
    id: str = Field(default_factory=lambda: str(uuid4()))
    pattern_type: str  # e.g., "recurring_error", "spike", "anomaly"
    description: str
    occurrences: int
    first_seen: datetime
    last_seen: datetime
    sample_entries: list[LogEntry] = Field(default_factory=list)
    severity: Severity = Severity.MEDIUM
    
    # Correlation with code
    suspected_files: list[str] = Field(default_factory=list)
    suspected_functions: list[str] = Field(default_factory=list)


class LogAnalysisResult(BaseModel):
    """Result of log analysis."""
    id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    source: str
    entries_analyzed: int
    patterns_detected: list[LogPattern] = Field(default_factory=list)
    errors_found: int = 0
    warnings_found: int = 0
    anomalies_found: int = 0


# =============================================================================
# CODE ANALYSIS MODELS
# =============================================================================

class CodeIssue(BaseModel):
    """Represents an issue found in code."""
    id: str = Field(default_factory=lambda: str(uuid4()))
    file_path: str
    line_start: int
    line_end: int | None = None
    column_start: int | None = None
    column_end: int | None = None
    
    issue_type: IssueType
    severity: Severity
    title: str
    description: str
    
    # Additional context
    code_snippet: str | None = None
    suggested_fix: str | None = None
    tool_name: str | None = None
    rule_id: str | None = None
    
    # Correlation with logs
    related_log_patterns: list[str] = Field(default_factory=list)


class FileAnalysis(BaseModel):
    """Analysis result for a single file."""
    file_path: str
    language: str
    lines_of_code: int
    
    # Complexity metrics
    cyclomatic_complexity: float = 0.0
    cognitive_complexity: float = 0.0
    maintainability_index: float = 100.0
    
    # Issues
    issues: list[CodeIssue] = Field(default_factory=list)
    
    # Functions/methods
    functions: list[FunctionAnalysis] = Field(default_factory=list)


class FunctionAnalysis(BaseModel):
    """Analysis of a single function/method."""
    name: str
    file_path: str
    line_start: int
    line_end: int
    
    parameters: int = 0
    lines_of_code: int = 0
    cyclomatic_complexity: float = 0.0
    cognitive_complexity: float = 0.0
    
    issues: list[str] = Field(default_factory=list)  # Issue IDs


class CodeAnalysisResult(BaseModel):
    """Complete code analysis result."""
    id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    files_analyzed: int = 0
    total_issues: int = 0
    issues_by_severity: dict[str, int] = Field(default_factory=dict)
    issues_by_type: dict[str, int] = Field(default_factory=dict)
    
    file_analyses: list[FileAnalysis] = Field(default_factory=list)
    
    # Aggregate metrics
    average_complexity: float = 0.0
    average_maintainability: float = 0.0


# =============================================================================
# IMPROVEMENT MODELS
# =============================================================================

class CodeChange(BaseModel):
    """Represents a single code change."""
    id: str = Field(default_factory=lambda: str(uuid4()))
    file_path: str
    
    # Change details
    original_code: str
    improved_code: str
    line_start: int
    line_end: int
    
    # Metadata
    change_type: ChangeType
    description: str
    reasoning: str
    
    # What triggered this change
    related_issues: list[str] = Field(default_factory=list)  # Issue IDs
    related_log_patterns: list[str] = Field(default_factory=list)  # Pattern IDs
    
    # Confidence
    confidence_score: float = Field(ge=0.0, le=1.0, default=0.8)
    
    # Generated tests (if any)
    test_code: str | None = None


class ImprovementPlan(BaseModel):
    """A plan for improving the codebase."""
    id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    title: str
    description: str
    change_type: ChangeType
    priority: int = 1
    
    # Changes included
    changes: list[CodeChange] = Field(default_factory=list)
    
    # Analysis that triggered this
    source_analysis_id: str | None = None
    source_log_patterns: list[str] = Field(default_factory=list)
    
    # Estimated impact
    estimated_complexity_reduction: float = 0.0
    estimated_bugs_fixed: int = 0
    security_issues_fixed: int = 0


# =============================================================================
# PR & GIT MODELS
# =============================================================================

class PullRequest(BaseModel):
    """Represents a pull request."""
    id: str = Field(default_factory=lambda: str(uuid4()))
    
    # Git info
    branch_name: str
    base_branch: str
    commit_sha: str | None = None
    
    # PR info
    pr_number: int | None = None
    pr_url: str | None = None
    title: str
    description: str
    
    # Status
    status: PRStatus = PRStatus.DRAFT
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    merged_at: datetime | None = None
    
    # Content
    improvement_plan_id: str
    files_changed: list[str] = Field(default_factory=list)
    
    # Review
    reviewers: list[str] = Field(default_factory=list)
    approvals: int = 0
    checks_passed: bool | None = None


# =============================================================================
# NOTIFICATION MODELS
# =============================================================================

class NotificationEvent(BaseModel):
    """An event that triggers notifications."""
    id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    event_type: str  # pr_created, error_detected, security_issue, etc.
    title: str
    message: str
    severity: Severity = Severity.MEDIUM
    
    # Related entities
    pull_request_id: str | None = None
    log_patterns: list[str] = Field(default_factory=list)
    code_issues: list[str] = Field(default_factory=list)
    
    # Notification status
    email_sent: bool = False
    slack_sent: bool = False
    webhook_sent: bool = False


# =============================================================================
# ORCHESTRATION MODELS
# =============================================================================

class CycleResult(BaseModel):
    """Result of a single improvement cycle."""
    id: str = Field(default_factory=lambda: str(uuid4()))
    started_at: datetime
    completed_at: datetime | None = None
    
    # What was done
    logs_analyzed: int = 0
    files_analyzed: int = 0
    issues_found: int = 0
    improvements_made: int = 0
    prs_created: int = 0
    notifications_sent: int = 0
    
    # Results
    log_analysis: LogAnalysisResult | None = None
    code_analysis: CodeAnalysisResult | None = None
    improvement_plans: list[ImprovementPlan] = Field(default_factory=list)
    pull_requests: list[PullRequest] = Field(default_factory=list)
    
    # Errors during cycle
    errors: list[str] = Field(default_factory=list)
    
    @property
    def duration_seconds(self) -> float | None:
        if self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None


class SystemState(BaseModel):
    """Current state of the ACIA system."""
    is_running: bool = False
    started_at: datetime | None = None
    
    # Statistics
    total_cycles: int = 0
    total_prs_created: int = 0
    total_issues_fixed: int = 0
    
    # Today's activity
    prs_today: int = 0
    last_cycle_at: datetime | None = None
    
    # Current cycle
    current_cycle_id: str | None = None
    
    # Health
    last_error: str | None = None
    consecutive_failures: int = 0
