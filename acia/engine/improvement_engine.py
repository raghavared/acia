"""
Improvement Engine - Uses AI/LLM to generate code improvements.

This module takes analysis results and generates actual code fixes,
refactoring suggestions, and optimizations.
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

import structlog

from acia.core.config import ImprovementEngineConfig, LLMProviderConfig
from acia.core.models import (
    ChangeType,
    CodeAnalysisResult,
    CodeChange,
    CodeIssue,
    ImprovementPlan,
    IssueType,
    LogAnalysisResult,
    LogPattern,
    Severity,
)


logger = structlog.get_logger(__name__)


# =============================================================================
# LLM PROVIDERS
# =============================================================================

class LLMProvider(ABC):
    """Abstract base for LLM providers."""
    
    def __init__(self, config: LLMProviderConfig):
        self.config = config
        self.model = config.model
    
    @abstractmethod
    async def generate(self, prompt: str, system: str | None = None) -> str:
        """Generate a response from the LLM."""
        pass


class AnthropicProvider(LLMProvider):
    """Anthropic Claude provider."""
    
    def __init__(self, config: LLMProviderConfig):
        super().__init__(config)
        self._client = None
    
    def _get_client(self):
        if self._client is None:
            import anthropic
            api_key = self.config.get_api_key()
            self._client = anthropic.Anthropic(api_key=api_key)
        return self._client
    
    async def generate(self, prompt: str, system: str | None = None) -> str:
        client = self._get_client()
        
        message = await asyncio.to_thread(
            client.messages.create,
            model=self.model,
            max_tokens=self.config.max_tokens,
            system=system or "You are an expert software engineer.",
            messages=[{"role": "user", "content": prompt}],
        )
        
        return message.content[0].text


class OpenAIProvider(LLMProvider):
    """OpenAI GPT provider."""
    
    def __init__(self, config: LLMProviderConfig):
        super().__init__(config)
        self._client = None
    
    def _get_client(self):
        if self._client is None:
            import openai
            api_key = self.config.get_api_key()
            self._client = openai.OpenAI(api_key=api_key)
        return self._client
    
    async def generate(self, prompt: str, system: str | None = None) -> str:
        client = self._get_client()
        
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        
        response = await asyncio.to_thread(
            client.chat.completions.create,
            model=self.model,
            max_tokens=self.config.max_tokens,
            messages=messages,
        )
        
        return response.choices[0].message.content


class LocalProvider(LLMProvider):
    """Local LLM provider (Ollama, etc.)."""
    
    async def generate(self, prompt: str, system: str | None = None) -> str:
        import httpx
        
        full_prompt = prompt
        if system:
            full_prompt = f"{system}\n\n{prompt}"
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.config.endpoint,
                json={
                    "model": self.model,
                    "prompt": full_prompt,
                    "stream": False,
                },
                timeout=120.0,
            )
            response.raise_for_status()
            return response.json().get("response", "")


# =============================================================================
# PROMPTS
# =============================================================================

SYSTEM_PROMPT = """You are an expert software engineer specializing in code improvement.
Your task is to analyze code issues and generate precise, minimal fixes.

Guidelines:
1. Make the smallest change possible to fix the issue
2. Maintain the existing code style
3. Don't change unrelated code
4. Ensure the fix is complete and correct
5. Add comments explaining complex changes
6. Consider edge cases
7. If tests are needed, include them

Output Format:
Respond with a JSON object containing:
{
    "original_code": "the original code snippet",
    "improved_code": "the fixed code",
    "explanation": "brief explanation of the change",
    "confidence": 0.0-1.0
}
"""

BUG_FIX_PROMPT = """Analyze and fix this bug:

File: {file_path}
Issue: {issue_title}
Description: {issue_description}
Line: {line_start}

Code context:
```
{code_context}
```

Error from logs (if available):
{log_context}

Generate a fix for this issue. Return ONLY valid JSON."""

SECURITY_FIX_PROMPT = """Fix this security vulnerability:

File: {file_path}
Vulnerability: {issue_title}
Description: {issue_description}
Severity: {severity}
Line: {line_start}

Vulnerable code:
```
{code_context}
```

Apply security best practices to fix this vulnerability. Return ONLY valid JSON."""

COMPLEXITY_FIX_PROMPT = """Refactor this complex code:

File: {file_path}
Issue: {issue_title}
Description: {issue_description}
Line: {line_start}-{line_end}

Complex code:
```
{code_context}
```

Simplify while maintaining functionality. Return ONLY valid JSON."""

ERROR_PATTERN_FIX_PROMPT = """Fix code causing this recurring error:

Error Pattern: {pattern_description}
Occurrences: {occurrences}
Suspected File: {file_path}
Suspected Function: {function_name}

Code:
```
{code_context}
```

Sample error messages:
{sample_errors}

Generate a fix to prevent this error. Return ONLY valid JSON."""


# =============================================================================
# IMPROVEMENT ENGINE
# =============================================================================

class ImprovementEngine:
    """
    AI-powered engine for generating code improvements.
    
    Takes analysis results and uses LLMs to generate actual fixes.
    """
    
    def __init__(self, config: ImprovementEngineConfig):
        self.config = config
        self._provider: LLMProvider | None = None
        self._initialized = False
    
    async def initialize(self) -> None:
        """Initialize the LLM provider."""
        if self._initialized:
            return
        
        provider_config = self.config.get_active_provider()
        
        providers = {
            "anthropic": AnthropicProvider,
            "openai": OpenAIProvider,
            "local": LocalProvider,
        }
        
        provider_class = providers.get(self.config.provider)
        if provider_class:
            self._provider = provider_class(provider_config)
        else:
            raise ValueError(f"Unknown provider: {self.config.provider}")
        
        self._initialized = True
        logger.info(f"Initialized {self.config.provider} LLM provider")
    
    async def generate_improvements(
        self,
        log_analysis: LogAnalysisResult | None = None,
        code_analysis: CodeAnalysisResult | None = None,
    ) -> list[ImprovementPlan]:
        """
        Generate improvement plans based on analysis results.
        
        This is the main entry point that:
        1. Prioritizes issues
        2. Generates fixes for each
        3. Groups fixes into coherent PRs
        """
        await self.initialize()
        
        plans: list[ImprovementPlan] = []
        
        # Get enabled strategies sorted by priority
        strategies = sorted(
            [s for s in self.config.strategies if s.enabled],
            key=lambda s: s.priority,
        )
        
        for strategy in strategies:
            strategy_plans = await self._apply_strategy(
                strategy.name,
                log_analysis,
                code_analysis,
            )
            plans.extend(strategy_plans)
        
        # Limit total plans based on constraints
        max_files = self.config.constraints.max_files_per_pr
        limited_plans = []
        total_files = 0
        
        for plan in plans:
            plan_files = len(set(c.file_path for c in plan.changes))
            if total_files + plan_files <= max_files * 3:  # Allow ~3 PRs worth
                limited_plans.append(plan)
                total_files += plan_files
        
        logger.info(f"Generated {len(limited_plans)} improvement plans")
        return limited_plans
    
    async def _apply_strategy(
        self,
        strategy: str,
        log_analysis: LogAnalysisResult | None,
        code_analysis: CodeAnalysisResult | None,
    ) -> list[ImprovementPlan]:
        """Apply a specific improvement strategy."""
        strategies = {
            "bug_fix": self._strategy_bug_fix,
            "security_fix": self._strategy_security_fix,
            "performance_optimization": self._strategy_performance,
            "code_cleanup": self._strategy_cleanup,
        }
        
        handler = strategies.get(strategy)
        if handler:
            return await handler(log_analysis, code_analysis)
        
        return []
    
    async def _strategy_bug_fix(
        self,
        log_analysis: LogAnalysisResult | None,
        code_analysis: CodeAnalysisResult | None,
    ) -> list[ImprovementPlan]:
        """Fix bugs identified from logs and code analysis."""
        plans = []
        
        # Fix issues from log patterns
        if log_analysis:
            for pattern in log_analysis.patterns_detected:
                if pattern.severity in (Severity.HIGH, Severity.CRITICAL):
                    plan = await self._fix_log_pattern(pattern)
                    if plan:
                        plans.append(plan)
        
        # Fix code issues
        if code_analysis:
            bug_issues = [
                issue for fa in code_analysis.file_analyses
                for issue in fa.issues
                if issue.issue_type == IssueType.BUG
                and issue.severity in (Severity.HIGH, Severity.CRITICAL)
            ]
            
            for issue in bug_issues[:5]:  # Limit
                plan = await self._fix_code_issue(issue, ChangeType.BUG_FIX)
                if plan:
                    plans.append(plan)
        
        return plans
    
    async def _strategy_security_fix(
        self,
        log_analysis: LogAnalysisResult | None,
        code_analysis: CodeAnalysisResult | None,
    ) -> list[ImprovementPlan]:
        """Fix security vulnerabilities."""
        plans = []
        
        if not code_analysis:
            return plans
        
        security_issues = [
            issue for fa in code_analysis.file_analyses
            for issue in fa.issues
            if issue.issue_type == IssueType.SECURITY
        ]
        
        # Sort by severity
        security_issues.sort(key=lambda i: i.severity.value, reverse=True)
        
        for issue in security_issues[:5]:
            plan = await self._fix_security_issue(issue)
            if plan:
                plans.append(plan)
        
        return plans
    
    async def _strategy_performance(
        self,
        log_analysis: LogAnalysisResult | None,
        code_analysis: CodeAnalysisResult | None,
    ) -> list[ImprovementPlan]:
        """Optimize performance issues."""
        plans = []
        
        if not code_analysis:
            return plans
        
        perf_issues = [
            issue for fa in code_analysis.file_analyses
            for issue in fa.issues
            if issue.issue_type == IssueType.PERFORMANCE
        ]
        
        for issue in perf_issues[:3]:
            plan = await self._fix_code_issue(issue, ChangeType.PERFORMANCE)
            if plan:
                plans.append(plan)
        
        return plans
    
    async def _strategy_cleanup(
        self,
        log_analysis: LogAnalysisResult | None,
        code_analysis: CodeAnalysisResult | None,
    ) -> list[ImprovementPlan]:
        """Clean up code complexity and style issues."""
        plans = []
        
        if not code_analysis:
            return plans
        
        complexity_issues = [
            issue for fa in code_analysis.file_analyses
            for issue in fa.issues
            if issue.issue_type == IssueType.COMPLEXITY
            and issue.severity in (Severity.MEDIUM, Severity.HIGH)
        ]
        
        for issue in complexity_issues[:3]:
            plan = await self._fix_complexity_issue(issue)
            if plan:
                plans.append(plan)
        
        return plans
    
    async def _fix_log_pattern(self, pattern: LogPattern) -> ImprovementPlan | None:
        """Generate a fix for a log pattern."""
        if not pattern.suspected_files:
            return None
        
        # Get the most likely file
        file_path = pattern.suspected_files[0]
        function_name = pattern.suspected_functions[0] if pattern.suspected_functions else "unknown"
        
        # Read file content
        code_context = await self._read_file_context(file_path)
        if not code_context:
            return None
        
        # Get sample errors
        sample_errors = "\n".join([
            f"- {e.message}" for e in pattern.sample_entries[:3]
        ])
        
        prompt = ERROR_PATTERN_FIX_PROMPT.format(
            pattern_description=pattern.description,
            occurrences=pattern.occurrences,
            file_path=file_path,
            function_name=function_name,
            code_context=code_context,
            sample_errors=sample_errors,
        )
        
        try:
            response = await self._provider.generate(prompt, SYSTEM_PROMPT)
            fix = self._parse_fix_response(response)
            
            if fix and fix.get("confidence", 0) >= 0.7:
                change = CodeChange(
                    file_path=file_path,
                    original_code=fix.get("original_code", ""),
                    improved_code=fix.get("improved_code", ""),
                    line_start=1,
                    line_end=1,
                    change_type=ChangeType.BUG_FIX,
                    description=fix.get("explanation", "Fix for recurring error"),
                    reasoning=f"Error occurred {pattern.occurrences} times",
                    related_log_patterns=[pattern.id],
                    confidence_score=fix.get("confidence", 0.8),
                )
                
                return ImprovementPlan(
                    title=f"Fix: {pattern.description[:50]}",
                    description=f"Fix recurring error pattern: {pattern.description}",
                    change_type=ChangeType.BUG_FIX,
                    priority=1,
                    changes=[change],
                    source_log_patterns=[pattern.id],
                )
        
        except Exception as e:
            logger.warning(f"Failed to generate fix for pattern: {e}")
        
        return None
    
    async def _fix_code_issue(
        self,
        issue: CodeIssue,
        change_type: ChangeType,
    ) -> ImprovementPlan | None:
        """Generate a fix for a code issue."""
        code_context = await self._read_file_context(
            issue.file_path,
            issue.line_start,
            issue.line_end,
        )
        
        if not code_context:
            return None
        
        prompt = BUG_FIX_PROMPT.format(
            file_path=issue.file_path,
            issue_title=issue.title,
            issue_description=issue.description,
            line_start=issue.line_start,
            code_context=code_context,
            log_context="N/A",
        )
        
        try:
            response = await self._provider.generate(prompt, SYSTEM_PROMPT)
            fix = self._parse_fix_response(response)
            
            if fix and fix.get("confidence", 0) >= 0.6:
                change = CodeChange(
                    file_path=issue.file_path,
                    original_code=fix.get("original_code", ""),
                    improved_code=fix.get("improved_code", ""),
                    line_start=issue.line_start,
                    line_end=issue.line_end or issue.line_start,
                    change_type=change_type,
                    description=fix.get("explanation", issue.description),
                    reasoning=f"Tool: {issue.tool_name}, Rule: {issue.rule_id}",
                    related_issues=[issue.id],
                    confidence_score=fix.get("confidence", 0.8),
                )
                
                return ImprovementPlan(
                    title=f"Fix: {issue.title}",
                    description=issue.description,
                    change_type=change_type,
                    priority=2,
                    changes=[change],
                )
        
        except Exception as e:
            logger.warning(f"Failed to generate fix for issue: {e}")
        
        return None
    
    async def _fix_security_issue(self, issue: CodeIssue) -> ImprovementPlan | None:
        """Generate a fix for a security vulnerability."""
        code_context = await self._read_file_context(
            issue.file_path,
            issue.line_start,
            issue.line_end,
        )
        
        if not code_context:
            return None
        
        prompt = SECURITY_FIX_PROMPT.format(
            file_path=issue.file_path,
            issue_title=issue.title,
            issue_description=issue.description,
            severity=issue.severity.value,
            line_start=issue.line_start,
            code_context=code_context,
        )
        
        try:
            response = await self._provider.generate(prompt, SYSTEM_PROMPT)
            fix = self._parse_fix_response(response)
            
            if fix and fix.get("confidence", 0) >= 0.7:
                change = CodeChange(
                    file_path=issue.file_path,
                    original_code=fix.get("original_code", ""),
                    improved_code=fix.get("improved_code", ""),
                    line_start=issue.line_start,
                    line_end=issue.line_end or issue.line_start,
                    change_type=ChangeType.SECURITY_FIX,
                    description=fix.get("explanation", issue.description),
                    reasoning=f"Security: {issue.title}",
                    related_issues=[issue.id],
                    confidence_score=fix.get("confidence", 0.8),
                )
                
                return ImprovementPlan(
                    title=f"Security: {issue.title}",
                    description=f"Fix security vulnerability: {issue.description}",
                    change_type=ChangeType.SECURITY_FIX,
                    priority=1,
                    changes=[change],
                    security_issues_fixed=1,
                )
        
        except Exception as e:
            logger.warning(f"Failed to generate security fix: {e}")
        
        return None
    
    async def _fix_complexity_issue(self, issue: CodeIssue) -> ImprovementPlan | None:
        """Generate a refactoring for complexity issues."""
        code_context = await self._read_file_context(
            issue.file_path,
            issue.line_start,
            issue.line_end,
        )
        
        if not code_context:
            return None
        
        prompt = COMPLEXITY_FIX_PROMPT.format(
            file_path=issue.file_path,
            issue_title=issue.title,
            issue_description=issue.description,
            line_start=issue.line_start,
            line_end=issue.line_end or issue.line_start + 50,
            code_context=code_context,
        )
        
        try:
            response = await self._provider.generate(prompt, SYSTEM_PROMPT)
            fix = self._parse_fix_response(response)
            
            if fix and fix.get("confidence", 0) >= 0.6:
                change = CodeChange(
                    file_path=issue.file_path,
                    original_code=fix.get("original_code", ""),
                    improved_code=fix.get("improved_code", ""),
                    line_start=issue.line_start,
                    line_end=issue.line_end or issue.line_start,
                    change_type=ChangeType.REFACTOR,
                    description=fix.get("explanation", issue.description),
                    reasoning="Complexity reduction",
                    related_issues=[issue.id],
                    confidence_score=fix.get("confidence", 0.8),
                )
                
                return ImprovementPlan(
                    title=f"Refactor: {issue.title}",
                    description=f"Reduce complexity: {issue.description}",
                    change_type=ChangeType.REFACTOR,
                    priority=3,
                    changes=[change],
                )
        
        except Exception as e:
            logger.warning(f"Failed to generate refactoring: {e}")
        
        return None
    
    async def _read_file_context(
        self,
        file_path: str,
        start_line: int | None = None,
        end_line: int | None = None,
        context_lines: int = 20,
    ) -> str | None:
        """Read file content with context."""
        try:
            path = Path(file_path)
            if not path.exists():
                return None
            
            with open(path) as f:
                lines = f.readlines()
            
            if start_line is None:
                return "".join(lines[:200])  # First 200 lines
            
            # Get context around the target lines
            start = max(0, start_line - context_lines - 1)
            end = min(len(lines), (end_line or start_line) + context_lines)
            
            return "".join(lines[start:end])
        
        except Exception as e:
            logger.warning(f"Failed to read {file_path}: {e}")
            return None
    
    def _parse_fix_response(self, response: str) -> dict | None:
        """Parse the LLM response as JSON."""
        import json
        
        # Try to extract JSON from response
        try:
            # First try direct parse
            return json.loads(response)
        except json.JSONDecodeError:
            pass
        
        # Try to find JSON in the response
        import re
        json_match = re.search(r'\{[^{}]*\}', response, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group())
            except json.JSONDecodeError:
                pass
        
        logger.warning("Could not parse LLM response as JSON")
        return None
