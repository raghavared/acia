"""
Code Analyzer - Analyzes codebase for issues, complexity, and security vulnerabilities.

This module performs static analysis, complexity checks, and security scans
to identify opportunities for improvement.
"""

from __future__ import annotations

import asyncio
import fnmatch
import subprocess
from abc import ABC, abstractmethod
from pathlib import Path

import structlog

from acia.core.config import AnalysisConfig, CodebaseConfig, StaticAnalyzerConfig
from acia.core.models import (
    CodeAnalysisResult,
    CodeIssue,
    FileAnalysis,
    FunctionAnalysis,
    IssueType,
    Severity,
)


logger = structlog.get_logger(__name__)


class StaticAnalyzer(ABC):
    """Base class for static analyzers."""
    
    def __init__(self, config: StaticAnalyzerConfig):
        self.config = config
        self.tool = config.tool
    
    @abstractmethod
    async def analyze_file(self, filepath: Path) -> list[CodeIssue]:
        """Analyze a single file and return issues."""
        pass
    
    @abstractmethod
    def supports_language(self, language: str) -> bool:
        """Check if this analyzer supports the given language."""
        pass


class PylintAnalyzer(StaticAnalyzer):
    """Pylint static analyzer for Python."""
    
    def supports_language(self, language: str) -> bool:
        return language.lower() == "python"
    
    async def analyze_file(self, filepath: Path) -> list[CodeIssue]:
        """Run pylint on a file."""
        issues = []
        
        cmd = ["pylint", str(filepath), "--output-format=json"]
        if self.config.config:
            cmd.extend(["--rcfile", self.config.config])
        
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            
            if stdout:
                import json
                results = json.loads(stdout.decode())
                
                for item in results:
                    severity = self._map_severity(item.get("type", "convention"))
                    issue = CodeIssue(
                        file_path=str(filepath),
                        line_start=item.get("line", 1),
                        column_start=item.get("column", 0),
                        issue_type=IssueType.STYLE,
                        severity=severity,
                        title=item.get("symbol", "unknown"),
                        description=item.get("message", ""),
                        tool_name="pylint",
                        rule_id=item.get("message-id"),
                    )
                    issues.append(issue)
        
        except Exception as e:
            logger.warning(f"Pylint failed on {filepath}: {e}")
        
        return issues
    
    def _map_severity(self, pylint_type: str) -> Severity:
        mapping = {
            "error": Severity.HIGH,
            "fatal": Severity.CRITICAL,
            "warning": Severity.MEDIUM,
            "convention": Severity.LOW,
            "refactor": Severity.LOW,
        }
        return mapping.get(pylint_type, Severity.LOW)


class BanditAnalyzer(StaticAnalyzer):
    """Bandit security analyzer for Python."""
    
    def supports_language(self, language: str) -> bool:
        return language.lower() == "python"
    
    async def analyze_file(self, filepath: Path) -> list[CodeIssue]:
        issues = []
        cmd = ["bandit", "-f", "json", str(filepath)]
        
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            
            if stdout:
                import json
                results = json.loads(stdout.decode())
                
                for item in results.get("results", []):
                    severity = self._map_severity(item.get("issue_severity", "LOW"))
                    issue = CodeIssue(
                        file_path=str(filepath),
                        line_start=item.get("line_number", 1),
                        issue_type=IssueType.SECURITY,
                        severity=severity,
                        title=item.get("test_id", "unknown"),
                        description=item.get("issue_text", ""),
                        code_snippet=item.get("code", ""),
                        tool_name="bandit",
                        rule_id=item.get("test_id"),
                    )
                    issues.append(issue)
        except Exception as e:
            logger.warning(f"Bandit failed on {filepath}: {e}")
        
        return issues
    
    def _map_severity(self, bandit_severity: str) -> Severity:
        mapping = {"HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}
        return mapping.get(bandit_severity.upper(), Severity.LOW)


class ComplexityAnalyzer:
    """Analyzes code complexity using radon."""
    
    async def analyze_file(self, filepath: Path, language: str) -> FileAnalysis:
        analysis = FileAnalysis(
            file_path=str(filepath),
            language=language,
            lines_of_code=0,
        )
        
        try:
            with open(filepath) as f:
                lines = f.readlines()
                analysis.lines_of_code = len([
                    l for l in lines if l.strip() and not l.strip().startswith('#')
                ])
        except Exception:
            pass
        
        if language.lower() == "python":
            await self._analyze_python_complexity(filepath, analysis)
        
        return analysis
    
    async def _analyze_python_complexity(self, filepath: Path, analysis: FileAnalysis) -> None:
        try:
            proc = await asyncio.create_subprocess_exec(
                "radon", "cc", "-j", str(filepath),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            
            if stdout:
                import json
                results = json.loads(stdout.decode())
                
                for filepath_key, functions in results.items():
                    complexities = []
                    for func in functions:
                        complexities.append(func.get("complexity", 0))
                        func_analysis = FunctionAnalysis(
                            name=func.get("name", "unknown"),
                            file_path=str(filepath),
                            line_start=func.get("lineno", 1),
                            line_end=func.get("endline", 1),
                            cyclomatic_complexity=func.get("complexity", 0),
                        )
                        analysis.functions.append(func_analysis)
                    
                    if complexities:
                        analysis.cyclomatic_complexity = sum(complexities) / len(complexities)
            
            proc = await asyncio.create_subprocess_exec(
                "radon", "mi", "-j", str(filepath),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            
            if stdout:
                import json
                results = json.loads(stdout.decode())
                for filepath_key, mi_data in results.items():
                    analysis.maintainability_index = mi_data.get("mi", 100)
        
        except Exception as e:
            logger.warning(f"Complexity analysis failed for {filepath}: {e}")


class CodeAnalyzer:
    """Main code analyzer that orchestrates all analysis tools."""
    
    def __init__(self, config: AnalysisConfig, codebase_config: CodebaseConfig):
        self.config = config
        self.codebase_config = codebase_config
        self.analyzers: list[StaticAnalyzer] = []
        self.complexity_analyzer = ComplexityAnalyzer()
        self._initialized = False
    
    async def initialize(self) -> None:
        if self._initialized:
            return
        
        analyzer_classes = {
            "pylint": PylintAnalyzer,
            "bandit": BanditAnalyzer,
        }
        
        for language, analyzers in self.config.static_analyzers.items():
            for analyzer_config in analyzers:
                analyzer_class = analyzer_classes.get(analyzer_config.tool)
                if analyzer_class:
                    self.analyzers.append(analyzer_class(analyzer_config))
        
        if self.config.security.enabled:
            for tool in self.config.security.tools:
                if tool == "bandit" and not any(isinstance(a, BanditAnalyzer) for a in self.analyzers):
                    self.analyzers.append(BanditAnalyzer(StaticAnalyzerConfig(tool="bandit")))
        
        self._initialized = True
        logger.info(f"Initialized {len(self.analyzers)} code analyzers")
    
    def _get_language(self, filepath: Path) -> str:
        ext_mapping = {
            ".py": "python", ".js": "javascript", ".ts": "typescript",
            ".jsx": "javascript", ".tsx": "typescript", ".java": "java",
            ".go": "go", ".rs": "rust", ".rb": "ruby", ".php": "php",
        }
        return ext_mapping.get(filepath.suffix.lower(), "unknown")
    
    def _should_analyze(self, filepath: Path) -> bool:
        filepath_str = str(filepath)
        for pattern in self.codebase_config.exclude_patterns:
            if fnmatch.fnmatch(filepath_str, pattern):
                return False
        for pattern in self.codebase_config.include_patterns:
            if fnmatch.fnmatch(filepath_str, pattern):
                return True
        return False
    
    async def _collect_files(self, root_path: Path) -> list[Path]:
        files = []
        for filepath in root_path.rglob("*"):
            if filepath.is_file() and self._should_analyze(filepath):
                files.append(filepath)
        return files
    
    async def analyze(self) -> CodeAnalysisResult:
        await self.initialize()
        result = CodeAnalysisResult()
        
        repo_path = Path(self.codebase_config.local_path)
        if not repo_path.exists():
            logger.warning(f"Repository path does not exist: {repo_path}")
            await self._ensure_repo()
        
        files = await self._collect_files(repo_path)
        result.files_analyzed = len(files)
        logger.info(f"Analyzing {len(files)} files...")
        
        all_issues: list[CodeIssue] = []
        
        for filepath in files:
            try:
                language = self._get_language(filepath)
                file_analysis = await self.complexity_analyzer.analyze_file(filepath, language)
                complexity_issues = self._check_complexity_thresholds(file_analysis)
                file_analysis.issues.extend(complexity_issues)
                all_issues.extend(complexity_issues)
                
                for analyzer in self.analyzers:
                    if analyzer.supports_language(language):
                        issues = await analyzer.analyze_file(filepath)
                        file_analysis.issues.extend(issues)
                        all_issues.extend(issues)
                
                result.file_analyses.append(file_analysis)
            except Exception as e:
                logger.warning(f"Failed to analyze {filepath}: {e}")
        
        result.total_issues = len(all_issues)
        
        for issue in all_issues:
            severity_key = issue.severity.value
            result.issues_by_severity[severity_key] = result.issues_by_severity.get(severity_key, 0) + 1
            type_key = issue.issue_type.value
            result.issues_by_type[type_key] = result.issues_by_type.get(type_key, 0) + 1
        
        if result.file_analyses:
            complexities = [fa.cyclomatic_complexity for fa in result.file_analyses if fa.cyclomatic_complexity > 0]
            maintainabilities = [fa.maintainability_index for fa in result.file_analyses if fa.maintainability_index > 0]
            if complexities:
                result.average_complexity = sum(complexities) / len(complexities)
            if maintainabilities:
                result.average_maintainability = sum(maintainabilities) / len(maintainabilities)
        
        logger.info("Code analysis complete", files=result.files_analyzed, issues=result.total_issues)
        return result
    
    def _check_complexity_thresholds(self, file_analysis: FileAnalysis) -> list[CodeIssue]:
        issues = []
        thresholds = self.config.complexity
        
        if file_analysis.lines_of_code > thresholds.max_file_length:
            issues.append(CodeIssue(
                file_path=file_analysis.file_path, line_start=1, issue_type=IssueType.COMPLEXITY,
                severity=Severity.MEDIUM, title="file_too_long",
                description=f"File has {file_analysis.lines_of_code} lines (max: {thresholds.max_file_length})",
            ))
        
        for func in file_analysis.functions:
            if func.cyclomatic_complexity > thresholds.max_cyclomatic:
                issues.append(CodeIssue(
                    file_path=file_analysis.file_path, line_start=func.line_start, line_end=func.line_end,
                    issue_type=IssueType.COMPLEXITY, severity=Severity.MEDIUM, title="high_cyclomatic_complexity",
                    description=f"Function '{func.name}' has complexity {func.cyclomatic_complexity} (max: {thresholds.max_cyclomatic})",
                ))
        
        return issues
    
    async def _ensure_repo(self) -> None:
        import git
        repo_path = Path(self.codebase_config.local_path)
        
        if not repo_path.exists():
            logger.info(f"Cloning repository to {repo_path}")
            repo_path.mkdir(parents=True, exist_ok=True)
            token = self.codebase_config.auth.get_token()
            url = self.codebase_config.repository_url
            if token and "github.com" in url:
                url = url.replace("https://", f"https://{token}@")
            git.Repo.clone_from(url, repo_path, branch=self.codebase_config.target_branch)
        else:
            logger.info("Updating repository")
            repo = git.Repo(repo_path)
            repo.remotes.origin.pull()
