"""
Log Analyzer - Analyzes production logs for errors and patterns.

This module ingests logs from various sources (files, Elasticsearch, CloudWatch, etc.)
and identifies patterns that indicate code issues.
"""

from __future__ import annotations

import asyncio
import json
import re
from abc import ABC, abstractmethod
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import AsyncIterator

import structlog

from acia.core.config import LogsConfig, LogSourceConfig
from acia.core.models import LogEntry, LogPattern, LogAnalysisResult, Severity


logger = structlog.get_logger(__name__)


# =============================================================================
# LOG SOURCE INTERFACES
# =============================================================================

class LogSource(ABC):
    """Abstract base class for log sources."""
    
    def __init__(self, config: LogSourceConfig):
        self.config = config
        self.name = config.name
    
    @abstractmethod
    async def fetch_entries(
        self,
        since: datetime,
        until: datetime | None = None,
    ) -> AsyncIterator[LogEntry]:
        """Fetch log entries from the source."""
        pass
    
    async def close(self) -> None:
        """Close any connections."""
        pass


class FileLogSource(LogSource):
    """Log source that reads from local files."""
    
    async def fetch_entries(
        self,
        since: datetime,
        until: datetime | None = None,
    ) -> AsyncIterator[LogEntry]:
        """Read log entries from files."""
        import aiofiles
        import glob
        
        pattern = self.config.path
        if not pattern:
            return
        
        for filepath in glob.glob(pattern):
            try:
                async with aiofiles.open(filepath, 'r') as f:
                    async for line in f:
                        entry = self._parse_line(line.strip(), filepath)
                        if entry and entry.timestamp >= since:
                            if until is None or entry.timestamp <= until:
                                yield entry
            except Exception as e:
                logger.warning(f"Failed to read {filepath}: {e}")
    
    def _parse_line(self, line: str, filepath: str) -> LogEntry | None:
        """Parse a log line based on format."""
        if not line:
            return None
        
        try:
            if self.config.format == "json":
                data = json.loads(line)
                return LogEntry(
                    timestamp=self._parse_timestamp(data.get("timestamp", data.get("time", ""))),
                    level=data.get("level", data.get("severity", "INFO")).upper(),
                    message=data.get("message", data.get("msg", "")),
                    source=self.name,
                    metadata=data,
                    error_type=data.get("error_type"),
                    stack_trace=data.get("stack_trace", data.get("traceback")),
                    file_path=data.get("file", data.get("filename")),
                    line_number=data.get("line", data.get("lineno")),
                    function_name=data.get("function", data.get("func_name")),
                )
            else:
                # Plain text - basic parsing
                return self._parse_plain_line(line, filepath)
        except Exception as e:
            logger.debug(f"Failed to parse line: {e}")
            return None
    
    def _parse_plain_line(self, line: str, filepath: str) -> LogEntry | None:
        """Parse a plain text log line."""
        # Common log format: TIMESTAMP LEVEL MESSAGE
        pattern = r'^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[^\s]*)\s+(\w+)\s+(.*)$'
        match = re.match(pattern, line)
        
        if match:
            timestamp_str, level, message = match.groups()
            return LogEntry(
                timestamp=self._parse_timestamp(timestamp_str),
                level=level.upper(),
                message=message,
                source=self.name,
            )
        
        # Fallback - treat entire line as message
        return LogEntry(
            timestamp=datetime.utcnow(),
            level="INFO",
            message=line,
            source=self.name,
        )
    
    def _parse_timestamp(self, ts: str) -> datetime:
        """Parse various timestamp formats."""
        formats = [
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(ts, fmt)
            except ValueError:
                continue
        
        return datetime.utcnow()


class ElasticsearchLogSource(LogSource):
    """Log source that reads from Elasticsearch."""
    
    def __init__(self, config: LogSourceConfig):
        super().__init__(config)
        self._client = None
    
    async def _get_client(self):
        """Get or create Elasticsearch client."""
        if self._client is None:
            from elasticsearch import AsyncElasticsearch
            import os
            
            api_key = os.getenv(self.config.auth_env_var) if self.config.auth_env_var else None
            self._client = AsyncElasticsearch(
                hosts=[self.config.host],
                api_key=api_key,
            )
        return self._client
    
    async def fetch_entries(
        self,
        since: datetime,
        until: datetime | None = None,
    ) -> AsyncIterator[LogEntry]:
        """Fetch entries from Elasticsearch."""
        client = await self._get_client()
        
        query = {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": since.isoformat()}}}
                ]
            }
        }
        
        if until:
            query["bool"]["filter"].append(
                {"range": {"@timestamp": {"lte": until.isoformat()}}}
            )
        
        async for hit in self._scroll_search(client, query):
            yield self._hit_to_entry(hit)
    
    async def _scroll_search(self, client, query):
        """Scroll through all search results."""
        resp = await client.search(
            index=self.config.index,
            query=query,
            scroll="5m",
            size=1000,
        )
        
        scroll_id = resp["_scroll_id"]
        hits = resp["hits"]["hits"]
        
        while hits:
            for hit in hits:
                yield hit
            
            resp = await client.scroll(scroll_id=scroll_id, scroll="5m")
            scroll_id = resp["_scroll_id"]
            hits = resp["hits"]["hits"]
        
        await client.clear_scroll(scroll_id=scroll_id)
    
    def _hit_to_entry(self, hit: dict) -> LogEntry:
        """Convert ES hit to LogEntry."""
        source = hit["_source"]
        return LogEntry(
            timestamp=datetime.fromisoformat(source.get("@timestamp", "").replace("Z", "")),
            level=source.get("level", source.get("log.level", "INFO")).upper(),
            message=source.get("message", ""),
            source=self.name,
            metadata=source,
            error_type=source.get("error.type"),
            stack_trace=source.get("error.stack_trace"),
        )
    
    async def close(self) -> None:
        if self._client:
            await self._client.close()


class CloudWatchLogSource(LogSource):
    """Log source that reads from AWS CloudWatch."""
    
    def __init__(self, config: LogSourceConfig):
        super().__init__(config)
        self._client = None
    
    async def _get_client(self):
        """Get or create CloudWatch client."""
        if self._client is None:
            import aioboto3
            session = aioboto3.Session()
            self._client = await session.client(
                "logs",
                region_name=self.config.region,
            ).__aenter__()
        return self._client
    
    async def fetch_entries(
        self,
        since: datetime,
        until: datetime | None = None,
    ) -> AsyncIterator[LogEntry]:
        """Fetch entries from CloudWatch."""
        client = await self._get_client()
        
        start_time = int(since.timestamp() * 1000)
        end_time = int((until or datetime.utcnow()).timestamp() * 1000)
        
        paginator = client.get_paginator("filter_log_events")
        
        async for page in paginator.paginate(
            logGroupName=self.config.log_group,
            startTime=start_time,
            endTime=end_time,
        ):
            for event in page.get("events", []):
                yield self._event_to_entry(event)
    
    def _event_to_entry(self, event: dict) -> LogEntry:
        """Convert CloudWatch event to LogEntry."""
        message = event.get("message", "")
        timestamp = datetime.fromtimestamp(event["timestamp"] / 1000)
        
        # Try to parse as JSON
        metadata = {}
        try:
            metadata = json.loads(message)
            message = metadata.get("message", message)
        except json.JSONDecodeError:
            pass
        
        return LogEntry(
            timestamp=timestamp,
            level=metadata.get("level", "INFO").upper(),
            message=message,
            source=self.name,
            metadata=metadata,
        )
    
    async def close(self) -> None:
        if self._client:
            await self._client.__aexit__(None, None, None)


# =============================================================================
# PATTERN DETECTION
# =============================================================================

class PatternDetector:
    """Detects patterns in log entries."""
    
    def __init__(self):
        # Error message normalization patterns
        self.normalization_patterns = [
            (r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', '<UUID>'),
            (r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '<IP>'),
            (r'\b\d+\b', '<NUM>'),
            (r'"[^"]*"', '"<STRING>"'),
            (r"'[^']*'", "'<STRING>'"),
        ]
    
    def detect_patterns(
        self,
        entries: list[LogEntry],
        min_occurrences: int = 3,
    ) -> list[LogPattern]:
        """Detect recurring patterns in log entries."""
        patterns = []
        
        # Group by normalized message
        grouped = self._group_by_normalized_message(entries)
        
        for normalized_msg, group_entries in grouped.items():
            if len(group_entries) >= min_occurrences:
                pattern = self._create_pattern(normalized_msg, group_entries)
                patterns.append(pattern)
        
        # Detect error spikes
        spike_patterns = self._detect_spikes(entries)
        patterns.extend(spike_patterns)
        
        return patterns
    
    def _normalize_message(self, message: str) -> str:
        """Normalize a message for grouping."""
        normalized = message
        for pattern, replacement in self.normalization_patterns:
            normalized = re.sub(pattern, replacement, normalized)
        return normalized
    
    def _group_by_normalized_message(
        self,
        entries: list[LogEntry],
    ) -> dict[str, list[LogEntry]]:
        """Group entries by their normalized message."""
        groups = defaultdict(list)
        for entry in entries:
            if entry.level in ("ERROR", "CRITICAL", "FATAL", "EXCEPTION"):
                normalized = self._normalize_message(entry.message)
                groups[normalized].append(entry)
        return groups
    
    def _create_pattern(
        self,
        normalized_msg: str,
        entries: list[LogEntry],
    ) -> LogPattern:
        """Create a pattern from grouped entries."""
        timestamps = [e.timestamp for e in entries]
        
        # Extract suspected files/functions
        suspected_files = set()
        suspected_functions = set()
        
        for entry in entries:
            if entry.file_path:
                suspected_files.add(entry.file_path)
            if entry.function_name:
                suspected_functions.add(entry.function_name)
            
            # Try to extract from stack trace
            if entry.stack_trace:
                files, funcs = self._extract_from_stack_trace(entry.stack_trace)
                suspected_files.update(files)
                suspected_functions.update(funcs)
        
        # Determine severity based on count and frequency
        severity = self._calculate_severity(entries)
        
        return LogPattern(
            pattern_type="recurring_error",
            description=f"Recurring error: {normalized_msg[:200]}",
            occurrences=len(entries),
            first_seen=min(timestamps),
            last_seen=max(timestamps),
            sample_entries=entries[:5],
            severity=severity,
            suspected_files=list(suspected_files)[:10],
            suspected_functions=list(suspected_functions)[:10],
        )
    
    def _extract_from_stack_trace(
        self,
        stack_trace: str,
    ) -> tuple[set[str], set[str]]:
        """Extract file paths and function names from stack trace."""
        files = set()
        functions = set()
        
        # Python-style: File "path/to/file.py", line X, in function_name
        python_pattern = r'File "([^"]+)", line \d+, in (\w+)'
        for match in re.finditer(python_pattern, stack_trace):
            files.add(match.group(1))
            functions.add(match.group(2))
        
        # Java-style: at package.Class.method(File.java:line)
        java_pattern = r'at [\w.]+\.(\w+)\(([\w.]+\.java):\d+\)'
        for match in re.finditer(java_pattern, stack_trace):
            functions.add(match.group(1))
            files.add(match.group(2))
        
        # JavaScript/Node-style: at function (file:line:col)
        js_pattern = r'at (\w+) \(([^)]+):\d+:\d+\)'
        for match in re.finditer(js_pattern, stack_trace):
            functions.add(match.group(1))
            files.add(match.group(2))
        
        return files, functions
    
    def _calculate_severity(self, entries: list[LogEntry]) -> Severity:
        """Calculate severity based on error frequency and levels."""
        count = len(entries)
        
        # Check for critical/fatal errors
        has_critical = any(
            e.level in ("CRITICAL", "FATAL") for e in entries
        )
        
        if has_critical or count >= 100:
            return Severity.CRITICAL
        elif count >= 50:
            return Severity.HIGH
        elif count >= 10:
            return Severity.MEDIUM
        else:
            return Severity.LOW
    
    def _detect_spikes(self, entries: list[LogEntry]) -> list[LogPattern]:
        """Detect unusual spikes in error frequency."""
        patterns = []
        
        # Group errors by hour
        hourly_counts = defaultdict(list)
        for entry in entries:
            if entry.level in ("ERROR", "CRITICAL", "FATAL"):
                hour_key = entry.timestamp.strftime("%Y-%m-%d %H:00")
                hourly_counts[hour_key].append(entry)
        
        if not hourly_counts:
            return patterns
        
        # Calculate average and detect spikes
        counts = [len(v) for v in hourly_counts.values()]
        avg_count = sum(counts) / len(counts)
        
        for hour, hour_entries in hourly_counts.items():
            if len(hour_entries) > avg_count * 3:  # 3x average is a spike
                patterns.append(LogPattern(
                    pattern_type="spike",
                    description=f"Error spike detected at {hour}: {len(hour_entries)} errors (avg: {avg_count:.1f})",
                    occurrences=len(hour_entries),
                    first_seen=min(e.timestamp for e in hour_entries),
                    last_seen=max(e.timestamp for e in hour_entries),
                    sample_entries=hour_entries[:5],
                    severity=Severity.HIGH,
                ))
        
        return patterns


# =============================================================================
# MAIN LOG ANALYZER
# =============================================================================

class LogAnalyzer:
    """
    Main log analyzer that orchestrates log collection and pattern detection.
    """
    
    def __init__(self, config: LogsConfig):
        self.config = config
        self.sources: list[LogSource] = []
        self.pattern_detector = PatternDetector()
        self._initialized = False
    
    async def initialize(self) -> None:
        """Initialize log sources."""
        if self._initialized:
            return
        
        for source_config in self.config.sources:
            source = self._create_source(source_config)
            if source:
                self.sources.append(source)
        
        self._initialized = True
        logger.info(f"Initialized {len(self.sources)} log sources")
    
    def _create_source(self, config: LogSourceConfig) -> LogSource | None:
        """Create a log source from configuration."""
        source_types = {
            "file": FileLogSource,
            "elasticsearch": ElasticsearchLogSource,
            "cloudwatch": CloudWatchLogSource,
        }
        
        source_class = source_types.get(config.type)
        if source_class:
            return source_class(config)
        
        logger.warning(f"Unknown log source type: {config.type}")
        return None
    
    def _parse_lookback(self, lookback: str) -> timedelta:
        """Parse lookback period string to timedelta."""
        match = re.match(r'^(\d+)([hdwm])$', lookback)
        if not match:
            return timedelta(hours=24)
        
        value = int(match.group(1))
        unit = match.group(2)
        
        units = {
            'h': timedelta(hours=value),
            'd': timedelta(days=value),
            'w': timedelta(weeks=value),
            'm': timedelta(days=value * 30),
        }
        
        return units.get(unit, timedelta(hours=24))
    
    async def analyze(self) -> LogAnalysisResult:
        """
        Analyze logs from all configured sources.
        
        Returns a LogAnalysisResult containing detected patterns.
        """
        await self.initialize()
        
        result = LogAnalysisResult(
            source="all",
            entries_analyzed=0,
        )
        
        # Calculate time range
        lookback = self._parse_lookback(self.config.lookback_period)
        since = datetime.utcnow() - lookback
        
        # Collect entries from all sources
        all_entries: list[LogEntry] = []
        
        for source in self.sources:
            try:
                logger.info(f"Fetching logs from {source.name}")
                source_entries = []
                
                async for entry in source.fetch_entries(since=since):
                    # Filter ignored patterns
                    if not self._should_ignore(entry):
                        source_entries.append(entry)
                
                all_entries.extend(source_entries)
                logger.info(f"Fetched {len(source_entries)} entries from {source.name}")
                
            except Exception as e:
                logger.error(f"Failed to fetch from {source.name}: {e}")
        
        result.entries_analyzed = len(all_entries)
        
        # Count by level
        for entry in all_entries:
            if entry.level == "ERROR":
                result.errors_found += 1
            elif entry.level == "WARNING":
                result.warnings_found += 1
        
        # Detect patterns
        if all_entries:
            patterns = self.pattern_detector.detect_patterns(
                all_entries,
                min_occurrences=self.config.error_threshold,
            )
            result.patterns_detected = patterns
            result.anomalies_found = sum(
                1 for p in patterns if p.pattern_type == "spike"
            )
        
        return result
    
    def _should_ignore(self, entry: LogEntry) -> bool:
        """Check if an entry should be ignored based on patterns."""
        for pattern in self.config.ignore_patterns:
            if pattern.lower() in entry.message.lower():
                return True
        return False
    
    async def close(self) -> None:
        """Close all log sources."""
        for source in self.sources:
            await source.close()
