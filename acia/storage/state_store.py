"""
State Store - Persists ACIA state and history.

This module handles storage of:
- System state
- Cycle history
- Analysis results
- PR tracking
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Any

import structlog

from acia.core.config import StorageConfig
from acia.core.models import CycleResult, SystemState


logger = structlog.get_logger(__name__)


class StateStore(ABC):
    """Abstract base for state storage."""
    
    def __init__(self, config: StorageConfig):
        self.config = config
    
    @abstractmethod
    async def initialize(self) -> None:
        """Initialize storage."""
        pass
    
    @abstractmethod
    async def close(self) -> None:
        """Close storage connections."""
        pass
    
    @abstractmethod
    async def save_state(self, state: SystemState) -> None:
        """Save system state."""
        pass
    
    @abstractmethod
    async def load_state(self) -> SystemState | None:
        """Load system state."""
        pass
    
    @abstractmethod
    async def save_cycle(self, cycle: CycleResult) -> None:
        """Save cycle result."""
        pass
    
    @abstractmethod
    async def get_cycles(
        self,
        limit: int = 100,
        since: datetime | None = None,
    ) -> list[CycleResult]:
        """Get cycle history."""
        pass
    
    async def get_recent_cycles(self, limit: int = 5) -> list[CycleResult]:
        """Get recent cycles - convenience method."""
        return await self.get_cycles(limit=limit)


class SQLiteStateStore(StateStore):
    """SQLite-based state storage."""
    
    def __init__(self, config: StorageConfig):
        super().__init__(config)
        self._db = None
        self._db_path = config.sqlite.get("path", "/var/acia/acia.db")
    
    async def initialize(self) -> None:
        """Initialize SQLite database."""
        import aiosqlite
        
        # Ensure directory exists
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        
        self._db = await aiosqlite.connect(self._db_path)
        
        # Create tables
        await self._db.execute("""
            CREATE TABLE IF NOT EXISTS system_state (
                id INTEGER PRIMARY KEY,
                state_json TEXT NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        await self._db.execute("""
            CREATE TABLE IF NOT EXISTS cycles (
                id TEXT PRIMARY KEY,
                started_at TIMESTAMP NOT NULL,
                completed_at TIMESTAMP,
                cycle_json TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        await self._db.execute("""
            CREATE INDEX IF NOT EXISTS idx_cycles_started
            ON cycles(started_at DESC)
        """)
        
        await self._db.commit()
        logger.info(f"SQLite state store initialized: {self._db_path}")
    
    async def close(self) -> None:
        """Close database connection."""
        if self._db:
            await self._db.close()
            self._db = None
    
    async def save_state(self, state: SystemState) -> None:
        """Save system state to database."""
        state_json = state.model_dump_json()
        
        await self._db.execute("""
            INSERT OR REPLACE INTO system_state (id, state_json, updated_at)
            VALUES (1, ?, CURRENT_TIMESTAMP)
        """, (state_json,))
        
        await self._db.commit()
    
    async def load_state(self) -> SystemState | None:
        """Load system state from database."""
        async with self._db.execute("""
            SELECT state_json FROM system_state WHERE id = 1
        """) as cursor:
            row = await cursor.fetchone()
            
            if row:
                return SystemState.model_validate_json(row[0])
            return None
    
    async def save_cycle(self, cycle: CycleResult) -> None:
        """Save cycle result to database."""
        cycle_json = cycle.model_dump_json()
        
        await self._db.execute("""
            INSERT OR REPLACE INTO cycles (id, started_at, completed_at, cycle_json)
            VALUES (?, ?, ?, ?)
        """, (
            cycle.id,
            cycle.started_at.isoformat(),
            cycle.completed_at.isoformat() if cycle.completed_at else None,
            cycle_json,
        ))
        
        await self._db.commit()
    
    async def get_cycles(
        self,
        limit: int = 100,
        since: datetime | None = None,
    ) -> list[CycleResult]:
        """Get cycle history."""
        if since:
            query = """
                SELECT cycle_json FROM cycles
                WHERE started_at >= ?
                ORDER BY started_at DESC
                LIMIT ?
            """
            params = (since.isoformat(), limit)
        else:
            query = """
                SELECT cycle_json FROM cycles
                ORDER BY started_at DESC
                LIMIT ?
            """
            params = (limit,)
        
        cycles = []
        async with self._db.execute(query, params) as cursor:
            async for row in cursor:
                cycle = CycleResult.model_validate_json(row[0])
                cycles.append(cycle)
        
        return cycles


class PostgresStateStore(StateStore):
    """PostgreSQL-based state storage."""
    
    def __init__(self, config: StorageConfig):
        super().__init__(config)
        self._pool = None
        self._config = config.postgres
    
    async def initialize(self) -> None:
        """Initialize PostgreSQL connection pool."""
        import asyncpg
        import os
        
        user = os.getenv(self._config.get("user_env_var", ""))
        password = os.getenv(self._config.get("password_env_var", ""))
        
        self._pool = await asyncpg.create_pool(
            host=self._config.get("host", "localhost"),
            port=self._config.get("port", 5432),
            database=self._config.get("database", "acia"),
            user=user,
            password=password,
        )
        
        # Create tables
        async with self._pool.acquire() as conn:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS system_state (
                    id INTEGER PRIMARY KEY DEFAULT 1,
                    state_json JSONB NOT NULL,
                    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                )
            """)
            
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS cycles (
                    id TEXT PRIMARY KEY,
                    started_at TIMESTAMP WITH TIME ZONE NOT NULL,
                    completed_at TIMESTAMP WITH TIME ZONE,
                    cycle_json JSONB NOT NULL,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                )
            """)
            
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_cycles_started
                ON cycles(started_at DESC)
            """)
        
        logger.info("PostgreSQL state store initialized")
    
    async def close(self) -> None:
        """Close connection pool."""
        if self._pool:
            await self._pool.close()
            self._pool = None
    
    async def save_state(self, state: SystemState) -> None:
        """Save system state."""
        state_dict = state.model_dump(mode="json")
        
        async with self._pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO system_state (id, state_json, updated_at)
                VALUES (1, $1, NOW())
                ON CONFLICT (id) DO UPDATE
                SET state_json = $1, updated_at = NOW()
            """, json.dumps(state_dict))
    
    async def load_state(self) -> SystemState | None:
        """Load system state."""
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow("""
                SELECT state_json FROM system_state WHERE id = 1
            """)
            
            if row:
                return SystemState.model_validate(row["state_json"])
            return None
    
    async def save_cycle(self, cycle: CycleResult) -> None:
        """Save cycle result."""
        cycle_dict = cycle.model_dump(mode="json")
        
        async with self._pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO cycles (id, started_at, completed_at, cycle_json)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (id) DO UPDATE
                SET completed_at = $3, cycle_json = $4
            """, cycle.id, cycle.started_at, cycle.completed_at, json.dumps(cycle_dict))
    
    async def get_cycles(
        self,
        limit: int = 100,
        since: datetime | None = None,
    ) -> list[CycleResult]:
        """Get cycle history."""
        async with self._pool.acquire() as conn:
            if since:
                rows = await conn.fetch("""
                    SELECT cycle_json FROM cycles
                    WHERE started_at >= $1
                    ORDER BY started_at DESC
                    LIMIT $2
                """, since, limit)
            else:
                rows = await conn.fetch("""
                    SELECT cycle_json FROM cycles
                    ORDER BY started_at DESC
                    LIMIT $1
                """, limit)
            
            return [CycleResult.model_validate(row["cycle_json"]) for row in rows]


def create_state_store(config: StorageConfig) -> StateStore:
    """Factory function to create the appropriate state store."""
    stores = {
        "sqlite": SQLiteStateStore,
        "postgres": PostgresStateStore,
    }
    
    store_class = stores.get(config.type)
    if store_class:
        return store_class(config)
    
    raise ValueError(f"Unknown storage type: {config.type}")