import logging
from typing import Optional, Any

from app.core.config import settings

logger = logging.getLogger(__name__)


class Neo4jClient:
    def __init__(self):
        self._driver = None
        self.is_connected = False

    async def connect(self):
        try:
            from neo4j import AsyncGraphDatabase
            self._driver = AsyncGraphDatabase.driver(
                settings.NEO4J_URI,
                auth=(settings.NEO4J_USER, settings.NEO4J_PASSWORD),
            )
            # Verify connectivity
            await self._driver.verify_connectivity()
            self.is_connected = True
            logger.info("Neo4j connected")
        except Exception as e:
            logger.warning(f"Neo4j unavailable: {e}")
            self._driver = None
            self.is_connected = False

    async def disconnect(self):
        if self._driver:
            await self._driver.close()
        self.is_connected = False

    async def run(self, query: str, parameters: dict = None) -> list[dict]:
        """Execute a Cypher query and return list of record dicts."""
        if not self._driver:
            return []
        try:
            async with self._driver.session() as session:
                result = await session.run(query, parameters or {})
                records = await result.data()
                return records
        except Exception as e:
            logger.warning(f"Neo4j query error: {e}")
            return []

    async def run_write(self, query: str, parameters: dict = None) -> list[dict]:
        """Execute a write Cypher query."""
        if not self._driver:
            return []
        try:
            async with self._driver.session() as session:
                result = await session.execute_write(
                    lambda tx: tx.run(query, parameters or {})
                )
                return []
        except Exception as e:
            logger.warning(f"Neo4j write error: {e}")
            return []

    async def execute_write_query(self, query: str, parameters: dict = None):
        """Write query via explicit write transaction."""
        if not self._driver:
            return
        try:
            async with self._driver.session() as session:
                await session.execute_write(self._run_tx, query, parameters or {})
        except Exception as e:
            logger.warning(f"Neo4j execute_write error: {e}")

    @staticmethod
    async def _run_tx(tx, query: str, parameters: dict):
        await tx.run(query, parameters)


neo4j_client = Neo4jClient()
