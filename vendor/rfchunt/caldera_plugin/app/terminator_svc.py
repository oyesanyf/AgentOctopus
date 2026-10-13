"""
Terminator Caldera Service:
Handles webhook ingestion of live findings from HTTP Terminator.
"""

import logging


class TerminatorService:
    def __init__(self, services):
        self.services = services
        self.log = logging.getLogger("terminator_service")

    async def ingest_finding(self, finding_data):
        self.log.info("Received live protocol finding from HTTP Terminator: %s", finding_data.get("vuln_id"))
        # Store dynamically into Caldera knowledge store
        return {"status": "INGESTED", "id": finding_data.get("vuln_id")}
