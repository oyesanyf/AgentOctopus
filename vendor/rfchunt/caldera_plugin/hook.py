"""
Caldera Plugin Hook: HTTP Terminator Autonomous Protocol Research
Registers non-MITRE protocol tactics, abilities, and research dashboards.
"""

from app.utility.base_world import BaseWorld

name = "Terminator"
description = "HTTP Terminator autonomous protocol flaw replay and non-MITRE adversary emulation."
address = "/plugin/terminator/gui"


async def enable(services):
    """Initializes the Terminator plugin inside Caldera."""
    app = services.get("auth_svc").app
    terminator_svc = services.get("terminator_svc")
    # Register custom tactics
    data_svc = services.get("data_svc")
    custom_tactics = ["protocol-framing", "queue-poisoning", "metamorphic-divergence", "parser-differential"]
    for t in custom_tactics:
        await data_svc.store(BaseWorld.create_tactic(name=t))
