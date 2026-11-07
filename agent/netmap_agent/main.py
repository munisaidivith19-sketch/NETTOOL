"""Agent entry point. The scheduler (discovery, polling, uploads) is built in Phase 2.

Run with:  python -m netmap_agent.main   (from the agent folder)
"""

import logging

from netmap_agent import __version__
from netmap_agent.config import get_settings

logger = logging.getLogger("netmap_agent")


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    settings = get_settings()
    logger.info(
        "NetMap agent %s: %d scan range(s), %d SNMP target(s). Scheduler arrives in Phase 2.",
        __version__,
        len(settings.scan_ranges),
        len(settings.snmp_targets),
    )


if __name__ == "__main__":
    main()
