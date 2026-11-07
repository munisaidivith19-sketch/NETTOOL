"""Agent entry point.

Run from the agent folder:
  python -m netmap_agent.main --once     one discovery cycle, then exit
  python -m netmap_agent.main            repeat every POLL_INTERVAL_SECONDS
"""

import argparse
import asyncio
import logging

from apscheduler.schedulers.asyncio import AsyncIOScheduler

from netmap_agent import __version__
from netmap_agent.config import AgentSettings, get_settings
from netmap_agent.discovery import ping, snmp
from netmap_agent.discovery.net import hosts_of, parse_scan_range, parse_target
from netmap_agent.report import build_report
from netmap_agent.uploader import Uploader, UploadError

logger = logging.getLogger("netmap_agent")


def plan_targets(
    settings: AgentSettings, known: list[dict]
) -> tuple[list[str], list[tuple[str, int]]]:
    """Work out what to ping and what to poll this cycle."""
    snmp_targets = dict.fromkeys(settings.targets)
    for device in known:
        try:
            target = f"[{device['mgmt_ip']}]:{device.get('snmp_port', 161)}"
            snmp_targets[parse_target(target)] = None
        except (KeyError, ValueError):
            logger.warning("Ignoring malformed known-device entry from the backend")
    ping_targets = {ip for ip, _ in snmp_targets}
    for item in settings.scan_ranges:
        ping_targets.update(hosts_of(parse_scan_range(item)))
    return sorted(ping_targets), list(snmp_targets)


async def run_cycle(settings: AgentSettings, uploader: Uploader) -> dict:
    known = await asyncio.to_thread(uploader.known_devices)
    ping_targets, snmp_targets = plan_targets(settings, known)
    logger.info("Cycle: %d addresses to ping, %d SNMP targets",
                len(ping_targets), len(snmp_targets))
    ping_results = await asyncio.to_thread(ping.sweep, ping_targets, settings.ping_timeout_ms)
    polls = await snmp.poll_all(settings, snmp_targets)
    report = build_report(ping_results, polls, settings.snmp_version)
    result = await asyncio.to_thread(uploader.send_report, report)
    logger.info("Report accepted: %s", result.get("summary", result))
    return result


async def run_forever(settings: AgentSettings, uploader: Uploader) -> None:
    async def safe_cycle() -> None:
        try:
            await run_cycle(settings, uploader)
        except UploadError as exc:
            logger.error("Upload failed: %s", exc)
        except Exception:
            logger.exception("Discovery cycle failed")

    scheduler = AsyncIOScheduler()
    # max_instances=1: a slow cycle is never overlapped by the next one.
    scheduler.add_job(safe_cycle, "interval", seconds=settings.poll_interval_seconds,
                      max_instances=1, coalesce=True)
    scheduler.start()
    await safe_cycle()
    try:
        await asyncio.Event().wait()
    finally:
        scheduler.shutdown(wait=False)


def main() -> None:
    parser = argparse.ArgumentParser(description="NetMap discovery agent")
    parser.add_argument("--once", action="store_true", help="run one cycle and exit")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    settings = get_settings()
    settings.warn_if_weak()
    snmp.use_selector_event_loop()
    logger.info("NetMap agent %s starting (backend %s)", __version__, settings.api_url)
    uploader = Uploader(settings)
    try:
        if args.once:
            asyncio.run(run_cycle(settings, uploader))
        else:
            asyncio.run(run_forever(settings, uploader))
    finally:
        uploader.close()


if __name__ == "__main__":
    main()
