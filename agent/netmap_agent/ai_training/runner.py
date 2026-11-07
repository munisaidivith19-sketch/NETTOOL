"""One AI run: fetch history from the backend, forecast, look for anomalies, classify, upload.

Runs on the agent (Render's free tier has no memory or scheduler for this). Each of the
three parts is independent: if one fails, the others still upload.
"""

from __future__ import annotations

import logging
from collections.abc import Callable

from netmap_agent.ai_training import anomaly, forecast
from netmap_agent.ai_training.classify import classify
from netmap_agent.ai_training.oui import OuiTable
from netmap_agent.ai_training.probe import probe

logger = logging.getLogger(__name__)

MAX_SUBNET_USABLE = 1_000_000  # bigger (IPv6 /64) subnets never run out: no forecast


class AIManager:
    def __init__(self, settings, uploader, *, oui: OuiTable | None = None,
                 probe_fn: Callable = probe) -> None:
        self.settings = settings
        self.uploader = uploader
        self.oui = oui
        self.probe_fn = probe_fn

    def run(self) -> dict:
        data = self.uploader.ai_training_data()
        summary = {}
        for name, step in (("predictions", self._predictions), ("anomalies", self._anomalies),
                           ("classifications", self._classifications)):
            try:
                summary[name] = step(data)
            except Exception:  # noqa: BLE001 - one broken part must not stop the others
                logger.exception("AI step %s failed", name)
                summary[name] = "failed"
        logger.info("AI run: %s", summary)
        return summary

    def _predictions(self, data: dict) -> dict:
        predictions = []
        for subnet in data.get("subnets", []):
            if not 0 < int(subnet["usable"]) <= MAX_SUBNET_USABLE:
                continue
            result = forecast.subnet_exhaustion(subnet.get("history", []), int(subnet["usable"]))
            predictions.append({"kind": "subnet_exhaustion", "subnet_id": subnet["id"], **result})
        for iface in data.get("interfaces", []):
            if not iface.get("uplink"):
                continue
            result = forecast.uplink_bandwidth(iface.get("points", []), iface.get("speed_mbps"))
            predictions.append({"kind": "uplink_bandwidth", "device_id": iface["device_id"],
                                "if_index": iface["if_index"], **result})
        if predictions:
            self.uploader.send_predictions({"predictions": predictions})
        return {"sent": len(predictions),
                "forecast": sum(1 for p in predictions if p["status"] != "insufficient_data")}

    def _anomalies(self, data: dict) -> dict:
        checked, found = [], []
        for iface in data.get("interfaces", []):
            result = anomaly.detect(iface.get("points", []), iface.get("label") or "interface")
            if not result["checked"]:
                continue
            target = {"device_id": iface["device_id"], "if_index": iface["if_index"]}
            checked.append(target)
            if result["anomaly"]:
                found.append(target | result["anomaly"])
        if checked:
            self.uploader.send_anomalies({"checked": checked, "anomalies": found})
        return {"checked": len(checked), "anomalies": len(found)}

    def _classifications(self, data: dict) -> dict:
        endpoints = [e for e in data.get("endpoints", []) if not e.get("manual")]
        oui = self.oui or OuiTable.load()
        open_ports: dict[str, list[int]] = {}
        if self.settings.classify_port_probe:
            ips = [ip for e in endpoints if not e.get("managed") for ip in e.get("ips", [])]
            open_ports = self.probe_fn(ips, self.settings.scan_ranges,
                                       self.settings.classify_probe_timeout_ms)
        items = []
        for endpoint in endpoints:
            ports = sorted({p for ip in endpoint.get("ips", []) for p in open_ports.get(ip, [])})
            result = classify(endpoint, oui, ports if self.settings.classify_port_probe else None)
            items.append({"mac": endpoint["mac"], **result.as_dict()})
        if items:
            self.uploader.send_classifications({"items": items})
        counts: dict[str, int] = {}
        for item in items:
            counts[item["type"]] = counts.get(item["type"], 0) + 1
        return counts
