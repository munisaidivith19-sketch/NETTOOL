"""SNMP polling with the pysnmp 7 asyncio API.

Numeric OIDs are used throughout (lookupMib=False): no MIB files to compile or ship, and the
parsing of every table index lives in oids.py as tested pure functions.
"""

import asyncio
import ipaddress
import logging
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone

from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    Udp6TransportTarget,
    UdpTransportTarget,
    UsmUserData,
    bulk_walk_cmd,
    get_cmd,
    usmAesCfb128Protocol,
    usmAesCfb256Protocol,
    usmHMAC192SHA256AuthProtocol,
    usmHMAC384SHA512AuthProtocol,
    usmHMACSHAAuthProtocol,
)

from netmap_agent.config import AgentSettings
from netmap_agent.discovery import oids
from netmap_agent.discovery.net import normalize_mac
from netmap_agent.discovery.vendor import detect_vendor

logger = logging.getLogger("netmap_agent.snmp")

MAX_CONCURRENT_DEVICES = 16
MAX_ROWS_PER_TABLE = 20000
TEXT_LIMIT = 1024

AUTH_PROTOCOLS = {
    "SHA": usmHMACSHAAuthProtocol,
    "SHA256": usmHMAC192SHA256AuthProtocol,
    "SHA512": usmHMAC384SHA512AuthProtocol,
}
PRIV_PROTOCOLS = {"AES": usmAesCfb128Protocol, "AES256": usmAesCfb256Protocol}


@dataclass
class Interface:
    if_index: int
    name: str | None = None
    descr: str | None = None
    alias: str | None = None
    if_type: int | None = None
    mtu: int | None = None
    speed_mbps: int | None = None
    mac: str | None = None
    admin_status: str | None = None
    oper_status: str | None = None


@dataclass
class Address:
    ip: str
    version: int
    if_index: int | None
    prefixlen: int | None


@dataclass
class Neighbor:
    ip: str
    version: int
    mac: str
    if_index: int
    kind: str


@dataclass
class Link:
    """A directly connected neighbour seen with LLDP or CDP on one local port."""

    protocol: str  # "lldp" | "cdp"
    if_index: int | None  # local port; None when an LLDP port number can't be mapped
    local_port: str | None = None
    remote_name: str | None = None
    remote_port: str | None = None
    remote_port_descr: str | None = None
    remote_chassis_id: str | None = None
    remote_mgmt_ip: str | None = None
    remote_platform: str | None = None


@dataclass
class MacEntry:
    mac: str
    if_index: int
    vlan: int | None  # None when the switch only has the VLAN-unaware BRIDGE-MIB table


@dataclass
class Counter:
    if_index: int
    in_octets: int | None = None
    out_octets: int | None = None
    in_errors: int | None = None
    out_errors: int | None = None
    bits: int = 64  # 32 when only the old ifInOctets/ifOutOctets exist (they wrap after 4 GB)


@dataclass
class DevicePoll:
    target: str
    port: int
    ok: bool
    error: str | None = None
    sys_name: str | None = None
    sys_descr: str | None = None
    sys_location: str | None = None
    sys_object_id: str | None = None
    vendor: str = "unknown"
    uptime_seconds: int | None = None
    interfaces: list[Interface] = field(default_factory=list)
    addresses: list[Address] = field(default_factory=list)
    neighbors: list[Neighbor] = field(default_factory=list)
    links: list[Link] = field(default_factory=list)
    mac_table: list[MacEntry] = field(default_factory=list)
    counters: list[Counter] = field(default_factory=list)
    counters_at: datetime | None = None  # when the counters were read; rates need exact times


class SnmpError(Exception):
    pass


def use_selector_event_loop() -> None:
    """On Windows, run asyncio on the selector loop instead of the default proactor loop.

    pysnmp sends every request through one UDP socket. When a target answers with ICMP "port
    unreachable" (SNMP disabled, or the device just went away), Windows reports WinError 10054
    on that socket, and Python 3.10's proactor loop then stops reading it for good, so every
    other device in the cycle times out too. The selector loop reports the error and keeps
    reading. Measured: tests/test_simulation.py::test_dead_target_does_not_break_live_one.
    """
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


def _text(value) -> str | None:
    """Render an SNMP value as safe, bounded text. Device strings are untrusted input."""
    if value is None:
        return None
    raw = value.asOctets() if hasattr(value, "asOctets") else str(value).encode()
    text = raw.decode("utf-8", errors="replace")
    cleaned = "".join(ch if ch.isprintable() or ch in "\n\t" else " " for ch in text)
    return cleaned.strip()[:TEXT_LIMIT] or None


def _int(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


class SnmpClient:
    def __init__(self, settings: AgentSettings) -> None:
        self.settings = settings
        self.engine = SnmpEngine()
        if settings.snmp_version == "v3":
            self.auth = UsmUserData(
                settings.snmp_v3_user,
                settings.snmp_v3_auth_key.get_secret_value(),
                settings.snmp_v3_priv_key.get_secret_value(),
                authProtocol=AUTH_PROTOCOLS[settings.snmp_v3_auth_protocol],
                privProtocol=PRIV_PROTOCOLS[settings.snmp_v3_priv_protocol],
            )
        else:
            # mpModel=1 selects SNMPv2c. Lab only: warned about at startup (warn_if_weak).
            community = settings.snmp_v2c_community.get_secret_value()
            self.auth = CommunityData(community, mpModel=1)  # noqa: S508
        self.context = ContextData(contextName=settings.snmp_v3_context)

    def close(self) -> None:
        self.engine.close_dispatcher()

    async def _transport(self, host: str, port: int):
        cls = Udp6TransportTarget if ipaddress.ip_address(host).version == 6 else UdpTransportTarget
        return await cls.create(
            (host, port), timeout=self.settings.snmp_timeout_seconds,
            retries=self.settings.snmp_retries,
        )

    async def get(self, transport, oid_list: tuple[str, ...]) -> dict[str, object]:
        error_indication, error_status, _, var_binds = await get_cmd(
            self.engine, self.auth, transport, self.context,
            *(ObjectType(ObjectIdentity(oid)) for oid in oid_list),
            lookupMib=False,
        )
        if error_indication:
            raise SnmpError(str(error_indication))
        if error_status:
            raise SnmpError(error_status.prettyPrint())
        return {str(name): value for name, value in var_binds}

    async def walk(self, transport, column: str) -> list[tuple[str, object]]:
        rows = []
        async for error_indication, error_status, _, var_binds in bulk_walk_cmd(
            self.engine, self.auth, transport, self.context, 0, 25,
            ObjectType(ObjectIdentity(column)),
            lookupMib=False, lexicographicMode=False,
        ):
            if error_indication:
                raise SnmpError(str(error_indication))
            if error_status:
                break  # e.g. noSuchName on old agents: treat the column as empty
            for name, value in var_binds:
                if value.__class__.__name__ in ("NoSuchObject", "NoSuchInstance", "EndOfMibView"):
                    continue
                rows.append((str(name), value))
                if len(rows) >= MAX_ROWS_PER_TABLE:
                    return rows
        return rows

    async def poll(self, host: str, port: int) -> DevicePoll:
        result = DevicePoll(target=host, port=port, ok=False)
        try:
            transport = await self._transport(host, port)
            system = await self.get(transport, oids.SYSTEM_SCALARS)
            result.sys_descr = _text(system.get(oids.SYS_DESCR))
            result.sys_name = _text(system.get(oids.SYS_NAME))
            result.sys_location = _text(system.get(oids.SYS_LOCATION))
            object_id = system.get(oids.SYS_OBJECT_ID)
            result.sys_object_id = str(object_id) if object_id is not None else None
            ticks = _int(system.get(oids.SYS_UPTIME))
            result.uptime_seconds = ticks // 100 if ticks is not None else None
            result.vendor = detect_vendor(result.sys_object_id)
            result.interfaces = await self._interfaces(transport)
            result.addresses = await self._addresses(transport)
            result.neighbors = await self._neighbors(transport)
            result.links = await self._links(transport, result.interfaces)
            result.mac_table = await self._mac_table(transport)
            result.counters_at = datetime.now(timezone.utc)
            result.counters = await self._counters(transport)
            result.ok = True
        except SnmpError as exc:
            result.error = str(exc)[:200]
            logger.warning("SNMP poll of %s:%d failed: %s", host, port, result.error)
        except Exception as exc:  # one broken device must never stop the whole cycle
            result.error = type(exc).__name__
            logger.exception("Unexpected error polling %s:%d", host, port)
        return result

    async def _column(self, transport, column: str) -> dict[tuple[int, ...], object]:
        values = {}
        for oid, value in await self.walk(transport, column):
            try:
                values[oids.suffix(oid, column)] = value
            except (oids.OidIndexError, ValueError):
                continue
        return values

    async def _interfaces(self, transport) -> list[Interface]:
        columns = {}
        for column in (oids.IF_DESCR, oids.IF_TYPE, oids.IF_MTU, oids.IF_SPEED,
                       oids.IF_PHYS_ADDRESS, oids.IF_ADMIN_STATUS, oids.IF_OPER_STATUS,
                       oids.IF_NAME, oids.IF_HIGH_SPEED, oids.IF_ALIAS):
            columns[column] = await self._column(transport, column)
        indexes = sorted({key[0] for col in columns.values() for key in col if len(key) == 1})
        interfaces = []
        for if_index in indexes:
            key = (if_index,)
            high_speed = _int(columns[oids.IF_HIGH_SPEED].get(key))
            speed_bps = _int(columns[oids.IF_SPEED].get(key))
            phys = columns[oids.IF_PHYS_ADDRESS].get(key)
            interfaces.append(Interface(
                if_index=if_index,
                name=_text(columns[oids.IF_NAME].get(key)),
                descr=_text(columns[oids.IF_DESCR].get(key)),
                alias=_text(columns[oids.IF_ALIAS].get(key)),
                if_type=_int(columns[oids.IF_TYPE].get(key)),
                mtu=_int(columns[oids.IF_MTU].get(key)),
                speed_mbps=high_speed if high_speed else (
                    speed_bps // 1_000_000 if speed_bps else None),
                mac=normalize_mac(phys.asOctets()) if phys is not None else None,
                admin_status=oids.IF_STATUS.get(_int(columns[oids.IF_ADMIN_STATUS].get(key))),
                oper_status=oids.IF_STATUS.get(_int(columns[oids.IF_OPER_STATUS].get(key))),
            ))
        return interfaces

    async def _addresses(self, transport) -> list[Address]:
        addresses: dict[str, Address] = {}
        if_indexes = await self._column(transport, oids.IP_ADDRESS_IFINDEX)
        if if_indexes:
            types = await self._column(transport, oids.IP_ADDRESS_TYPE)
            prefixes = await self._column(transport, oids.IP_ADDRESS_PREFIX)
            for index, if_index in if_indexes.items():
                try:
                    inet = oids.parse_inet_index(index)
                except (oids.OidIndexError, ValueError):
                    continue
                if _int(types.get(index)) not in (None, 1):  # keep unicast only
                    continue
                pointer = prefixes.get(index)
                addresses[inet.address] = Address(
                    inet.address, inet.version, _int(if_index),
                    oids.parse_prefix_pointer(str(pointer)) if pointer is not None else None,
                )
        else:
            # Old devices only have the IPv4 ipAddrTable.
            masks = await self._column(transport, oids.IP_ADENT_NETMASK)
            for index, if_index in (await self._column(transport, oids.IP_ADENT_IFINDEX)).items():
                try:
                    ip = oids.parse_ipv4_index(index)
                except (oids.OidIndexError, ValueError):
                    continue
                mask = masks.get(index)
                addresses[ip] = Address(ip, 4, _int(if_index),
                                        oids.netmask_to_prefix(str(mask)) if mask else None)
        return list(addresses.values())

    async def _neighbors(self, transport) -> list[Neighbor]:
        neighbors: dict[tuple[str, int], Neighbor] = {}
        phys = await self.walk(transport, oids.IP_NET_TO_PHYS_ADDRESS)
        if phys:
            types = await self._column(transport, oids.IP_NET_TO_PHYS_TYPE)
            for oid, value in phys:
                try:
                    if_index, inet = oids.parse_net_to_physical_index(
                        oid, oids.IP_NET_TO_PHYS_ADDRESS)
                except (oids.OidIndexError, ValueError):
                    continue
                kind = oids.NEIGHBOR_TYPE.get(
                    _int(types.get(oids.suffix(oid, oids.IP_NET_TO_PHYS_ADDRESS))), "other")
                mac = normalize_mac(value.asOctets())
                if mac and kind != "invalid":
                    neighbors[(inet.address, if_index)] = Neighbor(
                        inet.address, inet.version, mac, if_index, kind)
        else:
            types = await self._column(transport, oids.IP_NET_TO_MEDIA_TYPE)
            for oid, value in await self.walk(transport, oids.IP_NET_TO_MEDIA_PHYS_ADDRESS):
                try:
                    if_index, ip = oids.parse_net_to_media_index(
                        oid, oids.IP_NET_TO_MEDIA_PHYS_ADDRESS)
                except (oids.OidIndexError, ValueError):
                    continue
                kind = oids.NEIGHBOR_TYPE.get(
                    _int(types.get(oids.suffix(oid, oids.IP_NET_TO_MEDIA_PHYS_ADDRESS))), "other")
                mac = normalize_mac(value.asOctets())
                if mac and kind != "invalid":
                    neighbors[(ip, if_index)] = Neighbor(ip, 4, mac, if_index, kind)
        return list(neighbors.values())

    async def _links(self, transport, interfaces: list[Interface]) -> list[Link]:
        links = await self._lldp(transport, interfaces) + await self._cdp(transport)
        names = {i.if_index: i.name or i.descr for i in interfaces}
        for link in links:
            if link.local_port is None and link.if_index is not None:
                link.local_port = names.get(link.if_index)
        return links

    async def _lldp(self, transport, interfaces: list[Interface]) -> list[Link]:
        names = await self._column(transport, oids.LLDP_REM_SYS_NAME)
        chassis = await self._column(transport, oids.LLDP_REM_CHASSIS_ID)
        if not names and not chassis:
            return []  # LLDP not enabled (or not supported): skip the other columns
        chassis_types = await self._column(transport, oids.LLDP_REM_CHASSIS_SUBTYPE)
        port_ids = await self._column(transport, oids.LLDP_REM_PORT_ID)
        port_types = await self._column(transport, oids.LLDP_REM_PORT_SUBTYPE)
        port_descrs = await self._column(transport, oids.LLDP_REM_PORT_DESC)
        local_ports = await self._lldp_local_ports(transport, interfaces)

        mgmt_ips: dict[tuple[int, int], str] = {}
        for index in await self._column(transport, oids.LLDP_REM_MAN_ADDR_IF_SUBTYPE):
            try:
                port_num, rem_index, address = oids.parse_lldp_man_addr_index(index)
            except (oids.OidIndexError, ValueError):
                continue
            # Prefer an IPv4 address when a neighbour announces both.
            known = mgmt_ips.get((port_num, rem_index))
            if known is None or ":" in known:
                mgmt_ips[(port_num, rem_index)] = address

        links = []
        for index in sorted(set(names) | set(chassis)):
            try:
                port_num, rem_index = oids.parse_lldp_rem_index(index)
            except oids.OidIndexError:
                continue
            raw_chassis = chassis.get(index)
            raw_port = port_ids.get(index)
            if_index, local_name = local_ports.get(port_num, (None, None))
            links.append(Link(
                protocol="lldp",
                if_index=if_index,
                local_port=local_name,
                remote_name=_text(names.get(index)),
                remote_port=oids.lldp_port_id(_int(port_types.get(index)), raw_port.asOctets())
                if raw_port is not None else None,
                remote_port_descr=_text(port_descrs.get(index)),
                remote_chassis_id=oids.lldp_chassis_id(
                    _int(chassis_types.get(index)), raw_chassis.asOctets())
                if raw_chassis is not None else None,
                remote_mgmt_ip=mgmt_ips.get((port_num, rem_index)),
            ))
        return links

    async def _lldp_local_ports(self, transport, interfaces: list[Interface]
                                ) -> dict[int, tuple[int | None, str | None]]:
        """LLDP numbers local ports its own way. Map each lldpLocPortNum to an ifIndex.

        lldpLocPortId usually holds the interface name and lldpLocPortDesc its description, so
        match those against ifName / ifDescr. If nothing matches, many devices simply use the
        ifIndex as the port number, so accept that when such an interface exists.
        """
        by_name: dict[str, Interface] = {}
        for iface in interfaces:
            for text in (iface.name, iface.descr):
                if text:
                    by_name.setdefault(text.lower(), iface)
        by_index = {i.if_index: i for i in interfaces}
        port_ids = await self._column(transport, oids.LLDP_LOC_PORT_ID)
        port_descrs = await self._column(transport, oids.LLDP_LOC_PORT_DESC)
        mapping: dict[int, tuple[int | None, str | None]] = {}
        for key in set(port_ids) | set(port_descrs):
            if len(key) != 1:
                continue
            texts = [_text(port_ids.get(key)), _text(port_descrs.get(key))]
            match = next((by_name[t.lower()] for t in texts if t and t.lower() in by_name),
                         None) or by_index.get(key[0])
            if match:
                mapping[key[0]] = (match.if_index, match.name or match.descr)
            else:
                mapping[key[0]] = (None, texts[0] or texts[1])
        for if_index, iface in by_index.items():  # devices without a lldpLocPortTable
            mapping.setdefault(if_index, (if_index, iface.name or iface.descr))
        return mapping

    async def _cdp(self, transport) -> list[Link]:
        device_ids = await self._column(transport, oids.CDP_CACHE_DEVICE_ID)
        if not device_ids:
            return []
        ports = await self._column(transport, oids.CDP_CACHE_DEVICE_PORT)
        platforms = await self._column(transport, oids.CDP_CACHE_PLATFORM)
        addresses = await self._column(transport, oids.CDP_CACHE_ADDRESS)
        address_types = await self._column(transport, oids.CDP_CACHE_ADDRESS_TYPE)
        links = []
        for index in sorted(device_ids):
            try:
                if_index, _ = oids.parse_cdp_index(index)
            except oids.OidIndexError:
                continue
            raw_address = addresses.get(index)
            links.append(Link(
                protocol="cdp",
                if_index=if_index if if_index >= 1 else None,
                remote_name=_text(device_ids.get(index)),
                remote_port=_text(ports.get(index)),
                remote_platform=_text(platforms.get(index)),
                remote_mgmt_ip=oids.cdp_address(_int(address_types.get(index)),
                                                raw_address.asOctets())
                if raw_address is not None else None,
            ))
        return links

    async def _mac_table(self, transport) -> list[MacEntry]:
        """The switch forwarding table: which MAC was learned on which port (and VLAN)."""
        base_ports = await self._column(transport, oids.DOT1D_BASE_PORT_IFINDEX)
        port_if_index = {key[0]: _int(value) for key, value in base_ports.items() if len(key) == 1}
        entries: dict[tuple[str, int, int | None], MacEntry] = {}

        def add(mac: str, bridge_port, status, vlan: int | None) -> None:
            if oids.FDB_STATUS.get(_int(status), "learned") in ("self", "invalid", "mgmt"):
                return  # the switch's own MACs and dead rows say nothing about endpoints
            port = _int(bridge_port)
            if not port:
                return  # port 0 = learned but not on a known port
            if_index = port_if_index.get(port) or port  # no dot1dBasePortTable: assume equal
            entries[(mac, if_index, vlan)] = MacEntry(mac, if_index, vlan)

        q_ports = await self._column(transport, oids.DOT1Q_TP_FDB_PORT)
        if q_ports:
            q_status = await self._column(transport, oids.DOT1Q_TP_FDB_STATUS)
            for index, port in q_ports.items():
                try:
                    vlan, mac = oids.parse_qbridge_fdb_index(index)
                except oids.OidIndexError:
                    continue
                add(mac, port, q_status.get(index), vlan or None)
        else:
            status = await self._column(transport, oids.DOT1D_TP_FDB_STATUS)
            for index, port in (await self._column(transport, oids.DOT1D_TP_FDB_PORT)).items():
                try:
                    mac = oids.parse_mac_index(index)
                except oids.OidIndexError:
                    continue
                add(mac, port, status.get(index), None)
        return list(entries.values())

    async def _counters(self, transport) -> list[Counter]:
        bits = 64
        in_octets = await self._column(transport, oids.IF_HC_IN_OCTETS)
        if in_octets:
            out_octets = await self._column(transport, oids.IF_HC_OUT_OCTETS)
        else:
            bits = 32
            in_octets = await self._column(transport, oids.IF_IN_OCTETS)
            out_octets = await self._column(transport, oids.IF_OUT_OCTETS)
        in_errors = await self._column(transport, oids.IF_IN_ERRORS)
        out_errors = await self._column(transport, oids.IF_OUT_ERRORS)
        indexes = {key[0] for col in (in_octets, out_octets, in_errors, out_errors)
                   for key in col if len(key) == 1}
        return [Counter(
            if_index=i,
            in_octets=_int(in_octets.get((i,))),
            out_octets=_int(out_octets.get((i,))),
            in_errors=_int(in_errors.get((i,))),
            out_errors=_int(out_errors.get((i,))),
            bits=bits,
        ) for i in sorted(indexes) if i >= 1]


async def poll_all(settings: AgentSettings, targets: list[tuple[str, int]]) -> list[DevicePoll]:
    client = SnmpClient(settings)
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_DEVICES)

    async def limited(host: str, port: int) -> DevicePoll:
        async with semaphore:
            return await client.poll(host, port)

    try:
        return list(await asyncio.gather(*(limited(h, p) for h, p in targets)))
    finally:
        client.close()
