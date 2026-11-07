"""Device configuration templates (CLAUDE.md 7.4 / 7.5).

Templates live in the repository's templates/<vendor>/<name>.j2. Each one has a Pydantic model
for its variables, so every value is checked (type, range, allowed characters) *before* it
is put into a command. Rendering uses Jinja2's SandboxedEnvironment (a template can't reach
Python internals) with StrictUndefined (a missing variable is an error, never an empty
string that silently changes a command).

No variable may contain a newline or control character: one value can therefore never add
an extra command line.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Annotated

from pydantic import Field, StringConstraints, field_validator, model_validator

from app.models.common import StrictModel

DEFAULT_TEMPLATES_DIR = Path(__file__).resolve().parents[3] / "templates"

Hostname = Annotated[str, StringConstraints(pattern=r"^[A-Za-z][A-Za-z0-9-]{0,62}$")]
DomainName = Annotated[str, StringConstraints(
    max_length=100, pattern=r"^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")]
Word = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{1,32}$")]
VlanId = Annotated[int, Field(ge=1, le=4094)]
# Free text that ends up inside a command: printable characters only, no "^" (the banner
# delimiter), no quotes or braces.
SafeText = Annotated[str, StringConstraints(min_length=1, max_length=120,
                                            pattern=r"^[A-Za-z0-9 .,:;()/@_+-]+$")]
IosInterface = Annotated[str, StringConstraints(
    pattern=r"^(GigabitEthernet|FastEthernet|TenGigabitEthernet|Ethernet)\d+(/\d+){1,2}$")]
RouterOsName = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{1,32}$")]


class TemplateError(Exception):
    pass


def _ipv4(value: str) -> ipaddress.IPv4Address:
    try:
        return ipaddress.IPv4Address(value)
    except ValueError as exc:
        raise ValueError("must be an IPv4 address") from exc


def _ipv4_interface(value: str) -> ipaddress.IPv4Interface:
    try:
        iface = ipaddress.IPv4Interface(value)
    except ValueError as exc:
        raise ValueError("must look like 10.10.99.50/24") from exc
    if iface.network.prefixlen > 30 or iface.ip in (iface.network.network_address,
                                                     iface.network.broadcast_address):
        raise ValueError("must be a usable host address in a /8 to /30 network")
    return iface


class BaselineIOS(StrictModel):
    hostname: Hostname
    domain_name: DomainName
    mgmt_vlan: VlanId = 99
    mgmt_vlan_name: Word = "MGMT"
    mgmt_ip: str = Field(description="Management address with prefix, e.g. 10.10.99.50/24")
    default_gateway: str
    banner: SafeText = "Authorised access only. Activity is logged."
    shutdown_ports: list[IosInterface] = Field(default_factory=list, max_length=96)

    @field_validator("mgmt_ip")
    @classmethod
    def check_mgmt_ip(cls, value: str) -> str:
        return str(_ipv4_interface(value))

    @field_validator("default_gateway")
    @classmethod
    def check_gateway(cls, value: str) -> str:
        return str(_ipv4(value))

    @model_validator(mode="after")
    def gateway_in_subnet(self) -> BaselineIOS:
        iface = ipaddress.IPv4Interface(self.mgmt_ip)
        gateway = ipaddress.IPv4Address(self.default_gateway)
        if gateway not in iface.network or gateway == iface.ip:
            raise ValueError("default_gateway must be another address in the management subnet")
        return self

    def context(self) -> dict:
        iface = ipaddress.IPv4Interface(self.mgmt_ip)
        return self.model_dump() | {"mgmt_address": str(iface.ip),
                                    "mgmt_netmask": str(iface.network.netmask)}


class VlanIOS(StrictModel):
    vlan_id: Annotated[int, Field(ge=2, le=4094)]
    name: Word
    svi_ip: str | None = Field(None, description="Optional routed address, e.g. 10.10.40.1/24")

    @field_validator("svi_ip")
    @classmethod
    def check_svi(cls, value: str | None) -> str | None:
        return None if value in (None, "") else str(_ipv4_interface(value))

    def context(self) -> dict:
        iface = ipaddress.IPv4Interface(self.svi_ip) if self.svi_ip else None
        return self.model_dump() | {
            "svi_address": str(iface.ip) if iface else "",
            "svi_netmask": str(iface.network.netmask) if iface else "",
        }


class AccessPortIOS(StrictModel):
    interface: IosInterface
    vlan_id: VlanId
    description: SafeText
    port_security: bool = True
    max_macs: Annotated[int, Field(ge=1, le=10)] = 2

    def context(self) -> dict:
        return self.model_dump()


class BaselineRouterOS(StrictModel):
    identity: Hostname
    bridge: RouterOsName = "bridge"
    mgmt_vlan: VlanId = 99
    mgmt_ip: str = Field(description="Management address with prefix, e.g. 10.10.99.12/24")
    default_gateway: str

    @field_validator("mgmt_ip")
    @classmethod
    def check_mgmt_ip(cls, value: str) -> str:
        return str(_ipv4_interface(value))

    @field_validator("default_gateway")
    @classmethod
    def check_gateway(cls, value: str) -> str:
        return str(_ipv4(value))

    def context(self) -> dict:
        return self.model_dump()


@dataclass(frozen=True)
class Template:
    name: str
    vendor: str
    title: str
    description: str
    model: type[StrictModel]

    @property
    def file(self) -> str:
        return f"{self.vendor}/{self.name}.j2"

    @property
    def id(self) -> str:
        return f"{self.vendor}/{self.name}"


TEMPLATES: dict[str, Template] = {t.id: t for t in (
    Template("baseline", "cisco_ios", "Baseline for a new switch",
             "Hostname, management VLAN and address, SSH v2 only, password encryption, login "
             "banner, idle timeouts, archive (needed for automatic rollback), unused ports "
             "shut down.", BaselineIOS),
    Template("vlan", "cisco_ios", "Add a VLAN",
             "Creates a VLAN and, optionally, its routed interface.", VlanIOS),
    Template("access_port", "cisco_ios", "Secure access port",
             "Makes a port an access port in one VLAN with port security and PortFast.",
             AccessPortIOS),
    Template("baseline", "mikrotik_routeros", "Baseline for a new MikroTik",
             "Identity, management VLAN and address, default route; turns off Telnet, FTP and "
             "plain-HTTP services and enables strong SSH crypto.", BaselineRouterOS),
)}


@lru_cache(maxsize=4)
def _environment(templates_dir: str):
    # Imported lazily: only change requests need Jinja2.
    from jinja2 import FileSystemLoader, StrictUndefined
    from jinja2.sandbox import SandboxedEnvironment

    return SandboxedEnvironment(
        loader=FileSystemLoader(templates_dir),
        undefined=StrictUndefined,
        autoescape=False,  # noqa: S701 - output is device CLI text, not HTML; never rendered as HTML
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )


def render_text(source: str, context: dict, templates_dir: Path = DEFAULT_TEMPLATES_DIR) -> str:
    """Render template source text (used by tests); same sandbox and strict rules."""
    from jinja2 import TemplateError as JinjaError

    try:
        return _environment(str(templates_dir)).from_string(source).render(**context)
    except JinjaError as exc:
        raise TemplateError(f"Template could not be rendered: {exc}") from exc


def render(template_id: str, variables: dict,
           templates_dir: Path = DEFAULT_TEMPLATES_DIR) -> tuple[str, StrictModel]:
    """Validate the variables against the template's schema, then render it."""
    from jinja2 import TemplateError as JinjaError

    template = TEMPLATES.get(template_id)
    if template is None:
        raise TemplateError("Unknown template")
    model = template.model.model_validate(variables)  # raises pydantic.ValidationError
    try:
        text = _environment(str(templates_dir)).get_template(template.file).render(
            **model.context())
    except JinjaError as exc:
        raise TemplateError(f"Template could not be rendered: {exc}") from exc
    lines = [line.rstrip() for line in text.splitlines() if line.strip()]
    return "\n".join(lines) + "\n", model


def catalogue() -> list[dict]:
    return [{"id": t.id, "name": t.name, "vendor": t.vendor, "title": t.title,
             "description": t.description, "schema": t.model.model_json_schema()}
            for t in TEMPLATES.values()]
