# Known limitations and accepted risks

## Python 3.10 (project decision)
The project runs on **Python 3.10**, the version installed on the development machine.

- Python 3.10 reached **end of life in October 2026**, so CPython itself gets no more security
  fixes. The dev machine runs **3.10.0**, the very first 3.10 release. 3.10.11 is the last
  release with a Windows installer and fixes many bugs.
- Several libraries have dropped 3.10, so these are pinned to the last versions that support it:
  `pymongo 4.18.3`, `pydantic-settings 2.15.0`, and later `scikit-learn 1.7.2`.
- `pytest 9.2.0` crashes on Python 3.10.0 (a `dataclass(frozen=True, slots=True)` bug in that
  early release), so it is pinned to `9.1.1`.
- **Upgrade path:** moving to Python 3.12+ means changing `py -3.10` to `py -3.12` in the README,
  then unpinning the packages above and the vulnerable ones below.

## Open dependency findings (pip-audit, Phase 0)
These have fixes only in versions that **require Python 3.11+**, so they cannot be fixed on 3.10.

| Package | Where | Finding | Risk here |
|---|---|---|---|
| dnspython 2.8.0 | backend runtime (pulled in by pymongo) | CVE-2026-114605: a crafted DNS message can make name decompression use excessive CPU | **Low.** pymongo only uses dnspython to resolve the `mongodb+srv://` SRV/TXT records of our own Atlas cluster through the system resolver. Exploiting it needs a malicious DNS resolver or an on-path attacker answering those lookups, and the impact is CPU use (DoS), not code execution. Not used at all with a plain `mongodb://` URI. |
| filelock 4.1.0 | **dev only** (pulled in by pip-audit's cache) | 17 CVEs (CVE-2026-1129xx) in lock-file handling: symlink races, ACL/mode handling, stale-lock eviction | **Very low.** Not installed on Render. Only reachable by a local attacker on the developer's own machine, during `pip-audit` runs. |

The agent's runtime dependencies had no known vulnerabilities at Phase 0 or Phase 2.
`snmpsim` and `pysmi` (the simulator) are dev-only.

## Phase 1 (authentication)
- **Client IP behind a proxy.** Rate limiting and the audit log use the connecting address. On
  Render that is Render's proxy, not the real client, until Phase 9 adds trusted-proxy handling
  (`uvicorn --proxy-headers --forwarded-allow-ips`). Until then the per-IP limit would apply to
  all users together in production.
- **Account lockout can be abused** to lock a known username for 15 minutes (a small denial of
  service). This is the usual trade-off of lockouts; the per-IP limit slows it down, and MFA in
  Phase 8 reduces the value of guessing anyway.
- **`AGENT_KEY_ENCRYPTION_KEY` is a single point of failure.** If it leaks together with the
  database, agent keys can be decrypted. If it is lost, every agent needs a new key. Keep it only
  in the Render environment and your local `.env`.
- **The `Secure` cookie on http://localhost** works in Chrome, Edge and Firefox, which treat
  localhost as secure, but not in Safari. Use one of the first three for local development.
- **No TOTP MFA yet** (Phase 8).

## Phase 2 (discovery)
- **SNMP credentials sit in the agent's `.env` in plain text** until Phase 6 adds the
  encrypted credential store. Protect that file like a password file. They never reach the
  backend.
- **Devices are identified by management IP.** A device polled through two different
  addresses becomes two records. Merging by serial number or chassis MAC is not done yet.
- **No switch-port mapping yet.** We know IP to MAC (from ARP) but not yet MAC to switch port
  (BRIDGE-MIB forwarding table), and there are no LLDP/CDP neighbours. Both come in Phase 5;
  until then `GET /api/ips/{ip}` returns `"switch_port": null`.
- **Ping sweep is capped** at 1,024 addresses per range and 4,096 in total, and uses one OS
  `ping` process per address (32 at a time). Larger networks need several agents or ranges
  that change between cycles.
- **Device status needs ping to tell `down` from `snmp_error`.** In the loopback simulation
  every address answers ping, so a stopped simulated device shows `snmp_error`, never `down`.
- **Two agents polling the same device** both update it; the last report wins.
- **Interfaces that disappear** from a device's table are deleted, not kept as history.

## Phase 3 (IPAM)
- **Alerts are only re-checked when data arrives** (agent report or IPAM change), because
  Render has no background worker. If the agent stops reporting, a duplicate-IP alert stays
  open until the next report, even after the window has passed.
- **Alerts can't be acknowledged or resolved by hand yet.** The API is read-only; the actions
  come with the alerts page in Phase 4.
- **Deleting a discovered subnet is temporary.** The next agent report creates it again
  (without the manual name/VLAN/gateway). Delete is meant for manual subnets.
- **Subnet usage is computed on each request** (one indexed count per subnet). Fine for a few
  hundred subnets; thousands would need cached counters.
- **Duplicate detection needs both MACs in ARP tables.** Two hosts fighting over one IP are
  only caught if a polled router or switch has seen both within the window. Rogue DHCP and
  gratuitous-ARP detection are not done.
- **No IP history.** Only first/last seen per address and the current reservation are kept.

## Other
- The UI has been checked by automated tests and a production build only. No visual review in
  a browser has been done yet.
