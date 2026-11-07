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

| dnspython 2.8.0 | agent runtime (Phase 6, pulled in by ciscoconfparse2; also in the backend) | the same CVE | **Very low.** ciscoconfparse2 imports dnspython for optional DNS helper functions that NetMap never calls. The agent and backend parse configs only; no DNS messages are processed through it. |

The agent's runtime dependencies had no known vulnerabilities at Phase 0 or Phase 2. In
Phase 6 the only finding is the dnspython one above.
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
- **Deleting a discovered subnet is temporary.** The next agent report creates it again
  (without the manual name/VLAN/gateway). Delete is meant for manual subnets.
- **Subnet usage is computed on each request** (one indexed count per subnet). Fine for a few
  hundred subnets; thousands would need cached counters.
- **Duplicate detection needs both MACs in ARP tables.** Two hosts fighting over one IP are
  only caught if a polled router or switch has seen both within the window. Rogue DHCP and
  gratuitous-ARP detection are not done.
- **No IP history.** Only first/last seen per address and the current reservation are kept.

## Phase 4 (dashboard)
- **Polling, not push.** The dashboard and alert counter refresh every 30 seconds; there are
  no WebSockets (Render's free tier sleeps, and polling keeps the backend simple).
- **A reload keeps you signed in, but a second tab shares the session.** Signing out in one
  tab signs out all of them; the other tabs notice on their next request.
- **Lists are capped, not paged**, except the subnet IP table and the audit log: devices
  (1,000), subnets (1,000), alerts (500), search results (200).
- **Light mode was not visually re-checked in Phase 4.** The headless Edge run followed the
  OS dark theme. Light mode uses the same tokens as dark, so it should match, but no one has
  looked at it on these pages.
- **No end-to-end test runs in CI**; the headless browser script lives outside the repo.

## Phase 5 (topology and monitoring)
- **Uplink detection is a heuristic.** A port counts as an uplink if it has an LLDP/CDP
  neighbour, more than one VLAN in its MAC table, or more than 10 MACs. An unmanaged desk
  switch with 11 PCs looks like an uplink (the PCs are then reported as "only seen on uplink
  ports"), and a trunk to a switch that runs neither LLDP nor CDP and carries one VLAN with
  few MACs looks like an access port.
- **Location is only as fresh as the MAC tables.** Switches forget idle MACs after about
  5 minutes, so a sleeping PC may show its last known port with "not seen in the last
  24 hours". MAC-table rows older than 7 days are deleted.
- **Neighbour data is what the neighbour claims.** LLDP/CDP names, ports and addresses are
  not authenticated; a rogue device can announce any name. Matching prefers the management
  IP, and names are only used when they are unique.
- **No "agent offline" or "device down" alert without reports.** Checks run when a report
  arrives (Render has no scheduler). If the agent itself stops, nothing new is checked; the
  dashboard's "last agent check-in" tile turns to a warning after 15 minutes.
- **Notifications for IPAM-triggered alerts wait for the next agent report.** Alerts opened
  by a manual reservation or subnet change are queued and sent after the next report.
- **SMTP on Render's free tier** may be blocked for outgoing mail ports; use Telegram there.
- **Rates need two readings.** The first cycle after start-up or a device reboot shows no
  rate. A 32-bit counter that wraps more than once between polls can't be corrected (busy
  1 Gbit/s ports wrap every ~34 s); such readings are dropped when they exceed the port speed.
- **New-MAC alerts are capped at 50 per report** so a network-wide event can't create
  thousands of alerts; the rest are recorded as seen without an alert.
- **No traffic charts yet.** The device page shows the latest rates; the metrics API returns
  history, and charts are planned with the AI forecasting work in Phase 7.

## Phase 6 (configuration backup, compliance and changes)
- **MikroTik push is tested only against a fake connection.** Backup, masking, compliance and
  the safe-mode flow (Ctrl+X to enter, Ctrl+X to commit, Ctrl+D to undo) follow RouterOS
  documentation, but they have not been verified on a real CHR. Test on a lab CHR first.
- **Cisco automatic rollback needs `archive`.** `configure terminal revert timer` only works
  with an archive path. The baseline template adds the `archive` block first, and the agent
  refuses other changes on a device without it (`archive_missing`). On devices whose flash
  is full or read-only, the archive itself can fail.
- **The fake IOS SSH server is a demo, not IOS.** It knows enough commands for NetMap's flow.
  Real devices can answer differently: other prompts, `--More--` paging when
  `terminal length 0` fails, or slower revert. Netmiko handles most of this, but test every
  new platform in the lab.
- **Compliance rules are heuristics over the masked text.** They parse the config the way an
  engineer reads it, not the way IOS executes it. Examples: an access-class that blocks
  Telnet still counts as "Telnet enabled"; an "unused" port is one that is down right now; an
  interface range written with macros is not expanded. Each finding shows the reason, so you
  can judge it.
- **Unconfigured detection is a guess.** "Default host name", "no VLANs besides 1" and "no
  static management IP" are typical factory signs. A device with an IP on a routed port
  counts as a router, which needs no VLANs or default gateway. A small office switch that
  really uses only VLAN 1 and DHCP will be flagged.
- **Without `SSH_KNOWN_HOSTS_FILE`, host keys are accepted automatically** (trust on every
  use). Anyone who can take over a device's IP could then capture the SSH password. Set the
  file in production. With it, a changed key stops backups (`host_key_rejected`).
- **MikroTik `/export` hides secrets by default**, so a RouterOS password-only change does not
  change the fingerprint. `/export show-sensitive` would include them, but then they would
  pass through the agent's memory and masking unnecessarily.
- **Secrets can't be pushed through a change request.** Any line that masking would alter
  (password, secret, community, key) is refused, because the change text is stored and shown
  for approval. Set or rotate secrets on the device directly; the next backup records that a
  secret changed (masked) and raises a "changed outside NetMap" alert.
- **Jobs run one after another, at most 5 per poll.** A change waits for the agent's next poll (up
  to `JOB_POLL_INTERVAL_SECONDS`). An approved job expires after 24 hours. A job claimed by
  an agent that then dies is marked `failed` (`agent_timeout`) after 30 minutes; if the push
  did happen, the device's revert timer has undone it.
- **The approved-against config must still be current.** If the device changed between
  approval and push (someone typed on the CLI), the agent refuses with `config_changed`. The
  change must be re-created and approved against the new config.
- **Config history keeps the last 50 versions per device.** Older versions are deleted.
