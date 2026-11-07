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
| filelock 4.1.0 | **dev only** (pulled in by pip-audit's cache) | 16 CVEs (CVE-2026-1129xx) in lock-file handling: symlink races, ACL/mode handling, stale-lock eviction | **Very low.** Not installed on Render. Only reachable by a local attacker on the developer's own machine, during `pip-audit` runs. |

The agent's runtime dependencies had no known vulnerabilities at Phase 0.

## Other
- The UI has been checked by automated tests and a production build only. No visual review in
  a browser has been done yet.
