"""Mask secrets in device configs before they leave the agent (CLAUDE.md 7.6).

SHARED FILE: identical copies live in agent/netmap_agent/config_mgmt/ and
backend/app/config_mgmt/ (a test checks), so edit both or neither. The agent masks before
upload and the backend masks again on ingest (defence in depth: a bug or an old agent still
can't get a password into the database).

What is masked (the value only, so the line still shows what is configured):
- any value after a password / secret / community / key word, e.g.
  `enable secret 9 $9$abc`      -> `enable secret 9 <masked>` (the type number is kept, so
                                   compliance can still tell type 7 from type 9)
  `snmp-server community public RO` -> `snmp-server community <masked> RO`
  `tacacs-server key 7 0822..`  -> `tacacs-server key 7 <masked>`
- SNMPv3 user auth/priv keys and the community on `snmp-server host` lines;
- RouterOS `key=value` pairs such as `password=`, `secret=`, `*-key=`, `passphrase=`, and the
  community `name=` under `/snmp community`.
Masking is idempotent: masking an already masked config changes nothing.
"""

import re

MASK = "<masked>"

# Words whose next value is a secret (Cisco style, space separated).
_SECRET_WORDS = {"password", "secret", "community", "key", "key-string", "psk"}
_SECRET_SUFFIXES = ("-key", "-password", "-secret", "-psk")
# Tokens that sit between the secret word and the value: type numbers and algorithm names.
_SKIP = {
    "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
    "md5", "sha", "sha1", "sha256", "sha384", "sha512", "ascii", "hex",
    "encrypted", "unencrypted", "level",
}
# `key` followed by these is a command, not a secret (`crypto key generate rsa`, `key chain X`).
_KEY_COMMANDS = {
    "generate", "zeroize", "chain", "config-key", "storage", "import", "export", "pubkey-chain",
    "decrypt", "encrypt", "label", "string",
}
_ROUTEROS_PAIR = re.compile(r'([A-Za-z][\w-]*)=("(?:[^"\\]|\\.)*"|\S+)')
_ROUTEROS_SECRET_KEYS = re.compile(
    r"^(password|secret|passphrase|psk|private-key|.*-key|.*-password|.*-secret|.*-passphrase)$",
    re.IGNORECASE,
)
_SNMP_HOST = re.compile(
    r"^(\s*snmp-server\s+host\s+\S+\s+(?:(?:informs|traps)\s+)?"
    r"(?:version\s+(?:1|2c|3\s+\S+)\s+)?)(\S+)(.*)$",
    re.IGNORECASE,
)


def _is_secret_word(token: str) -> bool:
    low = token.lower()
    return low in _SECRET_WORDS or low.endswith(_SECRET_SUFFIXES)


def _mask_cisco_line(line: str) -> str:
    host = _SNMP_HOST.match(line)
    if host and host.group(2) != MASK and host.group(2).lower() not in ("version", "informs",
                                                                        "traps"):
        line = f"{host.group(1)}{MASK}{host.group(3)}"
    parts = re.split(r"(\s+)", line)  # keep the whitespace, so indentation survives
    tokens = [i for i in range(len(parts)) if parts[i] and not parts[i].isspace()]
    snmp_user = len(tokens) >= 2 and parts[tokens[0]].lower() == "snmp-server" and \
        parts[tokens[1]].lower() == "user"
    pos = 0
    while pos < len(tokens):
        word = parts[tokens[pos]].lower()
        if _is_secret_word(word) or (snmp_user and word in ("auth", "priv")):
            nxt = pos + 1
            if word == "key" and nxt < len(tokens) and parts[tokens[nxt]].lower() in _KEY_COMMANDS:
                pos += 1
                continue
            # Skip type numbers / algorithm names, but never skip the last token: in
            # `password 7` the 7 is the password itself.
            while nxt + 1 < len(tokens) and (
                parts[tokens[nxt]].lower() in _SKIP
                or (snmp_user and re.fullmatch(r"(des|3des|aes)\d*|128|192|256",
                                               parts[tokens[nxt]].lower()))
            ):
                # `level 15`: the privilege level is a number too, skip both tokens.
                nxt += 2 if parts[tokens[nxt]].lower() == "level" and nxt + 2 < len(tokens) else 1
            if nxt < len(tokens):
                parts[tokens[nxt]] = MASK
            pos = nxt + 1
            continue
        pos += 1
    return "".join(parts)


def _mask_routeros_line(line: str, path: str) -> str:
    in_snmp_community = path.startswith("/snmp community")

    def repl(match: re.Match[str]) -> str:
        name = match.group(1)
        if _ROUTEROS_SECRET_KEYS.match(name) or (in_snmp_community and name == "name"):
            return f"{name}={MASK}"
        return match.group(0)

    return _ROUTEROS_PAIR.sub(repl, line)


def mask_config(text: str, vendor: str) -> str:
    """Return the config with every secret value replaced by <masked>."""
    out = []
    path = ""
    for line in text.splitlines():
        if vendor == "mikrotik_routeros":
            stripped = line.strip()
            if stripped.startswith("/"):
                path = " ".join(t for t in stripped.split() if "=" not in t)
            out.append(_mask_routeros_line(line, path))
        else:
            out.append(_mask_cisco_line(line))
    return "\n".join(out) + ("\n" if text.endswith("\n") else "")
