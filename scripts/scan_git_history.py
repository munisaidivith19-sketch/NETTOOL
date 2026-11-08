"""Pre-deployment check: has a secret ever been committed? (Phase 9 checklist)

The GitHub repository is public, and git keeps every old version of every file, so a key
deleted in a later commit is still readable by anyone. This scans every line ever *added*
in any commit on any branch, plus every file name ever committed, for things that look like
real secrets:
  - MongoDB connection strings with a password
  - Fernet keys
  - Telegram bot tokens
  - Gemini, Groq, GitHub and AWS keys
  - private keys
  - committed .env, .pem, .key or credential files

Test files are skipped: they contain deliberately fake keys (marked "test-only") that the
test suite needs. Found values are printed masked.

From the project root:   python scripts/scan_git_history.py
Exit code 0 = nothing found, 1 = something to look at. If a real secret was ever committed,
deleting it is not enough: rotate it (new Atlas password, new Fernet key, new bot token).
"""

import re
import subprocess  # nosec B404 - runs git with a fixed argument list

PATTERNS = {
    "MongoDB URI with password": re.compile(r"mongodb(?:\+srv)?://[^\s:/@<>\"']+:[^\s@<>\"']+@"),
    "Fernet key": re.compile(r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{43}=(?![A-Za-z0-9_=-])"),
    "Telegram bot token": re.compile(r"\b[0-9]{8,10}:[A-Za-z0-9_-]{35}\b"),
    "Google / Gemini API key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "Groq API key": re.compile(r"\bgsk_[A-Za-z0-9]{40,}\b"),
    "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "AWS access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "Private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
}
SECRET_FILES = re.compile(r"(^|/)(\.env(\.[^/]+)?|[^/]+\.pem|[^/]+\.key|credentials[^/]*)$")
ALLOWED_FILES = re.compile(r"(^|/)\.env\.example$")
SKIP_PATHS = re.compile(r"(^|/)tests?/|(^|/)__tests__/|package-lock\.json$")


def git(*args: str) -> str:
    # A fixed program and argument list from this file, never shell=True (CLAUDE.md 7.4).
    result = subprocess.run(  # nosec B603 B607  # noqa: S603
        ["git", *args], capture_output=True, text=True,  # noqa: S607
        check=True, encoding="utf-8", errors="replace")
    return result.stdout


def mask(value: str) -> str:
    return value[:6] + "…" + f"({len(value)} chars)"


def main() -> int:
    findings = []
    for name in sorted(set(git("log", "--all", "--name-only", "--format=").split())):
        if SECRET_FILES.search(name) and not ALLOWED_FILES.search(name):
            findings.append(("-", name, "secret-looking file name", name))

    commit = path = ""
    for line in git("log", "--all", "-p", "--no-color", "--format=commit %H").splitlines():
        if line.startswith("commit "):
            commit = line[7:19]
        elif line.startswith("+++ "):
            path = line[6:] if line.startswith("+++ b/") else ""
        elif line.startswith("+") and path and not SKIP_PATHS.search(path):
            for label, pattern in PATTERNS.items():
                for match in pattern.finditer(line):
                    findings.append((commit, path, label, match.group(0)))

    if not findings:
        print("No secrets found in the git history.")
        return 0
    print(f"{len(findings)} possible secret(s) in the git history:")
    for commit, path, label, value in findings:
        print(f"  {commit}  {path}: {label}: {mask(value)}")
    print("Check each one. A real secret must be rotated; removing the line doesn't erase it.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
