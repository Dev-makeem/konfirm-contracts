#!/usr/bin/env python3
"""Fail if any `pub fn` in contracts/*/src/lib.rs neither calls
require_auth / require_signer / require_admin in its body nor carries a
`/// Permissionless` doc comment. See "Authorization convention" in README.md.

Also fail if any tracked file's deployed contract address disagrees with
README.md's "Deployed Addresses" table (issue #54: stale artifacts/addresses.json).
"""

import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
PUB_FN = re.compile(r"^\s*pub fn (\w+)")
AUTH_CALL = re.compile(r"\brequire_(auth|signer|admin)\b")
PERMISSIONLESS = re.compile(r"^\s*///\s*Permissionless\b")

# Stellar contract IDs are 56-char base32 strings starting with C.
CONTRACT_ID = re.compile(r"\bC[A-Z2-7]{55}\b")
# Files that legitimately hold the canonical address list or are not tracked
# sources of truth (README is the source; artifacts/ is gitignored/local-only).
ADDRESS_SCAN_SKIP = {"README.md"}
ADDRESS_SCAN_SKIP_DIRS = {".git", "target", "node_modules", "artifacts"}


def is_permissionless(lines, index):
    i = index - 1
    while i >= 0 and lines[i].lstrip().startswith(("///", "#[")):
        if PERMISSIONLESS.match(lines[i]):
            return True
        i -= 1
    return False


def fn_body(lines, start):
    code = "\n".join(line.split("//", 1)[0] for line in lines[start:])
    open_at = code.index("{")
    depth = 0
    for i in range(open_at, len(code)):
        if code[i] == "{":
            depth += 1
        elif code[i] == "}":
            depth -= 1
            if depth == 0:
                return code[open_at:i]
    raise ValueError(f"unclosed body for fn at line {start + 1}")


def readme_addresses():
    """Return the set of contract IDs listed in README's Deployed Addresses table."""
    readme = ROOT / "README.md"
    if not readme.exists():
        return None
    text = readme.read_text()
    marker = re.search(r"^#+\s*Deployed Addresses\s*$", text, re.MULTILINE)
    if not marker:
        return None
    section = text[marker.end():]
    next_heading = re.search(r"^#+\s", section, re.MULTILINE)
    if next_heading:
        section = section[: next_heading.start()]
    return set(CONTRACT_ID.findall(section))


def check_addresses():
    """Fail if any tracked file references a contract ID absent from README's table."""
    canonical = readme_addresses()
    if canonical is None:
        print(
            "README.md has no 'Deployed Addresses' table; cannot verify contract IDs",
            file=sys.stderr,
        )
        return ["README.md: missing 'Deployed Addresses' table"]

    failures = []
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(ROOT)
        if rel.as_posix() in ADDRESS_SCAN_SKIP:
            continue
        if any(part in ADDRESS_SCAN_SKIP_DIRS for part in rel.parts):
            continue
        try:
            text = path.read_text()
        except (UnicodeDecodeError, OSError):
            continue
        for cid in CONTRACT_ID.findall(text):
            if cid not in canonical:
                failures.append(
                    f"{rel}: contract ID {cid} is not in README.md's Deployed Addresses table"
                )
    return failures


def main():
    found = 0
    failures = []
    for path in sorted(ROOT.glob("contracts/*/src/lib.rs")):
        lines = path.read_text().splitlines()
        for index, line in enumerate(lines):
            match = PUB_FN.match(line)
            if not match:
                continue
            found += 1
            if is_permissionless(lines, index) or AUTH_CALL.search(fn_body(lines, index)):
                continue
            failures.append(
                f"{path.relative_to(ROOT)}:{index + 1}: pub fn {match.group(1)} calls no "
                "require_auth/require_signer/require_admin and is not documented `/// Permissionless`"
            )

    if found == 0:
        print("no pub fns found under contracts/*/src/lib.rs; check the glob", file=sys.stderr)
        return 1

    failures.extend(check_addresses())

    for failure in failures:
        print(failure, file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
