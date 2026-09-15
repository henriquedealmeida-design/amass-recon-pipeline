"""Amass execution and output parsing.

Amass is invoked with `-json -` so results stream on stdout as JSON Lines.
Each line looks like:

    {"name":"www.example.com","domain":"example.com","addresses":[{"ip":"1.2.3.4",...}],
     "tag":"dns","sources":["DNS"],"type":"fqdn", ...}

The parser is deliberately tolerant: malformed lines are skipped, and the
same parser is used for live scans and for importing archived JSON output
(which is what makes the diff engine testable offline).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Iterable, Iterator

from .db import Asset, ReconDB

AMASS_BIN = "amass"


class AmassNotFoundError(RuntimeError):
    pass


def parse_json_lines(lines: Iterable[str]) -> Iterator[Asset]:
    """Yield Asset objects from amass JSON-Lines output."""
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        name = rec.get("name")
        rtype = rec.get("type") or "fqdn"
        if not name:
            continue
        yield Asset(
            name=name,
            type=rtype,
            addresses=rec.get("addresses") or [],
            tag=rec.get("tag"),
            sources=rec.get("sources") or [],
        )


def run_amass(
    domain: str,
    *,
    passive: bool = True,
    timeout: int = 1800,
    extra_args: list[str] | None = None,
) -> subprocess.CompletedProcess:
    """Run `amass enum` and return the completed process (JSONL on stdout)."""
    if shutil.which(AMASS_BIN) is None:
        raise AmassNotFoundError(
            "amass binary not found in PATH — install OWASP Amass first"
        )
    cmd = [AMASS_BIN, "enum", "-d", domain, "-json", "-"]
    if passive:
        cmd.append("-passive")
    if extra_args:
        cmd.extend(extra_args)
    return subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout, check=False
    )


def scan_and_store(
    db: ReconDB,
    domain: str,
    *,
    passive: bool = True,
    timeout: int = 1800,
    extra_args: list[str] | None = None,
) -> tuple[int, int]:
    """Run a live amass scan and persist every asset. Returns (scan_id, count)."""
    scan_id = db.start_scan(domain)
    proc = run_amass(domain, passive=passive, timeout=timeout, extra_args=extra_args)
    count = 0
    for asset in parse_json_lines(proc.stdout.splitlines()):
        db.insert_asset(scan_id, asset)
        count += 1
    db.finish_scan(scan_id)
    db.commit()
    return scan_id, count


def import_and_store(db: ReconDB, domain: str, jsonl_path: str) -> tuple[int, int]:
    """Import an archived amass JSON-Lines file as a new scan snapshot."""
    scan_id = db.start_scan(domain, source="import")
    count = 0
    with open(jsonl_path, encoding="utf-8") as fh:
        for asset in parse_json_lines(fh):
            db.insert_asset(scan_id, asset)
            count += 1
    db.finish_scan(scan_id)
    db.commit()
    return scan_id, count
