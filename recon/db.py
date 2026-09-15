"""SQLite persistence layer for scan results.

One database per workspace. Each scan is stored as a snapshot so any two
points in time can be diffed later.
"""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    domain      TEXT NOT NULL,
    started_at  REAL NOT NULL,
    finished_at REAL,
    source      TEXT NOT NULL DEFAULT 'amass'
);

CREATE TABLE IF NOT EXISTS assets (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id    INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    type       TEXT NOT NULL,           -- fqdn | ip_address | netblock | asn
    addresses  TEXT NOT NULL DEFAULT '[]',  -- JSON list of {"ip": ..., "cidr": ...}
    tag        TEXT,                    -- amass tag: dns, api, scrape, cert...
    sources    TEXT NOT NULL DEFAULT '[]',  -- JSON list of amass source names
    UNIQUE (scan_id, name, type)
);

CREATE INDEX IF NOT EXISTS idx_assets_scan ON assets(scan_id);
CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain);
"""


@dataclass
class Asset:
    name: str
    type: str
    addresses: list[dict]
    tag: str | None
    sources: list[str]


class ReconDB:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    # -- scans -------------------------------------------------------------

    def start_scan(self, domain: str, source: str = "amass") -> int:
        cur = self.conn.execute(
            "INSERT INTO scans (domain, started_at, source) VALUES (?, ?, ?)",
            (domain, time.time(), source),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def finish_scan(self, scan_id: int) -> None:
        self.conn.execute(
            "UPDATE scans SET finished_at = ? WHERE id = ?", (time.time(), scan_id)
        )
        self.conn.commit()

    def insert_asset(self, scan_id: int, asset: Asset) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO assets (scan_id, name, type, addresses, tag, sources)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (
                scan_id,
                asset.name,
                asset.type,
                json.dumps(asset.addresses),
                asset.tag,
                json.dumps(asset.sources),
            ),
        )

    def commit(self) -> None:
        self.conn.commit()

    def list_scans(self, domain: str | None = None) -> list[sqlite3.Row]:
        if domain:
            return list(
                self.conn.execute(
                    "SELECT * FROM scans WHERE domain = ? ORDER BY id", (domain,)
                )
            )
        return list(self.conn.execute("SELECT * FROM scans ORDER BY id"))

    def latest_scan_id(self, domain: str) -> int | None:
        row = self.conn.execute(
            "SELECT id FROM scans WHERE domain = ? AND finished_at IS NOT NULL"
            " ORDER BY id DESC LIMIT 1",
            (domain,),
        ).fetchone()
        return int(row["id"]) if row else None

    def previous_scan_id(self, domain: str, before_scan_id: int) -> int | None:
        row = self.conn.execute(
            "SELECT id FROM scans WHERE domain = ? AND id < ? AND finished_at IS NOT NULL"
            " ORDER BY id DESC LIMIT 1",
            (domain, before_scan_id),
        ).fetchone()
        return int(row["id"]) if row else None

    def get_assets(self, scan_id: int) -> list[Asset]:
        rows = self.conn.execute(
            "SELECT name, type, addresses, tag, sources FROM assets WHERE scan_id = ?",
            (scan_id,),
        )
        return [
            Asset(
                name=r["name"],
                type=r["type"],
                addresses=json.loads(r["addresses"]),
                tag=r["tag"],
                sources=json.loads(r["sources"]),
            )
            for r in rows
        ]
