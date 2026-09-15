"""Command-line interface.

Usage examples:
    python -m recon scan example.com                 # live amass scan + diff + report
    python -m recon import example.com old.jsonl     # import archived amass output
    python -m recon history example.com              # list stored scans
    python -m recon report example.com               # re-render latest diff
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .db import ReconDB
from .differ import diff_scans
from .report import render_markdown
from .scanner import AmassNotFoundError, import_and_store, scan_and_store

DEFAULT_DB = "recon.db"


def _build_diff(db: ReconDB, domain: str, new_scan_id: int):
    prev_id = db.previous_scan_id(domain, new_scan_id)
    old_assets = db.get_assets(prev_id) if prev_id is not None else []
    new_assets = db.get_assets(new_scan_id)
    return diff_scans(domain, prev_id, old_assets, new_scan_id, new_assets)


def _write_report(diff, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{diff.domain}-scan{diff.new_scan_id}.md"
    path.write_text(render_markdown(diff), encoding="utf-8")
    return path


def cmd_scan(args) -> int:
    db = ReconDB(args.db)
    try:
        scan_id, count = scan_and_store(
            db, args.domain, passive=not args.active, timeout=args.timeout
        )
    except AmassNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    diff = _build_diff(db, args.domain, scan_id)
    path = _write_report(diff, Path(args.out))
    print(f"scan #{scan_id}: {count} assets stored")
    print(f"report written to {path}")
    _print_alert(diff)
    db.close()
    return 0


def cmd_import(args) -> int:
    db = ReconDB(args.db)
    scan_id, count = import_and_store(db, args.domain, args.file)
    diff = _build_diff(db, args.domain, scan_id)
    path = _write_report(diff, Path(args.out))
    print(f"imported as scan #{scan_id}: {count} assets")
    print(f"report written to {path}")
    _print_alert(diff)
    db.close()
    return 0


def cmd_history(args) -> int:
    db = ReconDB(args.db)
    scans = db.list_scans(args.domain)
    if not scans:
        print("no scans stored yet")
        return 0
    for s in scans:
        n = len(db.get_assets(s["id"]))
        print(f"  #{s['id']:<4} {s['domain']:<30} {n:>5} assets  (source: {s['source']})")
    db.close()
    return 0


def cmd_report(args) -> int:
    db = ReconDB(args.db)
    latest = db.latest_scan_id(args.domain)
    if latest is None:
        print("no finished scan for this domain", file=sys.stderr)
        return 1
    diff = _build_diff(db, args.domain, latest)
    path = _write_report(diff, Path(args.out))
    print(f"report written to {path}")
    db.close()
    return 0


def _print_alert(diff) -> None:
    """The part that matters day-to-day: shout when the surface moves."""
    if diff.old_scan_id is None:
        print(f"baseline established: {len(diff.new_assets)} assets")
    elif diff.has_changes:
        print(
            f"ALERT: {len(diff.new_assets)} new / "
            f"{len(diff.removed_assets)} removed / "
            f"{len(diff.changed_assets)} changed since scan #{diff.old_scan_id}"
        )
        for a in diff.new_assets[:10]:
            print(f"  + {a.name}")
    else:
        print("no change since previous scan")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="recon",
        description="Continuous attack-surface monitoring on top of OWASP Amass",
    )
    parser.add_argument("--db", default=DEFAULT_DB, help="SQLite database path")
    parser.add_argument("--out", default="reports", help="report output directory")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="run a live amass scan")
    p_scan.add_argument("domain")
    p_scan.add_argument("--active", action="store_true", help="enable active recon")
    p_scan.add_argument("--timeout", type=int, default=1800)
    p_scan.set_defaults(func=cmd_scan)

    p_imp = sub.add_parser("import", help="import archived amass JSON-Lines output")
    p_imp.add_argument("domain")
    p_imp.add_argument("file")
    p_imp.set_defaults(func=cmd_import)

    p_hist = sub.add_parser("history", help="list stored scans")
    p_hist.add_argument("domain", nargs="?")
    p_hist.set_defaults(func=cmd_history)

    p_rep = sub.add_parser("report", help="re-render report for the latest scan")
    p_rep.add_argument("domain")
    p_rep.set_defaults(func=cmd_report)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
