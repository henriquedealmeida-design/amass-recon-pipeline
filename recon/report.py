"""Markdown report generation from a ScanDiff."""

from __future__ import annotations

import datetime as dt

from .differ import ScanDiff


def _fmt_ips(asset) -> str:
    ips = [a.get("ip", "") for a in asset.addresses if a.get("ip")]
    return ", ".join(ips) if ips else "—"


def _md(text: str) -> str:
    """Escape characters that would break Markdown tables."""
    return text.replace("|", "\\|")


def render_markdown(diff: ScanDiff) -> str:
    today = dt.date.today().isoformat()
    lines: list[str] = []
    lines.append(f"# Recon report — {diff.domain} — {today}")
    lines.append("")
    if diff.old_scan_id is None:
        lines.append(
            f"Baseline scan (#{diff.new_scan_id}): "
            f"{len(diff.new_assets)} assets discovered."
        )
    else:
        lines.append(
            f"Comparing scan #{diff.old_scan_id} → scan #{diff.new_scan_id}: "
            f"**{len(diff.new_assets)} new**, "
            f"**{len(diff.removed_assets)} removed**, "
            f"**{len(diff.changed_assets)} changed**, "
            f"{diff.unchanged_count} unchanged."
        )
    lines.append("")

    if diff.new_assets:
        title = "## New assets" if diff.old_scan_id is not None else "## Discovered assets"
        lines.append(title)
        lines.append("")
        lines.append("| Name | Type | IPs | Source tag |")
        lines.append("|------|------|-----|------------|")
        for a in diff.new_assets:
            lines.append(
                f"| {_md(a.name)} | {a.type} | {_md(_fmt_ips(a))} | {a.tag or '—'} |"
            )
        lines.append("")

    if diff.removed_assets:
        lines.append("## Removed assets")
        lines.append("")
        for a in diff.removed_assets:
            lines.append(f"- `{a.name}` ({a.type})")
        lines.append("")

    if diff.changed_assets:
        lines.append("## Changed assets")
        lines.append("")
        for old, new in diff.changed_assets:
            lines.append(
                f"- `{new.name}` — IPs: {_fmt_ips(old)} → {_fmt_ips(new)}"
            )
        lines.append("")

    if not diff.has_changes:
        lines.append("_No changes detected since the previous scan._")
        lines.append("")

    return "\n".join(lines)
