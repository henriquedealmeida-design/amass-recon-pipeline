"""Diff engine: compare two scan snapshots of the same domain.

The interesting question in continuous recon is never "what exists?" but
"what *changed* since last time?" — a new subdomain appearing overnight is
often a forgotten staging environment or the beginning of a shadow-IT story.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .db import Asset


@dataclass
class ScanDiff:
    domain: str
    old_scan_id: int | None
    new_scan_id: int
    new_assets: list[Asset] = field(default_factory=list)
    removed_assets: list[Asset] = field(default_factory=list)
    changed_assets: list[tuple[Asset, Asset]] = field(default_factory=list)
    unchanged_count: int = 0

    @property
    def has_changes(self) -> bool:
        return bool(self.new_assets or self.removed_assets or self.changed_assets)


def _key(asset: Asset) -> tuple[str, str]:
    return (asset.name, asset.type)


def _fingerprint(asset: Asset) -> tuple:
    """What we consider 'the same asset, same state'."""
    ips = sorted(a.get("ip", "") for a in asset.addresses)
    return (tuple(ips), asset.tag, tuple(sorted(asset.sources)))


def diff_scans(
    domain: str,
    old_scan_id: int | None,
    old_assets: list[Asset],
    new_scan_id: int,
    new_assets: list[Asset],
) -> ScanDiff:
    """Compute the delta between two snapshots.

    `old_scan_id=None` means: first scan ever for this domain — everything
    is reported as new (baseline).
    """
    diff = ScanDiff(domain=domain, old_scan_id=old_scan_id, new_scan_id=new_scan_id)

    old_map = {_key(a): a for a in old_assets}
    new_map = {_key(a): a for a in new_assets}

    for key, asset in new_map.items():
        if key not in old_map:
            diff.new_assets.append(asset)
        elif _fingerprint(old_map[key]) != _fingerprint(asset):
            diff.changed_assets.append((old_map[key], asset))
        else:
            diff.unchanged_count += 1

    for key, asset in old_map.items():
        if key not in new_map:
            diff.removed_assets.append(asset)

    diff.new_assets.sort(key=lambda a: a.name)
    diff.removed_assets.sort(key=lambda a: a.name)
    diff.changed_assets.sort(key=lambda pair: pair[1].name)
    return diff
