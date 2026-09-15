# amass-recon-pipeline

Continuous external attack-surface monitoring built on top of [OWASP Amass](https://github.com/owasp-amass/amass).

Running Amass once gives you a list of subdomains. Running it *every week* and
diffing the results gives you something far more valuable: **the moment your
attack surface changes**. A new subdomain appearing overnight is often a
forgotten staging environment, a shadow-IT deployment, or the first visible
sign of a compromise.

This tool automates exactly that loop:

```
amass enum  →  snapshot in SQLite  →  diff vs previous scan  →  alert + Markdown report
```

## Features

- **Live scanning** — wraps `amass enum` (passive by default, `--active` optional)
- **Snapshot history** — every scan stored in SQLite, nothing is ever overwritten
- **Diff engine** — detects new / removed / changed assets (IP changes included)
- **Baseline mode** — first scan for a domain becomes the reference point
- **Markdown reports** — one report per scan, ready to archive or attach to a ticket
- **Offline import** — archived Amass JSON output can be imported as snapshots
  (useful for backfilling history or testing)
- **Zero dependencies** — Python 3.10+ standard library only

## Requirements

- Python 3.10+
- [OWASP Amass](https://github.com/owasp-amass/amass) installed and in `PATH`
  (only needed for live scans, not for imports)

## Usage

```bash
# Live scan (passive), store snapshot, diff against previous, write report
python -m recon scan example.com

# Active recon (slower, deeper)
python -m recon scan example.com --active

# Import archived amass output (amass enum -json out.jsonl ...)
python -m recon import example.com archived-output.jsonl

# List all stored scans
python -m recon history example.com

# Re-render the report for the latest scan
python -m recon report example.com
```

Options: `--db PATH` (default `recon.db`), `--out DIR` (default `reports/`).

## Example output

```
scan #7: 143 assets stored
report written to reports/example.com-scan7.md
ALERT: 2 new / 0 removed / 1 changed since scan #6
  + staging.example.com
  + vpn-backup.example.com
```

## Scheduled monitoring

A weekly cron entry is all you need:

```cron
0 6 * * 1  cd /opt/amass-recon-pipeline && python -m recon scan example.com --db /var/lib/recon/recon.db
```

## Project layout

```
recon/
  cli.py       command-line interface
  scanner.py   amass execution + JSON-Lines parsing
  db.py        SQLite snapshot storage
  differ.py    new / removed / changed detection
  report.py    Markdown report rendering
tests/
  test_pipeline.py   end-to-end tests on archived snapshots
```

## Running the tests

```bash
python -m unittest discover -s tests -v
```

## Roadmap

- [ ] Webhook notifications (Slack / Discord / generic HTTP)
- [ ] HTTP probing of new assets (status code, title, screenshot)
- [ ] Multi-domain watchlist with a single database
- [ ] HTML report with diff highlighting

## License

MIT — see [LICENSE](LICENSE).
