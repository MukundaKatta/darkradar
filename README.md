# DARKRADAR

Dark Web Monitor for leaked credentials and brand mentions.

DARKRADAR scans breach databases, monitors brand mentions, and detects typosquatting/phishing domains to help organizations understand their exposure to data breaches and dark web threats.

## Features

- **Credential Monitoring** - Check email addresses and password hashes against 30+ major breach databases
- **Brand Monitoring** - Scan for brand name mentions across breach data and dark web sources
- **Domain Monitoring** - Detect typosquatting and phishing domains targeting your organization
- **Exposure Risk Scoring** - Compute severity scores based on breach recency, data types, and volume
- **Breach Timeline** - Track exposure events over time with trend analysis
- **Duplicate Detection** - Identify repeat breaches and overlapping exposures
- **Rich CLI** - Interactive command-line interface with formatted tables and reports

## Installation

```bash
pip install -e .
```

## Quick Start

```bash
# Check an email against breach databases
darkradar check-email user@example.com

# Check a password hash
darkradar check-hash 5f4dcc3b5aa765d61d8327deb882cf99

# Monitor a brand
darkradar monitor-brand "Acme Corp"

# Check for typosquatting domains
darkradar check-domain acmecorp.com

# Generate a full exposure report
darkradar report user@example.com

# Show breach database statistics
darkradar stats
```

## Architecture

```
src/darkradar/
  cli.py              - Click CLI entry point
  models.py           - Pydantic data models
  report.py           - Report generation with Rich
  monitor/
    credential.py     - CredentialMonitor
    brand.py          - BrandMonitor
    domain.py         - DomainMonitor
  analyzer/
    risk.py           - ExposureRiskScorer
    timeline.py       - BreachTimeline
    dedup.py          - DuplicateDetector
  database/
    breaches.py       - BreachDatabase (30+ major breaches)
    hash.py           - PasswordHashChecker
```

## Development

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

## License

MIT
