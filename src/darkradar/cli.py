"""DARKRADAR CLI - Click-based command-line interface."""

from __future__ import annotations

import click
from rich.console import Console

from darkradar.analyzer.risk import ExposureRiskScorer
from darkradar.analyzer.timeline import BreachTimeline
from darkradar.database.breaches import BreachDatabase
from darkradar.database.hash import PasswordHashChecker
from darkradar.monitor.brand import BrandMonitor
from darkradar.monitor.credential import CredentialMonitor
from darkradar.monitor.domain import DomainMonitor
from darkradar.report import ReportGenerator

console = Console()
report_gen = ReportGenerator(console)


@click.group()
@click.version_option(version="0.1.0", prog_name="darkradar")
def cli() -> None:
    """DARKRADAR - Dark Web Monitor for leaked credentials and brand mentions."""


@cli.command()
@click.argument("email")
def check_email(email: str) -> None:
    """Check an email address against breach databases."""
    monitor = CredentialMonitor()
    exposures = monitor.check_email(email)
    report_gen.print_exposure_report(email, exposures)


@cli.command()
@click.argument("hash_value")
def check_hash(hash_value: str) -> None:
    """Check a password hash against known compromised hashes."""
    checker = PasswordHashChecker()
    hash_type = checker.detect_hash_type(hash_value)
    is_known, plain = checker.is_known_weak_hash(hash_value)
    report_gen.print_hash_check(hash_value, is_known, plain, hash_type.value)

    if is_known:
        monitor = CredentialMonitor()
        exposures = monitor.check_hash(hash_value)
        if exposures:
            console.print(f"\n[bold]Found in {len(exposures)} breach(es):[/bold]")
            for exp in exposures:
                console.print(f"  - {exp.breach.name} ({exp.breach.records_exposed:,} records)")


@cli.command()
@click.argument("brand_name")
def monitor_brand(brand_name: str) -> None:
    """Monitor for brand name mentions in breach data."""
    monitor = BrandMonitor()
    mentions = monitor.scan_breaches(brand_name)
    report_gen.print_brand_mentions(brand_name, mentions)

    alert = monitor.generate_alert(brand_name, mentions)
    if alert:
        console.print()
        report_gen.print_alert(alert)


@cli.command()
@click.argument("domain")
@click.option("--limit", "-n", default=30, help="Maximum candidates to display")
def check_domain(domain: str, limit: int) -> None:
    """Check for typosquatting and phishing domains."""
    monitor = DomainMonitor()
    candidates = monitor.generate_typosquat_candidates(domain)
    report_gen.print_domain_report(domain, candidates[:limit])

    alert = monitor.generate_alert(domain, candidates)
    if alert:
        console.print()
        report_gen.print_alert(alert)


@cli.command()
@click.argument("email")
def report(email: str) -> None:
    """Generate a full exposure report for an email address."""
    monitor = CredentialMonitor()
    exposures = monitor.check_email(email)

    scorer = ExposureRiskScorer()
    scorer.score_multiple_exposures(exposures)

    report_gen.print_exposure_report(email, exposures)

    # Timeline
    timeline = BreachTimeline()
    timeline.add_exposures(exposures)
    if exposures:
        console.print()
        report_gen.print_timeline(timeline)

    # Alert
    alert = monitor.generate_alert(email, exposures)
    if alert:
        console.print()
        report_gen.print_alert(alert)


@cli.command()
def stats() -> None:
    """Show breach database statistics."""
    db = BreachDatabase()
    report_gen.print_stats(db)

    console.print()
    report_gen.print_breach_table(db.get_largest(10), title="Top 10 Largest Breaches")


@cli.command()
def timeline() -> None:
    """Show breach timeline analysis."""
    tl = BreachTimeline()
    report_gen.print_timeline(tl)

    console.print()
    cumulative = tl.get_cumulative_exposure()
    if cumulative:
        last = cumulative[-1]
        console.print(
            f"[bold]Cumulative records exposed:[/bold] {last['cumulative_total']:,}"
        )


@cli.command()
@click.argument("password")
def check_password(password: str) -> None:
    """Check password strength and breach status."""
    checker = PasswordHashChecker()
    result = checker.check_password_strength(password)

    rating_colors = {
        "COMPROMISED": "bold red",
        "VERY WEAK": "red",
        "WEAK": "yellow",
        "MODERATE": "cyan",
        "STRONG": "green",
    }
    color = rating_colors.get(result["rating"], "white")

    console.print(f"\n[bold]Password Rating:[/bold] [{color}]{result['rating']}[/{color}]")
    console.print(f"[bold]Score:[/bold] {result['score']}/{result['max_score']}")
    console.print(f"[bold]Length:[/bold] {result['length']}")
    console.print(f"[bold]Uppercase:[/bold] {'Yes' if result['has_upper'] else 'No'}")
    console.print(f"[bold]Lowercase:[/bold] {'Yes' if result['has_lower'] else 'No'}")
    console.print(f"[bold]Digits:[/bold] {'Yes' if result['has_digit'] else 'No'}")
    console.print(f"[bold]Special chars:[/bold] {'Yes' if result['has_special'] else 'No'}")

    if result["is_common"]:
        console.print("\n[bold red]WARNING: This password appears in known breach databases![/bold red]")


if __name__ == "__main__":
    cli()
