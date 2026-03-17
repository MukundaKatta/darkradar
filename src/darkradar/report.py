"""Report generation with Rich formatted output."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from darkradar.analyzer.dedup import DuplicateDetector
from darkradar.analyzer.risk import ExposureRiskScorer
from darkradar.analyzer.timeline import BreachTimeline
from darkradar.database.breaches import BreachDatabase
from darkradar.models import Alert, Breach, BrandMention, Exposure, Severity, TyposquatDomain


_SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


class ReportGenerator:
    """Generate Rich-formatted reports for DARKRADAR findings."""

    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()

    def print_banner(self) -> None:
        """Print the DARKRADAR banner."""
        banner = Text()
        banner.append("DARKRADAR", style="bold red")
        banner.append(" - Dark Web Monitor", style="bold white")
        self.console.print(Panel(banner, border_style="red"))

    def print_exposure_report(self, email: str, exposures: list[Exposure]) -> None:
        """Print a full exposure report for an email."""
        self.print_banner()

        scorer = ExposureRiskScorer()
        summary = scorer.generate_risk_summary(exposures)

        # Summary panel
        severity = summary["severity"]
        color = _SEVERITY_COLORS.get(severity, "white")
        self.console.print(Panel(
            f"[bold]Email:[/bold] {email}\n"
            f"[bold]Exposures:[/bold] {summary['total_exposures']}\n"
            f"[bold]Risk Score:[/bold] {summary['aggregate_score']}\n"
            f"[bold]Severity:[/bold] [{color}]{severity.value.upper()}[/{color}]",
            title="Exposure Summary",
            border_style=color,
        ))

        if not exposures:
            self.console.print("[green]No exposures found. Stay vigilant![/green]")
            return

        # Exposure details table
        table = Table(title="Breach Exposures", show_lines=True)
        table.add_column("Breach", style="bold")
        table.add_column("Date", style="cyan")
        table.add_column("Records", justify="right")
        table.add_column("Data Types")
        table.add_column("Risk", justify="center")

        for exp in sorted(exposures, key=lambda e: e.risk_score, reverse=True):
            risk_color = _SEVERITY_COLORS.get(scorer.classify_severity(exp.risk_score), "white")
            table.add_row(
                exp.breach.name,
                str(exp.breach.date_occurred),
                f"{exp.breach.records_exposed:,}",
                ", ".join(dt.value for dt in exp.breach.data_types[:4]),
                f"[{risk_color}]{exp.risk_score:.2f}[/{risk_color}]",
            )

        self.console.print(table)

        # Recommendations
        if summary["recommendations"]:
            rec_text = "\n".join(f"  {i+1}. {r}" for i, r in enumerate(summary["recommendations"]))
            self.console.print(Panel(rec_text, title="Recommended Actions", border_style="yellow"))

    def print_alert(self, alert: Alert) -> None:
        """Print a formatted alert."""
        color = _SEVERITY_COLORS.get(alert.severity, "white")
        self.console.print(Panel(
            f"[bold]ID:[/bold] {alert.id}\n"
            f"[bold]Category:[/bold] {alert.category}\n"
            f"[bold]Severity:[/bold] [{color}]{alert.severity.value.upper()}[/{color}]\n"
            f"[bold]Description:[/bold] {alert.description}",
            title=f"Alert: {alert.title}",
            border_style=color,
        ))

        if alert.recommended_actions:
            for i, action in enumerate(alert.recommended_actions, 1):
                self.console.print(f"  [{color}]{i}.[/{color}] {action}")

    def print_breach_table(self, breaches: list[Breach], title: str = "Breach Database") -> None:
        """Print a table of breaches."""
        table = Table(title=title, show_lines=True)
        table.add_column("Name", style="bold", max_width=30)
        table.add_column("Source", style="cyan")
        table.add_column("Date")
        table.add_column("Records", justify="right", style="red")
        table.add_column("Severity", justify="center")
        table.add_column("Sensitive", justify="center")

        for breach in breaches:
            sev_color = _SEVERITY_COLORS.get(breach.severity, "white")
            table.add_row(
                breach.name,
                breach.source,
                str(breach.date_occurred),
                f"{breach.records_exposed:,}",
                f"[{sev_color}]{breach.severity.value}[/{sev_color}]",
                "[red]YES[/red]" if breach.is_sensitive else "[dim]no[/dim]",
            )

        self.console.print(table)

    def print_brand_mentions(self, brand: str, mentions: list[BrandMention]) -> None:
        """Print brand mention findings."""
        self.print_banner()

        if not mentions:
            self.console.print(f"[green]No mentions found for '{brand}'.[/green]")
            return

        self.console.print(f"\n[bold]Brand monitoring results for:[/bold] {brand}")
        self.console.print(f"[bold]Total mentions:[/bold] {len(mentions)}\n")

        table = Table(title=f"Brand Mentions: {brand}", show_lines=True)
        table.add_column("Source", style="bold")
        table.add_column("Severity", justify="center")
        table.add_column("Context", max_width=60)

        for mention in mentions:
            color = _SEVERITY_COLORS.get(mention.severity, "white")
            table.add_row(
                mention.source,
                f"[{color}]{mention.severity.value}[/{color}]",
                mention.context[:120] + "..." if len(mention.context) > 120 else mention.context,
            )

        self.console.print(table)

    def print_domain_report(self, domain: str, candidates: list[TyposquatDomain]) -> None:
        """Print typosquatting domain analysis."""
        self.print_banner()

        high_risk = [c for c in candidates if c.similarity_score >= 0.8]
        self.console.print(f"\n[bold]Domain analysis for:[/bold] {domain}")
        self.console.print(f"[bold]Total candidates:[/bold] {len(candidates)}")
        self.console.print(f"[bold]High risk (>=80%):[/bold] {len(high_risk)}\n")

        table = Table(title=f"Typosquatting Candidates: {domain}", show_lines=True)
        table.add_column("Suspect Domain", style="bold red")
        table.add_column("Technique", style="cyan")
        table.add_column("Similarity", justify="right")

        for candidate in candidates[:30]:  # Show top 30
            sim = candidate.similarity_score
            if sim >= 0.9:
                color = "bold red"
            elif sim >= 0.8:
                color = "red"
            elif sim >= 0.7:
                color = "yellow"
            else:
                color = "dim"
            table.add_row(
                candidate.suspect_domain,
                candidate.technique,
                f"[{color}]{sim:.0%}[/{color}]",
            )

        self.console.print(table)

    def print_stats(self, db: BreachDatabase) -> None:
        """Print breach database statistics."""
        self.print_banner()
        stats = db.stats()

        self.console.print(Panel(
            f"[bold]Total Breaches:[/bold] {stats['total_breaches']}\n"
            f"[bold]Total Records Exposed:[/bold] {stats['total_records_exposed']:,}\n"
            f"[bold]Date Range:[/bold] {stats['date_range']}\n"
            f"[bold]Sensitive Breaches:[/bold] {stats['sensitive_breaches']}",
            title="Breach Database Statistics",
            border_style="red",
        ))

        # Data type frequency table
        dt_table = Table(title="Data Type Frequency")
        dt_table.add_column("Data Type", style="bold")
        dt_table.add_column("Occurrences", justify="right", style="cyan")

        for dt, count in stats["data_type_frequency"].items():
            dt_table.add_row(dt, str(count))

        self.console.print(dt_table)

        # Breaches by year
        year_table = Table(title="Breaches by Year")
        year_table.add_column("Year", style="bold")
        year_table.add_column("Count", justify="right", style="cyan")

        for year, count in stats["breaches_by_year"].items():
            year_table.add_row(str(year), str(count))

        self.console.print(year_table)

    def print_hash_check(self, hash_value: str, is_known: bool, plain: str | None, hash_type: str) -> None:
        """Print password hash check results."""
        self.print_banner()

        if is_known:
            self.console.print(Panel(
                f"[bold red]WARNING: Hash found in breach database![/bold red]\n\n"
                f"[bold]Hash:[/bold] {hash_value}\n"
                f"[bold]Type:[/bold] {hash_type}\n"
                f"[bold]Plain text:[/bold] {'[red]' + plain + '[/red]' if plain else 'Unknown'}",
                title="Password Hash Check",
                border_style="red",
            ))
        else:
            self.console.print(Panel(
                f"[green]Hash not found in known breach databases.[/green]\n\n"
                f"[bold]Hash:[/bold] {hash_value}\n"
                f"[bold]Type:[/bold] {hash_type}",
                title="Password Hash Check",
                border_style="green",
            ))

    def print_timeline(self, timeline: BreachTimeline) -> None:
        """Print breach timeline analysis."""
        trend = timeline.get_trend_analysis()
        lag = timeline.get_discovery_lag_stats()

        self.console.print(Panel(
            f"[bold]Total Breaches:[/bold] {trend['total_breaches']}\n"
            f"[bold]Total Records:[/bold] {trend['total_records']:,}\n"
            f"[bold]Avg Discovery Lag:[/bold] {lag.get('avg_days', 'N/A')} days\n"
            f"[bold]Max Discovery Lag:[/bold] {lag.get('max_days', 'N/A')} days",
            title="Breach Timeline Analysis",
            border_style="cyan",
        ))

        table = Table(title="Yearly Breakdown")
        table.add_column("Year", style="bold")
        table.add_column("Breaches", justify="right")
        table.add_column("Records", justify="right", style="red")
        table.add_column("Sensitive", justify="right", style="yellow")

        for year, stats in sorted(trend["yearly_stats"].items()):
            table.add_row(
                str(year),
                str(stats["breach_count"]),
                f"{stats['total_records']:,}",
                str(stats["sensitive_count"]),
            )

        self.console.print(table)
