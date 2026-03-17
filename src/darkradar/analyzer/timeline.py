"""Breach timeline - track exposure events over time."""

from __future__ import annotations

from collections import defaultdict
from datetime import date
from typing import Optional

from darkradar.database.breaches import BreachDatabase
from darkradar.models import Breach, DataType, Exposure


class BreachTimeline:
    """Track and analyze breach exposure events over time."""

    def __init__(self, breach_db: Optional[BreachDatabase] = None) -> None:
        self.breach_db = breach_db or BreachDatabase()
        self._exposures: list[Exposure] = []

    def add_exposure(self, exposure: Exposure) -> None:
        """Add an exposure event to the timeline."""
        self._exposures.append(exposure)

    def add_exposures(self, exposures: list[Exposure]) -> None:
        """Add multiple exposure events to the timeline."""
        self._exposures.extend(exposures)

    @property
    def exposures(self) -> list[Exposure]:
        """Return all tracked exposures."""
        return list(self._exposures)

    def get_chronological(self) -> list[Exposure]:
        """Return exposures sorted by breach date."""
        return sorted(self._exposures, key=lambda e: e.breach.date_occurred)

    def get_by_year(self) -> dict[int, list[Exposure]]:
        """Group exposures by the year they occurred."""
        by_year: dict[int, list[Exposure]] = defaultdict(list)
        for exp in self._exposures:
            by_year[exp.breach.date_occurred.year].append(exp)
        return dict(sorted(by_year.items()))

    def get_breach_timeline(self) -> list[dict]:
        """Build a timeline of all breaches in the database."""
        timeline: list[dict] = []
        for breach in sorted(self.breach_db.breaches, key=lambda b: b.date_occurred):
            entry = {
                "date": breach.date_occurred.isoformat(),
                "name": breach.name,
                "source": breach.source,
                "records": breach.records_exposed,
                "severity": breach.severity.value,
                "data_types": [dt.value for dt in breach.data_types],
            }
            if breach.date_discovered and breach.date_discovered != breach.date_occurred:
                entry["discovery_lag_days"] = (breach.date_discovered - breach.date_occurred).days
            timeline.append(entry)
        return timeline

    def get_cumulative_exposure(self) -> list[dict]:
        """Calculate cumulative records exposed over time."""
        breaches = sorted(self.breach_db.breaches, key=lambda b: b.date_occurred)
        cumulative: list[dict] = []
        total = 0
        for breach in breaches:
            total += breach.records_exposed
            cumulative.append({
                "date": breach.date_occurred.isoformat(),
                "breach": breach.name,
                "records_added": breach.records_exposed,
                "cumulative_total": total,
            })
        return cumulative

    def get_trend_analysis(self) -> dict:
        """Analyze trends in breach frequency and severity."""
        by_year = self._breaches_by_year()

        yearly_stats: dict[int, dict] = {}
        for year, breaches in sorted(by_year.items()):
            total_records = sum(b.records_exposed for b in breaches)
            yearly_stats[year] = {
                "breach_count": len(breaches),
                "total_records": total_records,
                "avg_records": total_records // len(breaches) if breaches else 0,
                "sensitive_count": sum(1 for b in breaches if b.is_sensitive),
            }

        # Compute year-over-year changes
        years = sorted(yearly_stats.keys())
        yoy_changes: list[dict] = []
        for i in range(1, len(years)):
            prev_year, curr_year = years[i - 1], years[i]
            prev = yearly_stats[prev_year]
            curr = yearly_stats[curr_year]

            if prev["breach_count"] > 0:
                count_change = ((curr["breach_count"] - prev["breach_count"]) / prev["breach_count"]) * 100
            else:
                count_change = 0.0

            yoy_changes.append({
                "year": curr_year,
                "breach_count_change_pct": round(count_change, 1),
                "total_records": curr["total_records"],
            })

        return {
            "yearly_stats": yearly_stats,
            "year_over_year": yoy_changes,
            "total_breaches": len(self.breach_db.breaches),
            "total_records": sum(b.records_exposed for b in self.breach_db.breaches),
        }

    def get_discovery_lag_stats(self) -> dict:
        """Analyze the time between breach occurrence and discovery."""
        lags: list[int] = []
        for breach in self.breach_db.breaches:
            if breach.date_discovered and breach.date_discovered != breach.date_occurred:
                lag = (breach.date_discovered - breach.date_occurred).days
                if lag > 0:
                    lags.append(lag)

        if not lags:
            return {"count": 0, "avg_days": 0, "max_days": 0, "min_days": 0}

        return {
            "count": len(lags),
            "avg_days": round(sum(lags) / len(lags)),
            "max_days": max(lags),
            "min_days": min(lags),
            "median_days": sorted(lags)[len(lags) // 2],
        }

    def _breaches_by_year(self) -> dict[int, list[Breach]]:
        """Group database breaches by year."""
        by_year: dict[int, list[Breach]] = defaultdict(list)
        for breach in self.breach_db.breaches:
            by_year[breach.date_occurred.year].append(breach)
        return dict(by_year)
