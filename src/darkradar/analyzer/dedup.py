"""Duplicate detection - find repeat breaches and overlapping exposures."""

from __future__ import annotations

from collections import defaultdict

from darkradar.models import Breach, DataType, Exposure


class DuplicateDetector:
    """Detect duplicate and overlapping breach exposures."""

    def find_duplicate_exposures(self, exposures: list[Exposure]) -> list[list[Exposure]]:
        """Find groups of exposures that likely represent the same breach event.

        Groups exposures by source and overlapping data types.
        """
        if not exposures:
            return []

        # Group by breach source
        by_source: dict[str, list[Exposure]] = defaultdict(list)
        for exp in exposures:
            key = exp.breach.source.lower().strip()
            by_source[key].append(exp)

        # Find groups with more than one exposure
        duplicate_groups: list[list[Exposure]] = []
        for source, group in by_source.items():
            if len(group) > 1:
                duplicate_groups.append(group)

        return duplicate_groups

    def find_overlapping_breaches(self, breaches: list[Breach]) -> list[dict]:
        """Find breaches from the same source that may overlap."""
        by_source: dict[str, list[Breach]] = defaultdict(list)
        for breach in breaches:
            by_source[breach.source.lower()].append(breach)

        overlaps: list[dict] = []
        for source, source_breaches in by_source.items():
            if len(source_breaches) > 1:
                sorted_breaches = sorted(source_breaches, key=lambda b: b.date_occurred)
                shared_types = set(sorted_breaches[0].data_types)
                for b in sorted_breaches[1:]:
                    shared_types &= set(b.data_types)

                overlaps.append({
                    "source": source_breaches[0].source,
                    "breach_count": len(source_breaches),
                    "breaches": [b.name for b in sorted_breaches],
                    "date_range": f"{sorted_breaches[0].date_occurred} to {sorted_breaches[-1].date_occurred}",
                    "shared_data_types": [dt.value for dt in shared_types],
                    "total_records": sum(b.records_exposed for b in source_breaches),
                })

        return overlaps

    def deduplicate_exposures(self, exposures: list[Exposure]) -> list[Exposure]:
        """Remove duplicate exposures, keeping the highest-risk version."""
        if not exposures:
            return []

        # Key by (email, breach_name) to find duplicates
        best: dict[tuple[str, str], Exposure] = {}
        for exp in exposures:
            key = (exp.credential.email.lower(), exp.breach.name)
            if key not in best or exp.risk_score > best[key].risk_score:
                best[key] = exp

        return list(best.values())

    def find_rebreached_sources(self, breaches: list[Breach]) -> list[dict]:
        """Find organizations that have been breached multiple times."""
        source_counts: dict[str, list[Breach]] = defaultdict(list)
        for breach in breaches:
            source_counts[breach.source].append(breach)

        rebreached: list[dict] = []
        for source, source_breaches in source_counts.items():
            if len(source_breaches) > 1:
                sorted_b = sorted(source_breaches, key=lambda b: b.date_occurred)
                rebreached.append({
                    "source": source,
                    "breach_count": len(source_breaches),
                    "first_breach": sorted_b[0].name,
                    "latest_breach": sorted_b[-1].name,
                    "total_records": sum(b.records_exposed for b in source_breaches),
                    "span_days": (sorted_b[-1].date_occurred - sorted_b[0].date_occurred).days,
                })

        return sorted(rebreached, key=lambda r: r["breach_count"], reverse=True)

    def compute_overlap_score(self, breach1: Breach, breach2: Breach) -> float:
        """Compute how much two breaches overlap in exposed data types.

        Returns a score from 0.0 (no overlap) to 1.0 (identical data types).
        """
        types1 = set(breach1.data_types)
        types2 = set(breach2.data_types)

        if not types1 or not types2:
            return 0.0

        intersection = types1 & types2
        union = types1 | types2

        return len(intersection) / len(union)
