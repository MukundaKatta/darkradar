"""Brand monitoring - scan for brand name mentions across breach data."""

from __future__ import annotations

from datetime import datetime
from typing import Optional
from uuid import uuid4

from darkradar.database.breaches import BreachDatabase
from darkradar.models import Alert, BrandMention, Breach, Severity


class BrandMonitor:
    """Monitor for brand name mentions in breach data and dark web sources."""

    def __init__(self, breach_db: Optional[BreachDatabase] = None) -> None:
        self.breach_db = breach_db or BreachDatabase()

    def scan_breaches(self, brand_name: str) -> list[BrandMention]:
        """Scan breach database for mentions of a brand name."""
        mentions: list[BrandMention] = []
        brand_lower = brand_name.lower()
        brand_tokens = brand_lower.split()

        for breach in self.breach_db.breaches:
            match_score = self._compute_match_score(brand_tokens, breach)
            if match_score > 0:
                severity = self._score_to_severity(match_score, breach)
                mention = BrandMention(
                    brand_name=brand_name,
                    context=self._build_context(brand_name, breach, match_score),
                    source=f"Breach: {breach.name}",
                    severity=severity,
                    discovered_at=datetime.utcnow(),
                )
                mentions.append(mention)

        return mentions

    def scan_for_data_exposure(self, brand_name: str, domain: str) -> list[BrandMention]:
        """Scan for potential data exposure related to a brand's domain."""
        mentions = self.scan_breaches(brand_name)

        # Also check if the brand's domain appears in breach sources
        domain_base = domain.split(".")[0].lower()
        for breach in self.breach_db.breaches:
            source_lower = breach.source.lower().replace(" ", "")
            if domain_base in source_lower:
                already_found = any(breach.name in m.source for m in mentions)
                if not already_found:
                    mention = BrandMention(
                        brand_name=brand_name,
                        context=f"Direct breach of {brand_name} infrastructure: {breach.description}",
                        source=f"Breach: {breach.name}",
                        severity=Severity.CRITICAL,
                    )
                    mentions.append(mention)

        return mentions

    def generate_alert(self, brand_name: str, mentions: list[BrandMention]) -> Alert | None:
        """Generate an alert from brand mentions."""
        if not mentions:
            return None

        severity_order = {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }
        max_mention = max(mentions, key=lambda m: severity_order[m.severity])

        sources = list({m.source for m in mentions})
        return Alert(
            id=str(uuid4())[:8],
            title=f"Brand mentions detected for '{brand_name}'",
            severity=max_mention.severity,
            category="brand",
            description=f"Found {len(mentions)} mention(s) across: {', '.join(sources[:5])}",
            recommended_actions=[
                "Investigate each mention for potential data exposure",
                "Assess whether customer data was involved",
                "Prepare incident response if direct breach confirmed",
                "Monitor dark web forums for further mentions",
                "Consider engaging a threat intelligence service",
            ],
        )

    @staticmethod
    def _compute_match_score(brand_tokens: list[str], breach: Breach) -> float:
        """Compute how well a brand name matches a breach record."""
        searchable = f"{breach.name} {breach.source} {breach.description}".lower()
        full_brand = " ".join(brand_tokens)

        # Exact full match
        if full_brand in searchable:
            return 1.0

        # Token matching
        matched = sum(1 for token in brand_tokens if token in searchable and len(token) > 2)
        if matched == 0:
            return 0.0

        return matched / len(brand_tokens) * 0.8

    @staticmethod
    def _score_to_severity(score: float, breach: Breach) -> Severity:
        """Convert a match score and breach details to a severity level."""
        if score >= 0.9 and breach.is_sensitive:
            return Severity.CRITICAL
        if score >= 0.9:
            return Severity.HIGH
        if score >= 0.5:
            return Severity.MEDIUM
        return Severity.LOW

    @staticmethod
    def _build_context(brand_name: str, breach: Breach, score: float) -> str:
        """Build a human-readable context string for a mention."""
        match_type = "direct reference" if score >= 0.9 else "partial match"
        data = ", ".join(dt.value for dt in breach.data_types[:5])
        return (
            f"{match_type.capitalize()} to '{brand_name}' found in {breach.name} "
            f"({breach.records_exposed:,} records). "
            f"Exposed data types: {data}. "
            f"{breach.description}"
        )
