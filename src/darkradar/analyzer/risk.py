"""Exposure risk scoring - compute severity of credential and data exposure."""

from __future__ import annotations

from datetime import date, timedelta

from darkradar.models import Breach, DataType, Exposure, Severity


# Weights for different data types in risk calculation
_DATA_TYPE_WEIGHTS: dict[DataType, float] = {
    DataType.SSN: 1.0,
    DataType.CREDIT_CARD: 0.95,
    DataType.BIOMETRIC: 0.95,
    DataType.PASSWORD: 0.9,
    DataType.AUTH_TOKEN: 0.85,
    DataType.PASSWORD_HASH: 0.7,
    DataType.SALARY: 0.65,
    DataType.SECURITY_QUESTION: 0.6,
    DataType.DOB: 0.55,
    DataType.ADDRESS: 0.5,
    DataType.PHONE: 0.45,
    DataType.EMAIL: 0.3,
    DataType.NAME: 0.25,
    DataType.USERNAME: 0.2,
    DataType.EMPLOYER: 0.2,
    DataType.IP_ADDRESS: 0.35,
    DataType.GEOLOCATION: 0.3,
    DataType.GENDER: 0.1,
}


class ExposureRiskScorer:
    """Compute risk scores for data exposure events."""

    def __init__(self, reference_date: date | None = None) -> None:
        self.reference_date = reference_date or date.today()

    def score_breach(self, breach: Breach) -> float:
        """Compute a risk score (0.0 - 1.0) for a single breach."""
        data_score = self._data_type_score(breach.data_types)
        volume_score = self._volume_score(breach.records_exposed)
        recency_score = self._recency_score(breach.date_occurred)
        sensitivity_bonus = 0.1 if breach.is_sensitive else 0.0

        # Weighted combination
        raw_score = (
            data_score * 0.40
            + volume_score * 0.25
            + recency_score * 0.25
            + sensitivity_bonus
        )

        return min(max(raw_score, 0.0), 1.0)

    def score_exposure(self, exposure: Exposure) -> float:
        """Compute a risk score for an exposure event."""
        breach_score = self.score_breach(exposure.breach)

        # Adjust based on credential properties
        credential_modifier = 1.0
        if exposure.credential.plain_text:
            credential_modifier = 1.3  # Plain text passwords are worse
        elif exposure.credential.password_hash:
            from darkradar.models import HashType
            weak_hashes = {HashType.MD5, HashType.SHA1}
            if exposure.credential.hash_type in weak_hashes:
                credential_modifier = 1.15

        raw = breach_score * credential_modifier
        exposure.risk_score = min(max(raw, 0.0), 1.0)
        return exposure.risk_score

    def score_multiple_exposures(self, exposures: list[Exposure]) -> float:
        """Compute aggregate risk across multiple exposures.

        Multiple exposures compound risk - each additional exposure
        incrementally raises the overall score.
        """
        if not exposures:
            return 0.0

        scores = sorted([self.score_exposure(e) for e in exposures], reverse=True)

        # Highest score is the base; additional exposures add diminishing increments
        aggregate = scores[0]
        for i, score in enumerate(scores[1:], start=1):
            diminishing_factor = 1.0 / (i + 1)
            aggregate += score * diminishing_factor * 0.3

        return min(aggregate, 1.0)

    def classify_severity(self, score: float) -> Severity:
        """Classify a numeric risk score into a severity level."""
        if score >= 0.85:
            return Severity.CRITICAL
        if score >= 0.65:
            return Severity.HIGH
        if score >= 0.40:
            return Severity.MEDIUM
        if score >= 0.20:
            return Severity.LOW
        return Severity.INFO

    def generate_risk_summary(self, exposures: list[Exposure]) -> dict:
        """Generate a summary of risk across all exposures."""
        if not exposures:
            return {
                "total_exposures": 0,
                "aggregate_score": 0.0,
                "severity": Severity.INFO,
                "exposed_data_types": [],
                "highest_risk_breach": None,
                "recommendations": ["No exposures detected - maintain good security hygiene."],
            }

        aggregate = self.score_multiple_exposures(exposures)
        severity = self.classify_severity(aggregate)

        all_data_types: set[DataType] = set()
        for exp in exposures:
            all_data_types.update(exp.breach.data_types)

        highest = max(exposures, key=lambda e: e.risk_score)

        return {
            "total_exposures": len(exposures),
            "aggregate_score": round(aggregate, 3),
            "severity": severity,
            "exposed_data_types": sorted([dt.value for dt in all_data_types]),
            "highest_risk_breach": highest.breach.name,
            "recommendations": self._generate_recommendations(all_data_types, severity),
        }

    @staticmethod
    def _data_type_score(data_types: list[DataType]) -> float:
        """Score based on the sensitivity of exposed data types."""
        if not data_types:
            return 0.0
        weights = [_DATA_TYPE_WEIGHTS.get(dt, 0.1) for dt in data_types]
        # Use the max weight plus a bonus for each additional type
        max_weight = max(weights)
        bonus = sum(w * 0.1 for w in sorted(weights, reverse=True)[1:])
        return min(max_weight + bonus, 1.0)

    def _recency_score(self, breach_date: date) -> float:
        """Score based on how recent the breach is (more recent = higher risk)."""
        days_ago = (self.reference_date - breach_date).days
        if days_ago < 0:
            days_ago = 0

        if days_ago <= 90:
            return 1.0
        if days_ago <= 365:
            return 0.8
        if days_ago <= 730:
            return 0.6
        if days_ago <= 1825:  # 5 years
            return 0.4
        return 0.2

    @staticmethod
    def _volume_score(records: int) -> float:
        """Score based on the number of records exposed."""
        if records >= 1_000_000_000:
            return 1.0
        if records >= 100_000_000:
            return 0.9
        if records >= 10_000_000:
            return 0.7
        if records >= 1_000_000:
            return 0.5
        if records >= 100_000:
            return 0.3
        return 0.1

    @staticmethod
    def _generate_recommendations(data_types: set[DataType], severity: Severity) -> list[str]:
        """Generate prioritized recommendations based on exposure types."""
        recs: list[str] = []

        if severity in (Severity.CRITICAL, Severity.HIGH):
            recs.append("URGENT: Initiate incident response procedures immediately")

        if DataType.PASSWORD in data_types or DataType.PASSWORD_HASH in data_types:
            recs.append("Reset all passwords and enable multi-factor authentication")

        if DataType.SSN in data_types:
            recs.append("Place fraud alerts with all three credit bureaus (Equifax, Experian, TransUnion)")
            recs.append("Consider an identity theft protection service")

        if DataType.CREDIT_CARD in data_types:
            recs.append("Request new payment cards from your financial institution")

        if DataType.AUTH_TOKEN in data_types:
            recs.append("Revoke and rotate all API keys and authentication tokens")

        if DataType.PHONE in data_types:
            recs.append("Enable SIM lock with your carrier to prevent SIM swapping")

        if DataType.EMAIL in data_types:
            recs.append("Monitor email for phishing attempts referencing the breach")

        recs.append("Review and update security practices across all accounts")
        return recs
