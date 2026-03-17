"""Credential monitoring - check emails and password hashes against breach databases."""

from __future__ import annotations

from datetime import datetime
from typing import Optional
from uuid import uuid4

from darkradar.database.breaches import BreachDatabase
from darkradar.database.hash import PasswordHashChecker
from darkradar.models import (
    Alert,
    Breach,
    Credential,
    DataType,
    Exposure,
    HashType,
    Severity,
)


class CredentialMonitor:
    """Monitor credentials against known breach databases."""

    def __init__(
        self,
        breach_db: Optional[BreachDatabase] = None,
        hash_checker: Optional[PasswordHashChecker] = None,
    ) -> None:
        self.breach_db = breach_db or BreachDatabase()
        self.hash_checker = hash_checker or PasswordHashChecker()

    def check_email(self, email: str) -> list[Exposure]:
        """Check an email address against breach databases.

        Simulates checking by matching the email domain against breaches
        that exposed email data. In a real implementation, this would query
        external APIs (e.g., HIBP).
        """
        email_lower = email.strip().lower()
        domain = email_lower.split("@")[-1] if "@" in email_lower else ""

        # Find all breaches that exposed email data
        email_breaches = self.breach_db.search_by_data_type(DataType.EMAIL)

        exposures: list[Exposure] = []
        for breach in email_breaches:
            # Simulate: check if this email's domain relates to the breach source
            # In production, this would be an actual database lookup
            exposure = self._simulate_email_check(email_lower, domain, breach)
            if exposure is not None:
                exposures.append(exposure)

        return exposures

    def check_hash(self, password_hash: str) -> list[Exposure]:
        """Check a password hash against known compromised hashes."""
        hash_type = self.hash_checker.detect_hash_type(password_hash)
        is_known, plain_text = self.hash_checker.is_known_weak_hash(password_hash)

        exposures: list[Exposure] = []

        if is_known:
            # Find breaches that exposed password data
            password_breaches = self.breach_db.search_by_data_type(DataType.PASSWORD_HASH)
            password_breaches.extend(self.breach_db.search_by_data_type(DataType.PASSWORD))

            # Deduplicate
            seen_names: set[str] = set()
            unique_breaches: list[Breach] = []
            for b in password_breaches:
                if b.name not in seen_names:
                    seen_names.add(b.name)
                    unique_breaches.append(b)

            for breach in unique_breaches[:5]:  # Limit to top 5 matches
                credential = Credential(
                    email="unknown@unknown.com",
                    password_hash=password_hash,
                    hash_type=hash_type,
                    plain_text=plain_text is not None,
                    source_breach=breach.name,
                )
                exposure = Exposure(
                    credential=credential,
                    breach=breach,
                    risk_score=self._compute_hash_risk(hash_type, is_known),
                )
                exposures.append(exposure)

        return exposures

    def check_credential(self, email: str, password_hash: str) -> list[Exposure]:
        """Check both email and password hash, merging results."""
        email_exposures = self.check_email(email)
        hash_exposures = self.check_hash(password_hash)

        # Update hash exposures with the email
        for exp in hash_exposures:
            exp.credential.email = email

        # Merge and deduplicate by breach name
        all_exposures: dict[str, Exposure] = {}
        for exp in email_exposures:
            all_exposures[exp.breach.name] = exp
        for exp in hash_exposures:
            if exp.breach.name in all_exposures:
                # Both email and hash found - higher risk
                all_exposures[exp.breach.name].risk_score = max(
                    all_exposures[exp.breach.name].risk_score, exp.risk_score
                ) * 1.2
            else:
                all_exposures[exp.breach.name] = exp

        return list(all_exposures.values())

    def generate_alert(self, email: str, exposures: list[Exposure]) -> Alert | None:
        """Generate an alert from credential exposures."""
        if not exposures:
            return None

        max_severity = max(exposures, key=lambda e: e.risk_score)
        if max_severity.risk_score >= 0.8:
            severity = Severity.CRITICAL
        elif max_severity.risk_score >= 0.6:
            severity = Severity.HIGH
        elif max_severity.risk_score >= 0.4:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW

        breach_names = [e.breach.name for e in exposures]
        actions = self._recommend_actions(exposures)

        return Alert(
            id=str(uuid4())[:8],
            title=f"Credential exposure detected for {email}",
            severity=severity,
            category="credential",
            description=f"Email found in {len(exposures)} breach(es): {', '.join(breach_names[:5])}",
            exposures=exposures,
            recommended_actions=actions,
        )

    def _simulate_email_check(self, email: str, domain: str, breach: Breach) -> Exposure | None:
        """Simulate an email breach check.

        Uses domain matching and probabilistic simulation. A real
        implementation would query actual breach databases.
        """
        source_lower = breach.source.lower().replace(" ", "")
        domain_base = domain.split(".")[0] if domain else ""

        # Direct domain match (e.g., user@linkedin.com in LinkedIn breach)
        if domain_base and domain_base in source_lower:
            credential = Credential(
                email=email,
                source_breach=breach.name,
            )
            return Exposure(
                credential=credential,
                breach=breach,
                risk_score=0.9,
            )

        # Large breaches (Collection #1, Verifications.io) affect many domains
        if breach.records_exposed > 500_000_000:
            credential = Credential(
                email=email,
                source_breach=breach.name,
            )
            return Exposure(
                credential=credential,
                breach=breach,
                risk_score=0.5,
            )

        return None

    @staticmethod
    def _compute_hash_risk(hash_type: HashType, is_known: bool) -> float:
        """Compute risk score for a password hash finding."""
        base_score = 0.7 if is_known else 0.3

        # Weaker hash types are higher risk
        type_penalties = {
            HashType.MD5: 0.2,
            HashType.SHA1: 0.15,
            HashType.SHA256: 0.05,
            HashType.BCRYPT: 0.0,
            HashType.UNKNOWN: 0.1,
        }
        base_score += type_penalties.get(hash_type, 0.1)

        return min(base_score, 1.0)

    @staticmethod
    def _recommend_actions(exposures: list[Exposure]) -> list[str]:
        """Generate recommended actions based on exposure findings."""
        actions = ["Change passwords immediately for affected accounts"]

        data_types: set[DataType] = set()
        for exp in exposures:
            data_types.update(exp.breach.data_types)

        if DataType.PASSWORD in data_types or DataType.PASSWORD_HASH in data_types:
            actions.append("Enable two-factor authentication on all accounts")
            actions.append("Use a password manager to generate unique passwords")

        if DataType.SSN in data_types:
            actions.append("Place a fraud alert or credit freeze with credit bureaus")
            actions.append("Monitor credit reports for unauthorized activity")

        if DataType.CREDIT_CARD in data_types:
            actions.append("Contact your bank to issue new credit/debit cards")
            actions.append("Review recent transactions for unauthorized charges")

        if DataType.PHONE in data_types:
            actions.append("Be vigilant for SIM-swapping and phishing attempts")

        if DataType.EMAIL in data_types:
            actions.append("Watch for targeted phishing emails referencing the breach")

        return actions
