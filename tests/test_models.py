"""Tests for DARKRADAR data models."""

from datetime import date, datetime

from darkradar.models import (
    Alert,
    Breach,
    BrandMention,
    Credential,
    DataType,
    Exposure,
    HashType,
    Severity,
    TyposquatDomain,
)


class TestCredential:
    def test_create_credential(self):
        cred = Credential(email="user@example.com")
        assert cred.email == "user@example.com"
        assert cred.password_hash is None
        assert cred.hash_type == HashType.UNKNOWN
        assert cred.plain_text is False

    def test_credential_domain(self):
        cred = Credential(email="user@linkedin.com")
        assert cred.domain == "linkedin.com"

    def test_credential_domain_no_at(self):
        cred = Credential(email="noemail")
        assert cred.domain == ""

    def test_credential_with_hash(self):
        cred = Credential(
            email="test@test.com",
            password_hash="5f4dcc3b5aa765d61d8327deb882cf99",
            hash_type=HashType.MD5,
            plain_text=False,
            source_breach="Test Breach",
        )
        assert cred.hash_type == HashType.MD5
        assert cred.source_breach == "Test Breach"


class TestBreach:
    def test_create_breach(self):
        breach = Breach(
            name="Test Breach",
            source="TestCo",
            date_occurred=date(2023, 1, 1),
            records_exposed=1_000_000,
            data_types=[DataType.EMAIL, DataType.PASSWORD_HASH],
        )
        assert breach.name == "Test Breach"
        assert breach.records_exposed == 1_000_000

    def test_severity_critical(self):
        breach = Breach(
            name="Huge",
            source="Big Corp",
            date_occurred=date(2023, 1, 1),
            records_exposed=200_000_000,
            data_types=[DataType.EMAIL, DataType.PASSWORD, DataType.SSN],
        )
        assert breach.severity == Severity.CRITICAL

    def test_severity_high(self):
        breach = Breach(
            name="Large",
            source="Corp",
            date_occurred=date(2023, 1, 1),
            records_exposed=50_000_000,
            data_types=[DataType.EMAIL, DataType.USERNAME],
        )
        assert breach.severity == Severity.HIGH

    def test_severity_medium(self):
        breach = Breach(
            name="Medium",
            source="Corp",
            date_occurred=date(2023, 1, 1),
            records_exposed=5_000_000,
            data_types=[DataType.EMAIL, DataType.USERNAME],
        )
        assert breach.severity == Severity.MEDIUM

    def test_severity_low(self):
        breach = Breach(
            name="Small",
            source="Corp",
            date_occurred=date(2023, 1, 1),
            records_exposed=500_000,
            data_types=[DataType.EMAIL],
        )
        assert breach.severity == Severity.LOW

    def test_severity_info(self):
        breach = Breach(
            name="Tiny",
            source="Corp",
            date_occurred=date(2023, 1, 1),
            records_exposed=50_000,
            data_types=[DataType.EMAIL],
        )
        assert breach.severity == Severity.INFO

    def test_severity_sensitive_data_bumps_to_high(self):
        breach = Breach(
            name="Small but sensitive",
            source="Corp",
            date_occurred=date(2023, 1, 1),
            records_exposed=500_000,
            data_types=[DataType.EMAIL, DataType.SSN],
        )
        assert breach.severity == Severity.HIGH


class TestExposure:
    def test_create_exposure(self):
        cred = Credential(email="test@test.com")
        breach = Breach(
            name="Test",
            source="Test",
            date_occurred=date(2023, 1, 1),
            records_exposed=1000,
            data_types=[DataType.EMAIL],
        )
        exposure = Exposure(credential=cred, breach=breach, risk_score=0.5)
        assert exposure.risk_score == 0.5
        assert not exposure.is_resolved


class TestAlert:
    def test_create_alert(self):
        alert = Alert(
            id="test123",
            title="Test Alert",
            severity=Severity.HIGH,
            category="credential",
            description="Test description",
            recommended_actions=["Action 1"],
        )
        assert alert.id == "test123"
        assert alert.severity == Severity.HIGH
        assert len(alert.recommended_actions) == 1
        assert not alert.is_acknowledged


class TestBrandMention:
    def test_create_brand_mention(self):
        mention = BrandMention(
            brand_name="Acme",
            context="Found in dark web listing",
            source="Breach: Test",
        )
        assert mention.brand_name == "Acme"
        assert mention.severity == Severity.MEDIUM


class TestTyposquatDomain:
    def test_create_typosquat(self):
        domain = TyposquatDomain(
            original_domain="google.com",
            suspect_domain="gogle.com",
            technique="omission",
            similarity_score=0.91,
        )
        assert domain.suspect_domain == "gogle.com"
        assert domain.similarity_score == 0.91
