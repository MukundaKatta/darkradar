"""Tests for credential, brand, and domain monitors."""

from darkradar.monitor.brand import BrandMonitor
from darkradar.monitor.credential import CredentialMonitor
from darkradar.monitor.domain import DomainMonitor
from darkradar.models import Severity


class TestCredentialMonitor:
    def setup_method(self):
        self.monitor = CredentialMonitor()

    def test_check_email_finds_large_breaches(self):
        # Any email should match against very large aggregate breaches
        exposures = self.monitor.check_email("user@example.com")
        assert len(exposures) > 0

    def test_check_email_domain_match(self):
        # An email at a breached domain should match
        exposures = self.monitor.check_email("user@yahoo.com")
        assert any("Yahoo" in e.breach.name for e in exposures)

    def test_check_known_hash(self):
        # MD5 of "password"
        exposures = self.monitor.check_hash("5f4dcc3b5aa765d61d8327deb882cf99")
        assert len(exposures) > 0
        assert all(e.risk_score > 0 for e in exposures)

    def test_check_unknown_hash(self):
        exposures = self.monitor.check_hash("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1")
        assert len(exposures) == 0

    def test_check_credential_combines(self):
        exposures = self.monitor.check_credential(
            "user@yahoo.com",
            "5f4dcc3b5aa765d61d8327deb882cf99",
        )
        assert len(exposures) > 0

    def test_generate_alert_with_exposures(self):
        exposures = self.monitor.check_email("user@yahoo.com")
        alert = self.monitor.generate_alert("user@yahoo.com", exposures)
        assert alert is not None
        assert alert.category == "credential"
        assert len(alert.recommended_actions) > 0

    def test_generate_alert_empty(self):
        alert = self.monitor.generate_alert("safe@nowhere.com", [])
        assert alert is None


class TestBrandMonitor:
    def setup_method(self):
        self.monitor = BrandMonitor()

    def test_scan_breaches_finds_match(self):
        mentions = self.monitor.scan_breaches("LinkedIn")
        assert len(mentions) > 0

    def test_scan_breaches_yahoo(self):
        mentions = self.monitor.scan_breaches("Yahoo")
        assert len(mentions) >= 2

    def test_scan_breaches_no_match(self):
        mentions = self.monitor.scan_breaches("XyzNonExistentBrand12345")
        assert len(mentions) == 0

    def test_scan_for_data_exposure(self):
        mentions = self.monitor.scan_for_data_exposure("Adobe", "adobe.com")
        assert len(mentions) > 0

    def test_generate_alert(self):
        mentions = self.monitor.scan_breaches("Facebook")
        alert = self.monitor.generate_alert("Facebook", mentions)
        assert alert is not None
        assert alert.category == "brand"

    def test_generate_alert_empty(self):
        alert = self.monitor.generate_alert("Nothing", [])
        assert alert is None


class TestDomainMonitor:
    def setup_method(self):
        self.monitor = DomainMonitor()

    def test_generate_candidates(self):
        candidates = self.monitor.generate_typosquat_candidates("google.com")
        assert len(candidates) > 20

    def test_candidates_are_unique(self):
        candidates = self.monitor.generate_typosquat_candidates("example.com")
        domains = [c.suspect_domain for c in candidates]
        assert len(domains) == len(set(domains))

    def test_candidates_not_original(self):
        candidates = self.monitor.generate_typosquat_candidates("test.com")
        assert all(c.suspect_domain != "test.com" for c in candidates)

    def test_similarity_scores(self):
        candidates = self.monitor.generate_typosquat_candidates("google.com")
        assert all(0 <= c.similarity_score <= 1 for c in candidates)

    def test_high_risk_domains(self):
        self.monitor.generate_typosquat_candidates("google.com")
        high_risk = self.monitor.get_high_risk_domains(0.8)
        assert len(high_risk) > 0
        assert all(d.similarity_score >= 0.8 for d in high_risk)

    def test_techniques_included(self):
        candidates = self.monitor.generate_typosquat_candidates("example.com")
        techniques = {c.technique for c in candidates}
        assert "transposition" in techniques
        assert "omission" in techniques
        assert "homoglyph" in techniques
        assert "tld_swap" in techniques

    def test_generate_alert(self):
        candidates = self.monitor.generate_typosquat_candidates("google.com")
        alert = self.monitor.generate_alert("google.com", candidates)
        assert alert is not None
        assert alert.category == "domain"

    def test_generate_alert_empty(self):
        alert = self.monitor.generate_alert("test.com", [])
        assert alert is None
