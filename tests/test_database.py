"""Tests for breach database and hash checker."""

from datetime import date

from darkradar.database.breaches import BreachDatabase
from darkradar.database.hash import PasswordHashChecker
from darkradar.models import DataType, HashType


class TestBreachDatabase:
    def setup_method(self):
        self.db = BreachDatabase()

    def test_has_at_least_30_breaches(self):
        assert len(self.db.breaches) >= 30

    def test_total_records_exposed(self):
        assert self.db.total_records_exposed > 0

    def test_search_by_source_linkedin(self):
        results = self.db.search_by_source("LinkedIn")
        assert len(results) >= 1
        assert any("LinkedIn" in b.name for b in results)

    def test_search_by_source_yahoo(self):
        results = self.db.search_by_source("Yahoo")
        assert len(results) >= 2  # Yahoo had multiple breaches

    def test_search_by_source_case_insensitive(self):
        results = self.db.search_by_source("adobe")
        assert len(results) >= 1

    def test_search_by_data_type_email(self):
        results = self.db.search_by_data_type(DataType.EMAIL)
        assert len(results) > 10

    def test_search_by_data_type_ssn(self):
        results = self.db.search_by_data_type(DataType.SSN)
        assert len(results) >= 1

    def test_search_by_date_range(self):
        results = self.db.search_by_date_range(date(2019, 1, 1), date(2019, 12, 31))
        assert len(results) >= 3

    def test_get_largest(self):
        largest = self.db.get_largest(5)
        assert len(largest) == 5
        assert largest[0].records_exposed >= largest[1].records_exposed

    def test_get_most_recent(self):
        recent = self.db.get_most_recent(5)
        assert len(recent) == 5
        assert recent[0].date_occurred >= recent[1].date_occurred

    def test_get_sensitive_breaches(self):
        sensitive = self.db.get_sensitive_breaches()
        assert len(sensitive) >= 5
        assert all(b.is_sensitive for b in sensitive)

    def test_stats(self):
        stats = self.db.stats()
        assert stats["total_breaches"] >= 30
        assert stats["total_records_exposed"] > 0
        assert "email" in stats["data_type_frequency"]

    def test_known_breaches_present(self):
        all_names = [b.name for b in self.db.breaches]
        assert any("LinkedIn" in n for n in all_names)
        assert any("Adobe" in n for n in all_names)
        assert any("Yahoo" in n for n in all_names)
        assert any("Equifax" in n for n in all_names)
        assert any("Marriott" in n for n in all_names)


class TestPasswordHashChecker:
    def setup_method(self):
        self.checker = PasswordHashChecker()

    def test_detect_md5(self):
        assert self.checker.detect_hash_type("5f4dcc3b5aa765d61d8327deb882cf99") == HashType.MD5

    def test_detect_sha1(self):
        assert self.checker.detect_hash_type("7c4a8d09ca3762af61e59520943dc26494f8941b") == HashType.SHA1

    def test_detect_sha256(self):
        hash_val = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
        assert self.checker.detect_hash_type(hash_val) == HashType.SHA256

    def test_detect_bcrypt(self):
        assert self.checker.detect_hash_type("$2a$10$abcdefghijklmnopqrstuuAAAABBBBCCCCDDDDEEEEFFFF") == HashType.BCRYPT

    def test_detect_unknown(self):
        assert self.checker.detect_hash_type("not_a_hash") == HashType.UNKNOWN

    def test_known_weak_hash_md5_password(self):
        is_known, plain = self.checker.is_known_weak_hash("5f4dcc3b5aa765d61d8327deb882cf99")
        assert is_known is True
        assert plain == "password"

    def test_known_weak_hash_md5_123456(self):
        is_known, plain = self.checker.is_known_weak_hash("e10adc3949ba59abbe56e057f20f883e")
        assert is_known is True
        assert plain == "123456"

    def test_unknown_hash(self):
        is_known, plain = self.checker.is_known_weak_hash("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1")
        assert is_known is False
        assert plain is None

    def test_compute_md5(self):
        assert self.checker.compute_md5("password") == "5f4dcc3b5aa765d61d8327deb882cf99"

    def test_compute_sha1(self):
        assert self.checker.compute_sha1("123456") == "7c4a8d09ca3762af61e59520943dc26494f8941b"

    def test_compute_sha256(self):
        result = self.checker.compute_sha256("password")
        assert len(result) == 64

    def test_password_strength_weak(self):
        result = self.checker.check_password_strength("password")
        assert result["is_common"] is True
        assert result["rating"] == "COMPROMISED"

    def test_password_strength_strong(self):
        result = self.checker.check_password_strength("C0mpl3x!P@ssw0rd#2024")
        assert result["is_common"] is False
        assert result["rating"] in ("STRONG", "MODERATE")
        assert result["has_upper"] is True
        assert result["has_special"] is True

    def test_compare_hashes(self):
        assert self.checker.compare_hashes("ABC123", "abc123") is True
        assert self.checker.compare_hashes("abc", "def") is False

    def test_hash_email_for_lookup(self):
        result = self.checker.hash_email_for_lookup("Test@Example.com")
        assert "md5" in result
        assert "sha1" in result
        assert "sha256" in result
        # Should normalize to lowercase
        result2 = self.checker.hash_email_for_lookup("test@example.com")
        assert result == result2
