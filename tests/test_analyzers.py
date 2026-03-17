"""Tests for risk scorer, timeline, and duplicate detector."""

from datetime import date

from darkradar.analyzer.dedup import DuplicateDetector
from darkradar.analyzer.risk import ExposureRiskScorer
from darkradar.analyzer.timeline import BreachTimeline
from darkradar.database.breaches import BreachDatabase
from darkradar.models import Breach, Credential, DataType, Exposure, HashType, Severity


def _make_breach(name="Test", source="TestCo", records=1_000_000, data_types=None,
                 breach_date=None, is_sensitive=False):
    return Breach(
        name=name,
        source=source,
        date_occurred=breach_date or date(2023, 1, 1),
        records_exposed=records,
        data_types=data_types or [DataType.EMAIL],
        is_sensitive=is_sensitive,
    )


def _make_exposure(email="test@test.com", breach=None, risk_score=0.5):
    cred = Credential(email=email)
    return Exposure(
        credential=cred,
        breach=breach or _make_breach(),
        risk_score=risk_score,
    )


class TestExposureRiskScorer:
    def setup_method(self):
        self.scorer = ExposureRiskScorer(reference_date=date(2024, 1, 1))

    def test_score_breach_basic(self):
        breach = _make_breach(records=5_000_000, data_types=[DataType.EMAIL, DataType.NAME])
        score = self.scorer.score_breach(breach)
        assert 0.0 <= score <= 1.0

    def test_score_sensitive_higher(self):
        normal = _make_breach(records=5_000_000, data_types=[DataType.EMAIL])
        sensitive = _make_breach(records=5_000_000, data_types=[DataType.SSN, DataType.CREDIT_CARD], is_sensitive=True)
        assert self.scorer.score_breach(sensitive) > self.scorer.score_breach(normal)

    def test_score_larger_breach_higher(self):
        small = _make_breach(records=100_000)
        large = _make_breach(records=100_000_000)
        assert self.scorer.score_breach(large) > self.scorer.score_breach(small)

    def test_score_recent_higher(self):
        old = _make_breach(breach_date=date(2010, 1, 1))
        recent = _make_breach(breach_date=date(2023, 11, 1))
        assert self.scorer.score_breach(recent) > self.scorer.score_breach(old)

    def test_score_exposure(self):
        exposure = _make_exposure()
        score = self.scorer.score_exposure(exposure)
        assert 0.0 <= score <= 1.0
        assert exposure.risk_score == score

    def test_plain_text_password_penalty(self):
        cred_plain = Credential(email="a@b.com", plain_text=True)
        cred_hash = Credential(email="a@b.com", password_hash="abc", hash_type=HashType.SHA256)
        breach = _make_breach()
        exp_plain = Exposure(credential=cred_plain, breach=breach)
        exp_hash = Exposure(credential=cred_hash, breach=breach)
        assert self.scorer.score_exposure(exp_plain) > self.scorer.score_exposure(exp_hash)

    def test_multiple_exposures_compound(self):
        exposures = [_make_exposure() for _ in range(5)]
        aggregate = self.scorer.score_multiple_exposures(exposures)
        single = self.scorer.score_multiple_exposures([exposures[0]])
        assert aggregate >= single

    def test_multiple_exposures_empty(self):
        assert self.scorer.score_multiple_exposures([]) == 0.0

    def test_classify_severity(self):
        assert self.scorer.classify_severity(0.9) == Severity.CRITICAL
        assert self.scorer.classify_severity(0.7) == Severity.HIGH
        assert self.scorer.classify_severity(0.5) == Severity.MEDIUM
        assert self.scorer.classify_severity(0.3) == Severity.LOW
        assert self.scorer.classify_severity(0.1) == Severity.INFO

    def test_risk_summary(self):
        exposures = [_make_exposure()]
        summary = self.scorer.generate_risk_summary(exposures)
        assert summary["total_exposures"] == 1
        assert "aggregate_score" in summary
        assert "recommendations" in summary

    def test_risk_summary_empty(self):
        summary = self.scorer.generate_risk_summary([])
        assert summary["total_exposures"] == 0
        assert summary["severity"] == Severity.INFO


class TestBreachTimeline:
    def setup_method(self):
        self.timeline = BreachTimeline()

    def test_add_exposure(self):
        exp = _make_exposure()
        self.timeline.add_exposure(exp)
        assert len(self.timeline.exposures) == 1

    def test_add_multiple(self):
        exps = [_make_exposure() for _ in range(3)]
        self.timeline.add_exposures(exps)
        assert len(self.timeline.exposures) == 3

    def test_chronological_order(self):
        exp1 = _make_exposure(breach=_make_breach(breach_date=date(2020, 1, 1)))
        exp2 = _make_exposure(breach=_make_breach(breach_date=date(2015, 1, 1)))
        self.timeline.add_exposures([exp1, exp2])
        chrono = self.timeline.get_chronological()
        assert chrono[0].breach.date_occurred < chrono[1].breach.date_occurred

    def test_get_breach_timeline(self):
        timeline = self.timeline.get_breach_timeline()
        assert len(timeline) >= 30
        assert "date" in timeline[0]
        assert "name" in timeline[0]

    def test_cumulative_exposure(self):
        cumulative = self.timeline.get_cumulative_exposure()
        assert len(cumulative) >= 30
        # Cumulative should be non-decreasing
        for i in range(1, len(cumulative)):
            assert cumulative[i]["cumulative_total"] >= cumulative[i - 1]["cumulative_total"]

    def test_trend_analysis(self):
        trend = self.timeline.get_trend_analysis()
        assert "yearly_stats" in trend
        assert trend["total_breaches"] >= 30

    def test_discovery_lag_stats(self):
        lag = self.timeline.get_discovery_lag_stats()
        assert lag["count"] > 0
        assert lag["avg_days"] > 0


class TestDuplicateDetector:
    def setup_method(self):
        self.detector = DuplicateDetector()

    def test_find_duplicates_same_source(self):
        exp1 = _make_exposure(breach=_make_breach(name="Yahoo 2013", source="Yahoo"))
        exp2 = _make_exposure(breach=_make_breach(name="Yahoo 2014", source="Yahoo"))
        groups = self.detector.find_duplicate_exposures([exp1, exp2])
        assert len(groups) == 1
        assert len(groups[0]) == 2

    def test_find_no_duplicates(self):
        exp1 = _make_exposure(breach=_make_breach(name="A", source="Alpha"))
        exp2 = _make_exposure(breach=_make_breach(name="B", source="Beta"))
        groups = self.detector.find_duplicate_exposures([exp1, exp2])
        assert len(groups) == 0

    def test_deduplicate_exposures(self):
        breach = _make_breach()
        exp1 = _make_exposure(email="a@b.com", breach=breach, risk_score=0.3)
        exp2 = _make_exposure(email="a@b.com", breach=breach, risk_score=0.8)
        result = self.detector.deduplicate_exposures([exp1, exp2])
        assert len(result) == 1
        assert result[0].risk_score == 0.8  # Kept the higher one

    def test_find_overlapping_breaches(self):
        db = BreachDatabase()
        overlaps = self.detector.find_overlapping_breaches(db.breaches)
        # Yahoo should show up as overlapping
        yahoo_overlap = [o for o in overlaps if "yahoo" in o["source"].lower()]
        assert len(yahoo_overlap) >= 1

    def test_find_rebreached_sources(self):
        db = BreachDatabase()
        rebreached = self.detector.find_rebreached_sources(db.breaches)
        assert len(rebreached) >= 1  # At least Yahoo

    def test_compute_overlap_score(self):
        b1 = _make_breach(data_types=[DataType.EMAIL, DataType.PASSWORD_HASH])
        b2 = _make_breach(data_types=[DataType.EMAIL, DataType.NAME])
        score = self.detector.compute_overlap_score(b1, b2)
        assert 0.0 < score < 1.0  # Partial overlap (EMAIL in common)

    def test_compute_overlap_identical(self):
        b1 = _make_breach(data_types=[DataType.EMAIL])
        b2 = _make_breach(data_types=[DataType.EMAIL])
        assert self.detector.compute_overlap_score(b1, b2) == 1.0

    def test_compute_overlap_none(self):
        b1 = _make_breach(data_types=[DataType.EMAIL])
        b2 = _make_breach(data_types=[DataType.SSN])
        assert self.detector.compute_overlap_score(b1, b2) == 0.0
