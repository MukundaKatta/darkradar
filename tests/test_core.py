"""Tests for Darkradar."""
from src.core import Darkradar
def test_init(): assert Darkradar().get_stats()["ops"] == 0
def test_op(): c = Darkradar(); c.detect(x=1); assert c.get_stats()["ops"] == 1
def test_multi(): c = Darkradar(); [c.detect() for _ in range(5)]; assert c.get_stats()["ops"] == 5
def test_reset(): c = Darkradar(); c.detect(); c.reset(); assert c.get_stats()["ops"] == 0
def test_service_name(): c = Darkradar(); r = c.detect(); assert r["service"] == "darkradar"
