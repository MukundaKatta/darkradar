"""Tests for the CLI interface."""

from click.testing import CliRunner

from darkradar.cli import cli


class TestCLI:
    def setup_method(self):
        self.runner = CliRunner()

    def test_version(self):
        result = self.runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

    def test_help(self):
        result = self.runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "DARKRADAR" in result.output

    def test_check_email(self):
        result = self.runner.invoke(cli, ["check-email", "user@yahoo.com"])
        assert result.exit_code == 0
        assert "Yahoo" in result.output or "Exposure" in result.output

    def test_check_hash_known(self):
        result = self.runner.invoke(cli, ["check-hash", "5f4dcc3b5aa765d61d8327deb882cf99"])
        assert result.exit_code == 0
        assert "password" in result.output.lower() or "WARNING" in result.output

    def test_check_hash_unknown(self):
        result = self.runner.invoke(cli, ["check-hash", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1"])
        assert result.exit_code == 0
        assert "not found" in result.output.lower() or "Hash" in result.output

    def test_monitor_brand(self):
        result = self.runner.invoke(cli, ["monitor-brand", "Yahoo"])
        assert result.exit_code == 0

    def test_check_domain(self):
        result = self.runner.invoke(cli, ["check-domain", "google.com"])
        assert result.exit_code == 0
        assert "google" in result.output.lower()

    def test_stats(self):
        result = self.runner.invoke(cli, ["stats"])
        assert result.exit_code == 0

    def test_report(self):
        result = self.runner.invoke(cli, ["report", "user@example.com"])
        assert result.exit_code == 0

    def test_timeline(self):
        result = self.runner.invoke(cli, ["timeline"])
        assert result.exit_code == 0

    def test_check_password_weak(self):
        result = self.runner.invoke(cli, ["check-password", "password"])
        assert result.exit_code == 0
        assert "COMPROMISED" in result.output

    def test_check_password_strong(self):
        result = self.runner.invoke(cli, ["check-password", "Str0ng!P@ss#2024"])
        assert result.exit_code == 0
        assert "COMPROMISED" not in result.output
