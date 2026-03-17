"""Domain monitoring - detect typosquatting and phishing domains."""

from __future__ import annotations

import itertools
from typing import Optional
from uuid import uuid4

from darkradar.models import Alert, Severity, TyposquatDomain


# Common homoglyph substitutions
_HOMOGLYPHS: dict[str, list[str]] = {
    "a": ["@", "4", "q"],
    "b": ["d", "6"],
    "c": ["k", "("],
    "d": ["b", "cl"],
    "e": ["3"],
    "g": ["9", "q"],
    "h": ["n"],
    "i": ["1", "l", "!"],
    "l": ["1", "i", "|"],
    "m": ["rn", "nn"],
    "n": ["m", "r"],
    "o": ["0", "q"],
    "p": ["q"],
    "q": ["p", "g"],
    "r": ["n"],
    "s": ["5", "$", "z"],
    "t": ["7", "+"],
    "u": ["v"],
    "v": ["u", "w"],
    "w": ["vv", "uu"],
    "x": ["%"],
    "y": ["j"],
    "z": ["s", "2"],
}

# Common TLD alternatives for phishing
_TLD_VARIANTS: list[str] = [
    ".com", ".net", ".org", ".co", ".io", ".info", ".biz",
    ".xyz", ".online", ".site", ".app", ".dev", ".tech",
    ".cloud", ".shop", ".store", ".email", ".link",
]


class DomainMonitor:
    """Monitor for typosquatting and phishing domains."""

    def __init__(self) -> None:
        self._generated_domains: list[TyposquatDomain] = []

    def generate_typosquat_candidates(self, domain: str) -> list[TyposquatDomain]:
        """Generate potential typosquatting domain variants."""
        name, tld = self._split_domain(domain)
        candidates: list[TyposquatDomain] = []

        # 1. Character transposition (e.g., gogle.com)
        candidates.extend(self._transposition_variants(name, tld, domain))

        # 2. Missing character (e.g., goole.com)
        candidates.extend(self._omission_variants(name, tld, domain))

        # 3. Extra character / repetition (e.g., gooogle.com)
        candidates.extend(self._repetition_variants(name, tld, domain))

        # 4. Homoglyph substitution (e.g., g00gle.com)
        candidates.extend(self._homoglyph_variants(name, tld, domain))

        # 5. Adjacent key typos
        candidates.extend(self._adjacent_key_variants(name, tld, domain))

        # 6. TLD variations (e.g., google.net, google.co)
        candidates.extend(self._tld_variants(name, tld, domain))

        # 7. Hyphenation (e.g., goo-gle.com)
        candidates.extend(self._hyphenation_variants(name, tld, domain))

        # 8. Subdomain tricks (e.g., google.com.evil.com)
        candidates.extend(self._subdomain_variants(name, tld, domain))

        # Deduplicate and compute similarity
        seen: set[str] = set()
        unique: list[TyposquatDomain] = []
        for c in candidates:
            if c.suspect_domain not in seen and c.suspect_domain != domain:
                seen.add(c.suspect_domain)
                c.similarity_score = self._compute_similarity(domain, c.suspect_domain)
                unique.append(c)

        unique.sort(key=lambda d: d.similarity_score, reverse=True)
        self._generated_domains = unique
        return unique

    def get_high_risk_domains(self, threshold: float = 0.8) -> list[TyposquatDomain]:
        """Return generated domains above a similarity threshold."""
        return [d for d in self._generated_domains if d.similarity_score >= threshold]

    def generate_alert(self, domain: str, candidates: list[TyposquatDomain]) -> Alert | None:
        """Generate an alert from typosquatting domain findings."""
        if not candidates:
            return None

        high_risk = [c for c in candidates if c.similarity_score >= 0.8]
        if high_risk:
            severity = Severity.HIGH
        elif candidates:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW

        techniques = list({c.technique for c in candidates[:10]})

        return Alert(
            id=str(uuid4())[:8],
            title=f"Typosquatting domains detected for {domain}",
            severity=severity,
            category="domain",
            description=(
                f"Generated {len(candidates)} potential typosquatting domains. "
                f"{len(high_risk)} are high similarity (>=80%). "
                f"Techniques: {', '.join(techniques)}"
            ),
            recommended_actions=[
                "Register high-risk typosquatting domains defensively",
                "Set up monitoring for new domain registrations matching these patterns",
                "Implement DMARC/SPF/DKIM to prevent email spoofing",
                "Educate employees about phishing domain techniques",
                "Consider using a domain monitoring service",
            ],
        )

    @staticmethod
    def _split_domain(domain: str) -> tuple[str, str]:
        """Split domain into name and TLD."""
        parts = domain.rsplit(".", 1)
        if len(parts) == 2:
            return parts[0], f".{parts[1]}"
        return domain, ".com"

    @staticmethod
    def _transposition_variants(name: str, tld: str, original: str) -> list[TyposquatDomain]:
        """Generate character transposition variants."""
        variants: list[TyposquatDomain] = []
        for i in range(len(name) - 1):
            swapped = list(name)
            swapped[i], swapped[i + 1] = swapped[i + 1], swapped[i]
            candidate = "".join(swapped) + tld
            if candidate != original:
                variants.append(TyposquatDomain(
                    original_domain=original,
                    suspect_domain=candidate,
                    technique="transposition",
                ))
        return variants

    @staticmethod
    def _omission_variants(name: str, tld: str, original: str) -> list[TyposquatDomain]:
        """Generate character omission variants."""
        variants: list[TyposquatDomain] = []
        for i in range(len(name)):
            candidate = name[:i] + name[i + 1:] + tld
            if candidate != original:
                variants.append(TyposquatDomain(
                    original_domain=original,
                    suspect_domain=candidate,
                    technique="omission",
                ))
        return variants

    @staticmethod
    def _repetition_variants(name: str, tld: str, original: str) -> list[TyposquatDomain]:
        """Generate character repetition variants."""
        variants: list[TyposquatDomain] = []
        for i in range(len(name)):
            candidate = name[:i] + name[i] + name[i:] + tld
            if candidate != original:
                variants.append(TyposquatDomain(
                    original_domain=original,
                    suspect_domain=candidate,
                    technique="repetition",
                ))
        return variants

    @staticmethod
    def _homoglyph_variants(name: str, tld: str, original: str) -> list[TyposquatDomain]:
        """Generate homoglyph substitution variants."""
        variants: list[TyposquatDomain] = []
        for i, char in enumerate(name):
            if char.lower() in _HOMOGLYPHS:
                for replacement in _HOMOGLYPHS[char.lower()]:
                    candidate = name[:i] + replacement + name[i + 1:] + tld
                    if candidate != original:
                        variants.append(TyposquatDomain(
                            original_domain=original,
                            suspect_domain=candidate,
                            technique="homoglyph",
                        ))
        return variants

    @staticmethod
    def _adjacent_key_variants(name: str, tld: str, original: str) -> list[TyposquatDomain]:
        """Generate adjacent keyboard key typo variants."""
        keyboard_neighbors: dict[str, str] = {
            "q": "wa", "w": "qeas", "e": "wrds", "r": "etfs", "t": "ryg",
            "y": "tuh", "u": "yij", "i": "uok", "o": "ipl", "p": "ol",
            "a": "qwsz", "s": "wedxza", "d": "erfcxs", "f": "rtgvcd",
            "g": "tyhbvf", "h": "yujnbg", "j": "uikmnh", "k": "ioljm",
            "l": "opk", "z": "asx", "x": "zsdc", "c": "xdfv",
            "v": "cfgb", "b": "vghn", "n": "bhjm", "m": "njk",
        }
        variants: list[TyposquatDomain] = []
        for i, char in enumerate(name):
            if char.lower() in keyboard_neighbors:
                for neighbor in keyboard_neighbors[char.lower()]:
                    candidate = name[:i] + neighbor + name[i + 1:] + tld
                    if candidate != original:
                        variants.append(TyposquatDomain(
                            original_domain=original,
                            suspect_domain=candidate,
                            technique="adjacent_key",
                        ))
        return variants

    @staticmethod
    def _tld_variants(name: str, tld: str, original: str) -> list[TyposquatDomain]:
        """Generate TLD variation candidates."""
        variants: list[TyposquatDomain] = []
        for alt_tld in _TLD_VARIANTS:
            if alt_tld != tld:
                candidate = name + alt_tld
                variants.append(TyposquatDomain(
                    original_domain=original,
                    suspect_domain=candidate,
                    technique="tld_swap",
                ))
        return variants

    @staticmethod
    def _hyphenation_variants(name: str, tld: str, original: str) -> list[TyposquatDomain]:
        """Generate hyphenated variants."""
        variants: list[TyposquatDomain] = []
        for i in range(1, len(name)):
            candidate = name[:i] + "-" + name[i:] + tld
            variants.append(TyposquatDomain(
                original_domain=original,
                suspect_domain=candidate,
                technique="hyphenation",
            ))
        return variants

    @staticmethod
    def _subdomain_variants(name: str, tld: str, original: str) -> list[TyposquatDomain]:
        """Generate subdomain-based phishing variants."""
        variants: list[TyposquatDomain] = []
        evil_domains = ["secure-login.com", "account-verify.net", "auth-service.org"]
        for evil in evil_domains:
            candidate = f"{name}{tld}.{evil}"
            variants.append(TyposquatDomain(
                original_domain=original,
                suspect_domain=candidate,
                technique="subdomain_trick",
            ))
        return variants

    @staticmethod
    def _compute_similarity(original: str, candidate: str) -> float:
        """Compute Levenshtein-based similarity between two domain strings."""
        s1 = original.lower()
        s2 = candidate.lower()

        if s1 == s2:
            return 1.0

        len1, len2 = len(s1), len(s2)
        if len1 == 0 or len2 == 0:
            return 0.0

        # Levenshtein distance
        matrix = [[0] * (len2 + 1) for _ in range(len1 + 1)]
        for i in range(len1 + 1):
            matrix[i][0] = i
        for j in range(len2 + 1):
            matrix[0][j] = j

        for i in range(1, len1 + 1):
            for j in range(1, len2 + 1):
                cost = 0 if s1[i - 1] == s2[j - 1] else 1
                matrix[i][j] = min(
                    matrix[i - 1][j] + 1,
                    matrix[i][j - 1] + 1,
                    matrix[i - 1][j - 1] + cost,
                )

        distance = matrix[len1][len2]
        max_len = max(len1, len2)
        return 1.0 - (distance / max_len)
