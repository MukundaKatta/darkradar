"""Password hash checking utilities."""

from __future__ import annotations

import hashlib
import re

from darkradar.models import HashType


# Common weak password hashes for demonstration (MD5 of common passwords)
_COMMON_PASSWORD_HASHES: dict[str, str] = {
    # MD5 hashes
    "5f4dcc3b5aa765d61d8327deb882cf99": "password",
    "e10adc3949ba59abbe56e057f20f883e": "123456",
    "d8578edf8458ce06fbc5bb76a58c5ca4": "qwerty",
    "25d55ad283aa400af464c76d713c07ad": "12345678",
    "827ccb0eea8a706c4c34a16891f84e7b": "12345",
    "e99a18c428cb38d5f260853678922e03": "abc123",
    "fcea920f7412b5da7be0cf42b8c93759": "1234567",
    "25f9e794323b453885f5181f1b624d0b": "123456789",
    "0d107d09f5bbe40cade3de5c71e9e9b7": "letmein",
    "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8": "password",  # SHA256
    "7c4a8d09ca3762af61e59520943dc26494f8941b": "123456",  # SHA1
    "8cb2237d0679ca88db6464eac60da96345513964": "12345",  # SHA1
    "7c222fb2927d828af22f592134e8932480637c0d": "12345678",  # SHA1
    "b1b3773a05c0ed0176787a4f1574ff0075f7521e": "qwerty",  # SHA1
    "40be4e59c026e0e77e47c3e91f20bf0d3f9b3e68": "abc123",  # SHA1
}


class PasswordHashChecker:
    """Check password hashes against known weak/breached password databases."""

    def __init__(self) -> None:
        self._known_hashes = dict(_COMMON_PASSWORD_HASHES)

    @staticmethod
    def detect_hash_type(hash_string: str) -> HashType:
        """Detect the type of hash based on format and length."""
        hash_string = hash_string.strip()

        if hash_string.startswith(("$2a$", "$2b$", "$2y$")):
            return HashType.BCRYPT

        if re.match(r"^[a-fA-F0-9]{32}$", hash_string):
            return HashType.MD5

        if re.match(r"^[a-fA-F0-9]{40}$", hash_string):
            return HashType.SHA1

        if re.match(r"^[a-fA-F0-9]{64}$", hash_string):
            return HashType.SHA256

        return HashType.UNKNOWN

    @staticmethod
    def compute_md5(text: str) -> str:
        """Compute MD5 hash of a string."""
        return hashlib.md5(text.encode()).hexdigest()

    @staticmethod
    def compute_sha1(text: str) -> str:
        """Compute SHA1 hash of a string."""
        return hashlib.sha1(text.encode()).hexdigest()

    @staticmethod
    def compute_sha256(text: str) -> str:
        """Compute SHA256 hash of a string."""
        return hashlib.sha256(text.encode()).hexdigest()

    def is_known_weak_hash(self, hash_string: str) -> tuple[bool, str | None]:
        """Check if a hash matches a known weak password.

        Returns:
            Tuple of (is_known, plain_text_password_or_None).
        """
        hash_lower = hash_string.strip().lower()
        if hash_lower in self._known_hashes:
            return True, self._known_hashes[hash_lower]
        return False, None

    def check_password_strength(self, password: str) -> dict:
        """Evaluate password strength characteristics."""
        checks = {
            "length": len(password),
            "has_upper": any(c.isupper() for c in password),
            "has_lower": any(c.islower() for c in password),
            "has_digit": any(c.isdigit() for c in password),
            "has_special": any(not c.isalnum() for c in password),
            "is_common": False,
        }

        # Check if password's hash is in common hashes
        md5_hash = self.compute_md5(password)
        if md5_hash in self._known_hashes:
            checks["is_common"] = True

        score = 0
        if checks["length"] >= 8:
            score += 1
        if checks["length"] >= 12:
            score += 1
        if checks["length"] >= 16:
            score += 1
        if checks["has_upper"]:
            score += 1
        if checks["has_lower"]:
            score += 1
        if checks["has_digit"]:
            score += 1
        if checks["has_special"]:
            score += 1
        if not checks["is_common"]:
            score += 2

        checks["score"] = score
        checks["max_score"] = 9
        if checks["is_common"]:
            checks["rating"] = "COMPROMISED"
        elif score >= 7:
            checks["rating"] = "STRONG"
        elif score >= 5:
            checks["rating"] = "MODERATE"
        elif score >= 3:
            checks["rating"] = "WEAK"
        else:
            checks["rating"] = "VERY WEAK"

        return checks

    def compare_hashes(self, hash1: str, hash2: str) -> bool:
        """Compare two hashes in a case-insensitive manner."""
        return hash1.strip().lower() == hash2.strip().lower()

    def hash_email_for_lookup(self, email: str) -> dict[str, str]:
        """Generate lookup hashes for an email address (for API queries)."""
        email_lower = email.strip().lower()
        return {
            "md5": self.compute_md5(email_lower),
            "sha1": self.compute_sha1(email_lower),
            "sha256": self.compute_sha256(email_lower),
        }
