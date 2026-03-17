"""Pydantic data models for DARKRADAR."""

from __future__ import annotations

from datetime import date, datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class DataType(str, Enum):
    """Types of data exposed in a breach."""

    EMAIL = "email"
    PASSWORD = "password"
    PASSWORD_HASH = "password_hash"
    USERNAME = "username"
    PHONE = "phone"
    ADDRESS = "address"
    IP_ADDRESS = "ip_address"
    DOB = "date_of_birth"
    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    SECURITY_QUESTION = "security_question"
    GEOLOCATION = "geolocation"
    NAME = "name"
    EMPLOYER = "employer"
    GENDER = "gender"
    BIOMETRIC = "biometric"
    AUTH_TOKEN = "auth_token"
    SALARY = "salary"


class HashType(str, Enum):
    """Supported password hash types."""

    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    BCRYPT = "bcrypt"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    """Alert severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Credential(BaseModel):
    """A credential record found in breach data."""

    email: str
    password_hash: Optional[str] = None
    hash_type: HashType = HashType.UNKNOWN
    plain_text: bool = False
    source_breach: Optional[str] = None
    discovered_at: datetime = Field(default_factory=datetime.utcnow)

    @property
    def domain(self) -> str:
        """Extract the domain from the email address."""
        return self.email.split("@")[-1] if "@" in self.email else ""


class Breach(BaseModel):
    """A data breach record."""

    name: str
    source: str
    date_occurred: date
    date_discovered: Optional[date] = None
    records_exposed: int
    data_types: list[DataType]
    description: str = ""
    is_verified: bool = True
    is_sensitive: bool = False

    @property
    def severity(self) -> Severity:
        """Compute severity based on records exposed and data types."""
        sensitive_types = {
            DataType.SSN,
            DataType.CREDIT_CARD,
            DataType.BIOMETRIC,
            DataType.PASSWORD,
        }
        has_sensitive = bool(set(self.data_types) & sensitive_types)

        if self.records_exposed > 100_000_000 and has_sensitive:
            return Severity.CRITICAL
        if self.records_exposed > 10_000_000 or has_sensitive:
            return Severity.HIGH
        if self.records_exposed > 1_000_000:
            return Severity.MEDIUM
        if self.records_exposed > 100_000:
            return Severity.LOW
        return Severity.INFO


class Exposure(BaseModel):
    """An exposure event linking a credential to a breach."""

    credential: Credential
    breach: Breach
    risk_score: float = 0.0
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    is_resolved: bool = False
    notes: str = ""


class Alert(BaseModel):
    """An alert generated from monitoring activity."""

    id: str
    title: str
    severity: Severity
    category: str  # "credential", "brand", "domain"
    description: str
    exposures: list[Exposure] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    is_acknowledged: bool = False
    recommended_actions: list[str] = Field(default_factory=list)


class BrandMention(BaseModel):
    """A brand mention found in breach or dark web data."""

    brand_name: str
    context: str
    source: str
    severity: Severity = Severity.MEDIUM
    discovered_at: datetime = Field(default_factory=datetime.utcnow)


class TyposquatDomain(BaseModel):
    """A suspected typosquatting or phishing domain."""

    original_domain: str
    suspect_domain: str
    technique: str  # e.g. "homoglyph", "transposition", "addition"
    similarity_score: float = 0.0
    is_active: bool = False
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
