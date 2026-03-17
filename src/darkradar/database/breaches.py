"""Breach database with 30+ major real-world breach records."""

from __future__ import annotations

from datetime import date

from darkradar.models import Breach, DataType


# Real-world major data breaches
_BREACH_RECORDS: list[dict] = [
    {
        "name": "LinkedIn 2012",
        "source": "LinkedIn",
        "date_occurred": date(2012, 6, 5),
        "date_discovered": date(2012, 6, 6),
        "records_exposed": 164_700_000,
        "data_types": [DataType.EMAIL, DataType.PASSWORD_HASH],
        "description": "LinkedIn password hashes leaked; originally reported as 6.5M but later confirmed at 164M.",
    },
    {
        "name": "Adobe 2013",
        "source": "Adobe",
        "date_occurred": date(2013, 10, 4),
        "date_discovered": date(2013, 10, 4),
        "records_exposed": 153_000_000,
        "data_types": [DataType.EMAIL, DataType.PASSWORD_HASH, DataType.USERNAME, DataType.NAME],
        "description": "Adobe user database breach exposing encrypted passwords and password hints.",
    },
    {
        "name": "Yahoo 2013",
        "source": "Yahoo",
        "date_occurred": date(2013, 8, 1),
        "date_discovered": date(2016, 12, 14),
        "records_exposed": 3_000_000_000,
        "data_types": [DataType.EMAIL, DataType.PASSWORD_HASH, DataType.NAME, DataType.PHONE, DataType.DOB, DataType.SECURITY_QUESTION],
        "description": "Largest known data breach affecting all 3 billion Yahoo accounts.",
        "is_sensitive": True,
    },
    {
        "name": "Yahoo 2014",
        "source": "Yahoo",
        "date_occurred": date(2014, 1, 1),
        "date_discovered": date(2016, 9, 22),
        "records_exposed": 500_000_000,
        "data_types": [DataType.EMAIL, DataType.PASSWORD_HASH, DataType.NAME, DataType.PHONE, DataType.DOB, DataType.SECURITY_QUESTION],
        "description": "State-sponsored attack compromising 500 million Yahoo accounts.",
        "is_sensitive": True,
    },
    {
        "name": "MySpace 2016",
        "source": "MySpace",
        "date_occurred": date(2013, 6, 1),
        "date_discovered": date(2016, 5, 27),
        "records_exposed": 360_000_000,
        "data_types": [DataType.EMAIL, DataType.PASSWORD_HASH, DataType.USERNAME],
        "description": "MySpace breach from 2013 surfaced in 2016 with SHA1-hashed passwords.",
    },
    {
        "name": "Equifax 2017",
        "source": "Equifax",
        "date_occurred": date(2017, 5, 13),
        "date_discovered": date(2017, 7, 29),
        "records_exposed": 147_900_000,
        "data_types": [DataType.NAME, DataType.SSN, DataType.DOB, DataType.ADDRESS, DataType.CREDIT_CARD],
        "description": "Credit bureau breach exposing SSNs, birth dates, and credit card numbers.",
        "is_sensitive": True,
    },
    {
        "name": "Marriott 2018",
        "source": "Marriott International",
        "date_occurred": date(2014, 1, 1),
        "date_discovered": date(2018, 11, 30),
        "records_exposed": 500_000_000,
        "data_types": [DataType.NAME, DataType.EMAIL, DataType.PHONE, DataType.ADDRESS, DataType.CREDIT_CARD, DataType.DOB],
        "description": "Starwood reservation database compromised for four years before discovery.",
        "is_sensitive": True,
    },
    {
        "name": "Dropbox 2012",
        "source": "Dropbox",
        "date_occurred": date(2012, 7, 1),
        "date_discovered": date(2016, 8, 30),
        "records_exposed": 68_648_009,
        "data_types": [DataType.EMAIL, DataType.PASSWORD_HASH],
        "description": "Dropbox user credentials leaked including bcrypt and SHA1 hashes.",
    },
    {
        "name": "Canva 2019",
        "source": "Canva",
        "date_occurred": date(2019, 5, 24),
        "date_discovered": date(2019, 5, 24),
        "records_exposed": 137_000_000,
        "data_types": [DataType.EMAIL, DataType.USERNAME, DataType.NAME, DataType.PASSWORD_HASH, DataType.GEOLOCATION],
        "description": "Canva breach exposing usernames, emails, and bcrypt password hashes.",
    },
    {
        "name": "Capital One 2019",
        "source": "Capital One",
        "date_occurred": date(2019, 3, 22),
        "date_discovered": date(2019, 7, 19),
        "records_exposed": 106_000_000,
        "data_types": [DataType.NAME, DataType.ADDRESS, DataType.PHONE, DataType.EMAIL, DataType.DOB, DataType.SSN, DataType.CREDIT_CARD],
        "description": "Capital One credit card application data exposed via misconfigured WAF.",
        "is_sensitive": True,
    },
    {
        "name": "Facebook 2019",
        "source": "Facebook",
        "date_occurred": date(2019, 4, 1),
        "date_discovered": date(2019, 4, 3),
        "records_exposed": 533_000_000,
        "data_types": [DataType.NAME, DataType.PHONE, DataType.EMAIL, DataType.DOB, DataType.GEOLOCATION],
        "description": "Facebook user records found on exposed servers including phone numbers.",
    },
    {
        "name": "Twitter 2022",
        "source": "Twitter",
        "date_occurred": date(2022, 1, 1),
        "date_discovered": date(2022, 7, 21),
        "records_exposed": 5_400_000,
        "data_types": [DataType.EMAIL, DataType.PHONE, DataType.USERNAME],
        "description": "Twitter API vulnerability exploited to link phone numbers to accounts.",
    },
    {
        "name": "Zynga 2019",
        "source": "Zynga",
        "date_occurred": date(2019, 9, 1),
        "date_discovered": date(2019, 9, 12),
        "records_exposed": 173_000_000,
        "data_types": [DataType.EMAIL, DataType.USERNAME, DataType.PASSWORD_HASH, DataType.PHONE],
        "description": "Words With Friends player data breach exposing hashed passwords.",
    },
    {
        "name": "Dubsmash 2018",
        "source": "Dubsmash",
        "date_occurred": date(2018, 12, 1),
        "date_discovered": date(2019, 2, 11),
        "records_exposed": 162_000_000,
        "data_types": [DataType.EMAIL, DataType.USERNAME, DataType.PASSWORD_HASH, DataType.NAME],
        "description": "Dubsmash user data sold on the dark web as part of a larger collection.",
    },
    {
        "name": "Under Armour / MyFitnessPal 2018",
        "source": "MyFitnessPal",
        "date_occurred": date(2018, 2, 1),
        "date_discovered": date(2018, 3, 25),
        "records_exposed": 150_000_000,
        "data_types": [DataType.EMAIL, DataType.USERNAME, DataType.PASSWORD_HASH],
        "description": "MyFitnessPal user accounts compromised with SHA1 and bcrypt hashes.",
    },
    {
        "name": "Exactis 2018",
        "source": "Exactis",
        "date_occurred": date(2018, 6, 1),
        "date_discovered": date(2018, 6, 26),
        "records_exposed": 340_000_000,
        "data_types": [DataType.NAME, DataType.EMAIL, DataType.PHONE, DataType.ADDRESS],
        "description": "Marketing data firm exposed database of nearly every US adult.",
    },
    {
        "name": "Collection #1",
        "source": "Various",
        "date_occurred": date(2019, 1, 1),
        "date_discovered": date(2019, 1, 16),
        "records_exposed": 773_000_000,
        "data_types": [DataType.EMAIL, DataType.PASSWORD],
        "description": "Massive aggregation of breached credentials posted on hacking forums.",
    },
    {
        "name": "Verifications.io 2019",
        "source": "Verifications.io",
        "date_occurred": date(2019, 2, 25),
        "date_discovered": date(2019, 3, 7),
        "records_exposed": 763_000_000,
        "data_types": [DataType.EMAIL, DataType.NAME, DataType.PHONE, DataType.ADDRESS, DataType.GENDER, DataType.DOB, DataType.EMPLOYER, DataType.IP_ADDRESS],
        "description": "Email validation service exposed massive MongoDB with personal data.",
    },
    {
        "name": "First American 2019",
        "source": "First American Financial",
        "date_occurred": date(2019, 5, 1),
        "date_discovered": date(2019, 5, 24),
        "records_exposed": 885_000_000,
        "data_types": [DataType.NAME, DataType.SSN, DataType.ADDRESS, DataType.CREDIT_CARD, DataType.EMAIL],
        "description": "Title insurance company exposed bank account numbers and SSNs.",
        "is_sensitive": True,
    },
    {
        "name": "Wattpad 2020",
        "source": "Wattpad",
        "date_occurred": date(2020, 6, 1),
        "date_discovered": date(2020, 7, 14),
        "records_exposed": 271_000_000,
        "data_types": [DataType.EMAIL, DataType.USERNAME, DataType.PASSWORD_HASH, DataType.NAME, DataType.DOB, DataType.IP_ADDRESS],
        "description": "Storytelling platform breach exposing bcrypt password hashes.",
    },
    {
        "name": "Sina Weibo 2020",
        "source": "Sina Weibo",
        "date_occurred": date(2020, 3, 1),
        "date_discovered": date(2020, 3, 19),
        "records_exposed": 538_000_000,
        "data_types": [DataType.USERNAME, DataType.NAME, DataType.PHONE, DataType.GEOLOCATION, DataType.GENDER],
        "description": "Chinese social media platform data dump with phone numbers.",
    },
    {
        "name": "CAM4 2020",
        "source": "CAM4",
        "date_occurred": date(2020, 3, 1),
        "date_discovered": date(2020, 3, 16),
        "records_exposed": 10_880_000_000,
        "data_types": [DataType.EMAIL, DataType.NAME, DataType.IP_ADDRESS, DataType.USERNAME, DataType.GEOLOCATION],
        "description": "Adult streaming site Elasticsearch cluster exposed production logs.",
        "is_sensitive": True,
    },
    {
        "name": "MGM Resorts 2020",
        "source": "MGM Resorts",
        "date_occurred": date(2019, 7, 1),
        "date_discovered": date(2020, 2, 19),
        "records_exposed": 142_000_000,
        "data_types": [DataType.NAME, DataType.EMAIL, DataType.PHONE, DataType.ADDRESS, DataType.DOB],
        "description": "Hotel guest data including celebrities and government officials.",
    },
    {
        "name": "T-Mobile 2021",
        "source": "T-Mobile",
        "date_occurred": date(2021, 8, 1),
        "date_discovered": date(2021, 8, 15),
        "records_exposed": 76_600_000,
        "data_types": [DataType.NAME, DataType.SSN, DataType.DOB, DataType.PHONE, DataType.ADDRESS],
        "description": "T-Mobile customer data including SSNs and driver license information.",
        "is_sensitive": True,
    },
    {
        "name": "Twitch 2021",
        "source": "Twitch",
        "date_occurred": date(2021, 10, 4),
        "date_discovered": date(2021, 10, 6),
        "records_exposed": 7_500_000,
        "data_types": [DataType.EMAIL, DataType.USERNAME, DataType.PASSWORD_HASH, DataType.SALARY],
        "description": "Twitch source code, internal tools, and streamer payout data leaked.",
        "is_sensitive": True,
    },
    {
        "name": "Uber 2016",
        "source": "Uber",
        "date_occurred": date(2016, 10, 1),
        "date_discovered": date(2017, 11, 21),
        "records_exposed": 57_000_000,
        "data_types": [DataType.NAME, DataType.EMAIL, DataType.PHONE],
        "description": "Uber concealed breach of rider and driver data for over a year.",
    },
    {
        "name": "Anthem 2015",
        "source": "Anthem Inc.",
        "date_occurred": date(2015, 1, 29),
        "date_discovered": date(2015, 1, 29),
        "records_exposed": 78_800_000,
        "data_types": [DataType.NAME, DataType.EMAIL, DataType.SSN, DataType.DOB, DataType.ADDRESS, DataType.EMPLOYER],
        "description": "Health insurer breach exposing SSNs and employment information.",
        "is_sensitive": True,
    },
    {
        "name": "eBay 2014",
        "source": "eBay",
        "date_occurred": date(2014, 2, 1),
        "date_discovered": date(2014, 5, 21),
        "records_exposed": 145_000_000,
        "data_types": [DataType.EMAIL, DataType.PASSWORD_HASH, DataType.NAME, DataType.PHONE, DataType.ADDRESS, DataType.DOB],
        "description": "eBay employee credentials used to access user database.",
    },
    {
        "name": "Target 2013",
        "source": "Target",
        "date_occurred": date(2013, 11, 27),
        "date_discovered": date(2013, 12, 15),
        "records_exposed": 110_000_000,
        "data_types": [DataType.NAME, DataType.CREDIT_CARD, DataType.EMAIL, DataType.ADDRESS, DataType.PHONE],
        "description": "Point-of-sale malware captured 40M credit card numbers plus 70M contact records.",
        "is_sensitive": True,
    },
    {
        "name": "Home Depot 2014",
        "source": "Home Depot",
        "date_occurred": date(2014, 4, 1),
        "date_discovered": date(2014, 9, 8),
        "records_exposed": 56_000_000,
        "data_types": [DataType.CREDIT_CARD, DataType.EMAIL, DataType.NAME],
        "description": "Self-checkout POS systems compromised exposing payment card data.",
        "is_sensitive": True,
    },
    {
        "name": "JP Morgan Chase 2014",
        "source": "JP Morgan Chase",
        "date_occurred": date(2014, 6, 1),
        "date_discovered": date(2014, 8, 27),
        "records_exposed": 83_000_000,
        "data_types": [DataType.NAME, DataType.EMAIL, DataType.PHONE, DataType.ADDRESS],
        "description": "Largest bank breach in US history compromising contact information.",
    },
    {
        "name": "SolarWinds 2020",
        "source": "SolarWinds",
        "date_occurred": date(2020, 3, 1),
        "date_discovered": date(2020, 12, 13),
        "records_exposed": 18_000,
        "data_types": [DataType.AUTH_TOKEN, DataType.EMAIL],
        "description": "Supply chain attack compromising Orion software updates; affected government agencies.",
        "is_sensitive": True,
    },
    {
        "name": "LastPass 2022",
        "source": "LastPass",
        "date_occurred": date(2022, 8, 1),
        "date_discovered": date(2022, 12, 22),
        "records_exposed": 33_000_000,
        "data_types": [DataType.EMAIL, DataType.PASSWORD_HASH, DataType.NAME, DataType.PHONE, DataType.ADDRESS],
        "description": "Password manager vault data exfiltrated including encrypted password vaults.",
        "is_sensitive": True,
    },
    {
        "name": "Optus 2022",
        "source": "Optus",
        "date_occurred": date(2022, 9, 1),
        "date_discovered": date(2022, 9, 22),
        "records_exposed": 11_200_000,
        "data_types": [DataType.NAME, DataType.EMAIL, DataType.PHONE, DataType.ADDRESS, DataType.DOB, DataType.SSN],
        "description": "Australian telco breach exposing passport and driver license numbers.",
        "is_sensitive": True,
    },
    {
        "name": "MOVEit 2023",
        "source": "MOVEit Transfer",
        "date_occurred": date(2023, 5, 27),
        "date_discovered": date(2023, 5, 31),
        "records_exposed": 77_000_000,
        "data_types": [DataType.NAME, DataType.EMAIL, DataType.SSN, DataType.DOB, DataType.ADDRESS],
        "description": "SQL injection in MOVEit file transfer software exploited by Cl0p ransomware group.",
        "is_sensitive": True,
    },
]


class BreachDatabase:
    """Database of known major data breaches."""

    def __init__(self) -> None:
        self._breaches: list[Breach] = [Breach(**record) for record in _BREACH_RECORDS]

    @property
    def breaches(self) -> list[Breach]:
        """Return all breach records."""
        return list(self._breaches)

    @property
    def total_records_exposed(self) -> int:
        """Return total number of records exposed across all breaches."""
        return sum(b.records_exposed for b in self._breaches)

    def search_by_source(self, source: str) -> list[Breach]:
        """Find breaches matching a source name (case-insensitive partial match)."""
        source_lower = source.lower()
        return [b for b in self._breaches if source_lower in b.source.lower() or source_lower in b.name.lower()]

    def search_by_data_type(self, data_type: DataType) -> list[Breach]:
        """Find breaches that exposed a specific data type."""
        return [b for b in self._breaches if data_type in b.data_types]

    def search_by_date_range(self, start: date, end: date) -> list[Breach]:
        """Find breaches that occurred within a date range."""
        return [b for b in self._breaches if start <= b.date_occurred <= end]

    def get_by_severity(self, severity: str) -> list[Breach]:
        """Filter breaches by computed severity level."""
        return [b for b in self._breaches if b.severity.value == severity]

    def get_largest(self, n: int = 10) -> list[Breach]:
        """Return the N largest breaches by records exposed."""
        return sorted(self._breaches, key=lambda b: b.records_exposed, reverse=True)[:n]

    def get_most_recent(self, n: int = 10) -> list[Breach]:
        """Return the N most recent breaches."""
        return sorted(self._breaches, key=lambda b: b.date_occurred, reverse=True)[:n]

    def get_sensitive_breaches(self) -> list[Breach]:
        """Return breaches marked as containing sensitive data."""
        return [b for b in self._breaches if b.is_sensitive]

    def stats(self) -> dict:
        """Return summary statistics about the breach database."""
        from collections import Counter

        data_type_counts: Counter[str] = Counter()
        for b in self._breaches:
            for dt in b.data_types:
                data_type_counts[dt.value] += 1

        years = [b.date_occurred.year for b in self._breaches]
        year_counts = Counter(years)

        return {
            "total_breaches": len(self._breaches),
            "total_records_exposed": self.total_records_exposed,
            "date_range": f"{min(years)}-{max(years)}",
            "sensitive_breaches": len(self.get_sensitive_breaches()),
            "data_type_frequency": dict(data_type_counts.most_common()),
            "breaches_by_year": dict(sorted(year_counts.items())),
        }
