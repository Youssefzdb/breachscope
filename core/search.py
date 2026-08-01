"""
BreachScope — Search Engine
Privacy-first search: returns boolean only, never exposes raw data.
"""
from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession
from ..core.models import Breach, BreachRecord
from ..core.crypto import normalize_email, normalize_username, normalize_phone, sha256_hash
from typing import Optional


class SearchResult:
    """Boolean-only search result — no data exposed."""
    def __init__(self, query: str, query_type: str):
        self.query = query
        self.query_type = query_type  # email, username, phone, domain
        self.found: bool = False
        self.breach_count: int = 0
        self.breach_names: list = []  # only names, not data
        self.data_types_found: list = []

    def to_dict(self) -> dict:
        return {
            "query": self.query,
            "query_type": self.query_type,
            "compromised": self.found,
            "breach_count": self.breach_count,
            "breaches": [
                {"name": name, "verified": True} for name in self.breach_names
            ],
            "data_types": self.data_types_found,
            "data_exposed": False,  # True only after verification
            "message": "Your data was found in breaches. Verify ownership to see details."
                if self.found else "No breaches found. You're safe!"
        }


async def search_by_email(session: AsyncSession, email: str) -> SearchResult:
    """Search by email — returns boolean only."""
    email = normalize_email(email)
    email_hash = sha256_hash(email)
    result = SearchResult(email, "email")

    stmt = (
        select(Breach, BreachRecord)
        .join(BreachRecord, BreachRecord.breach_id == Breach.id)
        .where(BreachRecord.email_hash == email_hash)
    )
    rows = await session.execute(stmt)
    records = rows.all()

    if records:
        result.found = True
        result.breach_count = len(records)
        result.breach_names = list(set(r[0].name for r in records))
        all_types = set()
        for breach, record in records:
            all_types.update(breach.data_types or [])
        result.data_types_found = list(all_types)

    return result


async def search_by_username(session: AsyncSession, username: str) -> SearchResult:
    """Search by username — returns boolean only."""
    username = normalize_username(username)
    username_hash = sha256_hash(username)
    result = SearchResult(username, "username")

    stmt = (
        select(Breach, BreachRecord)
        .join(BreachRecord, BreachRecord.breach_id == Breach.id)
        .where(BreachRecord.username_hash == username_hash)
    )
    rows = await session.execute(stmt)
    records = rows.all()

    if records:
        result.found = True
        result.breach_count = len(records)
        result.breach_names = list(set(r[0].name for r in records))

    return result


async def search_by_phone(session: AsyncSession, phone: str) -> SearchResult:
    """Search by phone — returns boolean only."""
    phone = normalize_phone(phone)
    phone_hash = sha256_hash(phone)
    result = SearchResult(phone, "phone")

    stmt = (
        select(Breach, BreachRecord)
        .join(BreachRecord, BreachRecord.breach_id == Breach.id)
        .where(BreachRecord.phone_hash == phone_hash)
    )
    rows = await session.execute(stmt)
    records = rows.all()

    if records:
        result.found = True
        result.breach_count = len(records)
        result.breach_names = list(set(r[0].name for r in records))

    return result


async def search_by_domain(session: AsyncSession, domain: str) -> SearchResult:
    """Search by domain — returns count of compromised emails only."""
    domain = domain.strip().lower()
    result = SearchResult(domain, "domain")

    stmt = (
        select(func.count(BreachRecord.id))
        .where(BreachRecord.email.like(f"%@{domain}"))
    )
    count = await session.execute(stmt)
    result.breach_count = count.scalar() or 0
    result.found = result.breach_count > 0
    result.breach_names = []

    return result


async def get_verified_data(session: AsyncSession, email: str) -> dict:
    """
    Get full breach data for a verified email.
    This is ONLY called after OTP verification.

    Returns breach details + record info — but NEVER plaintext passwords.
    Password hashes are returned for the owner to cross-check.
    """
    email = normalize_email(email)
    email_hash = sha256_hash(email)
    result = {
        "email": email,
        "breaches": [],
        "total_breaches": 0,
    }

    stmt = (
        select(Breach, BreachRecord)
        .join(BreachRecord, BreachRecord.breach_id == Breach.id)
        .where(BreachRecord.email_hash == email_hash)
        .order_by(Breach.breach_date.desc())
    )
    rows = await session.execute(stmt)
    records = rows.all()

    for breach, record in records:
        breach_info = {
            "breach_name": breach.name,
            "source": breach.source_name,
            "breach_date": breach.breach_date.isoformat() if breach.breach_date else None,
            "ingested_date": breach.ingested_date.isoformat() if breach.ingested_date else None,
            "description": breach.description,
            "data_types": breach.data_types,
            "record": {
                "username": record.username,
                "phone": record.phone,
                "ip_address": record.ip_address,
                "full_name": record.full_name,
                "country": record.country,
                "city": record.city,
                "extra_data": record.extra_data,
                # Return password hash (NOT plaintext) for verification
                "password_sha1_prefix": record.password_hash_sha1[:5] if record.password_hash_sha1 else None,
                "password_sha1_suffix": record.password_hash_sha1[-5:] if record.password_hash_sha1 else None,
                "password_present": bool(record.password_hash_argon2),
            }
        }
        result["breaches"].append(breach_info)

    result["total_breaches"] = len(result["breaches"])
    return result


async def get_stats(session: AsyncSession) -> dict:
    """Get platform statistics."""
    breach_count = await session.execute(select(func.count(Breach.id)))
    record_count = await session.execute(select(func.count(BreachRecord.id)))

    return {
        "total_breaches": breach_count.scalar() or 0,
        "total_records": record_count.scalar() or 0,
        "breaches": [
            {
                "name": b.name,
                "source": b.source_name,
                "records": b.record_count,
                "date": b.breach_date.isoformat() if b.breach_date else None,
                "data_types": b.data_types,
            }
            for b in (await session.execute(select(Breach).order_by(Breach.ingested_date.desc()))).scalars()
        ]
    }
