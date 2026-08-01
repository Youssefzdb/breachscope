"""
BreachScope — Database Models (SQLAlchemy)
"""
from sqlalchemy import (
    Column, Integer, String, Text, DateTime, Boolean, ForeignKey,
    JSON, Index, UniqueConstraint, LargeBinary
)
from sqlalchemy.orm import declarative_base, relationship
from datetime import datetime, timezone

Base = declarative_base()


def utcnow():
    return datetime.now(timezone.utc)


class Breach(Base):
    """Represents a single breach/dump that was ingested."""
    __tablename__ = "breaches"

    id = Column(Integer, primary_key=True)
    name = Column(String(256), nullable=False, unique=True)
    source_name = Column(String(256))  # e.g., "LinkedIn", "Adobe"
    breach_date = Column(DateTime)      # when the breach occurred
    ingested_date = Column(DateTime, default=utcnow)
    description = Column(Text)
    record_count = Column(Integer, default=0)
    data_types = Column(JSON, default=list)  # ["emails", "passwords", "usernames", "phones"]
    severity = Column(String(32), default="high")  # low, medium, high, critical
    is_verified = Column(Boolean, default=False)
    file_path = Column(String(512))  # original file path
    file_hash = Column(String(64))    # sha256 of source file

    records = relationship("BreachRecord", back_populates="breach", cascade="all, delete-orphan")

    # source_name and breach_date indexed via column definitions


class BreachRecord(Base):
    """Individual record from a breach — indexed for fast lookup.
    Stores ONLY hashes of sensitive fields, never plaintext passwords."""
    __tablename__ = "breach_records"

    id = Column(Integer, primary_key=True)
    breach_id = Column(Integer, ForeignKey("breaches.id", ondelete="CASCADE"), nullable=False)
    email = Column(String(512), index=True)       # stored as-is for lookup
    email_hash = Column(String(64), index=True)   # sha256 for fast matching
    username = Column(String(256), index=True)
    username_hash = Column(String(64), index=True)
    phone = Column(String(64), index=True)
    phone_hash = Column(String(64), index=True)
    password_hash_argon2 = Column(String(256))     # Argon2 hash of password (never plaintext)
    password_hash_sha1 = Column(String(40))       # SHA1 (HIBP-style, for cross-checking)
    ip_address = Column(String(45))
    full_name = Column(String(256))
    country = Column(String(64))
    city = Column(String(64))
    extra_data = Column(JSON, default=dict)       # any other fields from the dump
    record_hash = Column(String(64))              # hash of entire record for dedup

    breach = relationship("Breach", back_populates="records")

    __table_args__ = (
        Index("ix_records_email_hash", "email_hash"),
        Index("ix_records_username_hash", "username_hash"),
        Index("ix_records_phone_hash", "phone_hash"),
        Index("ix_records_breach", "breach_id"),
    )


class User(Base):
    """Registered user — for verification and alerts."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    email = Column(String(512), nullable=False, unique=True)
    email_verified = Column(Boolean, default=False)
    created_date = Column(DateTime, default=utcnow)
    is_admin = Column(Boolean, default=False)
    api_key = Column(String(64), unique=True)  # for API access
    last_login = Column(DateTime)


class VerificationToken(Base):
    """OTP tokens for email verification before showing breach data."""
    __tablename__ = "verification_tokens"

    id = Column(Integer, primary_key=True)
    email = Column(String(512), nullable=False, index=True)
    token_hash = Column(String(256), nullable=False)  # Argon2 hash of OTP
    created_date = Column(DateTime, default=utcnow)
    expires_date = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False)
    ip_address = Column(String(45))
    query_identifier = Column(String(256))  # what they searched for


class MonitorAlert(Base):
    """User subscribes to be notified when their email appears in new breaches."""
    __tablename__ = "monitor_alerts"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    email = Column(String(512), nullable=False, index=True)
    last_checked = Column(DateTime, default=utcnow)
    last_breach_count = Column(Integer, default=0)
    is_active = Column(Boolean, default=True)
    notification_email = Column(String(512))


class SearchLog(Base):
    """Audit log of all searches — for compliance and rate limiting."""
    __tablename__ = "search_logs"

    id = Column(Integer, primary_key=True)
    query = Column(String(512), nullable=False)
    query_type = Column(String(32))  # email, username, phone, domain
    result_found = Column(Boolean)
    ip_address = Column(String(45))
    user_agent = Column(String(256))
    timestamp = Column(DateTime, default=utcnow, index=True)

    # timestamp already indexed via column definition
