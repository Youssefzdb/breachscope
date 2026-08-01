"""
BreachScope — Ingestion Engine
Parsers for SQL dumps, CSV, JSON, text breach files.
Extracts emails, usernames, passwords, phones and indexes them.
"""
import re
import csv
import json
import hashlib
import sqlite3
from pathlib import Path
from datetime import datetime
from typing import AsyncIterator, Optional

from ..core.crypto import (
    sha256_hash, sha1_hash, argon2_hash,
    normalize_email, normalize_phone, normalize_username, record_hash
)
from ..core.config import settings
from ..core.models import Breach, BreachRecord
from ..core.database import AsyncSessionLocal

# Email regex — RFC 5322 simplified
EMAIL_RE = re.compile(
    r'\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b',
    re.IGNORECASE
)

# Phone regex — international format
PHONE_RE = re.compile(
    r'\b(\+?\d{1,3}?[\s.-]?\(?\d{1,4}?\)?[\s.-]?\d{3,4}[\s.-]?\d{3,4})\b'
)

# Username regex — common patterns in dumps
USERNAME_RE = re.compile(
    r'(?:username|user|login|uname|nick|nickname|account)\s*[:=]\s*([^\s,;|]+)',
    re.IGNORECASE
)

# Password patterns
PASSWORD_RE = re.compile(
    r'(?:password|passwd|pwd|pass|hash)\s*[:=]\s*([^\s,;|]+)',
    re.IGNORECASE
)

# Field delimiter patterns in text dumps
DELIMITERS = [':', ';', '|', ',', '\t']


class ParsedRecord:
    """A single record extracted from a breach file."""
    def __init__(self):
        self.email: str = ""
        self.username: str = ""
        self.phone: str = ""
        self.password: str = ""
        self.password_hash_raw: str = ""  # original hash from dump
        self.ip_address: str = ""
        self.full_name: str = ""
        self.country: str = ""
        self.city: str = ""
        self.extra: dict = {}

    def to_breach_record(self, breach_id: int) -> BreachRecord:
        """Convert to ORM BreachRecord — NEVER stores plaintext passwords."""
        return BreachRecord(
            breach_id=breach_id,
            email=self.email if self.email else None,
            email_hash=sha256_hash(self.email) if self.email else None,
            username=self.username if self.username else None,
            username_hash=sha256_hash(self.username) if self.username else None,
            phone=self.phone if self.phone else None,
            phone_hash=sha256_hash(self.phone) if self.phone else None,
            password_hash_argon2=argon2_hash(self.password) if self.password else None,
            password_hash_sha1=sha1_hash(self.password) if self.password else None,
            ip_address=self.ip_address if self.ip_address else None,
            full_name=self.full_name if self.full_name else None,
            country=self.country if self.country else None,
            city=self.city if self.city else None,
            extra_data=self.extra if self.extra else None,
            record_hash=record_hash(self.email, self.username, self.phone, self.password, self.extra),
        )


def detect_format(file_path: str) -> str:
    """Detect file format from content."""
    path = Path(file_path)
    ext = path.suffix.lower().lstrip('.')

    if ext in ('sql', 'dump', 'sql.gz'):
        return 'sql'
    elif ext == 'csv':
        return 'csv'
    elif ext in ('json', 'jsonl', 'ndjson'):
        return 'json'
    elif ext in ('txt', 'log', 'lst', 'list'):
        return 'text'
    elif ext == 'tsv':
        return 'tsv'
    else:
        # Try to detect from content
        with open(file_path, 'r', errors='ignore') as f:
            first_chunk = f.read(4096)

        if first_chunk.lstrip().upper().startswith(('INSERT', 'CREATE', 'COPY')):
            return 'sql'
        elif first_chunk.strip().startswith('{') or first_chunk.strip().startswith('['):
            return 'json'
        elif '|' in first_chunk.split('\n')[0] or '\t' in first_chunk.split('\n')[0]:
            return 'csv'
        else:
            return 'text'


def parse_sql_dump(file_path: str) -> AsyncIterator[ParsedRecord]:
    """Parse SQL dump files — extracts INSERT statements."""
    insert_re = re.compile(
        r'INSERT\s+INTO\s+\S+(?:\s*\([^)]*\))?\s*VALUES\s*(.+?);',
        re.IGNORECASE | re.DOTALL
    )

    with open(file_path, 'r', errors='ignore') as f:
        buffer = ""
        for line in f:
            buffer += line
            if buffer.count(';') >= 1:
                for match in insert_re.finditer(buffer):
                    values_str = match.group(1)
                    # Parse values — handle nested parens
                    values = parse_sql_values(values_str)
                    for val_row in values:
                        record = ParsedRecord()
                        for i, val in enumerate(val_row):
                            val = str(val).strip("'\"")
                            # Try to identify field type by content
                            if EMAIL_RE.match(val):
                                record.email = normalize_email(val)
                            elif record.email and not record.password and val:
                                # After email, next non-numeric is likely password
                                record.password = val
                            elif not record.username and val and len(val) < 64:
                                record.username = val
                        if record.email:
                            yield record
                buffer = ""


def parse_sql_values(values_str: str) -> list:
    """Parse SQL VALUES into a list of rows."""
    rows = []
    # Split by ),(
    val_re = re.compile(r"\(([^)]*)\)")
    for match in val_re.finditer(values_str):
        row_str = match.group(1)
        # Split by comma, respecting quotes
        values = []
        current = ""
        in_quote = False
        for char in row_str:
            if char == "'" and not in_quote:
                in_quote = True
            elif char == "'" and in_quote:
                in_quote = False
            elif char == ',' and not in_quote:
                values.append(current.strip())
                current = ""
            else:
                current += char
        values.append(current.strip())
        rows.append(values)
    return rows


def parse_csv_file(file_path: str, delimiter: str = ',') -> AsyncIterator[ParsedRecord]:
    """Parse CSV/TSV files — auto-detects columns by header or content."""
    with open(file_path, 'r', errors='ignore', newline='') as f:
        reader = csv.reader(f, delimiter=delimiter)

        # Try to read header
        try:
            header = next(reader)
            header = [h.strip().lower() for h in header]
        except StopIteration:
            return

        # Map header columns to fields
        col_map = {}
        for i, col in enumerate(header):
            if col in ('email', 'e-mail', 'mail', 'email_address'):
                col_map['email'] = i
            elif col in ('username', 'user', 'login', 'uname', 'nick', 'nickname'):
                col_map['username'] = i
            elif col in ('password', 'passwd', 'pwd', 'pass', 'hash', 'password_hash'):
                col_map['password'] = i
            elif col in ('phone', 'mobile', 'tel', 'telephone'):
                col_map['phone'] = i
            elif col in ('ip', 'ip_address', 'ip_addr'):
                col_map['ip_address'] = i
            elif col in ('name', 'full_name', 'fullname', 'first_name'):
                col_map['full_name'] = i
            elif col in ('country', 'country_code'):
                col_map['country'] = i
            elif col in ('city', 'location'):
                col_map['city'] = i

        for row in reader:
            record = ParsedRecord()
            for field, idx in col_map.items():
                if idx < len(row):
                    val = row[idx].strip()
                    if field == 'email':
                        record.email = normalize_email(val)
                    elif field == 'username':
                        record.username = normalize_username(val)
                    elif field == 'password':
                        record.password = val
                    elif field == 'phone':
                        record.phone = normalize_phone(val)
                    elif field == 'ip_address':
                        record.ip_address = val
                    elif field == 'full_name':
                        record.full_name = val
                    elif field == 'country':
                        record.country = val
                    elif field == 'city':
                        record.city = val

            # Also try regex extraction for fields not in header
            if not record.email:
                for val in row:
                    m = EMAIL_RE.match(val)
                    if m:
                        record.email = normalize_email(m.group(1))
                        break

            if record.email or record.username:
                yield record


def parse_json_file(file_path: str) -> AsyncIterator[ParsedRecord]:
    """Parse JSON/JSONL files."""
    with open(file_path, 'r', errors='ignore') as f:
        content = f.read().strip()

    if content.startswith('['):
        # JSON array
        data = json.loads(content) if content else []
        records = data if isinstance(data, list) else [data]
    elif content.startswith('{'):
        # JSONL — one object per line, or single object
        records = []
        for line in content.split('\n'):
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    else:
        # JSONL
        records = []
        for line in content.split('\n'):
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    for item in records:
        record = ParsedRecord()
        for key, val in item.items():
            key = key.lower().strip()
            val = str(val).strip() if val else ""
            if key in ('email', 'e-mail', 'mail'):
                record.email = normalize_email(val)
            elif key in ('username', 'user', 'login', 'uname'):
                record.username = normalize_username(val)
            elif key in ('password', 'passwd', 'pwd', 'pass'):
                record.password = val
            elif key in ('phone', 'mobile', 'tel'):
                record.phone = normalize_phone(val)
            elif key in ('ip', 'ip_address'):
                record.ip_address = val
            elif key in ('name', 'full_name'):
                record.full_name = val
            elif key in ('country',):
                record.country = val
            elif key in ('city',):
                record.city = val
            else:
                record.extra[key] = val

        if record.email or record.username:
            yield record


def parse_text_dump(file_path: str) -> AsyncIterator[ParsedRecord]:
    """Parse plain text dumps — email:password format or similar."""
    with open(file_path, 'r', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            record = ParsedRecord()

            # Try delimiter-based parsing
            parts = None
            for delim in DELIMITERS:
                if delim in line:
                    parts = line.split(delim)
                    break

            if parts:
                # email:password or email:user:pass format
                for i, part in enumerate(parts):
                    part = part.strip()
                    if EMAIL_RE.match(part):
                        record.email = normalize_email(part)
                    elif not record.password and i > 0 and part:
                        record.password = part
                    elif not record.username and part:
                        record.username = part
            else:
                # Try regex extraction
                email_match = EMAIL_RE.search(line)
                if email_match:
                    record.email = normalize_email(email_match.group(1))

                phone_match = PHONE_RE.search(line)
                if phone_match:
                    record.phone = normalize_phone(phone_match.group(1))

            if record.email or record.username:
                yield record


async def ingest_file(file_path: str, breach_name: str,
                      source_name: str = None,
                      breach_date: datetime = None,
                      description: str = None) -> dict:
    """
    Main ingestion function — parses and indexes a breach file.

    Args:
        file_path: Path to the breach file
        breach_name: Unique name for this breach
        source_name: The service that was breached (e.g., "LinkedIn")
        breach_date: When the breach occurred
        description: Description of the breach

    Returns:
        dict with ingestion stats
    """
    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    fmt = detect_format(str(file_path))
    file_hash = hashlib.sha256(file_path.read_bytes()).hexdigest()

    print(f"[*] Ingesting {file_path.name} as {fmt} format...")

    # Select parser based on format
    if fmt == 'sql':
        parser = parse_sql_dump
    elif fmt == 'csv':
        parser = lambda f: parse_csv_file(f, ',')
    elif fmt == 'tsv':
        parser = lambda f: parse_csv_file(f, '\t')
    elif fmt == 'json':
        parser = parse_json_file
    else:
        parser = parse_text_dump

    # Create breach record in database
    async with AsyncSessionLocal() as session:
        # Check if breach already exists
        from sqlalchemy import select
        existing = await session.execute(
            select(Breach).where(Breach.name == breach_name)
        )
        if existing.scalar_one_or_none():
            raise ValueError(f"Breach '{breach_name}' already exists")

        breach = Breach(
            name=breach_name,
            source_name=source_name or breach_name,
            breach_date=breach_date,
            description=description,
            file_path=str(file_path),
            file_hash=file_hash,
            data_types=[],
        )
        session.add(breach)
        await session.commit()
        await session.refresh(breach)
        breach_id = breach.id

    # Parse and index records
    record_count = 0
    batch_size = 5000
    batch = []
    data_types_found = set()
    seen_hashes = set()

    for record in parser(str(file_path)):
        # Skip duplicates within this breach
        r_hash = record_hash(
            record.email, record.username,
            record.phone, record.password, record.extra
        )
        if r_hash in seen_hashes:
            continue
        seen_hashes.add(r_hash)

        br = record.to_breach_record(breach_id)
        batch.append(br)

        if record.email:
            data_types_found.add("emails")
        if record.username:
            data_types_found.add("usernames")
        if record.password:
            data_types_found.add("passwords")
        if record.phone:
            data_types_found.add("phones")

        if len(batch) >= batch_size:
            async with AsyncSessionLocal() as session:
                session.add_all(batch)
                await session.commit()
            record_count += len(batch)
            print(f"  [*] Indexed {record_count:,} records...")
            batch = []

    # Insert remaining records
    if batch:
        async with AsyncSessionLocal() as session:
            session.add_all(batch)
            await session.commit()
        record_count += len(batch)

    # Update breach stats
    async with AsyncSessionLocal() as session:
        from sqlalchemy import update
        await session.execute(
            update(Breach)
            .where(Breach.id == breach_id)
            .values(record_count=record_count, data_types=list(data_types_found))
        )
        await session.commit()

    stats = {
        "breach_name": breach_name,
        "breach_id": breach_id,
        "format": fmt,
        "records_indexed": record_count,
        "data_types": list(data_types_found),
        "file_hash": file_hash,
    }
    print(f"[+] Ingestion complete: {record_count:,} records indexed")
    return stats
