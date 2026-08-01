# BreachScope 🔍

**Advanced Breach Intelligence Platform** — Index, search, and verify leaked credentials with privacy-first design.

## Overview

BreachScope is a self-hosted breach intelligence tool that allows security researchers and organizations to:
- **Index** breach data from various formats (SQL dumps, CSV, JSON, text)
- **Search** by email, username, domain, or phone — boolean result only (compromised/not)
- **Verify** ownership via email OTP before revealing any breach data
- **Monitor** alerts when new breach data matches your identifiers
- **API** access for integration with existing security tooling

## Privacy Model

```
User searches email → BreachScope returns: YES/NO only
User verifies email ownership (OTP) → BreachScope shows ONLY their data
No full database dumps are ever exposed
No plaintext passwords are stored (Argon2 hashes only)
```

## Quick Start

```bash
pip install -r requirements.txt
python -m breachscope.init_db
python -m breachscope.api.server
```

## Architecture

```
breachscope/
├── core/           # Database models, indexing engine, search engine
├── ingestion/      # Parsers for SQL, CSV, JSON, text breach files
├── api/            # FastAPI REST API + JWT auth
├── web/            # Web dashboard (Jinja2 templates)
├── utils/          # Hashing, email verification, helpers
├── data/           # Breach data files (gitignored)
└── indexes/        # SQLite FTS5 indexes (gitignored)
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/search` | Search by email/username (boolean only) |
| POST | `/api/verify/request` | Request OTP for data access |
| POST | `/api/verify/confirm` | Confirm OTP + get breach data |
| POST | `/api/ingest` | Upload breach file (admin only) |
| GET  | `/api/breaches` | List indexed breaches |
| POST | `/api/alerts` | Create monitor alert |
| GET  | `/api/stats` | Platform statistics |

## Disclaimer

For authorized security research and defensive purposes only. Users are responsible for compliance with applicable laws regarding breach data handling in their jurisdiction.

## License

MIT
