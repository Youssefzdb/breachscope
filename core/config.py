"""
BreachScope — Configuration
"""
from pydantic_settings import BaseSettings
from pathlib import Path


class Settings(BaseSettings):
    # Database
    db_path: str = "breachscope/data/breachscope.db"
    index_path: str = "breachscope/indexes/fts5_index"

    # API
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    secret_key: str = "change-this-in-production-use-a-strong-random-key"

    # Security
    otp_ttl_seconds: int = 600  # 10 minutes
    otp_length: int = 6
    jwt_ttl_seconds: int = 3600
    argon2_time_cost: int = 3
    argon2_memory_cost: int = 65536
    argon2_parallelism: int = 4

    # Rate limiting
    rate_limit_search: int = 30  # per minute
    rate_limit_verify: int = 5   # per minute

    # Data
    max_upload_size_mb: int = 500
    supported_formats: list = ["sql", "csv", "json", "txt", "tsv"]

    # Paths
    base_dir: Path = Path(__file__).parent

    class Config:
        env_file = ".env"


settings = Settings()
