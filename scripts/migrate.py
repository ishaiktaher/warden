#!/usr/bin/env python3
"""Apply Warden PostgreSQL schema changes under a dedicated migration role."""

from __future__ import annotations

import os

from dotenv import load_dotenv

from control_plane.config import ROOT
from control_plane.database import PostgresDatabase


def main() -> None:
    load_dotenv(ROOT / ".env")
    database_url = os.getenv("DATABASE_URL", "").strip()
    if not database_url.startswith(("postgresql://", "postgresql+psycopg://")):
        raise SystemExit("DATABASE_URL must be a PostgreSQL connection string")
    database = PostgresDatabase(database_url, migrate=True)
    database.pool.close()
    print("Warden PostgreSQL schema migration complete")


if __name__ == "__main__":
    main()
