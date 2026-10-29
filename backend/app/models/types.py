"""Shared column types.

Lesson: PostgreSQL has a binary JSON type (JSONB) that can be indexed and
queried. SQLite (which we use for fast unit tests) does not. `with_variant`
says: "use plain JSON generically, but JSONB when talking to PostgreSQL".
"""

from sqlalchemy import JSON
from sqlalchemy.dialects.postgresql import JSONB

JsonType = JSON().with_variant(JSONB(), "postgresql")
