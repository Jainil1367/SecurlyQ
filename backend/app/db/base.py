"""Declarative base class that every table model inherits from."""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass
