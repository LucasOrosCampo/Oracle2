from sqlalchemy import Integer, String, Text, Float
from sqlalchemy.orm import Mapped, relationship, mapped_column
from sqlalchemy.sql import func
from data.models.base import Base
from typing import TYPE_CHECKING


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[str] = mapped_column(
        String, server_default=func.now(), nullable=False
    )
    updated_at: Mapped[str] = mapped_column(
        String, server_default=func.now(), onupdate=func.now(), nullable=False
    )
    username: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    email: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    password_hash: Mapped[str] = mapped_column(String, nullable=False)
    tokens_spent_lifetime: Mapped[float] = mapped_column(
        Float, nullable=False, default=0
    )
    tokens_spent_current_month: Mapped[float] = mapped_column(
        Float, nullable=False, default=0
    )
    tokens_spent_counter: Mapped[float] = mapped_column(
        Float, nullable=False, default=0
    )
    home_address: Mapped[str] = mapped_column(String, nullable=False, default="")
    self_assessment: Mapped[str] = mapped_column(Text, nullable=False, default="")
    job_prototype: Mapped[str] = mapped_column(Text, nullable=False, default="")
    job_preferences: Mapped[str] = mapped_column(Text, nullable=False, default="")
    job_dislikes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    desired_compensation: Mapped[str] = mapped_column(
        String, nullable=False, default=""
    )
    cover_letter: Mapped[str] = mapped_column(Text, nullable=False, default="")
    resume: Mapped[str] = mapped_column(Text, nullable=False, default="")
    encoded_openai_api_key: Mapped[str] = mapped_column(
        String, nullable=False, default=""
    )

    # OPTIONS
    duplicate_behavior: Mapped[str] = mapped_column(
        String, nullable=False, default="skip_duplicates"
    )

    # UTILS
    role: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    def __repr__(self):
        return f"{self.id}, {self.username}"
