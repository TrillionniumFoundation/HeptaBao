"""Immutable in-process authority from the actual auto-auth token owner."""
from dataclasses import dataclass


@dataclass(frozen=True, repr=False)
class TokenAuthority:
    phase: str
    generation: int
    token_hash: str
    wall_deadline: float
    mono_deadline: float
    observed_wall: float
