"""Finding ranking utilities."""

from __future__ import annotations


def leverage_score(ease: float, blast: float, likelihood: float) -> float:
    """Compute leverage score based on weighted components."""
    return round(max(min(ease * 0.4 + blast * 0.35 + likelihood * 0.25, 10.0), 0.0), 2)
