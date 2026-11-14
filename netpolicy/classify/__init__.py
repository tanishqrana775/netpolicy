"""Classification engine containing pure functions to analyze raw observations.

Design rule: list[Observation] -> Verdict with confidence levels and human-readable evidence.
Strictly zero I/O within classifiers.
"""

__all__ = ["tcp", "dns", "http"]
