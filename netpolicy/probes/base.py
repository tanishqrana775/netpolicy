"""Base probe abstract class and interface definitions."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from netpolicy.models import Observation, Target

if TYPE_CHECKING:
    from netpolicy.engine.context import Context


class Probe(ABC):
    """Abstract base class for all network probes.

    Probes only record raw observations (what was seen: replies, flags, TTLs,
    ICMP type/code, timings). They never decide what it means.
    """

    name: str = "base"
    requires_root: bool = False

    @abstractmethod
    def run(self, ctx: Context, target: Target) -> list[Observation]:
        """Execute probe against target and return raw observations without interpretation."""
        raise NotImplementedError


# Backwards compatibility alias
BaseProbe = Probe
