"""Small helpers shared by adapters and the evidence engine."""

from collections.abc import Sequence

from rea_mcp.core.models import BackendItem, BackendResult


class GenerationCounter:
    """Change counter for a backend; the router keeps its own authoritative epoch on top."""

    def __init__(self) -> None:
        self._value = 1

    @property
    def value(self) -> int:
        return self._value

    def bump(self) -> None:
        self._value += 1


def window(items: Sequence[BackendItem], limit: int, offset: int, generation: int) -> BackendResult:
    """Sources produce ``limit + 1`` entries; the extra one only proves that more remain."""
    more = len(items) > limit
    return BackendResult(
        items=tuple(items[:limit]), next_offset=offset + limit if more else None, generation=generation
    )
