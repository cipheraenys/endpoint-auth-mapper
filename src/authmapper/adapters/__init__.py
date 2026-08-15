"""Framework adapters and the registry the runner dispatches through."""

from __future__ import annotations

from collections.abc import Callable

from authmapper.core.v2 import Adapter

from .express import ExpressAdapter
from .express_semantics import build_express_graph

__all__ = ["ADAPTERS", "ExpressAdapter", "build_express_graph", "get_adapter"]

ADAPTERS: dict[str, Callable[[], Adapter]] = {
    ExpressAdapter.id: ExpressAdapter,
}


def get_adapter(adapter_id: str) -> Adapter:
    """Instantiate a registered adapter, or raise KeyError naming the known ids."""
    try:
        factory = ADAPTERS[adapter_id]
    except KeyError:
        known = ", ".join(sorted(ADAPTERS)) or "none"
        raise KeyError(f"unknown adapter {adapter_id!r}; registered adapters: {known}") from None
    return factory()
