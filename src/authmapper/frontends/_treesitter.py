"""Tree-sitter helpers shared by parser frontends."""

from __future__ import annotations

from collections.abc import Iterable

from tree_sitter import Node

from authmapper.core.v2 import SourceSpan

__all__ = ["file_span", "span", "text", "walk"]


def walk(node: Node) -> Iterable[Node]:
    yield node
    for child in node.children:
        yield from walk(child)


def text(node: Node, source: bytes) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8")


def span(path: str, node: Node) -> SourceSpan:
    return SourceSpan(
        path,
        node.start_point.row + 1,
        node.start_point.column + 1,
        node.end_point.row + 1,
        node.end_point.column + 1,
    )


def file_span(path: str) -> SourceSpan:
    return SourceSpan(path, 1, 1, 1, 1)
