"""Recursive immutable containers for public evidence and policy state."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any, Never, Self, SupportsIndex


class FrozenDict(dict[Any, Any]):
    """A JSON-serializable dictionary that rejects mutation after construction."""

    @staticmethod
    def _immutable(*_: object, **__: object) -> Never:
        raise TypeError("FrozenDict is immutable")

    def __setitem__(self, key: Any, value: Any) -> None:
        self._immutable(key, value)

    def __delitem__(self, key: Any) -> None:
        self._immutable(key)

    def clear(self) -> None:
        self._immutable()

    def pop(self, key: Any, default: Any = None) -> Any:
        return self._immutable(key, default)

    def popitem(self) -> tuple[Any, Any]:
        return self._immutable()

    def setdefault(self, key: Any, default: Any = None) -> Any:
        return self._immutable(key, default)

    def update(self, *args: Any, **kwargs: Any) -> None:
        self._immutable(*args, **kwargs)

    def __ior__(self, other: Mapping[Any, Any], /) -> Self:  # type: ignore[override,misc]
        return self._immutable(other)


class FrozenList(list[Any]):
    """A JSON-serializable list that rejects mutation after construction."""

    @staticmethod
    def _immutable(*_: object, **__: object) -> Never:
        raise TypeError("FrozenList is immutable")

    def __setitem__(self, key: Any, value: Any) -> None:
        self._immutable(key, value)

    def __delitem__(self, key: Any) -> None:
        self._immutable(key)

    def append(self, value: Any) -> None:
        self._immutable(value)

    def extend(self, values: Any) -> None:
        self._immutable(values)

    def insert(self, index: SupportsIndex, value: Any) -> None:
        self._immutable(index, value)

    def clear(self) -> None:
        self._immutable()

    def pop(self, index: SupportsIndex = -1) -> Any:
        return self._immutable(index)

    def remove(self, value: Any) -> None:
        self._immutable(value)

    def reverse(self) -> None:
        self._immutable()

    def sort(self, *args: Any, **kwargs: Any) -> None:
        self._immutable(*args, **kwargs)

    def __iadd__(self, values: Iterable[Any]) -> Self:  # type: ignore[misc]
        return self._immutable(values)

    def __imul__(self, count: SupportsIndex) -> Self:
        return self._immutable(count)


def deep_freeze(value: Any) -> Any:
    """Recursively freeze mutable JSON-like containers while preserving serialization."""

    if isinstance(value, FrozenDict):
        return value
    if isinstance(value, Mapping):
        return FrozenDict({key: deep_freeze(item) for key, item in value.items()})
    if isinstance(value, FrozenList):
        return value
    if isinstance(value, list):
        return FrozenList(deep_freeze(item) for item in value)
    if isinstance(value, tuple):
        return tuple(deep_freeze(item) for item in value)
    if isinstance(value, set | frozenset):
        return frozenset(deep_freeze(item) for item in value)
    return value
