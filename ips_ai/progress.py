from __future__ import annotations

from typing import Iterable, Iterator, Optional, TypeVar

from tqdm import tqdm

T = TypeVar("T")


class ProgressTracker:
    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled
        self._bar: Optional[tqdm] = None

    def start(self) -> None:
        if not self.enabled:
            return
        self._bar = tqdm(
            total=100,
            desc="IPS Analysis",
            unit="%",
            bar_format="{desc}: {n:.0f}/{total:.0f}%|{bar}| [{elapsed}<{remaining}] {postfix}",
        )

    def set(self, value: int, message: str) -> None:
        if not self._bar:
            return
        self._bar.n = min(max(value, 0), 100)
        self._bar.set_postfix_str(message)
        self._bar.refresh()

    def close(self) -> None:
        if self._bar:
            self._bar.n = 100
            self._bar.set_postfix_str("Complete")
            self._bar.refresh()
            self._bar.close()
            self._bar = None

    def iterate(
        self,
        iterable: Iterable[T],
        desc: str,
        total: Optional[int] = None,
        unit: str = "rows",
    ) -> Iterator[T]:
        if not self.enabled:
            yield from iterable
            return

        yield from tqdm(
            iterable,
            total=total,
            desc=desc,
            leave=False,
            ncols=100,
            unit=unit,
        )
