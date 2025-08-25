import time
from types import TracebackType
from typing import Optional, Self, Type


class timing:
    def __enter__(self) -> Self:
        self.start = time.perf_counter()
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        self.end = time.perf_counter()
        self.duration = self.end - self.start
