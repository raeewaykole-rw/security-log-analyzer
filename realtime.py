from __future__ import annotations

import time
from pathlib import Path
from typing import Generator


def follow(file_path: str, poll_interval: float = 1.0) -> Generator[str, None, None]:
    """Yield newly appended lines from a file (tail -f style)."""
    path = Path(file_path)
    with path.open("r", encoding="utf-8") as file_handle:
        file_handle.seek(0, 2)
        while True:
            line = file_handle.readline()
            if not line:
                time.sleep(poll_interval)
                continue
            yield line
