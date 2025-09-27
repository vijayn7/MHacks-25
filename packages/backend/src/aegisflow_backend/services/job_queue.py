"""Placeholder job queue for orchestrating crawls."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict

from ..models import Run


@dataclass
class Job:
    run_id: int
    callback: Callable[[Run], None]


class InMemoryJobQueue:
    """Extremely small job queue abstraction for the MVP skeleton."""

    def __init__(self) -> None:
        self._jobs: Dict[int, Job] = {}

    def enqueue(self, run: Run, callback: Callable[[Run], None]) -> None:
        self._jobs[run.id] = Job(run_id=run.id, callback=callback)

    def run_all(self) -> None:
        for job in list(self._jobs.values()):
            job.callback(Run(id=job.run_id, target_id=0, status="completed"))
            del self._jobs[job.run_id]


queue = InMemoryJobQueue()
