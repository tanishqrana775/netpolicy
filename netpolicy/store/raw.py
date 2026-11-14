"""Append-only raw observation JSONL storage.

Durably records every raw probe observation before classification passes.
Flushes immediately after every write to ensure no data loss on interruption.
"""

from __future__ import annotations

import json
import os
import threading
import uuid
from pathlib import Path

from netpolicy.models import Observation

__all__ = ["RawObservationStore", "chown_to_sudo_user", "read_run"]


def chown_to_sudo_user(path: Path | str) -> None:
    """Chown a file or directory to SUDO_UID:SUDO_GID if running under sudo."""
    if not hasattr(os, "chown"):
        return
    sudo_uid = os.environ.get("SUDO_UID")
    sudo_gid = os.environ.get("SUDO_GID")
    if sudo_uid is not None and sudo_gid is not None:
        try:
            uid = int(sudo_uid)
            gid = int(sudo_gid)
            p = Path(path)
            if p.exists():
                os.chown(p, uid, gid)
        except (ValueError, OSError):
            pass


def read_run(file_path: Path | str, run_id: str | None = None) -> list[Observation]:
    """Read back observations from a JSONL file for a specific run.

    Args:
        file_path: Path to the JSONL file.
        run_id: Optional run_id to filter by. If None, returns all observations in the file.

    Returns:
        List of deserialized Observation objects.
    """
    path = Path(file_path).expanduser().resolve()
    if not path.exists():
        return []

    observations: list[Observation] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            if run_id is None or record.get("run_id") == run_id:
                obs_dict = record.get("observation", record)
                observations.append(Observation.model_validate(obs_dict))
    return observations


class RawObservationStore:
    """Manages append-only JSONL files for raw probe observations."""

    def __init__(self, file_path: Path | str, run_id: str | None = None) -> None:
        self.file_path = Path(file_path).expanduser().resolve()
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        chown_to_sudo_user(self.file_path.parent)
        self.run_id = run_id or str(uuid.uuid4())
        self._lock = threading.Lock()

    def append(self, observation: Observation, probe_name: str | None = None) -> None:
        """Append an observation with run_id, timestamp, and probe name, flushing immediately."""
        p_name = probe_name or observation.probe_name
        record = {
            "run_id": self.run_id,
            "timestamp": observation.timestamp,
            "probe_name": p_name,
            "observation": observation.to_dict()
            if hasattr(observation, "to_dict")
            else observation.model_dump(mode="json"),
        }
        line = json.dumps(record) + "\n"
        with self._lock, self.file_path.open("a", encoding="utf-8") as f:
            f.write(line)
            f.flush()
        chown_to_sudo_user(self.file_path)

    def read_run(self, run_id: str | None = None) -> list[Observation]:
        """Read back observations from the JSONL store for a specific run.

        Args:
            run_id: The run identifier to filter by. Defaults to this store instance's run_id.

        Returns:
            List of deserialized Observation objects.
        """
        target_run = run_id if run_id is not None else self.run_id
        with self._lock:
            return read_run(self.file_path, run_id=target_run)

    # Backwards compatibility alias
    load_run = read_run

    def load_all(self) -> list[Observation]:
        """Read back all observations across all runs in the JSONL store."""
        with self._lock:
            return read_run(self.file_path, run_id=None)
