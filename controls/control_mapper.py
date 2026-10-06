"""Reads controls/control_map.csv: one best-fit requirement per framework for each control.

Mappings are illustrative and imply no certification.
"""
from __future__ import annotations

import csv
from functools import lru_cache
from pathlib import Path

MAP_FILE = Path(__file__).resolve().parent / "control_map.csv"
FRAMEWORKS = ("NIST CSF 2.0", "ISO/IEC 27001:2022")


@lru_cache(maxsize=1)
def load_map() -> dict[str, dict]:
    with open(MAP_FILE, newline="", encoding="utf-8") as f:
        return {r["control_id"]: r for r in csv.DictReader(f)}


def refs(control_id: str) -> dict[str, str]:
    """{'NIST CSF 2.0': 'PR.AA-03', 'ISO/IEC 27001:2022': 'A.8.5'}"""
    row = load_map()[control_id]
    return {fw: row[fw] for fw in FRAMEWORKS}


def refs_text(control_id: str) -> str:
    return load_map()[control_id]["framework_ref"]
