"""Shared test setup.

All test evidence comes from ONE file: inputs/evidence_samples.json (30 samples).
The `scenario` fixture hands a test a fresh copy of one named sample, so a test
can change it freely without affecting any other test.
"""
import json
from pathlib import Path

import pytest

from engine.samples import build_sample_input

ROOT = Path(__file__).resolve().parents[1]
SAMPLES_FILE = ROOT / "inputs" / "evidence_samples.json"

_samples_document = None


def load_samples_document():
    """Read the samples file once and remember it (about 500 KB)."""
    global _samples_document
    if _samples_document is None:
        _samples_document = json.loads(SAMPLES_FILE.read_text(encoding="utf-8"))
    return _samples_document


def get_sample_input(sample_name):
    """Return the complete evidence of the sample with this name (a private copy).

    Variation samples store only their changes, so build_sample_input() rebuilds them.
    """
    return build_sample_input(load_samples_document(), sample_name)


@pytest.fixture
def scenario():
    """Use as: data = scenario("secure_state")"""
    return get_sample_input


@pytest.fixture(scope="module")
def scenario_module():
    """Same as `scenario`, for fixtures that are built once per test file."""
    return get_sample_input
