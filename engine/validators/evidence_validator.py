"""Step 1b of the pipeline: evidence rules that a JSON schema cannot express.

  * every record must point at an asset that exists in the asset inventory
  * every record_id must be unique inside one assessment
"""
from pathlib import Path

import yaml

from .input_validator import ROOT, ValidationResult

ASSET_INVENTORY_FILE = ROOT / "company" / "asset_inventory.yaml"


def load_asset_ids(path=ASSET_INVENTORY_FILE):
    """Return the set of asset ids (for example AST-IDP-001) in the inventory."""
    inventory_text = Path(path).read_text(encoding="utf-8")
    inventory = yaml.safe_load(inventory_text)
    asset_ids = set()
    for asset in inventory["assets"]:
        asset_ids.add(asset["asset_id"])
    return asset_ids


def validate_evidence(data, asset_ids=None):
    """Return a ValidationResult listing unknown assets and duplicate record ids."""
    if asset_ids is None:
        known_asset_ids = load_asset_ids()
    else:
        known_asset_ids = asset_ids

    errors = []
    times_record_id_seen = {}

    # The schema step reports a badly shaped 'evidence' value, so skip it here.
    if not isinstance(data, dict):
        return ValidationResult()
    evidence = data.get("evidence")
    if not isinstance(evidence, dict):
        return ValidationResult()

    for block_name, block in evidence.items():
        if not isinstance(block, dict):
            continue
        for list_name, records in block.items():
            if not isinstance(records, list):
                continue
            for position, record in enumerate(records):
                if not isinstance(record, dict):
                    continue
                where = f"evidence/{block_name}/{list_name}/{position}"

                asset_id = record.get("asset_id")
                if isinstance(asset_id, str) and asset_id not in known_asset_ids:
                    message = f"asset {asset_id} is not in the inventory"
                    errors.append({"path": f"{where}/asset_id", "message": message})

                record_id = record.get("record_id")
                if isinstance(record_id, str):
                    times_seen = times_record_id_seen.get(record_id, 0) + 1
                    times_record_id_seen[record_id] = times_seen
                    if times_seen == 2:
                        message = f"duplicate record_id {record_id}"
                        errors.append({"path": f"{where}/record_id", "message": message})

    errors.sort(key=lambda error: error["path"])
    return ValidationResult(errors)
