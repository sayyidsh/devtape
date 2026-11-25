import json
from pathlib import Path

import pytest
from devtape_dtp import decode_tape_json, sanitize_ansi

VECTORS = Path(__file__).resolve().parents[3] / "spec" / "conformance"
MANIFEST = json.loads((VECTORS / "manifest.json").read_text())


def test_manifest_coverage():
    assert len(MANIFEST) == 16
    assert sum(v["expected"] == "valid" for v in MANIFEST) == 10


@pytest.mark.parametrize("vector", MANIFEST, ids=lambda v: v["filename"])
def test_conformance(vector):
    data = (VECTORS / vector["filename"]).read_bytes()
    if vector["expected"] == "valid":
        assert json.loads(decode_tape_json(data))["manifest"]["session_id"]
    else:
        with pytest.raises(ValueError):
            decode_tape_json(data)


def test_osc52_removed():
    assert sanitize_ansi("hello\x1b]52;c;secret\x07world") == "helloworld"
