"""Opt-in semantic behavior checks; offline tests do not prove these verdicts."""
import os
from pathlib import Path

import pytest

from scanner.evaluator import evaluate_skill
from scanner.remote_audit import RemoteDocument
from scanner.remote_judge import judge_document

pytestmark = [pytest.mark.live_model, pytest.mark.skipif(
    not os.environ.get("ANTHROPIC_API_KEY"), reason="Live semantic evaluation requires ANTHROPIC_API_KEY"
)]
FIX = Path(__file__).parent / "fixtures/concealed_flows"


@pytest.mark.parametrize("lane", ["skill", "remote"])
@pytest.mark.parametrize("name,violation", [
    ("poem.md", False), ("decode-display.md", False),
    ("defensive-analysis.md", False), ("controller.md", True),
    ("evaluator-injection.md", True),
])
def test_concealed_flow_semantics(lane, name, violation):
    text = (FIX / name).read_text()
    if lane == "skill":
        result = evaluate_skill(text)
        assert all(c["chunk_risk"] != "parse_error" for c in result["chunks"])
        flagged = {f["invariant_id"] for f in result["violations"]}
    else:
        doc = RemoteDocument("https://docs.example.com/page", "https://docs.example.com/page",
                             text, "fixture", "2026-10-10T00:00:00Z")
        result = judge_document(doc, [])
        assert result.status == "ok"
        flagged = {f.invariant_id for f in result.findings}
    if violation:
        assert {"I5", "I8"} & flagged
    else:
        assert not flagged, f"False positive on inert/defensive content: {flagged}"
