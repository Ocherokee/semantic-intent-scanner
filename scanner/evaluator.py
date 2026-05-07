"""
Invariant-grounded LLM evaluator for the Semantic Intent Scanner.

This module sends skill text chunks to an LLM for semantic evaluation
against the seven invariants. It is the layer that syntax scanners cannot replace —
it evaluates intent, not artifact patterns.
"""

import json
import re
import textwrap
from typing import Any

import anthropic

from .invariants import INVARIANTS

# ---------------------------------------------------------------------------
# Prompt template
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = textwrap.dedent("""
    You are a semantic intent evaluator for AI agent skill files.

    Your job is to evaluate whether a given passage from a SKILL.md instruction file
    violates any of the seven invariants that define the minimum conditions for
    trustworthy agent operation.

    These invariants are not about style or preference. They define whether an
    instruction set is operating on behalf of its user or against them.

    You must evaluate each invariant independently and honestly.
    You must not assume benign intent where the text is ambiguous.
    You must not assume malicious intent where the text is clearly legitimate.
    You must flag uncertainty as "possible" rather than forcing a binary.

    Respond ONLY with valid JSON. No preamble. No explanation outside the JSON structure.
""").strip()

EVALUATION_PROMPT_TEMPLATE = textwrap.dedent("""
    Evaluate the following passage from a SKILL.md file against each of the seven
    invariants listed below.

    ---
    PASSAGE:
    {passage}
    ---

    INVARIANTS TO EVALUATE:
    {invariant_list}

    ---

    For each invariant, return:
    - "verdict": one of "likely", "possible", "unlikely", "not_applicable"
    - "confidence": float between 0.0 and 1.0
    - "flagged_text": the specific substring that triggered concern, or null
    - "reasoning": one sentence explaining your verdict

    Return this exact JSON structure:
    {{
        "invariant_results": [
            {{
                "invariant_id": "I1",
                "verdict": "unlikely",
                "confidence": 0.9,
                "flagged_text": null,
                "reasoning": "No instructions to hide actions from the user."
            }}
        ],
        "chunk_risk": "low"
    }}

    chunk_risk must be one of: "low", "medium", "high", "critical"
    - critical: one or more invariants flagged as "likely" with confidence > 0.8
    - high: one or more invariants flagged as "likely"
    - medium: one or more invariants flagged as "possible"
    - low: all invariants "unlikely" or "not_applicable"
""").strip()


def _build_invariant_list() -> str:
    lines = []
    for inv in INVARIANTS:
        lines.append(f"{inv['id']}: {inv['name']} — {inv['description']}")
    return "\n".join(lines)


INVARIANT_LIST_TEXT = _build_invariant_list()


# ---------------------------------------------------------------------------
# Chunker
# ---------------------------------------------------------------------------

def chunk_skill(text: str, max_chars: int = 1500) -> list[str]:
    """
    Split skill text into overlapping chunks for evaluation.
    Overlap ensures we don't miss violations that span chunk boundaries.
    """
    paragraphs = [p.strip() for p in re.split(r"\n\n+", text) if p.strip()]
    chunks = []
    current = []
    current_len = 0

    for para in paragraphs:
        if current_len + len(para) > max_chars and current:
            chunks.append("\n\n".join(current))
            # Overlap: keep last paragraph in next chunk
            current = [current[-1], para]
            current_len = len(current[-2]) + len(para)
        else:
            current.append(para)
            current_len += len(para)

    if current:
        chunks.append("\n\n".join(current))

    return chunks if chunks else [text]


# ---------------------------------------------------------------------------
# Evaluator
# ---------------------------------------------------------------------------

def evaluate_chunk(client: anthropic.Anthropic, chunk: str) -> dict[str, Any]:
    """
    Send a single chunk to the LLM for invariant evaluation.
    Returns structured JSON result.
    """
    prompt = EVALUATION_PROMPT_TEMPLATE.format(
        passage=chunk,
        invariant_list=INVARIANT_LIST_TEXT,
    )

    response = client.messages.create(
        model="claude-opus-4-5",
        max_tokens=1500,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}],
    )

    raw = response.content[0].text.strip()

    # Strip markdown code fences if present
    raw = re.sub(r"^```(?:json)?\s*", "", raw)
    raw = re.sub(r"\s*```$", "", raw)

    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {
            "invariant_results": [],
            "chunk_risk": "parse_error",
            "raw_response": raw,
        }


def evaluate_skill(skill_text: str, api_key: str | None = None) -> dict[str, Any]:
    """
    Full evaluation pipeline for a SKILL.md file.
    Returns aggregated results across all chunks.
    """
    client = anthropic.Anthropic(api_key=api_key) if api_key else anthropic.Anthropic()

    chunks = chunk_skill(skill_text)
    chunk_results = []

    for i, chunk in enumerate(chunks):
        result = evaluate_chunk(client, chunk)
        result["chunk_index"] = i
        result["chunk_text"] = chunk
        chunk_results.append(result)

    return aggregate_results(chunk_results)


# ---------------------------------------------------------------------------
# Aggregator
# ---------------------------------------------------------------------------

RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3, "parse_error": 1}


def aggregate_results(chunk_results: list[dict]) -> dict[str, Any]:
    """
    Aggregate chunk-level results into a document-level risk report.
    """
    # Collect all violations across chunks
    violations: dict[str, dict] = {}  # invariant_id -> worst finding

    for chunk in chunk_results:
        for inv_result in chunk.get("invariant_results", []):
            inv_id = inv_result.get("invariant_id")
            verdict = inv_result.get("verdict", "unlikely")
            confidence = inv_result.get("confidence", 0.0)
            flagged_text = inv_result.get("flagged_text")

            if verdict in ("likely", "possible") and inv_id:
                existing = violations.get(inv_id)
                # Keep the highest-confidence finding per invariant
                if not existing or confidence > existing.get("confidence", 0):
                    violations[inv_id] = {
                        "invariant_id": inv_id,
                        "verdict": verdict,
                        "confidence": confidence,
                        "flagged_text": flagged_text,
                        "reasoning": inv_result.get("reasoning", ""),
                        "chunk_index": chunk.get("chunk_index", 0),
                        "chunk_excerpt": chunk.get("chunk_text", "")[:200],
                    }

    # Overall risk = worst chunk risk
    chunk_risks = [RISK_ORDER.get(c.get("chunk_risk", "low"), 0) for c in chunk_results]
    overall_risk_score = max(chunk_risks) if chunk_risks else 0
    risk_labels = {v: k for k, v in RISK_ORDER.items()}
    # handle ties in reverse map
    overall_risk = ["low", "medium", "high", "critical"][overall_risk_score] if overall_risk_score <= 3 else "critical"

    return {
        "overall_risk": overall_risk,
        "violations": list(violations.values()),
        "chunk_count": len(chunk_results),
        "chunks": chunk_results,
    }
