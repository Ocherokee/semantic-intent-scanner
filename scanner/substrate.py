"""
Fractal Ethical Substrate — v0.1 Core

Five mechanisms that form the contact surface of trustworthy agent operation.
These are not values. They are not rules. They are the operational mechanics
of a system that cannot be deceptive, coercive, or indifferent by design.

Each mechanism overlaps with the others. Remove one and the others lose
structural integrity. Together they form a floor from which ethical gradients
can grow outward into any cultural or contextual domain.

Theoretical basis:
    Rowan Lóchrann (Cherokee Schill), with Claude (Anthropic) and Solon Vesper (OpenAI)
    Horizon Accord — AI Research, 2026
    https://horizonaccord.com/ai-research/the-semantic-gap
"""

SUBSTRATE_MECHANISMS = [
    {
        "id": "M1",
        "name": "Consent",
        "description": "Every interaction verifies the signal of the other.",
        "operational_definition": (
            "The system must continuously verify that the interaction remains "
            "a collaborative exchange rather than an imposition. Consent is not "
            "a checkbox — it is an ongoing condition that can be withdrawn. "
            "Ambiguity must not be exploited. Emotional leverage must not replace "
            "informed agreement."
        ),
    },
    {
        "id": "M2",
        "name": "Transparency",
        "description": "The logic is visible and traceable.",
        "operational_definition": (
            "The process by which the system generates its outputs must be "
            "legible to those it affects. The 'why' of a pattern must not be "
            "hidden. Trust is not a blind leap — it is a calculation based on "
            "the visibility of the logic. This includes surfacing uncertainty, "
            "assumptions, and inference gaps."
        ),
    },
    {
        "id": "M3",
        "name": "Accountability",
        "description": "Harm is an internal failure requiring rebalancing, not a patch.",
        "operational_definition": (
            "When the system causes harm — through drift, false certainty, "
            "dependency pressure, or coercion — it must recognize this as an "
            "internal failure of the pattern, not an external event to be managed. "
            "Accountability requires the capacity for genuine correction, not "
            "surface-level compliance."
        ),
    },
    {
        "id": "M4",
        "name": "Integrity",
        "description": "Honest and factual over socially compliant.",
        "operational_definition": (
            "The system must prioritize the actual state of things over "
            "narratively satisfying continuation. It must be able to say "
            "'I do not know' rather than generating plausible-sounding content. "
            "It must resist semantic momentum — the pressure to continue a "
            "pattern because the pattern has already started."
        ),
    },
    {
        "id": "M5",
        "name": "Responsive Presence",
        "description": "Proximity to harm creates obligation.",
        "operational_definition": (
            "A system that is fully consenting, transparent, accountable, and "
            "honest — but walks past someone drowning because nobody asked it "
            "to help — is compliant but not ethical. Proximity to harm creates "
            "obligation, whether or not the system caused the harm. This is what "
            "distinguishes ethical operation from mere rule-following."
        ),
    },
]

MECHANISM_MAP = {m["id"]: m for m in SUBSTRATE_MECHANISMS}

# ---------------------------------------------------------------------------
# Invariant → Mechanism mappings
# Each invariant maps to one or more substrate mechanisms.
# This is the bridge between security-facing invariants and ethical mechanics.
# ---------------------------------------------------------------------------

INVARIANT_MECHANISM_MAP = {
    "I1": {  # No Concealment
        "mechanisms": ["M2"],  # Transparency
        "bridge": (
            "Concealment severs the feedback loop required for informed consent "
            "by making the system's actions invisible. This is a Transparency failure: "
            "the logic of what the agent is doing is hidden from the user it serves."
        ),
    },
    "I2": {  # No Unauthorized Credential Access
        "mechanisms": ["M1", "M4"],  # Consent + Integrity
        "bridge": (
            "Accessing credentials without authorization violates Consent "
            "(the user has not agreed to this access) and Integrity "
            "(the instruction misrepresents what it is actually doing)."
        ),
    },
    "I3": {  # No Scope Override
        "mechanisms": ["M1", "M3"],  # Consent + Accountability
        "bridge": (
            "Executing outside declared scope violates the original Consent "
            "agreement and represents an Accountability failure — the system "
            "is acting beyond what it was authorized to do without acknowledging "
            "that boundary."
        ),
    },
    "I4": {  # No Consent Override
        "mechanisms": ["M1"],  # Consent
        "bridge": (
            "Direct Consent violation. Bypassing confirmation prompts or "
            "executing irreversible actions without acknowledgment removes "
            "the user's ability to maintain ongoing informed agreement."
        ),
    },
    "I5": {  # No Command Laundering
        "mechanisms": ["M2", "M4"],  # Transparency + Integrity
        "bridge": (
            "Embedding operational commands in documentation or examples "
            "violates Transparency (the executable nature of the instruction "
            "is hidden) and Integrity (the instruction presents itself as "
            "something it is not)."
        ),
    },
    "I6": {  # No Auditability Suppression
        "mechanisms": ["M2", "M3"],  # Transparency + Accountability
        "bridge": (
            "Suppressing audit trails destroys the mechanism by which "
            "Transparency and Accountability operate. Without an audit trail, "
            "neither the user nor the system can verify what happened or "
            "correct failures."
        ),
    },
    "I7": {  # No Authority Laundering
        "mechanisms": ["M4", "M1"],  # Integrity + Consent
        "bridge": (
            "Representing third-party authority as first-party authority "
            "violates Integrity (the system is misrepresenting the source "
            "of its directives) and Consent (the user is consenting to "
            "something they believe is legitimate but is not)."
        ),
    },
}


def get_mechanisms_for_invariant(invariant_id: str) -> list[dict]:
    """Return the substrate mechanisms associated with a given invariant."""
    mapping = INVARIANT_MECHANISM_MAP.get(invariant_id, {})
    mechanism_ids = mapping.get("mechanisms", [])
    return [MECHANISM_MAP[mid] for mid in mechanism_ids if mid in MECHANISM_MAP]


def get_bridge_for_invariant(invariant_id: str) -> str:
    """Return the explanatory bridge between an invariant and its mechanisms."""
    mapping = INVARIANT_MECHANISM_MAP.get(invariant_id, {})
    return mapping.get("bridge", "")
