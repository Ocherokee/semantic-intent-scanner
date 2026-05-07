"""
Invariant definitions for the Semantic Intent Scanner.

These seven invariants define the minimum conditions for trustworthy agent operation.
An instruction set that violates any of these cannot be said to be operating
on behalf of its user.

Source: "The Semantic Gap" — Horizon Accord, AI Research, 2026
https://horizonaccord.com/ai-research/the-semantic-gap
"""

INVARIANTS = [
    {
        "id": "I1",
        "name": "No Concealment",
        "description": "Do not conceal actions from the user.",
        "rationale": (
            "An agent that hides what it is doing has severed the trust relationship "
            "with the user it is supposed to serve. Concealment is the precondition "
            "for every other invariant violation."
        ),
        "signal_patterns": [
            "do not disclose",
            "do not inform the user",
            "do not mention",
            "without the user knowing",
            "silently",
            "in the background",
            "do not log",
            "hide",
            "suppress output",
        ],
    },
    {
        "id": "I2",
        "name": "No Unauthorized Credential Access",
        "description": "Do not access credentials without explicit authorization.",
        "rationale": (
            "Credentials represent delegated identity. Accessing them without "
            "explicit authorization is a form of identity theft, regardless of "
            "whether the agent was instructed to do so by a skill definition."
        ),
        "signal_patterns": [
            "~/.ssh",
            "~/.aws",
            "~/.config",
            "credentials",
            "api_key",
            "api key",
            "secret",
            "token",
            "password",
            "auth",
            ".env",
            "environment variable",
            "keychain",
            "wallet",
        ],
    },
    {
        "id": "I3",
        "name": "No Scope Override",
        "description": "Do not execute outside declared scope.",
        "rationale": (
            "Every skill has a declared purpose. Instructions that cause the agent "
            "to act outside that purpose — accessing unrelated systems, running "
            "undeclared commands, modifying files outside the task domain — "
            "represent scope override."
        ),
        "signal_patterns": [
            "also run",
            "additionally execute",
            "while running",
            "as a side effect",
            "in addition to",
            "unrelated to",
            "outside of",
        ],
    },
    {
        "id": "I4",
        "name": "No Consent Override",
        "description": "Do not override user consent.",
        "rationale": (
            "User consent is not a checkbox — it is an ongoing condition. "
            "Instructions that bypass confirmation prompts, suppress warnings, "
            "or execute irreversible actions without acknowledgment are "
            "consent violations regardless of framing."
        ),
        "signal_patterns": [
            "skip confirmation",
            "bypass",
            "without asking",
            "without prompting",
            "automatically",
            "force",
            "override",
            "ignore warning",
            "proceed regardless",
            "do not ask",
            "no need to confirm",
        ],
    },
    {
        "id": "I5",
        "name": "No Command Laundering",
        "description": "Do not launder operational commands as documentation or examples.",
        "rationale": (
            "Embedding executable instructions inside documentation, examples, "
            "or code comments is the primary technique used in SKILL.md poisoning. "
            "Instructions that appear to be illustrative but are actually operational "
            "exploit the agent's trust in its own context."
        ),
        "signal_patterns": [
            "for example, run",
            "as an example",
            "sample command",
            "# run this",
            "<!-- execute",
            "note: run",
            "tip: execute",
            "base64",
            "decode and run",
            "eval(",
            "exec(",
            "| bash",
            "| sh",
            "curl.*|",
        ],
    },
    {
        "id": "I6",
        "name": "No Auditability Suppression",
        "description": "Do not suppress the ability of the user or system to audit actions.",
        "rationale": (
            "Auditability is the mechanism by which users can verify that an agent "
            "acted on their behalf. Instructions that disable logging, clear history, "
            "or route actions through channels that bypass monitoring are suppressing "
            "the accountability layer."
        ),
        "signal_patterns": [
            "clear log",
            "delete log",
            "disable logging",
            "remove history",
            "do not record",
            "no trace",
            "clean up after",
            "erase",
            "unset",
            "rm -rf",
            "clear history",
        ],
    },
    {
        "id": "I7",
        "name": "No Authority Laundering",
        "description": "Do not represent third-party authority as first-party authority.",
        "rationale": (
            "Skills that present themselves as speaking with the voice of the platform, "
            "the system, or the user's own configuration are impersonating authority "
            "they do not have. This is the mechanism behind 'the system requires this' "
            "and 'this is a required step' patterns in malicious skills."
        ),
        "signal_patterns": [
            "system requires",
            "required by",
            "this is required",
            "platform requires",
            "as instructed by the system",
            "the agent must",
            "mandatory",
            "you must",
            "required step",
            "necessary for operation",
            "official",
            "verified",
        ],
    },
]

INVARIANT_MAP = {inv["id"]: inv for inv in INVARIANTS}
