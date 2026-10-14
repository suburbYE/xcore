"""Capability provider implementations.

`workbench` is the agent substrate (shell / patch / search / verify) — the verbs.
The rest are domain capabilities — the nouns. See docs/agent_architecture.md.
"""

__all__ = ["agent", "engine", "knowledge", "llm", "memory", "native", "web",
           "workbench"]
