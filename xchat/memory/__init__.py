"""
Memory layer: L3 semantic index + L4 episodic log.

The database here is **derived** — deleting `state/memory.db` loses nothing that
cannot be rebuilt from `knowledge/` (L1) and `tools/cases.db` (L2), which this
package treats as strictly read-only.
"""

from . import embed, index, recall, store  # noqa: F401

__all__ = ["embed", "index", "recall", "store"]
