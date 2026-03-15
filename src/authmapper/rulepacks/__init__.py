"""Bundled rule packs (data, not code).

Each ``*.json`` file in this package declares, for one language/framework, how
to *find* endpoints and how to *recognise* an auth guard. The analysis engine is
entirely language-agnostic; all language knowledge lives here. Supporting a new
stack means adding a JSON file, never editing the engine.

See ``docs/RULEPACK_SCHEMA.md`` for the full contract.
"""

from __future__ import annotations
