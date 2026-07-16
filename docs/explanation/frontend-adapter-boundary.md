# Frontend and Adapter Boundary

Shared frontends answer: "what syntax and provenance exist?" Framework adapters
answer: "which supported framework owns that evidence, and what facts can be
derived?" The resolver alone answers endpoint posture from proof obligations.

Keeping these boundaries separate prevents receiver-name activation,
cross-package leakage, framework branches in core, and parser output from
silently becoming auth assurance. Runtime identity is metadata unless a native
runtime declaration has its own separately evaluated adapter.

Frontend quality metrics therefore enable adapter development but cannot promote
framework support. Promotion requires independent framework-level evidence and
capability governance.
