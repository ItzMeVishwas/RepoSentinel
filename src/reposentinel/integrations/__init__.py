"""Optional adapters for established external scanners.

An integration is an ordinary ``Check``: it receives the same ``ScanContext``,
returns the same ``Finding`` objects, and is isolated by the engine in the
same way. Integrations never run unless the user asks for them, and a missing
tool makes the check *skipped* (and the scan incomplete), never silently clean.
"""

from __future__ import annotations

from reposentinel.integrations.gitleaks import GitleaksCheck

__all__ = ["GitleaksCheck"]
