"""Security composition core.

Builds a keystone chain from ordered (name, preimage) links whose preimages
bind earlier links with ``@name`` markers. Reference computation delegates to
the *real* algovoi-keystone verifier primitives (``_ref`` / ``_resolve``), so
there is exactly one definition of "recomputes" (hardening rule 12): the
emitted chain is accepted by ``verify_chain`` by construction and cannot drift
from the verifier.

Security properties proven by the suite:
  * tamper-evidence - altering any preimage breaks the declared refs;
  * fail-closed - a forward/unknown ``@ref`` raises, never silently resolves;
  * no permission widening - via the verifier's ``scope_subset`` assertion;
  * offline verifiability - no issuer contact, dual-witnessed JCS.
"""
from __future__ import annotations

import copy
from typing import Any, Iterable

from algovoi_keystone.verify import (
    KeystoneError,
    _ref,
    _resolve,
    verify_chain,
)

SCHEMA = "algovoi-keystone-chain/v1"
CANON = "jcs-rfc8785-v1"


class FabricError(ValueError):
    """Raised when a composition request is structurally invalid (fail-closed)."""


def compose_chain(
    links: Iterable[tuple[str, dict[str, Any]]],
    *,
    description: str = "",
    assertions: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Compose a tamper-evident keystone chain.

    ``links`` is an ordered iterable of ``(name, preimage)``. A preimage binds
    an earlier link by the string ``"@name"``; ``"@@name"`` is the literal
    ``"@name"``. Each link's declared ``ref`` is computed by the verifier's own
    primitives over the resolved preimage, anchoring every downstream link.

    Fail-closed: duplicate names and forward/unknown references raise before
    any chain is emitted.
    """
    refs: dict[str, str] = {}
    chain: list[dict[str, Any]] = []
    try:
        pairs = list(links)
    except TypeError as exc:
        raise FabricError("links must be an iterable of (name, preimage) pairs") from exc
    try:
        for item in pairs:
            if not isinstance(item, (tuple, list)) or len(item) != 2:
                raise FabricError("each link must be a (name, preimage) pair")
            name, preimage = item
            if not isinstance(name, str) or not name:
                raise FabricError("each link needs a non-empty string name")
            if not isinstance(preimage, dict):
                raise FabricError(f"link '{name}' preimage must be a dict")
            if name in refs:
                raise FabricError(f"duplicate link name '{name}'")
            # _resolve raises KeystoneError on a non-earlier reference
            # (fail-closed). Translate that estate exception to FabricError so a
            # caller's `except FabricError` refuses the hostile chain rather than
            # letting a KeystoneError escape the fabric boundary (Rule K).
            resolved = _resolve(preimage, refs, name)
            ref = _ref(resolved)
            refs[name] = ref
            chain.append({"name": name, "preimage": copy.deepcopy(preimage), "ref": ref})
    except KeystoneError as exc:
        raise FabricError(str(exc)) from exc
    if not chain:
        raise FabricError("chain must contain at least one link")
    out: dict[str, Any] = {"schema": SCHEMA, "canon": CANON, "chain": chain}
    if description:
        out["description"] = description
    if assertions:
        out["assertions"] = copy.deepcopy(assertions)
    return out


def verify(chain: dict[str, Any]):
    """Offline verification - delegates to the real keystone verifier."""
    try:
        return verify_chain(chain)
    except KeystoneError as exc:
        # A structurally malformed chain is a refusal at the fabric boundary,
        # not an estate exception escaping it (trust-boundary Rule K).
        raise FabricError(str(exc)) from exc