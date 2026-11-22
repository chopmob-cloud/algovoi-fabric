"""AlgoVoi Fabric - the highest-assurance security composition core.

Every agent action becomes one tamper-evident, fail-closed keystone chain
that the real algovoi-keystone and algovoi-pef verifiers accept offline.
Nothing is trusted on the issuer's word: the customer recomputes the whole
posture themselves.
"""
from .compose import compose_chain, verify, FabricError

__version__ = "0.1.0"
__all__ = ["compose_chain", "verify", "FabricError", "__version__"]