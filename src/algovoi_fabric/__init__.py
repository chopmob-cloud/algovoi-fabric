"""AlgoVoi Fabric - the highest-assurance security composition core.

Every agent action becomes one tamper-evident, fail-closed keystone chain
that the real algovoi-keystone and algovoi-pef verifiers accept offline.
The full journey spans AV-RAILS (decision) -> AV-PEF (evidence) -> AV-VCS
(sealed-archive binding), so it can be started and finished as one artefact.
Nothing is trusted on the issuer's word: the customer recomputes the whole
posture themselves.
"""
from .compose import compose_chain, verify, FabricError
from .journey import compose_journey, verify_journey, archive_binding_ref

__version__ = "0.2.0"
__all__ = ["compose_chain", "verify", "FabricError",
           "compose_journey", "verify_journey", "archive_binding_ref",
           "__version__"]