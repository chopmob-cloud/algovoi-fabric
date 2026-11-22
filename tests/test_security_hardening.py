"""Security hardening: uniform fail-closed refusal (trust-boundary Rule K + A).

Every public entry point must reject hostile / absent / malformed input with
the module's OWN FabricError (ProtocolError is a subclass), never a
TypeError / KeyError / KeystoneError that escapes a caller's
``except FabricError`` and can be swallowed into a pass. Each case below was
observed to raise the wrong type (or not raise at all) on 0.3.0 @ 31821ff.
"""
import pytest

from algovoi_fabric import compose as C
from algovoi_fabric import journey as J
from algovoi_fabric import protocols as P
from algovoi_fabric.compose import FabricError


# --- compose_chain: forward/unknown refs must surface as FabricError ---------
@pytest.mark.parametrize("links", [
    [("a", {"x": "@b"}), ("b", {"y": 1})],   # forward reference
    [("a", {"x": "@ghost"})],                 # unknown reference
    [("a", {"x": "@a"})],                     # self reference
])
def test_compose_chain_bad_ref_is_fabric_error(links):
    with pytest.raises(FabricError):
        C.compose_chain(links)


def test_compose_protocol_chain_execution_fwd_ref_is_fabric_error():
    with pytest.raises(FabricError):
        P.compose_protocol_chain("x402", "2", {"a": 1}, execution={"x": "@nope"})


# --- compose_journey: hostile chain shapes must surface as FabricError -------
@pytest.mark.parametrize("chain", [
    {"chain": "str"},
    {"chain": 42},
    {"chain": [{}]},
    {"chain": [{"name": "execution", "preimage": {}}]},          # no ref
    {"chain": [{"name": "execution", "ref": "r"}]},              # no preimage (was FAIL-OPEN)
    {"chain": [{"name": "execution", "ref": "r", "preimage": "notdict"}]},
    {"chain": [{"ref": "r", "preimage": {}}]},                   # no name
    {"chain": [None]},
])
def test_compose_journey_malformed_chain_is_fabric_error(chain):
    with pytest.raises(FabricError):
        J.compose_journey(chain)


def test_compose_journey_preimageless_link_not_emitted():
    # The clearest 0.3.0 fail-open: a link with no preimage was accepted and a
    # journey envelope emitted. It must now be refused, never emitted.
    with pytest.raises(FabricError):
        J.compose_journey({"chain": [{"name": "execution", "ref": "r"}]})


# --- verify_journey: hostile envelopes must surface as FabricError -----------
def test_verify_journey_missing_chain_is_fabric_error():
    with pytest.raises(FabricError):
        J.verify_journey({"schema": J.JOURNEY_SCHEMA})


def test_verify_journey_malformed_chain_is_fabric_error():
    with pytest.raises(FabricError):
        J.verify_journey({"schema": J.JOURNEY_SCHEMA,
                          "chain": {"chain": [{}]},
                          "execution": "execution", "execution_ref": "r"})


def test_verify_journey_chain_not_list_is_fabric_error():
    with pytest.raises(FabricError):
        J.verify_journey({"schema": J.JOURNEY_SCHEMA,
                          "chain": {"chain": "str"},
                          "execution": "execution", "execution_ref": "r"})


# --- the valid path still works (no over-rejection) --------------------------
def test_valid_protocol_chain_still_composes_and_verifies():
    chain = P.compose_protocol_chain("x402", "2", {"amount": 100})
    env = J.compose_journey(chain)
    res = J.verify_journey(env)
    assert res["ok"] is True
    assert "av-rails" in res["levels"]


# --- compose_chain: hostile links iterable must surface as FabricError -------
# (independent Claude security review finding 1: raw TypeError/ValueError leak)
def test_compose_chain_non_iterable_links_is_fabric_error():
    with pytest.raises(FabricError):
        C.compose_chain(5)


@pytest.mark.parametrize("links", [
    [("passport", {"a": 1}, "extra")],   # 3-tuple, not a pair
    ["abc"],                              # string element, not a pair
    [None],                               # None element
])
def test_compose_chain_non_pair_link_is_fabric_error(links):
    with pytest.raises(FabricError):
        C.compose_chain(links)


# --- compose_journey: a forged chain must be refused at compose, not bound ---
# (independent Claude security review finding 2: compose never re-verified refs)
def test_compose_journey_forged_chain_refused_at_compose():
    forged = {"schema": "algovoi-keystone-chain/v1",
              "chain": [{"name": "execution", "ref": "sha256:" + "0" * 64,
                         "preimage": {"action_class": "x"}}],
              "root": "sha256:" + "0" * 64}
    with pytest.raises(FabricError):
        J.compose_journey(forged)


# --- verify_journey: non-dict pef_frame/archive must surface as FabricError ---
# (independent Claude second-opinion finding: verify_journey lacked the dict
# guards compose_journey has, leaking AttributeError from verify_pef / a.get)
@pytest.mark.parametrize("key,val", [
    ("pef_frame", "forged"), ("pef_frame", None), ("pef_frame", 123),
    ("archive", "forged"), ("archive", None), ("archive", 123),
])
def test_verify_journey_non_dict_subblock_is_fabric_error(key, val):
    chain = P.compose_protocol_chain("x402", "2", {"amount": 100})
    env = J.compose_journey(chain)   # valid envelope, correct execution_ref
    env[key] = val
    with pytest.raises(FabricError):
        J.verify_journey(env)
