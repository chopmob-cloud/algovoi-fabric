"""Conformance suite for the fail-closed protocol-version front-door.

One positive case per supported (protocol, version), negative cases for
unknown protocols and unsupported versions, tamper-evidence on the message
binding, and end-to-end composition into the AV-RAILS journey. The reference
is recomputed independently with the estate primitive, not taken on trust.
"""
import copy

import pytest
from algovoi_keystone_connect import keystone_ref

from algovoi_fabric import compose_journey, verify, verify_journey
from algovoi_fabric.protocols import (
    SUPPORTED_VERSIONS,
    ProtocolError,
    check_version,
    compose_protocol_chain,
    protocol_face,
    supported_matrix,
)

# Every supported (protocol, version) pair, derived from the declared matrix.
PAIRS = sorted((p, v) for p, vs in SUPPORTED_VERSIONS.items() for v in vs)

MSG = {"resource": "https://api.example/x", "amount": "1000", "currency": "USDC"}


def test_matrix_is_declared_and_sorted():
    m = supported_matrix()
    assert m == {
        "x402": ["1", "2"],
        "ap2": ["0.1", "0.2"],
        "mpp": ["2"],
        "a2a": ["0.3", "1.0.1"],
    }
    # returned copy is mutable without touching the source of truth
    m["x402"].append("99")
    assert "99" not in SUPPORTED_VERSIONS["x402"]


@pytest.mark.parametrize("protocol,version", PAIRS)
def test_supported_pair_composes_and_verifies(protocol, version):
    chain = compose_protocol_chain(protocol, version, MSG)
    assert verify(chain).ok is True
    face = chain["chain"][0]["preimage"]
    assert face["protocol"] == protocol
    assert face["version"] == version
    # independent recomputation of the content address
    assert face["message_ref"] == keystone_ref(MSG)
    # the execution link structurally binds the face
    assert chain["chain"][1]["preimage"]["protocol_ref"] == "@protocol"


@pytest.mark.parametrize("protocol,version", PAIRS)
def test_supported_pair_flows_into_journey(protocol, version):
    chain = compose_protocol_chain(protocol, version, MSG)
    env = compose_journey(chain)
    res = verify_journey(env)
    assert res["ok"] is True
    assert res["levels"] == ["av-rails"]


@pytest.mark.parametrize("protocol", ["x402", "ap2", "mpp", "a2a", "bogus", ""])
def test_unknown_protocol_fails_closed(protocol):
    if protocol in SUPPORTED_VERSIONS:
        pytest.skip("known protocol")
    with pytest.raises(ProtocolError):
        check_version(protocol, "1")
    with pytest.raises(ProtocolError):
        compose_protocol_chain(protocol, "1", MSG)


@pytest.mark.parametrize("protocol,version", [
    ("x402", "3"), ("x402", "0"), ("ap2", "1.0"),
    ("mpp", "1"), ("mpp", "3"), ("a2a", "0.2"), ("a2a", "2.0"),
])
def test_unsupported_version_fails_closed(protocol, version):
    with pytest.raises(ProtocolError):
        check_version(protocol, version)
    with pytest.raises(ProtocolError):
        protocol_face(protocol, version, MSG)
    with pytest.raises(ProtocolError):
        compose_protocol_chain(protocol, version, MSG)


@pytest.mark.parametrize("bad", [None, 1, True, [], object()])
def test_non_string_version_fails_closed(bad):
    with pytest.raises(ProtocolError):
        check_version("x402", bad)


def test_non_dict_message_fails_closed():
    for bad in (None, "x", 5, [], True):
        with pytest.raises(ProtocolError):
            protocol_face("x402", "2", bad)


def test_message_binding_is_tamper_evident():
    chain = compose_protocol_chain("x402", "2", MSG)
    assert verify(chain).ok is True
    tampered = copy.deepcopy(chain)
    # alter the bound message ref -> the declared face ref no longer recomputes.
    # The verifier reports this as .ok False / first_broken (it does not raise).
    tampered["chain"][0]["preimage"]["message_ref"] = "sha256:" + "0" * 64
    res = verify(tampered)
    assert res.ok is False
    assert res.first_broken is not None


def test_message_content_change_changes_ref():
    a = protocol_face("ap2", "0.1", MSG)
    b = protocol_face("ap2", "0.1", {**MSG, "amount": "2000"})
    assert a["message_ref"] != b["message_ref"]


def test_execution_override_cannot_unbind_face():
    chain = compose_protocol_chain(
        "a2a", "0.3", MSG,
        execution={"protocol_ref": "@evil", "action_type": "evil", "note": "ok"},
    )
    exec_pre = chain["chain"][1]["preimage"]
    assert exec_pre["protocol_ref"] == "@protocol"
    assert exec_pre["action_type"] == "execute"
    assert exec_pre["note"] == "ok"
    assert verify(chain).ok is True


def test_execution_override_must_be_dict():
    with pytest.raises(ProtocolError):
        compose_protocol_chain("mpp", "2", MSG, execution="nope")


def test_ap2_v0_2_conformance_additive():
    """AP2 v0.2 is a supported face ALONGSIDE v0.1 (additive widen, not a swap).

    Fabric's face is version-agnostic: it gates the version label and binds the
    caller's message by content address. This pins that a v0.2-labelled AP2
    message binds to the independent estate reference, composes+verifies, and
    flows through the AV-RAILS journey. It does NOT assert AP2 v0.2 mandate
    crypto semantics (Fabric never parses the wire schema).
    """
    assert "0.1" in SUPPORTED_VERSIONS["ap2"], "v0.1 must remain supported"
    assert "0.2" in SUPPORTED_VERSIONS["ap2"], "v0.2 must be added"
    msg = {"amount": "500", "currency": "USD"}
    face = protocol_face("ap2", "0.2", msg)
    assert face["version"] == "0.2"
    assert face["message_ref"] == keystone_ref(msg)  # independent reference
    chain = compose_protocol_chain("ap2", "0.2", msg)
    assert verify(chain).ok
    journey = compose_journey(
        chain, archive={"doc_hash": "sha256:" + "ab" * 32, "entry_id": "e1", "seq": 1}
    )
    assert verify_journey(journey)["ok"] is True
