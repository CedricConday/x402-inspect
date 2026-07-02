import base64
import json

import pytest

from x402_inspect.core import Kind, Level, classify, decode, inspect

# PaymentPayload example straight from the x402 v2 spec (section 5.2.1).
PAYLOAD = {
    "x402Version": 2,
    "resource": {"url": "https://api.example.com/premium-data"},
    "accepted": {
        "scheme": "exact",
        "network": "eip155:84532",
        "amount": "10000",
        "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
        "payTo": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
        "maxTimeoutSeconds": 60,
    },
    "payload": {
        "signature": "0x" + "a" * 130,
        "authorization": {
            "from": "0x857b06519E91e3A54538791bDbb0E22373e36b66",
            "to": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
            "value": "10000",
            "validAfter": "1740672089",
            "validBefore": "1740672154",
            "nonce": "0x" + "f" * 64,
        },
    },
}

REQUIRED = {
    "x402Version": 2,
    "resource": {"url": "https://api.example.com/premium-data"},
    "accepts": [
        {
            "scheme": "exact",
            "network": "eip155:84532",
            "amount": "10000",
            "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
            "payTo": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
        }
    ],
}

SETTLEMENT = {
    "success": True,
    "transaction": "0x" + "1" * 64,
    "network": "eip155:84532",
    "payer": "0x857b06519E91e3A54538791bDbb0E22373e36b66",
}


def b64(obj) -> str:
    return base64.b64encode(json.dumps(obj).encode()).decode()


def test_decode_base64_and_json():
    obj, enc, err = decode(b64(PAYLOAD))
    assert enc == "base64" and err is None and obj == PAYLOAD
    obj2, enc2, _ = decode(json.dumps(PAYLOAD))
    assert enc2 == "json" and obj2 == PAYLOAD


def test_decode_garbage_reports_error():
    obj, _, err = decode("!!!not valid!!!")
    assert obj is None and err


@pytest.mark.parametrize(
    "obj,kind",
    [
        (PAYLOAD, Kind.PAYMENT_PAYLOAD),
        (REQUIRED, Kind.PAYMENT_REQUIRED),
        (SETTLEMENT, Kind.SETTLEMENT_RESPONSE),
        ({"foo": "bar"}, Kind.UNKNOWN),
    ],
)
def test_classify(obj, kind):
    assert classify(obj) == kind


def test_valid_payload_from_spec_passes():
    rep = inspect(b64(PAYLOAD))
    assert rep.kind is Kind.PAYMENT_PAYLOAD
    assert rep.ok, [f.__dict__ for f in rep.findings]


def test_valid_required_and_settlement_pass():
    assert inspect(b64(REQUIRED)).ok
    assert inspect(b64(SETTLEMENT)).ok


def test_missing_required_field_is_error():
    bad = json.loads(json.dumps(PAYLOAD))
    del bad["payload"]["authorization"]["value"]
    rep = inspect(b64(bad))
    assert not rep.ok
    assert any(f.level is Level.ERROR and f.path == "payload.authorization.value" for f in rep.findings)


def test_bad_value_type_is_error():
    bad = json.loads(json.dumps(PAYLOAD))
    bad["payload"]["authorization"]["value"] = "not-a-number"
    rep = inspect(b64(bad))
    assert not rep.ok


def test_non_evm_address_is_warn_not_error():
    warned = json.loads(json.dumps(PAYLOAD))
    warned["accepted"]["payTo"] = "merchant"  # role constant is allowed
    assert inspect(b64(warned)).ok
    warned2 = json.loads(json.dumps(PAYLOAD))
    warned2["accepted"]["asset"] = "SOLmintAddr111"
    rep = inspect(b64(warned2))
    assert rep.ok  # non-EVM asset warns, doesn't fail
    assert any(f.level is Level.WARN for f in rep.findings)


def test_wrong_version_warns():
    v1 = json.loads(json.dumps(PAYLOAD))
    v1["x402Version"] = 1
    rep = inspect(b64(v1))
    assert any(f.path == "x402Version" and f.level is Level.WARN for f in rep.findings)
