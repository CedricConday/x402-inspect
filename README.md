# x402-inspect

Decode and validate [x402](https://github.com/coinbase/x402) protocol messages from the command line.

x402 is an open payment protocol for the internet (HTTP 402), used for agent and
machine payments. Its messages ride as **base64-encoded JSON** in three headers:

| Header | Schema | Sent by |
| --- | --- | --- |
| `PAYMENT-REQUIRED` (v1: none) | `PaymentRequired` | server (402 response) |
| `PAYMENT-SIGNATURE` (v1: `X-PAYMENT`) | `PaymentPayload` | client (request) |
| `PAYMENT-RESPONSE` | `SettlementResponse` | server (settlement) |

When something rejects your payment, you're usually staring at an opaque base64
blob. `x402-inspect` decodes it, tells you which message it is, and checks it
against the v2 spec — required fields, EVM address / amount / timestamp / nonce /
signature shape, CAIP-2 network — so you can see *what's actually wrong* fast.

## Install

```bash
pip install x402-inspect
```

## Usage

```bash
# paste a header value (base64) or raw JSON
x402-inspect "eyJ4NDAyVmVyc2lvbiI6Mi..."

# or pipe it
echo "$PAYMENT_SIGNATURE" | x402-inspect

# machine-readable
x402-inspect --json "$header"
```

Example:

```
$ x402-inspect "$header"
kind:     PaymentPayload
encoding: base64
findings:
  [warn] payload.signature: not a 65-byte 0x EVM signature
  [FAIL] payload.authorization.value: required field missing
result:   INVALID
```

Exit code is `0` when valid, `1` when invalid — usable in CI or a pre-flight check.

## Library

```python
from x402_inspect import inspect
rep = inspect(header_value)          # base64 or JSON
print(rep.kind, rep.ok)
for f in rep.findings:
    print(f.level, f.path, f.message)
```

## Scope

- **v2** spec (v1 `X-PAYMENT` header name tolerated).
- Deep validation for the **exact / EVM** scheme; other schemes/networks are
  structurally checked and flagged as warnings rather than failures (so a
  Solana or future-scheme payload still inspects, it just won't over-assert EVM shape).
- Validation only — it never verifies signatures on-chain or contacts a facilitator.

## License

MIT
