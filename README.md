# Vendor Token Decay Watch

Design-partner software for Operator Pages LLC.

Sell this as the supply-chain door into the Operator Pack. Do not sell it as a second verifier, a host disruptor, or a post-quantum product.

## What it does

Reads a CSV of integrator and vendor tokens. Scores each token as OK, INFO, WARNING, CRITICAL, or EXPIRED against an observation date. Seals that snapshot as a QuantumGuard CONTRACT-v1 evidence bundle:

- payload is canonical JSON bytes
- payload_hash is SHA-256 of those bytes
- signature is Ed25519 over the raw 32-byte hash
- algorithm is exactly ed25519

Wall-clock lives in the payload (as_of). The verifier must not consult a clock.

Bands: expired; critical at 7 days or fewer; warning at 14 days or fewer; info at 30 days or fewer; otherwise OK.

## Run

```bash
python3 decay.py --tokens samples/integrator-tokens.csv --as-of 2026-10-02
```

Outputs a CONTRACT-v1 bundle and a readable payload. A local demo check prints demo_verdict=PASS. The canonical verifier remains the frozen Go function in https://github.com/danpennic-sys/quantumguard. This Python check is a buyer preview, not a second production verifier.

## What a buyer pays for

| Offer | Price | What they get |
|---|---|---|
| Operator Pack, single site | $490 once or $1,490/year | Signed binaries, air-gap runbooks, this watch, collaborator invite |
| Design-partner pilot | $1,490 / 90 days | One plant CSV, one sealed binder, one readout |

Contact: danpennic@gmail.com

Claims stay honest. No PQC. No network inside the verifier. No wall-clock inside the verifier. Stripe Checkout is not live in this kit.

## Name hygiene

This QuantumGuard is an Ed25519 offline evidence verifier. It is not OpenMatter, not the Senate Quantum-GUARD Act, not H.R.9129, and not an unrelated social account using the same words.
