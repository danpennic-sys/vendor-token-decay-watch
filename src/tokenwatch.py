#!/usr/bin/env python3
"""Vendor Token Decay Watch.

Score a CSV of integrator tokens against an observation date and seal that
snapshot as a QuantumGuard CONTRACT-v1 bundle.

This buyer preview is not the production verifier. The canonical verifier is
the frozen Go function in github.com/danpennic-sys/quantumguard. Verification
there is a pure function of the bundle bytes: no network and no wall-clock.

Documented command:
  python3 src/tokenwatch.py --tokens samples/integrator-tokens.csv --as-of 2026-10-02
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import json
import sys
from datetime import date, datetime

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

CONTRACT_VERSION = "1"
ALG = "ed25519"
TOOL = "vendor-token-decay-watch/0.1.0"
DEMO_SEED_LABEL = b"TokenWatch demo signer v1 - not a production key"
COLUMNS = (
    "token_id",
    "vendor",
    "scope",
    "system",
    "issued",
    "expires",
    "last_used",
    "owner",
)


def demo_private_key() -> Ed25519PrivateKey:
    seed = hashlib.sha256(DEMO_SEED_LABEL).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def parse_day(value: str, field: str) -> date:
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError as exc:
        raise SystemExit(f"bad {field} date: {value!r}") from exc


def band_for(days_remaining: int) -> str:
    if days_remaining < 0:
        return "EXPIRED"
    if days_remaining <= 7:
        return "CRITICAL"
    if days_remaining <= 14:
        return "WARNING"
    if days_remaining <= 30:
        return "INFO"
    return "OK"


def load_rows(path: str) -> list[dict[str, str]]:
    with open(path, newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != list(COLUMNS):
            raise SystemExit(f"unexpected CSV header: {reader.fieldnames}")
        rows: list[dict[str, str]] = []
        for raw in reader:
            if raw.get("token_id") is None or raw["token_id"].strip() == "":
                raise SystemExit("blank token_id")
            rows.append({key: (raw[key] or "").strip() for key in COLUMNS})
        if not rows:
            raise SystemExit("no token rows")
        return rows


def snapshot(rows: list[dict[str, str]], as_of: date) -> dict:
    tokens = []
    for row in rows:
        expires = parse_day(row["expires"], "expires")
        parse_day(row["issued"], "issued")
        parse_day(row["last_used"], "last_used")
        days = (expires - as_of).days
        item = {key: row[key] for key in COLUMNS}
        item["days_remaining"] = days
        item["band"] = band_for(days)
        tokens.append(item)
    return {"as_of": as_of.isoformat(), "tool": TOOL, "tokens": tokens}


def canonical_payload(body: dict) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def seal(payload: bytes, private_key: Ed25519PrivateKey) -> dict:
    digest = hashlib.sha256(payload).digest()
    public = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    signature = private_key.sign(digest)
    return {
        "version": CONTRACT_VERSION,
        "payload": base64.b64encode(payload).decode("ascii"),
        "payload_hash": digest.hex(),
        "signature": signature.hex(),
        "public_key": public.hex(),
        "alg": ALG,
    }


def demo_check(bundle: dict) -> str:
    """Buyer preview of the bundle bytes. Not the QuantumGuard verifier."""
    try:
        if bundle.get("version") != CONTRACT_VERSION or bundle.get("alg") != ALG:
            return "FAIL"
        payload = base64.b64decode(bundle["payload"])
        claimed = bytes.fromhex(bundle["payload_hash"])
        signature = bytes.fromhex(bundle["signature"])
        public = bytes.fromhex(bundle["public_key"])
        if len(claimed) != 32 or len(signature) != 64 or len(public) != 32:
            return "FAIL"
        if hashlib.sha256(payload).digest() != claimed:
            return "FAIL"
        Ed25519PublicKey.from_public_bytes(public).verify(signature, claimed)
    except Exception:
        return "FAIL"
    return "PASS"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Score integrator tokens and seal a CONTRACT-v1 snapshot."
    )
    parser.add_argument("--tokens", required=True)
    parser.add_argument("--as-of", required=True)
    args = parser.parse_args(argv)

    as_of = parse_day(args.as_of, "as-of")
    body = snapshot(load_rows(args.tokens), as_of)
    payload = canonical_payload(body)
    bundle = seal(payload, demo_private_key())
    verdict = demo_check(bundle)

    print("payload:")
    print(json.dumps(body, sort_keys=True, indent=2))
    print("bundle:")
    print(json.dumps(bundle, indent=2))
    print("signer=demo")
    print(f"demo_verdict={verdict}")
    print("demo_scope=buyer_preview")
    print("canonical_verifier=not_run")
    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
