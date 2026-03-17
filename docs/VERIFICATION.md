# Oracle Verification

This document is for external verifiers and integrators who want to check that the live oracle is running inside Intel TDX and that the measured oracle address matches the on-chain trust configuration.

It does not describe the operator deployment workflow.

## Scope

What you can verify today:

- the oracle is running inside Intel TDX
- the quote is Intel/DCAP-verifiable
- the quote binds a measured oracle address
- the measured oracle address matches the address trusted by the marketplace contract

What is not contract-enforced on every settlement today:

- MRTD / RTMR[3] quote verification

Mainnet currently uses direct oracle registration, so settlement checks the recovered oracle address, not a fresh quote per transaction.

## Current mainnet trust model

The live oracle exposes:

- `/info` for version and derived oracle address
- `/attestation` for a fresh DCAP quote

The marketplace contract currently trusts a registered oracle address. In the contract:

- `registerOracleDirect(address)` adds a trusted oracle
- `submitSettlement(...)` accepts a settlement only if the recovered signer is trusted
- buy-order attestation verification does the same

So the honest security model is:

1. the TEE is publicly auditable off-chain
2. the contract enforces the trusted oracle address on-chain
3. quote verification is operationally important today, but not re-checked by the contract on each settlement

## Live deployment

- Oracle URL: `https://3f351d27b464ed7779351cae4b7c548b0ee648c7-7047.dstack-pha-prod5.phala.network`
- Oracle address: `0xC7F1AeE5C20871162d1B9E3BB5e0C2dA6674D843`
- JJSKIN contract: `0x966F2BBF404B36d6E30f226838e772AfcbE6Dcf7`
- Chain: Arbitrum One (`42161`)

Existing public attestation report:

- [proof.t16z.com report](https://proof.t16z.com/reports/62ba84e794cc696c99dc9c3373d0075da085f3664c5bf14e2445710ccf835893)

## 1. Fetch a fresh quote

```bash
curl -s https://3f351d27b464ed7779351cae4b7c548b0ee648c7-7047.dstack-pha-prod5.phala.network/attestation -o quote.bin
```

You can also inspect `/info`:

```bash
curl -s https://3f351d27b464ed7779351cae4b7c548b0ee648c7-7047.dstack-pha-prod5.phala.network/info | jq
```

## 2. Extract measurements and oracle address

```python
with open("quote.bin", "rb") as f:
    data = f.read()

# TDX Quote v4, TD Report Body v1.5
mrtd = data[184:232]
rtmr3 = data[520:568]
oracle_addr = data[568:588]

print(f"MRTD:    {mrtd.hex()}")
print(f"RTMR[3]: {rtmr3.hex()}")
print(f"Oracle:  0x{oracle_addr.hex()}")
```

## 3. Verify the DCAP quote

Use any standard DCAP verifier:

- [proof.t16z.com](https://proof.t16z.com)
- [trust.phala.com](https://trust.phala.com)
- [`dcap-qvl`](https://github.com/aspect-build/dcap-qvl)
- [`@aspect-build/dstack-verifier`](https://www.npmjs.com/package/@aspect-build/dstack-verifier)

The quote should validate and expose the same measured oracle address you extracted locally.

## 4. Check the on-chain trust anchor

Verify that the measured oracle address is the one trusted by the marketplace:

```bash
cast call 0x966F2BBF404B36d6E30f226838e772AfcbE6Dcf7 "oracles(address)(bool)" 0xC7F1AeE5C20871162d1B9E3BB5e0C2dA6674D843 --rpc-url https://arb1.arbitrum.io/rpc
```

This should return `true`.

## 5. Rebuild if you want source-level assurance

The oracle image is reproducible enough for independent rebuilding because base images are pinned in `Dockerfile.tdx`.

```bash
GIT_HASH=$(git rev-parse --short HEAD)
docker build --platform linux/amd64 -f Dockerfile.tdx --build-arg GIT_HASH=$GIT_HASH -t jjskin-oracle .
```

A source-level verifier can compare the rebuilt result and the live quote measurements as part of a deeper audit.

## RTMR[3] note

dstack extends `RTMR[3]` using the deployed compose configuration. That makes `RTMR[3]` operationally meaningful, but on mainnet today it is not the contract-enforced settlement gate. The contract-enforced gate is the registered oracle address.

If mainnet later switches to attestation-based on-chain registration, both the measured address and the quote measurements become part of the contract-enforced trust path.
