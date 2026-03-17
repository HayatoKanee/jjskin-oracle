# jjskin-oracle

TDX oracle for the [JJSKIN](https://jjskin.com) CS2 skin marketplace. Runs MPC-TLS verification and settlement decisions inside an Intel TDX confidential VM, so neither the operator nor the hosting provider can tamper with trade outcomes.

Built on [TLSNotary](https://github.com/tlsnotary/tlsn) `v0.1.0-alpha.14` and deployed via [dstack](https://github.com/aspect-build/dstack) (Phala Network).

**Live deployment**: `https://3f351d27b464ed7779351cae4b7c548b0ee648c7-7047.dstack-pha-prod5.phala.network`

**Verification reports**:
- [proof.t16z.com report](https://proof.t16z.com/reports/62ba84e794cc696c99dc9c3373d0075da085f3664c5bf14e2445710ccf835893)
- [Phala Trust Center](https://trust.phala.com/app/3f351d27b464ed7779351cae4b7c548b0ee648c7)

| | |
|---|---|
| Oracle address | `0xC7F1AeE5C20871162d1B9E3BB5e0C2dA6674D843` |
| JJSKIN contract | `0x966F2BBF404B36d6E30f226838e772AfcbE6Dcf7` |
| Chain | Arbitrum One (42161) |

## How it works

1. **MPC-TLS** — The oracle co-computes the TLS session with the prover (browser extension). Neither party sees the other's share of the key material.
2. **Settlement** — After the TLS session, the oracle parses the authenticated Steam API response and decides Release or Refund based on trade state.
3. **EIP-712 signing** — The decision is signed with the oracle's Ethereum key. Anyone can submit it on-chain.
4. **TDX attestation** — The entire binary runs inside Intel TDX. A DCAP quote proves the measured runtime, the application measurement registers, and the derived oracle address for off-chain verification.

## Modules

```
src/
  main.rs                  Axum server, routes, session lifecycle
  config.rs                YAML + env configuration
  verifier.rs              MPC-TLS protocol + post-protocol settlement
  attestation.rs           TDX DCAP quote generation via dstack
  proxy.rs                 WebSocket-to-TCP proxy for browser clients
  steam_inventory.rs       Public Steam inventory fetch + proxy pool
  item_detail.rs           uint64 itemDetail encoder
  inventory_attestation/   Inventory-backed buy-order attestation
  settlement/
    oracle.rs              Core decision engine (3 proof paths)
    parsing.rs             HTTP/JSON/HTML parsing for Steam responses
    types.rs               EscrowSnapshot, Decision, RefundReason, Settlement
    decision.rs            Fault attribution (expired, canceled, declined)
    signer.rs              EIP-712 typed-data signing
    chain_reader.rs        On-chain escrow reads (Arbitrum)
```

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check (`"ok"`) |
| GET | `/info` | Version, oracle address, TDX status |
| GET | `/attestation` | Fresh TDX DCAP quote (binary) |
| POST | `/session` | Create MPC-TLS session (requires `assetId` query param) |
| GET | `/notarize` | WebSocket MPC-TLS session |
| GET | `/proxy` | WebSocket-to-TCP proxy for browser provers |
| POST | `/inventory/attest` | Inventory-backed `ItemAttestation(assetId,itemDetail)` signing |

## Settlement decision logic

Three proof paths, each targeting a different Steam endpoint:

| Proof source | Endpoint verified | Can Release? | Can Refund? |
|---|---|---|---|
| `GetTradeOffer` | `api.steampowered.com/IEconService/GetTradeOffer` | No | Yes (expired, canceled, declined) |
| `GetTradeStatus` | `api.steampowered.com/IEconService/GetTradeStatus` | Yes (status 3 + escrow passed) | Yes (status 4-12 rollback) |
| `Community HTML` | `steamcommunity.com/tradeoffer/<id>` | No | Yes (trade abandonment, 24h wait) |

## Docker image

The production image is published to Docker Hub:

```
lumio1/jjskin-oracle
```

## Verification

The live oracle exposes a fresh DCAP quote at `/attestation`. Public verifiers can use that quote to check:

- genuine Intel TDX hardware
- the measured oracle address
- the measurement registers, including `RTMR[3]`

At a high level:

- `MRTD` measures the initial TD image
- `RTMR[3]` is the application-specific measurement extended by dstack from the deployed application manifest and runtime event log
- the quote also binds the derived oracle Ethereum address

Current mainnet trust model:

- settlement is enforced on-chain by registered oracle address
- the quote and `RTMR[3]` are publicly auditable and operationally verified off-chain
- mainnet does not yet re-verify a fresh TDX quote on every settlement

Public verification references:

- [proof.t16z.com report](https://proof.t16z.com/reports/62ba84e794cc696c99dc9c3373d0075da085f3664c5bf14e2445710ccf835893)
- [Phala Trust Center](https://trust.phala.com/app/3f351d27b464ed7779351cae4b7c548b0ee648c7)
- [Detailed verification guide](docs/VERIFICATION.md)

## Run locally (no TDX)

```bash
docker run -p 7047:7047 jjskin-oracle
```

The `/attestation` endpoint returns 503 outside TDX. All other endpoints work normally.

## Configuration

```yaml
host: "0.0.0.0"
port: 7047

notarization:
  max_pending_sessions: 100
  max_active_sessions: 2
  max_sent_data: 4096
  max_recv_data: 16384
  timeout: 120

oracle:
  contract_address: "0x966F2BBF404B36d6E30f226838e772AfcbE6Dcf7"
  chain_id: 42161
  rpc_url: "https://arb1.arbitrum.io/rpc"
```

The oracle signing key is derived deterministically inside dstack using `TappdClient::derive_key()`, so no private key is stored or configured.

Steam inventory proxy pool loading order mirrors the dapp:
- `STEAM_SOCKS_PROXIES_FILE`
- `STEAM_SOCKS_PROXIES`
- `STEAM_INVENTORY_PROXY_URL` as a single-proxy compatibility fallback

## Build & test

```bash
cargo build --release
cargo test
```

## License

MIT OR Apache-2.0
