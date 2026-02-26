# jjskin-oracle

TDX oracle for the [JJSKIN](https://jjskin.com) CS2 skin marketplace. Runs MPC-TLS verification and settlement decisions inside an Intel TDX confidential VM, so neither the operator nor the hosting provider can tamper with trade outcomes.

Built on [TLSNotary](https://github.com/tlsnotary/tlsn) `v0.1.0-alpha.14` and deployed via [dstack](https://github.com/aspect-build/dstack) (Phala Network).

**Live deployment**: `https://3f351d27b464ed7779351cae4b7c548b0ee648c7-7047.dstack-pha-prod5.phala.network`

**TDX attestation verified**: [proof.t16z.com/reports/f2f06952d3f4fcfc9fa304d20f9316ba230153f7cec028d2799b2f736dc74852](https://proof.t16z.com/reports/f2f06952d3f4fcfc9fa304d20f9316ba230153f7cec028d2799b2f736dc74852)

| | |
|---|---|
| Oracle address | `0xC7F1AeE5C20871162d1B9E3BB5e0C2dA6674D843` |
| JJSKIN contract | `0x966F2BBF404B36d6E30f226838e772AfcbE6Dcf7` |
| Chain | Arbitrum One (42161) |

## How it works

1. **MPC-TLS** — The oracle co-computes the TLS session with the prover (browser extension). Neither party sees the other's share of the key material.
2. **Settlement** — After the TLS session, the oracle parses the authenticated Steam API response and decides Release or Refund based on trade state.
3. **EIP-712 signing** — The decision is signed with the oracle's Ethereum key. Anyone can submit it on-chain.
4. **TDX attestation** — The entire binary runs inside Intel TDX. A DCAP quote proves the exact code (MRTD) and Docker image (RTMR[3]) that produced the signature.

## Modules

```
src/
  main.rs                  Axum server, routes, session lifecycle
  config.rs                YAML + env configuration
  verifier.rs              MPC-TLS protocol + post-protocol settlement
  attestation.rs           TDX DCAP quote generation via dstack
  proxy.rs                 WebSocket-to-TCP proxy for browser clients
  settlement/
    oracle.rs              Core decision engine (3 proof paths)
    parsing.rs             HTTP/JSON/HTML parsing for Steam responses
    types.rs               EscrowSnapshot, Decision, RefundReason, Settlement
    decision.rs            Fault attribution (expired, canceled, declined)
    signer.rs              EIP-712 typed-data signing
    chain_reader.rs        On-chain escrow reads (Arbitrum)
  inspect/
    bot_pool.rs            Steam bot pool with proxy rotation
    gc_client.rs           CS2 Game Coordinator protocol client
    cache.rs               In-memory inspect result cache
    link_parser.rs         Steam inspect link parser (S/M/A/D params)
    item_detail.rs         Protobuf encoding for item details
    types.rs               Inspect request/response types
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
| GET | `/inspect` | CS2 item inspection (float, paint seed, stickers) |
| POST | `/inspect/bulk` | Bulk inspection (up to 100 items) |

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

The `docker-compose-mainnet.yaml` pins the image by SHA256 digest. dstack hashes this file into RTMR[3], binding the exact image to the TDX attestation.

### Reproducible build

Base images are pinned to SHA256 digests in `Dockerfile.tdx` for reproducible MRTD measurements.

```bash
GIT_HASH=$(git rev-parse --short HEAD)
docker build --platform linux/amd64 -f Dockerfile.tdx --build-arg GIT_HASH=$GIT_HASH -t jjskin-oracle .
```

### Run locally (no TDX)

```bash
docker run -p 7047:7047 jjskin-oracle
```

The `/attestation` endpoint returns 503 outside TDX. All other endpoints work normally.

## Verify the oracle (TDX attestation)

Anyone can independently verify that the oracle is running the expected code inside Intel TDX — no trust in the operator or Phala is required.

### Trust model

| Layer | Trust basis | What it proves |
|-------|------------|----------------|
| Intel TDX | Silicon | Private key never leaves encrypted memory; code can't be modified at runtime |
| DCAP quote | Intel-signed | Exact binary (MRTD) and Docker image (RTMR[3]) running in the VM |
| dstack | Phala runtime | Extends RTMR[3] with compose-hash; provides deterministic key derivation |
| Reproducible build | Open source | Anyone can rebuild the Docker image and verify MRTD matches |

**What Phala cannot do** (even if compromised): read the oracle's private key, forge attestation quotes, or change the code without changing MRTD.

### Quick verification

The current attestation report is already verified and publicly accessible:

[**View verified attestation on proof.t16z.com**](https://proof.t16z.com/reports/f2f06952d3f4fcfc9fa304d20f9316ba230153f7cec028d2799b2f736dc74852)

### 1. Get a fresh attestation quote

```bash
curl -s https://3f351d27b464ed7779351cae4b7c548b0ee648c7-7047.dstack-pha-prod5.phala.network/attestation -o quote.bin
```

### 2. Extract measurements

```python
with open('quote.bin', 'rb') as f:
    data = f.read()

# TDX Quote v4, TD Report Body v1.5
mrtd = data[184:232]           # 48 bytes — hash of the TD (binary measurement)
rtmr3 = data[520:568]          # 48 bytes — dstack compose-hash extension
oracle_addr = data[568:588]    # 20 bytes — oracle's Ethereum address

print(f'MRTD:    {mrtd.hex()}')
print(f'RTMR[3]: {rtmr3.hex()}')
print(f'Oracle:  0x{oracle_addr.hex()}')
```

### 3. Verify the DCAP quote (off-chain)

The quote is an Intel-signed attestation. Verify it using any of these tools:

- **TEE Attestation Explorer**: [proof.t16z.com](https://proof.t16z.com) — paste the hex-encoded quote
- **Phala Trust Center**: [trust.phala.com](https://trust.phala.com) — lookup by CVM app ID
- **dcap-qvl** (Rust CLI): [github.com/aspect-build/dcap-qvl](https://github.com/aspect-build/dcap-qvl)
- **@aspect-build/dstack-verifier** (TypeScript): [npmjs.com/package/@aspect-build/dstack-verifier](https://www.npmjs.com/package/@aspect-build/dstack-verifier)

### 4. Verify the code matches (reproducible build)

```bash
# Rebuild the exact same image from source
GIT_HASH=$(git rev-parse --short HEAD)
docker build --platform linux/amd64 -f Dockerfile.tdx --build-arg GIT_HASH=$GIT_HASH -t jjskin-oracle .

# The MRTD from your build should match the MRTD in the attestation quote.
# Base images are pinned to SHA256 digests in Dockerfile.tdx for reproducibility.
```

### 5. Verify RTMR[3] matches docker-compose

```bash
# dstack extends RTMR[3] with SHA384(compose-hash), where compose-hash = SHA256(docker-compose-mainnet.yaml)
sha256sum docker-compose-mainnet.yaml
```

### 6. Check on-chain registration

```bash
# Verify the oracle address is registered on the JJSKIN contract
cast call 0x966F2BBF404B36d6E30f226838e772AfcbE6Dcf7 "oracles(address)(bool)" 0xC7F1AeE5C20871162d1B9E3BB5e0C2dA6674D843 --rpc-url https://arb1.arbitrum.io/rpc

# Verify the expected MRTD measurement is set
cast call 0x4D455ceA16E65c7566105caDEAd68851625BD8a9 "activeMeasurement()(bytes32)" --rpc-url https://arb1.arbitrum.io/rpc

# Verify the expected RTMR[3] is set
cast call 0x4D455ceA16E65c7566105caDEAd68851625BD8a9 "activeRtmr3()(bytes32)" --rpc-url https://arb1.arbitrum.io/rpc
```

The on-chain values should match `keccak256(mrtd_48_bytes)` and `keccak256(rtmr3_48_bytes)` from the attestation quote.

### On-chain DCAP verification (future)

The contract includes `registerOracle(bytes attestation)` for fully trustless on-chain DCAP verification via [Automata](https://ata.network). This requires Intel collateral to be registered on the Automata on-chain PCCS for Arbitrum One.

**Upgrade path**: ZK-based DCAP verification via [Automata TDX Attestation SDK](https://github.com/aspect-build/tdx-attestation-sdk) (RISC Zero / SP1) will enable on-chain verification without collateral infrastructure.

## Configuration

```yaml
host: "0.0.0.0"
port: 7047

notarization:
  max_sent_data: 4096
  max_recv_data: 16384
  timeout: 120

oracle:
  contract_address: "0x..."
  chain_id: 421614
  rpc_url: "https://sepolia-rollup.arbitrum.io/rpc"

inspect:
  bots_config_path: "bots.json"
  cache_ttl_secs: 300
```

The oracle signing key is derived deterministically inside dstack using `TappdClient::derive_key()`, so no private key is stored or configured.

## Build & test

```bash
cargo build --release
cargo test
```

## License

MIT OR Apache-2.0
