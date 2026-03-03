//! Phase 4: Full MPC-TLS local integration tests.
//!
//! Runs the real MPC-TLS protocol over in-process duplex sockets:
//!   Prover ↔ Verifier ↔ Mock Steam HTTPS
//!
//! NO production code is modified. All test code lives here in tests/.
//! The verifier side calls oracle library functions directly (lib crate).

use futures_util::io::{AsyncReadExt, AsyncWriteExt};
use rustls::crypto::CryptoProvider;
use tlsn::{
    Session,
    config::{
        prove::ProveConfig,
        prover::ProverConfig,
        tls::TlsClientConfig,
        tls_commit::{TlsCommitConfig, mpc::MpcTlsConfig},
        verifier::VerifierConfig,
    },
    connection::ServerName,
    transcript::{Direction, TranscriptCommitConfig, TranscriptCommitmentKind},
    hash::HashAlgId,
    webpki::{CertificateDer, RootCertStore},
};
use tlsn_server::{
    config::OracleConfig,
    settlement::{EscrowSnapshot, OracleSigner, SettlementResult},
    verifier,
};
use tokio_util::compat::TokioAsyncReadCompatExt;

mod helpers;

use helpers::cert_gen::{self, TestCerts};
use helpers::escrow_builder::{self, TestParams};
use helpers::mock_steam::{self, SteamFixture};
use helpers::eip712_verify;

// MPC-TLS limits (match oracle's NotarizationConfig defaults)
const MAX_SENT_DATA: usize = 4096;
const MAX_SENT_RECORDS: usize = 4;
const MAX_RECV_DATA: usize = 16384;
const MAX_RECV_RECORDS: usize = 6;

// Anvil account #0 private key (well-known, no secret)
const TEST_ORACLE_KEY: &str =
    "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const TEST_CONTRACT_ADDRESS: &str = "0x5FbDB2315678afecb367f032d93F642f64180aa3";
const TEST_CHAIN_ID: u64 = 31337;

/// Well-known default fixture output directory.
/// Phase 5A reads from the same path.
const DEFAULT_FIXTURE_DIR: &str = "/tmp/jjskin-settlement-fixtures";

// ============================================================================
// Helper: create OracleSigner from temp file (no global env mutation)
// ============================================================================

fn default_oracle_config() -> OracleConfig {
    let key_path = std::env::temp_dir().join("test-oracle-key.hex");
    std::fs::write(&key_path, TEST_ORACLE_KEY).unwrap();

    OracleConfig {
        signing_key_path: Some(key_path.to_string_lossy().to_string()),
        contract_address: TEST_CONTRACT_ADDRESS.to_string(),
        chain_id: TEST_CHAIN_ID,
        ..Default::default()
    }
}

async fn create_test_signer() -> OracleSigner {
    OracleSigner::from_config(&default_oracle_config()).await.unwrap()
}

// ============================================================================
// Helper: run the full MPC-TLS flow (prover + verifier + mock Steam)
// ============================================================================

struct MpcTlsTestResult {
    settlement: SettlementResult,
}

async fn run_mpc_tls_flow(
    certs: &TestCerts,
    fixture: SteamFixture,
    escrow: &EscrowSnapshot,
    oracle_config: &OracleConfig,
    http_request: &str,
) -> MpcTlsTestResult {
    run_mpc_tls_flow_with_host(certs, fixture, escrow, oracle_config, http_request, "api.steampowered.com").await
}

async fn run_mpc_tls_flow_with_host(
    certs: &TestCerts,
    fixture: SteamFixture,
    escrow: &EscrowSnapshot,
    oracle_config: &OracleConfig,
    http_request: &str,
    server_host: &str,
) -> MpcTlsTestResult {
    // Install ring crypto provider (idempotent — ok if already installed)
    CryptoProvider::install_default(rustls::crypto::ring::default_provider()).ok();

    // 1. Create prover ↔ verifier duplex socket (16 MB buffer)
    let (prover_socket, verifier_socket) = tokio::io::duplex(2 << 23);

    // 2. Clone data for the verifier task
    let escrow_clone = escrow.clone();
    let ca_cert_der = certs.ca_cert_der.clone();

    // Create signer from the provided config (respects chain_id etc.)
    let verifier_signer = OracleSigner::from_config(oracle_config).await.unwrap();

    // 3. Spawn verifier task
    let verifier_task = tokio::spawn(async move {
        let verifier_config = VerifierConfig::builder()
            .root_store(RootCertStore {
                roots: vec![CertificateDer(ca_cert_der)],
            })
            .build()
            .unwrap();

        // Run the real MPC-TLS verifier protocol
        let (mpc_result, mut socket) =
            verifier::run_mpc_tls(verifier_socket.compat(), verifier_config)
                .await
                .expect("run_mpc_tls failed");

        // Run the real settlement decision + EIP-712 signing
        verifier::handle_post_protocol(&mpc_result, &mut socket, &escrow_clone, &verifier_signer)
            .await
            .expect("handle_post_protocol failed");
    });

    // 4. Run prover side
    let mut session = Session::new(prover_socket.compat());

    let prover = session
        .new_prover(ProverConfig::builder().build().unwrap())
        .unwrap();

    let (driver, handle) = session.split();
    let driver_task = tokio::spawn(driver);

    // 4a. Create mock Steam server on a separate duplex socket
    let (client_socket, server_socket) = tokio::io::duplex(2 << 16);
    let certs_for_server = TestCerts {
        ca_cert_der: certs.ca_cert_der.clone(),
        server_cert_der: certs.server_cert_der.clone(),
        server_key_der: certs.server_key_der.clone(),
    };
    tokio::spawn(async move {
        mock_steam::bind_steam_fixture(server_socket, &certs_for_server, fixture).await;
    });

    // 4b. MPC-TLS commit
    let prover = prover
        .commit(
            TlsCommitConfig::builder()
                .protocol(
                    MpcTlsConfig::builder()
                        .max_sent_data(MAX_SENT_DATA)
                        .max_sent_records(MAX_SENT_RECORDS)
                        .max_recv_data(MAX_RECV_DATA)
                        .max_recv_records_online(MAX_RECV_RECORDS)
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap(),
        )
        .await
        .unwrap();

    // 4c. Connect to mock Steam via MPC-TLS
    let (mut tls_conn, prover_fut) = prover
        .connect(
            TlsClientConfig::builder()
                .server_name(ServerName::Dns(server_host.try_into().unwrap()))
                .root_store(RootCertStore {
                    roots: vec![CertificateDer(certs.ca_cert_der.clone())],
                })
                .build()
                .unwrap(),
            client_socket.compat(),
        )
        .await
        .unwrap();
    let prover_task = tokio::spawn(prover_fut);

    // 4d. Send HTTP request to mock Steam through MPC-TLS
    tls_conn
        .write_all(http_request.as_bytes())
        .await
        .unwrap();
    tls_conn.close().await.unwrap();

    // Read response
    let mut response = vec![0u8; MAX_RECV_DATA];
    tls_conn.read_to_end(&mut response).await.unwrap();

    // 4e. Build prove config + prove (reveals transcript to verifier)
    let mut prover = prover_task.await.unwrap().unwrap();
    let sent_len = prover.transcript().sent().len();
    let recv_len = prover.transcript().received().len();

    // Commit transcript ranges
    let mut commit_builder = TranscriptCommitConfig::builder(prover.transcript());
    let kind = TranscriptCommitmentKind::Hash {
        alg: HashAlgId::SHA256,
    };
    commit_builder
        .commit_with_kind(&(0..sent_len), Direction::Sent, kind)
        .unwrap();
    commit_builder
        .commit_with_kind(&(0..recv_len), Direction::Received, kind)
        .unwrap();

    let mut prove_builder = ProveConfig::builder(prover.transcript());
    prove_builder.server_identity();
    prove_builder.reveal_sent(&(0..sent_len)).unwrap();
    prove_builder.reveal_recv(&(0..recv_len)).unwrap();
    prove_builder.transcript_commit(commit_builder.build().unwrap());

    let config = prove_builder.build().unwrap();
    prover.prove(&config).await.unwrap();
    prover.close().await.unwrap();

    // 4f. Close session and reclaim socket
    handle.close();
    let mut socket = driver_task.await.unwrap().unwrap();

    // 4g. Read settlement result from wire protocol
    // Wire format: u64 LE length + bincode(SettlementResult)
    let mut len_buf = [0u8; 8];
    socket.read_exact(&mut len_buf).await.unwrap();
    let result_len = u64::from_le_bytes(len_buf) as usize;

    let mut result_bytes = vec![0u8; result_len];
    socket.read_exact(&mut result_bytes).await.unwrap();

    let settlement: SettlementResult =
        bincode::deserialize(&result_bytes).expect("Failed to deserialize SettlementResult");

    // Wait for verifier to complete
    verifier_task.await.unwrap();

    MpcTlsTestResult { settlement }
}

// ============================================================================
// Helper: write settlement fixture JSON for Phase 5A
// ============================================================================

fn write_fixture_json(
    result: &SettlementResult,
    escrow: &EscrowSnapshot,
    signer: &OracleSigner,
    filename: &str,
) {
    let fixture = serde_json::json!({
        "assetId": result.asset_id.to_string(),
        "tradeOfferId": escrow.trade_offer_id.to_string(),
        "decision": result.decision,
        "refundReason": result.refund_reason,
        "signature": format!("0x{}", hex::encode(&result.signature)),
        "oracleAddress": format!("{:?}", signer.address()),
        "contractAddress": TEST_CONTRACT_ADDRESS,
        "chainId": TEST_CHAIN_ID,
    });

    let fixture_dir = std::env::var("SETTLEMENT_FIXTURE_DIR")
        .unwrap_or_else(|_| DEFAULT_FIXTURE_DIR.to_string());
    std::fs::create_dir_all(&fixture_dir).unwrap();
    let fixture_path = std::path::Path::new(&fixture_dir).join(filename);
    std::fs::write(&fixture_path, serde_json::to_string_pretty(&fixture).unwrap()).unwrap();
    eprintln!("Wrote settlement fixture to: {}", fixture_path.display());
}

// ============================================================================
// Test 1: Happy path — Release (GetTradeStatus complete)
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_mpc_tls_release_happy_path() {
    let _ = tracing_subscriber::fmt::try_init();

    let certs = cert_gen::generate_test_certs();
    let params = TestParams::default();
    let escrow = escrow_builder::build_test_escrow(&params);
    let oracle_config = default_oracle_config();
    let signer = OracleSigner::from_config(&oracle_config).await.unwrap();

    let fixture = SteamFixture::TradeStatusComplete {
        trade_id: params.trade_id,
        asset_id: params.asset_id,
        buyer_steam_id: params.buyer_steam_id,
    };

    let http_request = format!(
        "GET /IEconService/GetTradeStatus/v1/?key=REDACTED&tradeid={} HTTP/1.1\r\n\
         Host: api.steampowered.com\r\n\
         Connection: close\r\n\r\n",
        params.trade_id
    );

    let result = run_mpc_tls_flow(&certs, fixture, &escrow, &oracle_config, &http_request).await;
    let s = &result.settlement;

    // Verify settlement decision
    assert_eq!(s.decision, 0, "Expected Release (0)");
    assert_eq!(s.refund_reason, 0, "Expected RefundReason::None (0)");
    assert_eq!(s.asset_id, params.asset_id);

    // Verify EIP-712 signature via ecrecover
    let contract_address: alloy::primitives::Address =
        TEST_CONTRACT_ADDRESS.parse().unwrap();
    let recovered = eip712_verify::verify_settlement_signature(
        &s.signature,
        s.asset_id,
        escrow.trade_offer_id,
        s.decision,
        s.refund_reason,
        TEST_CHAIN_ID,
        contract_address,
    );
    assert_eq!(
        recovered,
        signer.address(),
        "ecrecover must match oracle signer address"
    );

    // Write fixture for Phase 5A
    write_fixture_json(s, &escrow, &signer, "settlement-fixture-release.json");
}

// ============================================================================
// Test 2: Happy path — Refund (GetTradeOffer expired)
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_mpc_tls_refund_happy_path() {
    let _ = tracing_subscriber::fmt::try_init();

    let certs = cert_gen::generate_test_certs();
    let params = TestParams::default();
    let escrow = escrow_builder::build_test_escrow(&params);
    let oracle_config = default_oracle_config();
    let signer = OracleSigner::from_config(&oracle_config).await.unwrap();

    // Seller captures the proof (is_our_offer=true means seller created the offer,
    // so seller is the capturer). Partner is buyer.
    let fixture = SteamFixture::TradeOfferExpired {
        trade_offer_id: params.trade_offer_id,
        partner_account_id: params.buyer_account_id,
        asset_id: params.asset_id,
        is_our_offer: true,
    };

    // Seller captures (cookie has seller steam ID)
    let http_request = format!(
        "GET /IEconService/GetTradeOffer/v1/?tradeofferid={} HTTP/1.1\r\n\
         Host: api.steampowered.com\r\n\
         Cookie: steamLoginSecure={}%7C%7CeyToken\r\n\
         Connection: close\r\n\r\n",
        params.trade_offer_id, params.seller_steam_id
    );

    let result = run_mpc_tls_flow(&certs, fixture, &escrow, &oracle_config, &http_request).await;
    let s = &result.settlement;

    // Verify settlement decision
    assert_eq!(s.decision, 1, "Expected Refund (1)");
    // Seller created offer + expired → BuyerExpired (7)
    assert_eq!(s.refund_reason, 7, "Expected RefundReason::BuyerExpired (7)");
    assert_eq!(s.asset_id, params.asset_id);

    // Verify EIP-712 signature via ecrecover
    let contract_address: alloy::primitives::Address =
        TEST_CONTRACT_ADDRESS.parse().unwrap();
    let recovered = eip712_verify::verify_settlement_signature(
        &s.signature,
        s.asset_id,
        escrow.trade_offer_id,
        s.decision,
        s.refund_reason,
        TEST_CHAIN_ID,
        contract_address,
    );
    assert_eq!(
        recovered,
        signer.address(),
        "ecrecover must match oracle signer address"
    );

    // Write fixture for Phase 5A
    write_fixture_json(s, &escrow, &signer, "settlement-fixture-refund.json");
}

// ============================================================================
// Test 2b: Happy path — Refund via Community HTML (trade abandonment)
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_mpc_tls_community_refund_happy_path() {
    let _ = tracing_subscriber::fmt::try_init();

    let certs = cert_gen::generate_test_certs();
    let params = TestParams::default();
    let escrow = escrow_builder::build_test_escrow(&params);
    let oracle_config = default_oracle_config();
    let signer = OracleSigner::from_config(&oracle_config).await.unwrap();

    let fixture = SteamFixture::CommunityTradeNotFound;

    // Buyer visits the community trade offer page — cookie has buyer steam ID
    let http_request = format!(
        "GET /tradeoffer/{} HTTP/1.1\r\n\
         Host: steamcommunity.com\r\n\
         Cookie: steamLoginSecure={}%7C%7CeyToken\r\n\
         Connection: close\r\n\r\n",
        params.trade_offer_id, params.buyer_steam_id
    );

    let result = run_mpc_tls_flow_with_host(
        &certs, fixture, &escrow, &oracle_config, &http_request, "steamcommunity.com",
    ).await;
    let s = &result.settlement;

    // Verify settlement decision: Refund with TradeNotExist (16)
    assert_eq!(s.decision, 1, "Expected Refund (1)");
    assert_eq!(s.refund_reason, 16, "Expected RefundReason::TradeNotExist (16)");
    assert_eq!(s.asset_id, params.asset_id);

    // Verify EIP-712 signature via ecrecover
    let contract_address: alloy::primitives::Address =
        TEST_CONTRACT_ADDRESS.parse().unwrap();
    let recovered = eip712_verify::verify_settlement_signature(
        &s.signature,
        s.asset_id,
        escrow.trade_offer_id,
        s.decision,
        s.refund_reason,
        TEST_CHAIN_ID,
        contract_address,
    );
    assert_eq!(
        recovered,
        signer.address(),
        "ecrecover must match oracle signer address"
    );
}

// ============================================================================
// Test 3: Security — Wrong CA cert (TLS handshake must fail)
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_mpc_tls_wrong_ca_rejected() {
    let _ = tracing_subscriber::fmt::try_init();
    CryptoProvider::install_default(rustls::crypto::ring::default_provider()).ok();

    // Generate TWO independent CA certs
    let certs_for_server = cert_gen::generate_test_certs(); // Server uses CA-A
    let certs_for_prover = cert_gen::generate_test_certs(); // Prover trusts CA-B (different!)

    let params = TestParams::default();
    let escrow = escrow_builder::build_test_escrow(&params);

    let fixture = SteamFixture::TradeStatusComplete {
        trade_id: params.trade_id,
        asset_id: params.asset_id,
        buyer_steam_id: params.buyer_steam_id,
    };

    // Prover ↔ Verifier socket
    let (prover_socket, verifier_socket) = tokio::io::duplex(2 << 23);

    // Verifier trusts server's CA (CA-A) — it will validate the server cert
    let verifier_ca = certs_for_server.ca_cert_der.clone();
    let verifier_signer = create_test_signer().await;
    let escrow_clone = escrow.clone();

    let verifier_task = tokio::spawn(async move {
        let verifier_config = VerifierConfig::builder()
            .root_store(RootCertStore {
                roots: vec![CertificateDer(verifier_ca)],
            })
            .build()
            .unwrap();

        let result = verifier::run_mpc_tls(verifier_socket.compat(), verifier_config).await;
        // The verifier may succeed or fail depending on when the error propagates.
        // What matters is the prover side fails.
        result
    });

    // Prover side — trusts CA-B (NOT the server's CA-A)
    let mut session = Session::new(prover_socket.compat());
    let prover = session
        .new_prover(ProverConfig::builder().build().unwrap())
        .unwrap();
    let (driver, handle) = session.split();
    tokio::spawn(driver);

    // Mock Steam server with CA-A certs
    let (client_socket, server_socket) = tokio::io::duplex(2 << 16);
    tokio::spawn(async move {
        mock_steam::bind_steam_fixture(server_socket, &certs_for_server, fixture).await;
    });

    let prover = prover
        .commit(
            TlsCommitConfig::builder()
                .protocol(
                    MpcTlsConfig::builder()
                        .max_sent_data(MAX_SENT_DATA)
                        .max_sent_records(MAX_SENT_RECORDS)
                        .max_recv_data(MAX_RECV_DATA)
                        .max_recv_records_online(MAX_RECV_RECORDS)
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap(),
        )
        .await
        .unwrap();

    // Connect with WRONG root store (CA-B) — should fail TLS handshake
    let connect_result = prover
        .connect(
            TlsClientConfig::builder()
                .server_name(ServerName::Dns("api.steampowered.com".try_into().unwrap()))
                .root_store(RootCertStore {
                    roots: vec![CertificateDer(certs_for_prover.ca_cert_der.clone())],
                })
                .build()
                .unwrap(),
            client_socket.compat(),
        )
        .await;

    // The TLS handshake should fail because the server cert (signed by CA-A)
    // is not trusted by the prover (which only trusts CA-B).
    // The error may surface at connect() or during the MPC-TLS run.
    let mut connect_failed = false;
    let mut prover_failed = false;

    match connect_result {
        Err(e) => {
            eprintln!("[test] TLS connect correctly failed: {e}");
            connect_failed = true;
        }
        Ok((mut tls_conn, prover_fut)) => {
            let prover_task = tokio::spawn(prover_fut);

            // Try to send data — should fail during MPC-TLS
            let write_result = tls_conn
                .write_all(b"GET / HTTP/1.1\r\nHost: api.steampowered.com\r\nConnection: close\r\n\r\n")
                .await;

            if write_result.is_ok() {
                let _ = tls_conn.close().await;
            }

            // Check prover outcome
            let prover_result = prover_task.await;
            match prover_result {
                Ok(Ok(_)) => {
                    eprintln!("[test] Prover unexpectedly succeeded");
                }
                Ok(Err(e)) => {
                    eprintln!("[test] Prover correctly failed: {e}");
                    prover_failed = true;
                }
                Err(e) => {
                    eprintln!("[test] Prover task panicked: {e}");
                    prover_failed = true;
                }
            }
        }
    }

    handle.close();

    let verifier_result = verifier_task.await.unwrap();
    let verifier_failed = verifier_result.is_err();
    if let Err(e) = &verifier_result {
        eprintln!("[test] Verifier correctly failed: {e:?}");
    }

    assert!(
        connect_failed || prover_failed || verifier_failed,
        "MPC-TLS flow must fail when prover trusts wrong CA. \
         connect_failed={connect_failed}, prover_failed={prover_failed}, verifier_failed={verifier_failed}"
    );
}

// ============================================================================
// Test 4: Security — Wrong asset_id in Steam response
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_mpc_tls_wrong_asset_rejected() {
    let _ = tracing_subscriber::fmt::try_init();

    let certs = cert_gen::generate_test_certs();
    let params = TestParams::default();
    let escrow = escrow_builder::build_test_escrow(&params);
    let oracle_config = default_oracle_config();

    // Steam response has a DIFFERENT asset_id than escrow expects
    let fixture = SteamFixture::TradeStatusWrongAsset {
        trade_id: params.trade_id,
        wrong_asset_id: 99999999999, // Doesn't match escrow.asset_id
        buyer_steam_id: params.buyer_steam_id,
    };

    let http_request = format!(
        "GET /IEconService/GetTradeStatus/v1/?key=REDACTED&tradeid={} HTTP/1.1\r\n\
         Host: api.steampowered.com\r\n\
         Connection: close\r\n\r\n",
        params.trade_id
    );

    // This should panic in handle_post_protocol because oracle::decide() returns
    // an error (InvalidReleaseProof — asset_id mismatch).
    // We run it in a spawned task to catch the panic.
    let certs_clone = TestCerts {
        ca_cert_der: certs.ca_cert_der.clone(),
        server_cert_der: certs.server_cert_der.clone(),
        server_key_der: certs.server_key_der.clone(),
    };
    let escrow_clone = escrow.clone();
    let http_req = http_request.clone();

    // Run in a separate task so we can catch the error
    let result = tokio::spawn(async move {
        run_mpc_tls_flow(&certs_clone, fixture, &escrow_clone, &oracle_config, &http_req).await
    })
    .await;

    // The verifier's handle_post_protocol should fail with settlement error
    assert!(
        result.is_err(),
        "MPC-TLS flow should fail when Steam response has wrong asset_id"
    );
}

// ============================================================================
// Test 5: Security — Wrong chain_id in signer (EIP-712 domain mismatch)
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_mpc_tls_wrong_chain_id_signature() {
    let _ = tracing_subscriber::fmt::try_init();

    let certs = cert_gen::generate_test_certs();
    let params = TestParams::default();
    let escrow = escrow_builder::build_test_escrow(&params);

    // Create signer with WRONG chain_id (mainnet instead of local)
    let key_path = std::env::temp_dir().join("test-oracle-key-wrong-chain.hex");
    std::fs::write(&key_path, TEST_ORACLE_KEY).unwrap();
    let wrong_config = OracleConfig {
        signing_key_path: Some(key_path.to_string_lossy().to_string()),
        contract_address: TEST_CONTRACT_ADDRESS.to_string(),
        chain_id: 1, // Ethereum mainnet instead of 31337!
        ..Default::default()
    };
    let wrong_signer = OracleSigner::from_config(&wrong_config).await.unwrap();

    let fixture = SteamFixture::TradeStatusComplete {
        trade_id: params.trade_id,
        asset_id: params.asset_id,
        buyer_steam_id: params.buyer_steam_id,
    };

    let http_request = format!(
        "GET /IEconService/GetTradeStatus/v1/?key=REDACTED&tradeid={} HTTP/1.1\r\n\
         Host: api.steampowered.com\r\n\
         Connection: close\r\n\r\n",
        params.trade_id
    );

    // The MPC-TLS flow itself succeeds (decision is correct)
    // But the signature uses wrong domain separator
    let result =
        run_mpc_tls_flow(&certs, fixture, &escrow, &wrong_config, &http_request).await;
    let s = &result.settlement;

    // Decision is still correct
    assert_eq!(s.decision, 0, "Expected Release (0)");
    assert_eq!(s.asset_id, params.asset_id);

    // But ecrecover with CORRECT chain_id should NOT match the signer
    let contract_address: alloy::primitives::Address =
        TEST_CONTRACT_ADDRESS.parse().unwrap();
    let recovered_with_correct_chain = eip712_verify::verify_settlement_signature(
        &s.signature,
        s.asset_id,
        escrow.trade_offer_id,
        s.decision,
        s.refund_reason,
        TEST_CHAIN_ID, // 31337 — correct chain
        contract_address,
    );

    // The recovered address should NOT be the oracle because the signature
    // was made with chain_id=1 but we verify with chain_id=31337
    assert_ne!(
        recovered_with_correct_chain,
        wrong_signer.address(),
        "ecrecover with correct chain_id must NOT match signer that used wrong chain_id"
    );

    // But with the WRONG chain_id (matching the signer), it DOES match
    let recovered_with_wrong_chain = eip712_verify::verify_settlement_signature(
        &s.signature,
        s.asset_id,
        escrow.trade_offer_id,
        s.decision,
        s.refund_reason,
        1, // Wrong chain — matches signer's domain
        contract_address,
    );
    assert_eq!(
        recovered_with_wrong_chain,
        wrong_signer.address(),
        "ecrecover with wrong chain_id should match signer"
    );
}
