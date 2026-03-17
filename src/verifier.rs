use std::fmt;
use std::time::{Duration, Instant};

use eyre::{Result, eyre};
use futures_util::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _};
use tokio::{task::JoinHandle, time::timeout};
use tracing::{info, warn};

use tlsn::{
    config::tls_commit::{TlsCommitProtocolConfig, TlsCommitRequest},
    config::verifier::VerifierConfig,
    connection::ServerName,
    transcript::ContentType,
    verifier::VerifierOutput,
    Session,
};

use crate::settlement::{oracle, EscrowSnapshot, OracleSigner, SettlementResult};

// ============================================================================
// MPC-TLS Result
// ============================================================================

/// Bundles MPC-TLS output needed by settlement.
pub struct MpcTlsResult {
    pub server_name: Option<ServerName>,
    pub sent_bytes: Vec<u8>,
    pub recv_bytes: Vec<u8>,
    pub ciphertext_sent_bytes: usize,
    pub ciphertext_recv_bytes: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct MpcTlsRuntimeLimits {
    pub max_sent_data: usize,
    pub max_recv_data: usize,
}

#[derive(Debug)]
pub enum MpcTlsError {
    Timeout { timeout: Duration },
    Session(eyre::Report),
}

impl fmt::Display for MpcTlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout { timeout } => {
                write!(
                    f,
                    "MPC-TLS session timed out after {}ms",
                    timeout.as_millis()
                )
            }
            Self::Session(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for MpcTlsError {}

const DRIVER_SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

// ============================================================================
// Step 1: Run MPC-TLS Protocol
// ============================================================================

/// Run MPC-TLS, extract plaintext, return result + reclaimed socket.
pub async fn run_mpc_tls<S: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
    session_id: &str,
    socket: S,
    verifier_config: VerifierConfig,
    limits: MpcTlsRuntimeLimits,
    timeout_duration: Duration,
) -> std::result::Result<(MpcTlsResult, S), MpcTlsError> {
    info!(session_id, "Starting MPC-TLS session");

    let session = Session::new(socket);
    let (driver, mut handle) = session.split();

    let mut driver_task = tokio::spawn(driver);

    info!(session_id, "Running MPC-TLS verifier protocol");
    let total_start = Instant::now();

    let protocol_result = timeout(timeout_duration, async {
        // Step 1: Create verifier + OT setup (commit)
        let t0 = Instant::now();
        let verifier = handle
            .new_verifier(verifier_config)
            .map_err(|e| eyre!("Failed to create verifier: {}", e))?
            .commit()
            .await
            .map_err(|e| eyre!("Commitment failed: {}", e))?;
        info!(session_id, stage = "commit", duration_ms = t0.elapsed().as_millis() as u64, "[TIMING] commit (OT setup)");

        if let Some(reject_reason) = validate_commit_request(verifier.request(), limits) {
            info!(
                session_id,
                max_sent_data = limits.max_sent_data,
                max_recv_data = limits.max_recv_data,
                reject_reason = reject_reason.as_str(),
                "Rejecting prover commit request that exceeds runtime limits"
            );
            verifier
                .reject(Some(&reject_reason))
                .await
                .map_err(|e| eyre!("Failed to reject oversized commitment request: {}", e))?;
            return Err(eyre!("Commitment request rejected: {reject_reason}"));
        }

        // Step 2: Accept (prover ready)
        let t1 = Instant::now();
        let verifier = verifier
            .accept()
            .await
            .map_err(|e| eyre!("Accept failed: {}", e))?;
        info!(session_id, stage = "accept", duration_ms = t1.elapsed().as_millis() as u64, "[TIMING] accept");

        // Step 3: Run MPC-TLS (garbled circuits over TLS)
        let t2 = Instant::now();
        let verifier = verifier
            .run()
            .await
            .map_err(|e| eyre!("MPC-TLS run failed: {}", e))?;
        info!(session_id, stage = "run", duration_ms = t2.elapsed().as_millis() as u64, "[TIMING] run (MPC-TLS)");

        info!(session_id, "MPC-TLS protocol complete, verifying transcript");

        // Step 4: Verify transcript
        let t3 = Instant::now();
        let verifier = verifier
            .verify()
            .await
            .map_err(|e| eyre!("Verification failed: {}", e))?;
        info!(session_id, stage = "verify", duration_ms = t3.elapsed().as_millis() as u64, "[TIMING] verify");

        // Step 5: Accept verification output
        let t4 = Instant::now();
        let (
            VerifierOutput {
                server_name,
                transcript,
                ..
            },
            verifier,
        ) = verifier
            .accept()
            .await
            .map_err(|e| eyre!("Accept verification failed: {}", e))?;
        info!(session_id, stage = "accept_verification", duration_ms = t4.elapsed().as_millis() as u64, "[TIMING] accept_verification");
        info!(session_id, stage = "mpc_tls_total", duration_ms = total_start.elapsed().as_millis() as u64, "[TIMING] total MPC-TLS");

        let tls_transcript = verifier.tls_transcript();

        // Extract plaintext from MPC-verified transcript
        let (sent_bytes, recv_bytes) = match transcript {
            Some(ref t) => (t.sent_unsafe().to_vec(), t.received_unsafe().to_vec()),
            None => (Vec::new(), Vec::new()),
        };

        // Log transcript lengths
        let sent_len: usize = tls_transcript
            .sent()
            .iter()
            .filter_map(|record| match record.typ {
                ContentType::ApplicationData => Some(record.ciphertext.len()),
                _ => None,
            })
            .sum();

        let recv_len: usize = tls_transcript
            .recv()
            .iter()
            .filter_map(|record| match record.typ {
                ContentType::ApplicationData => Some(record.ciphertext.len()),
                _ => None,
            })
            .sum();

        info!(
            session_id,
            ciphertext_sent_bytes = sent_len,
            ciphertext_recv_bytes = recv_len,
            plaintext_sent_bytes = sent_bytes.len(),
            plaintext_recv_bytes = recv_bytes.len(),
            "Transcript sizes recorded"
        );

        if let Some(ref name) = server_name {
            info!(session_id, server_name = %name, "Server name recorded");
        }

        verifier
            .close()
            .await
            .map_err(|e| eyre!("Failed to close verifier: {}", e))?;

        Ok(MpcTlsResult {
            server_name,
            sent_bytes,
            recv_bytes,
            ciphertext_sent_bytes: sent_len,
            ciphertext_recv_bytes: recv_len,
        })
    })
    .await;

    match protocol_result {
        Ok(Ok(result)) => {
            let t_close = Instant::now();
            handle.close();
            let socket = reclaim_socket_after_close(session_id, &mut driver_task)
                .await
                .map_err(MpcTlsError::Session)?;
            info!(session_id, stage = "close", duration_ms = t_close.elapsed().as_millis() as u64, "[TIMING] close + reclaim socket");
            Ok((result, socket))
        }
        Ok(Err(error)) => {
            handle.close();
            teardown_failed_session(session_id, &mut driver_task).await;
            Err(MpcTlsError::Session(error))
        }
        Err(_) => {
            handle.close();
            teardown_failed_session(session_id, &mut driver_task).await;
            Err(MpcTlsError::Timeout {
                timeout: timeout_duration,
            })
        }
    }
}

async fn reclaim_socket_after_close<S, E>(
    session_id: &str,
    driver_task: &mut JoinHandle<std::result::Result<S, E>>,
) -> Result<S>
where
    E: fmt::Display,
{
    match timeout(DRIVER_SHUTDOWN_GRACE, &mut *driver_task).await {
        Ok(joined) => joined
            .map_err(|e| eyre!("Driver task failed: {}", e))?
            .map_err(|e| eyre!("Session driver error: {}", e)),
        Err(_) => {
            warn!(
                session_id,
                grace_ms = DRIVER_SHUTDOWN_GRACE.as_millis() as u64,
                "Driver task did not stop after close, aborting"
            );
            driver_task.abort();
            let _ = driver_task.await;
            Err(eyre!(
                "Driver task did not stop after close within {}ms",
                DRIVER_SHUTDOWN_GRACE.as_millis()
            ))
        }
    }
}

async fn teardown_failed_session<S, E>(
    session_id: &str,
    driver_task: &mut JoinHandle<std::result::Result<S, E>>,
) where
    E: fmt::Display,
{
    match timeout(DRIVER_SHUTDOWN_GRACE, &mut *driver_task).await {
        Ok(Ok(Ok(_socket))) => {
            info!(session_id, "Failed MPC-TLS session driver shut down cleanly");
        }
        Ok(Ok(Err(error))) => {
            warn!(session_id, error = %error, "Failed MPC-TLS session driver returned an error during cleanup");
        }
        Ok(Err(error)) => {
            warn!(session_id, error = %error, "Failed MPC-TLS session driver join failed during cleanup");
        }
        Err(_) => {
            warn!(
                session_id,
                grace_ms = DRIVER_SHUTDOWN_GRACE.as_millis() as u64,
                "Failed MPC-TLS session driver did not stop after close, aborting"
            );
            driver_task.abort();
            let _ = driver_task.await;
        }
    }
}

fn validate_commit_request(
    request: &TlsCommitRequest,
    limits: MpcTlsRuntimeLimits,
) -> Option<String> {
    let TlsCommitProtocolConfig::Mpc(mpc_tls_config) = request.protocol() else {
        return Some("expecting to use MPC-TLS".to_string());
    };

    if mpc_tls_config.max_sent_data() > limits.max_sent_data {
        return Some(format!(
            "max_sent_data is too large (requested {}, allowed {})",
            mpc_tls_config.max_sent_data(),
            limits.max_sent_data
        ));
    }

    if mpc_tls_config.max_recv_data() > limits.max_recv_data {
        return Some(format!(
            "max_recv_data is too large (requested {}, allowed {})",
            mpc_tls_config.max_recv_data(),
            limits.max_recv_data
        ));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use tlsn::config::tls_commit::{TlsCommitConfig, mpc::MpcTlsConfig};

    fn request_with_limits(max_sent_data: usize, max_recv_data: usize) -> TlsCommitRequest {
        TlsCommitConfig::builder()
            .protocol(
                MpcTlsConfig::builder()
                    .max_sent_data(max_sent_data)
                    .max_recv_data(max_recv_data)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap()
            .to_request()
    }

    #[test]
    fn accepts_commit_request_within_runtime_limits() {
        let request = request_with_limits(1024, 2048);
        let limits = MpcTlsRuntimeLimits {
            max_sent_data: 1024,
            max_recv_data: 2048,
        };

        assert!(validate_commit_request(&request, limits).is_none());
    }

    #[test]
    fn rejects_commit_request_when_sent_limit_is_too_large() {
        let request = request_with_limits(2048, 2048);
        let limits = MpcTlsRuntimeLimits {
            max_sent_data: 1024,
            max_recv_data: 2048,
        };

        let rejection = validate_commit_request(&request, limits)
            .expect("expected request to be rejected");
        assert!(rejection.contains("max_sent_data"));
    }

    #[test]
    fn rejects_commit_request_when_recv_limit_is_too_large() {
        let request = request_with_limits(1024, 4096);
        let limits = MpcTlsRuntimeLimits {
            max_sent_data: 1024,
            max_recv_data: 2048,
        };

        let rejection = validate_commit_request(&request, limits)
            .expect("expected request to be rejected");
        assert!(rejection.contains("max_recv_data"));
    }
}

// ============================================================================
// Step 2: Post-MPC Settlement (single verifier path)
// ============================================================================

/// Handle post-MPC settlement: decide using MPC-verified plaintext, sign EIP-712.
///
/// Wire protocol (server → prover only):
///   result_len(u64) | bincode(SettlementResult)
///
/// The prover sends nothing — the server already has MPC-verified plaintext.
pub async fn handle_post_protocol<S: AsyncRead + AsyncWrite + Unpin>(
    session_id: &str,
    mpc: &MpcTlsResult,
    socket: &mut S,
    escrow: &EscrowSnapshot,
    signer: &OracleSigner,
) -> Result<()> {
    // Use MPC-verified plaintext directly (NOT prover-sent data)
    let server_name_str = mpc
        .server_name
        .as_ref()
        .map(|sn| sn.to_string())
        .unwrap_or_default();

    info!(
        session_id,
        "Settlement: server={}, sent={} bytes, recv={} bytes",
        server_name_str,
        mpc.sent_bytes.len(),
        mpc.recv_bytes.len()
    );

    let t_decide = Instant::now();
    // proof_timestamp from server wall clock, not MPC transcript.
    // Accepted risk: in TDX VM with NTP, clock drift is <1s.
    // Used for time_settlement comparison and 24h abandonment check —
    // both have hour-scale margins, so sub-second drift is harmless.
    let proof_timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs();
    let settlement = oracle::decide(&server_name_str, &mpc.sent_bytes, &mpc.recv_bytes, escrow, proof_timestamp)
        .map_err(|e| eyre!("Settlement decision failed: {e}"))?;
    info!(session_id, stage = "oracle_decide", duration_ms = t_decide.elapsed().as_millis() as u64, "[TIMING] oracle::decide");

    info!(
        session_id,
        "Decision: asset_id={}, decision={:?}, refund_reason={:?}",
        settlement.asset_id, settlement.decision, settlement.refund_reason
    );

    let t_sign = Instant::now();
    let signature = signer
        .sign_settlement(&settlement)
        .await
        .map_err(|e| eyre!("EIP-712 signing failed: {e}"))?;
    info!(session_id, stage = "sign", duration_ms = t_sign.elapsed().as_millis() as u64, "[TIMING] EIP-712 sign");

    info!(
        session_id,
        "Signed settlement: sig=0x{}",
        hex::encode(&signature)
    );

    let wire_result = SettlementResult {
        signature,
        asset_id: settlement.asset_id,
        decision: settlement.decision as u8,
        refund_reason: settlement.refund_reason as u8,
    };

    let result_bytes =
        bincode::serialize(&wire_result).map_err(|e| eyre!("Failed to serialize result: {e}"))?;

    // Send: result_len(u64) | result_bytes
    socket
        .write_all(&(result_bytes.len() as u64).to_le_bytes())
        .await
        .map_err(|e| eyre!("Failed to send result length: {e}"))?;
    socket
        .write_all(&result_bytes)
        .await
        .map_err(|e| eyre!("Failed to send result: {e}"))?;
    socket
        .flush()
        .await
        .map_err(|e| eyre!("Failed to flush: {e}"))?;

    info!(
        "Settlement result sent ({} bytes): asset_id={}, decision={:?}",
        result_bytes.len(),
        settlement.asset_id,
        settlement.decision
    );

    Ok(())
}
