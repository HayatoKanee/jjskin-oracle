//! Mock Steam HTTPS fixture server for MPC-TLS integration tests.
//!
//! Serves Steam API JSON responses over TLS using test certificates.
//! Runs over a duplex socket (in-process, no TCP).

use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio_rustls::TlsAcceptor;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use super::cert_gen::TestCerts;

/// Steam fixture variants for mock HTTPS server.
#[derive(Debug, Clone)]
pub enum SteamFixture {
    /// GetTradeStatus: status=3 (Complete), items exchanged successfully.
    TradeStatusComplete {
        trade_id: u64,
        asset_id: u64,
        buyer_steam_id: u64,
    },
    /// GetTradeOffer: state=5 (Expired).
    TradeOfferExpired {
        trade_offer_id: u64,
        partner_account_id: u64,
        asset_id: u64,
        is_our_offer: bool,
    },
    /// GetTradeStatus: status=3 but with WRONG asset_id (security test).
    TradeStatusWrongAsset {
        trade_id: u64,
        wrong_asset_id: u64,
        buyer_steam_id: u64,
    },
    /// Community HTML: trade-not-found error page (abandonment refund).
    CommunityTradeNotFound,
}

/// Response body + content type for the mock server.
struct FixtureResponse {
    body: String,
    content_type: &'static str,
}

impl SteamFixture {
    /// Generate the HTTP response body and content type for this fixture.
    fn to_response(&self) -> FixtureResponse {
        match self {
            SteamFixture::TradeStatusComplete {
                trade_id,
                asset_id,
                buyer_steam_id,
            } => FixtureResponse {
                body: format!(
                    r#"{{"response":{{"trades":[{{"tradeid":"{trade_id}","status":3,"steamid_other":"{buyer_steam_id}","time_init":1700100000,"time_escrow_end":0,"assets_given":[{{"appid":730,"contextid":"2","assetid":"{asset_id}","new_assetid":"99999","new_contextid":"2","amount":"1"}}],"assets_received":[],"time_settlement":1700100100}}]}}}}"#
                ),
                content_type: "application/json; charset=UTF-8",
            },
            SteamFixture::TradeOfferExpired {
                trade_offer_id,
                partner_account_id,
                asset_id,
                is_our_offer,
            } => {
                let is_our = if *is_our_offer { "true" } else { "false" };
                FixtureResponse {
                    body: format!(
                        r#"{{"response":{{"offer":{{"tradeofferid":"{trade_offer_id}","accountid_other":{partner_account_id},"trade_offer_state":5,"items_to_give":[{{"appid":730,"assetid":"{asset_id}"}}],"items_to_receive":[],"is_our_offer":{is_our}}}}}}}"#
                    ),
                    content_type: "application/json; charset=UTF-8",
                }
            }
            SteamFixture::TradeStatusWrongAsset {
                trade_id,
                wrong_asset_id,
                buyer_steam_id,
            } => FixtureResponse {
                body: format!(
                    r#"{{"response":{{"trades":[{{"tradeid":"{trade_id}","status":3,"steamid_other":"{buyer_steam_id}","time_init":1700100000,"time_escrow_end":0,"assets_given":[{{"appid":730,"contextid":"2","assetid":"{wrong_asset_id}","new_assetid":"99999","new_contextid":"2","amount":"1"}}],"assets_received":[],"time_settlement":1700100100}}]}}}}"#
                ),
                content_type: "application/json; charset=UTF-8",
            },
            SteamFixture::CommunityTradeNotFound => FixtureResponse {
                body: "<title>Steam Community :: Error</title>The trade offer does not exist, or the trade offer belongs to another user.".to_string(),
                content_type: "text/html; charset=UTF-8",
            },
        }
    }
}

/// Bind a mock Steam HTTPS server on the given socket.
///
/// Accepts one TLS connection, reads one HTTP request, responds with the fixture JSON,
/// then closes the connection.
pub async fn bind_steam_fixture<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    socket: S,
    certs: &TestCerts,
    fixture: SteamFixture,
) {
    // Build rustls ServerConfig with test certs
    let server_cert = CertificateDer::from(certs.server_cert_der.clone());
    let server_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certs.server_key_der.clone()));

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![server_cert], server_key)
        .expect("Failed to build server TLS config");

    let acceptor = TlsAcceptor::from(Arc::new(config));

    // Accept TLS connection
    let mut tls_stream = match acceptor.accept(socket).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[mock_steam] TLS accept failed: {e}");
            return;
        }
    };

    // Read HTTP request (just need to consume it)
    let mut reader = BufReader::new(&mut tls_stream);
    let mut request_line = String::new();
    if let Err(e) = reader.read_line(&mut request_line).await {
        eprintln!("[mock_steam] Failed to read request line: {e}");
        return;
    }

    // Consume remaining headers until empty line
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                if line.trim().is_empty() {
                    break;
                }
            }
        }
    }

    // Build HTTP response
    let fixture_resp = fixture.to_response();
    let response = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: {}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        fixture_resp.content_type,
        fixture_resp.body.len(),
        fixture_resp.body
    );

    // Send response
    // We need to get back the underlying stream from the BufReader
    drop(reader);
    if let Err(e) = tls_stream.write_all(response.as_bytes()).await {
        eprintln!("[mock_steam] Failed to write response: {e}");
        return;
    }
    if let Err(e) = tls_stream.shutdown().await {
        // Shutdown errors are expected when the other side closes first
        eprintln!("[mock_steam] TLS shutdown (expected): {e}");
    }
}
