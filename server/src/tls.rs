// Builds the server-side TLS configuration. Everything that actually
// *serves* Modbus requests over the resulting stream is unchanged —
// `connection::serve_tcp_connection` is already generic over
// `S: AsyncRead + AsyncWrite + Unpin`, so a `TlsStream<TcpStream>` (from
// wrapping an accepted TCP connection with a `tokio_rustls::TlsAcceptor`
// built from this config) works with it as-is. No new serve-loop needed.

use crate::client_trust::ApprovedClients;
use fuse_fs::client_trust::ClientTrustState;
use protocol::tls::{Fingerprint, Identity};
use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, Error as TlsError, ServerConfig};
use std::sync::{Arc, Mutex};

/// The `ClientCertVerifier` methods concerned with checking that a
/// handshake signature is cryptographically valid — i.e. that the peer
/// really holds the private key for the certificate it presented — as
/// opposed to *whether that certificate should be trusted*, which is a
/// separate decision each verifier below makes its own way. Mirrors
/// `client::connection::SignatureVerification` (same shape, can't share the
/// type across crates since each side's `ClientCertVerifier`/
/// `ServerCertVerifier` trait methods differ).
#[derive(Debug)]
struct SignatureVerification {
    supported_algorithms: WebPkiSupportedAlgorithms,
}

impl SignatureVerification {
    fn new() -> Self {
        Self {
            supported_algorithms: rustls::crypto::ring::default_provider()
                .signature_verification_algorithms,
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.supported_algorithms.supported_schemes()
    }
}

/// Verifies a presented client certificate by comparing its public-key
/// fingerprint against `approved`, the server's live client-approval roster
/// (Milestone N's `client-trust`/`approved/` design) — this project's only
/// real client-authentication decision, matching `PinnedFingerprintServerCertVerifier`
/// on the client side: no CA, no certificate fields other than the raw
/// public key ever consulted. Fail-closed: an empty `approved` set (the
/// default at startup, before Milestone P's admin channel adds anything)
/// rejects every client.
#[derive(Debug)]
struct ApprovedFingerprintClientCertVerifier {
    approved: Arc<Mutex<ApprovedClients>>,
    // Every attempt is logged here for `client-trust/connection_attempts/`
    // to display (O3) — the *same* state the FUSE side reads, not a
    // separate copy (see server::main's own comment on why: this is what
    // closes O2's "known gap").
    client_trust: Arc<Mutex<ClientTrustState>>,
    signature_verification: SignatureVerification,
}

impl ApprovedFingerprintClientCertVerifier {
    fn new(
        approved: Arc<Mutex<ApprovedClients>>,
        client_trust: Arc<Mutex<ClientTrustState>>,
    ) -> Self {
        Self {
            approved,
            client_trust,
            signature_verification: SignatureVerification::new(),
        }
    }
}

/// Parses `cert` and computes its public-key fingerprint — shared by
/// `verify_client_cert` below (during the handshake) and `peer_fingerprint`
/// (after it, see R2's connection-tracking accept loop in `server::main`),
/// since both need exactly the same "raw certificate bytes -> `Fingerprint`"
/// step.
fn fingerprint_of_certificate(cert: &CertificateDer<'_>) -> Option<Fingerprint> {
    let parsed = webpki::EndEntityCert::try_from(cert).ok()?;
    Some(Fingerprint::of(parsed.subject_public_key_info().as_ref()))
}

/// The client certificate fingerprint of an already-completed handshake —
/// used by the TLS accept loop (R2) to know which `LiveConnections` entry a
/// newly-served connection belongs to. `build_server_config` always makes
/// a client certificate mandatory, so a successfully completed handshake
/// has always verified and parsed one already; this only re-derives the
/// same fingerprint from the now-established connection rather than
/// threading it out of `ApprovedFingerprintClientCertVerifier` by hand.
/// `None` should therefore never actually happen in practice, but callers
/// still have to handle it (no certificate at all, or one that somehow
/// doesn't parse here despite having passed verification).
pub fn peer_fingerprint(connection: &rustls::ServerConnection) -> Option<Fingerprint> {
    let certificates = connection.peer_certificates()?;
    let end_entity = certificates.first()?;
    fingerprint_of_certificate(end_entity)
}

impl ClientCertVerifier for ApprovedFingerprintClientCertVerifier {
    // Empty: this server has no CA/trust-anchor concept at all (matches the
    // project's fingerprint-only design), so there is nothing meaningful to
    // hint to a connecting client about which authorities it should pick a
    // certificate from.
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        let Some(presented_fingerprint) = fingerprint_of_certificate(end_entity) else {
            // No fingerprint to log here — parsing failed before one could
            // be computed at all, a genuinely different failure mode from
            // "valid certificate, just not approved" (see `log_rejected`'s
            // own doc comment for why this goes there, not `log_pending`).
            self.client_trust
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .log_rejected(format!("{} malformed certificate", unix_timestamp()));
            return Err(TlsError::InvalidCertificate(
                rustls::CertificateError::BadEncoding,
            ));
        };
        let is_approved = self
            .approved
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains(&presented_fingerprint);
        let mut client_trust = self
            .client_trust
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if is_approved {
            client_trust.log_approved(format!("{} {presented_fingerprint}", unix_timestamp()));
            drop(client_trust);
            Ok(ClientCertVerified::assertion())
        } else {
            client_trust.log_pending(format!("{} {presented_fingerprint}", unix_timestamp()));
            drop(client_trust);
            Err(TlsError::General(format!(
                "client TLS fingerprint {presented_fingerprint} is not approved"
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.signature_verification
            .verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.signature_verification
            .verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.signature_verification.supported_verify_schemes()
    }
}

// Plain Unix-epoch seconds rather than a calendar-formatted string — no
// need to add a date/time-formatting dependency just for this, and every
// existing consumer (a technician reading a log by eye) can convert one
// with `date -d @<seconds>` if they need to.
fn unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Builds a `rustls::ServerConfig` presenting `identity`. **Requires** a
/// client certificate (mTLS on) and checks it against `approved` — see
/// `ApprovedFingerprintClientCertVerifier`. Fail-closed: an empty
/// `approved` set (the default until Milestone P's admin channel adds
/// something) rejects every client. Every attempt is also logged into
/// `client_trust` (`client-trust/connection_attempts/*.log`, Milestone O3).
pub fn build_server_config(
    identity: &Identity,
    approved: Arc<Mutex<ApprovedClients>>,
    client_trust: Arc<Mutex<ClientTrustState>>,
) -> Result<ServerConfig, String> {
    let certificate = CertificateDer::from(identity.certificate_der.clone());
    let private_key = PrivateKeyDer::try_from(identity.private_key_der.clone())
        .map_err(|error| error.to_string())?;
    ServerConfig::builder()
        .with_client_cert_verifier(Arc::new(ApprovedFingerprintClientCertVerifier::new(
            approved,
            client_trust,
        )))
        .with_single_cert(vec![certificate], private_key)
        .map_err(|error| error.to_string())
}

/// Completes a TLS handshake on `stream`, bounded by `timeout` (Milestone
/// U1) — separate from the per-I/O-step timeout `connection::
/// serve_tcp_connection` applies once a connection is already serving real
/// Modbus PDUs. A peer that opens a TCP connection and then never sends a
/// `ClientHello` (or drags the handshake out deliberately) would otherwise
/// tie up an accepted connection and its task indefinitely. Returns `None`
/// uniformly for either a handshake failure (e.g. a peer not actually
/// speaking TLS) or a timeout — callers already treat both the same way
/// (drop the connection without taking the server down), so there is
/// nothing a caller could usefully do differently between the two anyway.
pub async fn accept_with_timeout<IO>(
    acceptor: &tokio_rustls::TlsAcceptor,
    stream: IO,
    timeout: std::time::Duration,
) -> Option<tokio_rustls::server::TlsStream<IO>>
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    tokio::time::timeout(timeout, acceptor.accept(stream))
        .await
        .ok()?
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::serve_tcp_connection;
    use fuse_fs::{CoilStore, RegisterStore};
    use protocol::adu::TcpAdu;
    use protocol::device_description::{AccessRight, DataType, MemLayout, RegisterDescription};
    use protocol::pdu::{ReadHoldingRegistersRequest, ReadHoldingRegistersResponse};
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::crypto::WebPkiSupportedAlgorithms;
    use rustls::pki_types::{ServerName, UnixTime};
    use rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    // Mirrors `client::connection::InsecureAcceptAnyServerCert` (K6a) — a
    // minimal in-test client double standing in for the real `client`
    // binary, which this crate can't depend on. Same "temporary, proves the
    // transport only" caveat applies.
    #[derive(Debug)]
    struct InsecureAcceptAnyServerCert {
        supported_algorithms: WebPkiSupportedAlgorithms,
    }

    impl InsecureAcceptAnyServerCert {
        fn new() -> Self {
            Self {
                supported_algorithms: rustls::crypto::ring::default_provider()
                    .signature_verification_algorithms,
            }
        }
    }

    impl ServerCertVerifier for InsecureAcceptAnyServerCert {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, TlsError> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, TlsError> {
            rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported_algorithms)
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, TlsError> {
            rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported_algorithms)
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.supported_algorithms.supported_schemes()
        }
    }

    fn test_client_trust() -> Arc<Mutex<ClientTrustState>> {
        Arc::new(Mutex::new(ClientTrustState::new()))
    }

    #[test]
    fn builds_a_server_config_from_a_generated_identity() {
        let identity = protocol::tls::generate_self_signed_identity().unwrap();
        let approved = Arc::new(Mutex::new(ApprovedClients::new()));
        assert!(build_server_config(&identity, approved, test_client_trust()).is_ok());
    }

    #[tokio::test]
    async fn accept_with_timeout_returns_none_if_the_peer_never_completes_the_handshake() {
        let identity = protocol::tls::generate_self_signed_identity().unwrap();
        let server_config = build_server_config(
            &identity,
            Arc::new(Mutex::new(ApprovedClients::new())),
            test_client_trust(),
        )
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

        // Nothing is ever written to this end, so the acceptor never even
        // receives a ClientHello — the handshake can never complete on its
        // own, only via the timeout.
        let (server_side, _never_written_to) = tokio::io::duplex(1024);

        let result =
            accept_with_timeout(&acceptor, server_side, std::time::Duration::from_millis(20)).await;

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn accept_with_timeout_succeeds_for_a_real_handshake_within_the_timeout() {
        let identity = protocol::tls::generate_self_signed_identity().unwrap();
        let client_identity = protocol::tls::generate_self_signed_identity().unwrap();
        let mut approved_clients = ApprovedClients::new();
        approved_clients.insert(Fingerprint::of(&client_identity.public_key_der));
        let server_config = build_server_config(
            &identity,
            Arc::new(Mutex::new(approved_clients)),
            test_client_trust(),
        )
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();

        let server_task = tokio::spawn(async move {
            let (tcp_stream, _peer) = listener.accept().await.unwrap();
            accept_with_timeout(&acceptor, tcp_stream, std::time::Duration::from_secs(5)).await
        });

        let client_certificate = CertificateDer::from(client_identity.certificate_der);
        let client_private_key = PrivateKeyDer::try_from(client_identity.private_key_der).unwrap();
        let client_config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureAcceptAnyServerCert::new()))
            .with_client_auth_cert(vec![client_certificate], client_private_key)
            .unwrap();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
        let tcp_stream = tokio::net::TcpStream::connect(&address).await.unwrap();
        let _stream = connector
            .connect(ServerName::try_from("localhost").unwrap(), tcp_stream)
            .await
            .unwrap();

        assert!(server_task.await.unwrap().is_some());
    }

    // `ApprovedFingerprintClientCertVerifier` tests below exercise
    // `verify_client_cert` directly against a real certificate — no TLS
    // handshake needed to test the decision logic itself, only real DER
    // bytes for `webpki::EndEntityCert::try_from` to parse.

    #[test]
    fn approved_fingerprint_client_cert_verifier_accepts_an_approved_fingerprint() {
        let identity = protocol::tls::generate_self_signed_identity().unwrap();
        let fingerprint = Fingerprint::of(&identity.public_key_der);
        let mut approved_clients = ApprovedClients::new();
        approved_clients.insert(fingerprint);
        let verifier = ApprovedFingerprintClientCertVerifier::new(
            Arc::new(Mutex::new(approved_clients)),
            test_client_trust(),
        );

        let end_entity = CertificateDer::from(identity.certificate_der);
        let result = verifier.verify_client_cert(&end_entity, &[], UnixTime::now());

        assert!(result.is_ok());
    }

    #[test]
    fn approved_fingerprint_client_cert_verifier_rejects_an_unapproved_fingerprint() {
        let identity = protocol::tls::generate_self_signed_identity().unwrap();
        // Empty — nothing approved, matching the fail-closed default before
        // Milestone P's admin channel ever inserts anything.
        let verifier = ApprovedFingerprintClientCertVerifier::new(
            Arc::new(Mutex::new(ApprovedClients::new())),
            test_client_trust(),
        );

        let end_entity = CertificateDer::from(identity.certificate_der);
        let result = verifier.verify_client_cert(&end_entity, &[], UnixTime::now());

        assert!(result.is_err());
    }

    #[test]
    fn approved_fingerprint_client_cert_verifier_rejects_one_identity_when_a_different_one_is_approved()
     {
        let approved_identity = protocol::tls::generate_self_signed_identity().unwrap();
        let other_identity = protocol::tls::generate_self_signed_identity().unwrap();
        let mut approved_clients = ApprovedClients::new();
        approved_clients.insert(Fingerprint::of(&approved_identity.public_key_der));
        let verifier = ApprovedFingerprintClientCertVerifier::new(
            Arc::new(Mutex::new(approved_clients)),
            test_client_trust(),
        );

        let end_entity = CertificateDer::from(other_identity.certificate_der);
        let result = verifier.verify_client_cert(&end_entity, &[], UnixTime::now());

        assert!(result.is_err());
    }

    #[test]
    fn approved_attempt_is_logged_to_the_approved_log() {
        let identity = protocol::tls::generate_self_signed_identity().unwrap();
        let fingerprint = Fingerprint::of(&identity.public_key_der);
        let mut approved_clients = ApprovedClients::new();
        approved_clients.insert(fingerprint);
        let client_trust = test_client_trust();
        let verifier = ApprovedFingerprintClientCertVerifier::new(
            Arc::new(Mutex::new(approved_clients)),
            Arc::clone(&client_trust),
        );

        let end_entity = CertificateDer::from(identity.certificate_der);
        verifier
            .verify_client_cert(&end_entity, &[], UnixTime::now())
            .unwrap();

        let state = client_trust.lock().unwrap();
        assert!(
            state
                .approved_log_content()
                .contains(&fingerprint.to_string())
        );
        assert_eq!(state.pending_log_content(), "");
        assert_eq!(state.rejected_log_content(), "");
    }

    #[test]
    fn unapproved_attempt_is_logged_to_the_pending_log() {
        let identity = protocol::tls::generate_self_signed_identity().unwrap();
        let fingerprint = Fingerprint::of(&identity.public_key_der);
        let client_trust = test_client_trust();
        let verifier = ApprovedFingerprintClientCertVerifier::new(
            Arc::new(Mutex::new(ApprovedClients::new())),
            Arc::clone(&client_trust),
        );

        let end_entity = CertificateDer::from(identity.certificate_der);
        // Rejected, but logged as "pending" — a technician might still
        // approve it later; see `ClientTrustState::log_pending`'s own doc
        // comment for why this is distinct from `log_rejected`.
        let _ = verifier.verify_client_cert(&end_entity, &[], UnixTime::now());

        let state = client_trust.lock().unwrap();
        assert!(
            state
                .pending_log_content()
                .contains(&fingerprint.to_string())
        );
        assert_eq!(state.approved_log_content(), "");
        assert_eq!(state.rejected_log_content(), "");
    }

    #[test]
    fn unparseable_certificate_is_logged_to_the_rejected_log() {
        let client_trust = test_client_trust();
        let verifier = ApprovedFingerprintClientCertVerifier::new(
            Arc::new(Mutex::new(ApprovedClients::new())),
            Arc::clone(&client_trust),
        );

        let bogus_end_entity = CertificateDer::from(b"not a real certificate".to_vec());
        let result = verifier.verify_client_cert(&bogus_end_entity, &[], UnixTime::now());

        assert!(result.is_err());
        let state = client_trust.lock().unwrap();
        assert!(!state.rejected_log_content().is_empty());
        assert_eq!(state.approved_log_content(), "");
        assert_eq!(state.pending_log_content(), "");
    }

    #[tokio::test]
    async fn tls_connection_is_served_like_any_other_stream() {
        let identity = protocol::tls::generate_self_signed_identity().unwrap();
        // The server now checks the presented client fingerprint against an
        // approved set (N2b) — generate the test client's identity first so
        // it can be approved before the server config is even built.
        let client_identity = protocol::tls::generate_self_signed_identity().unwrap();
        let mut approved_clients = ApprovedClients::new();
        approved_clients.insert(Fingerprint::of(&client_identity.public_key_der));
        let approved = Arc::new(Mutex::new(approved_clients));
        let server_config = build_server_config(&identity, approved, test_client_trust()).unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();

        let registers = Arc::new(vec![RegisterDescription {
            name: "Tank_Temperature".to_string(),
            address: 40001,
            data_type: DataType::U16,
            access: AccessRight::ReadOnly,
        }]);
        let store = Arc::new(Mutex::new(RegisterStore::new()));
        store
            .lock()
            .unwrap()
            .set("Tank_Temperature", fuse_fs::RegisterValue::U16(72));
        let coils = Arc::new(Vec::new());
        let coil_store = Arc::new(Mutex::new(CoilStore::new()));
        let discrete_inputs = Arc::new(Vec::new());
        let discrete_input_store = Arc::new(Mutex::new(fuse_fs::DiscreteInputStore::new()));
        let input_registers = Arc::new(Vec::new());
        let input_register_store = Arc::new(Mutex::new(fuse_fs::InputRegisterStore::new()));
        let file_records = Arc::new(Vec::new());
        let file_record_store = Arc::new(Mutex::new(fuse_fs::FileRecordStore::new()));

        tokio::spawn(async move {
            let (tcp_stream, _peer) = listener.accept().await.unwrap();
            let tls_stream = acceptor.accept(tcp_stream).await.unwrap();
            serve_tcp_connection(
                tls_stream,
                crate::server_options::ServerOptions::allow_all(),
                registers,
                store,
                coils,
                coil_store,
                discrete_inputs,
                discrete_input_store,
                input_registers,
                input_register_store,
                file_records,
                file_record_store,
                MemLayout::Abcd,
                MemLayout::Abcd,
                Arc::new(String::new()),
                Arc::new(None),
                Duration::from_secs(1),
            )
            .await;
        });

        // Present the identity that was approved above — an unapproved one
        // would now be rejected (N2b), unlike back when M2 first wrote this
        // test and any identity worked.
        let client_certificate = CertificateDer::from(client_identity.certificate_der);
        let client_private_key = PrivateKeyDer::try_from(client_identity.private_key_der).unwrap();
        let client_config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureAcceptAnyServerCert::new()))
            .with_client_auth_cert(vec![client_certificate], client_private_key)
            .unwrap();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
        let tcp_stream = tokio::net::TcpStream::connect(&address).await.unwrap();
        let mut stream = connector
            .connect(ServerName::try_from("localhost").unwrap(), tcp_stream)
            .await
            .unwrap();

        let request = TcpAdu {
            transaction_id: 0x0001,
            unit_id: 0x01,
            pdu: ReadHoldingRegistersRequest {
                starting_address: 40001,
                quantity: 1,
            }
            .encode(),
        };
        stream.write_all(&request.encode()).await.unwrap();

        let expected_response = TcpAdu {
            transaction_id: 0x0001,
            unit_id: 0x01,
            pdu: ReadHoldingRegistersResponse {
                register_values: vec![72],
            }
            .encode(),
        };
        let expected_bytes = expected_response.encode();
        let mut received = vec![0u8; expected_bytes.len()];
        stream.read_exact(&mut received).await.unwrap();
        assert_eq!(received, expected_bytes);
    }

    #[tokio::test]
    async fn peer_fingerprint_returns_the_clients_own_fingerprint_after_a_real_handshake() {
        let identity = protocol::tls::generate_self_signed_identity().unwrap();
        let client_identity = protocol::tls::generate_self_signed_identity().unwrap();
        let client_fingerprint = Fingerprint::of(&client_identity.public_key_der);
        let mut approved_clients = ApprovedClients::new();
        approved_clients.insert(client_fingerprint);
        let approved = Arc::new(Mutex::new(approved_clients));
        let server_config = build_server_config(&identity, approved, test_client_trust()).unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();

        let server_task = tokio::spawn(async move {
            let (tcp_stream, _peer) = listener.accept().await.unwrap();
            let tls_stream = acceptor.accept(tcp_stream).await.unwrap();
            let (_io, connection) = tls_stream.get_ref();
            peer_fingerprint(connection)
        });

        let client_certificate = CertificateDer::from(client_identity.certificate_der);
        let client_private_key = PrivateKeyDer::try_from(client_identity.private_key_der).unwrap();
        let client_config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureAcceptAnyServerCert::new()))
            .with_client_auth_cert(vec![client_certificate], client_private_key)
            .unwrap();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
        let tcp_stream = tokio::net::TcpStream::connect(&address).await.unwrap();
        let _stream = connector
            .connect(ServerName::try_from("localhost").unwrap(), tcp_stream)
            .await
            .unwrap();

        assert_eq!(server_task.await.unwrap(), Some(client_fingerprint));
    }

    #[tokio::test]
    async fn rejects_a_connection_without_any_client_certificate() {
        let identity = protocol::tls::generate_self_signed_identity().unwrap();
        // Empty on purpose — this test is about presenting *no* certificate
        // at all, which fails regardless of what's approved.
        let approved = Arc::new(Mutex::new(ApprovedClients::new()));
        let server_config = build_server_config(&identity, approved, test_client_trust()).unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();

        tokio::spawn(async move {
            let (tcp_stream, _peer) = listener.accept().await.unwrap();
            // The handshake is expected to fail here — nothing to assert on
            // the server side beyond not hanging; the real assertion is on
            // the client side below.
            let _ = acceptor.accept(tcp_stream).await;
        });

        let client_config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureAcceptAnyServerCert::new()))
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
        let tcp_stream = tokio::net::TcpStream::connect(&address).await.unwrap();
        let connect_result = connector
            .connect(ServerName::try_from("localhost").unwrap(), tcp_stream)
            .await;

        // TLS 1.3: the client can consider its side of the handshake
        // "done" before it has actually seen the server's rejection of the
        // missing mandatory client cert — that rejection alert only
        // arrives as the next thing read from the stream. So `connect()`
        // succeeding by itself doesn't prove anything; the first real I/O
        // on the resulting stream does.
        match connect_result {
            Err(_) => {}
            Ok(mut stream) => {
                let write_result = stream.write_all(b"anything").await;
                let read_result = stream.read_u8().await;
                assert!(
                    write_result.is_err() || read_result.is_err(),
                    "expected the connection to fail somewhere without a client certificate"
                );
            }
        }
    }

    #[tokio::test]
    async fn rejects_a_connection_with_an_unapproved_client_certificate() {
        let identity = protocol::tls::generate_self_signed_identity().unwrap();
        // Non-empty, but doesn't contain the fingerprint the client below
        // will present — proves the real wiring (N2b), not just N2a's
        // already-tested isolated decision logic.
        let mut approved_clients = ApprovedClients::new();
        approved_clients.insert(Fingerprint::of(
            &protocol::tls::generate_self_signed_identity()
                .unwrap()
                .public_key_der,
        ));
        let approved = Arc::new(Mutex::new(approved_clients));
        let server_config = build_server_config(&identity, approved, test_client_trust()).unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();

        tokio::spawn(async move {
            let (tcp_stream, _peer) = listener.accept().await.unwrap();
            let _ = acceptor.accept(tcp_stream).await;
        });

        let client_identity = protocol::tls::generate_self_signed_identity().unwrap();
        let client_certificate = CertificateDer::from(client_identity.certificate_der);
        let client_private_key = PrivateKeyDer::try_from(client_identity.private_key_der).unwrap();
        let client_config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureAcceptAnyServerCert::new()))
            .with_client_auth_cert(vec![client_certificate], client_private_key)
            .unwrap();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
        let tcp_stream = tokio::net::TcpStream::connect(&address).await.unwrap();
        let connect_result = connector
            .connect(ServerName::try_from("localhost").unwrap(), tcp_stream)
            .await;

        // Same TLS 1.3 timing caveat as the no-certificate-at-all test above.
        match connect_result {
            Err(_) => {}
            Ok(mut stream) => {
                let write_result = stream.write_all(b"anything").await;
                let read_result = stream.read_u8().await;
                assert!(
                    write_result.is_err() || read_result.is_err(),
                    "expected the connection to fail somewhere with an unapproved client certificate"
                );
            }
        }
    }
}
