// Builds the server-side TLS configuration. Everything that actually
// *serves* Modbus requests over the resulting stream is unchanged —
// `connection::serve_tcp_connection` is already generic over
// `S: AsyncRead + AsyncWrite + Unpin`, so a `TlsStream<TcpStream>` (from
// wrapping an accepted TCP connection with a `tokio_rustls::TlsAcceptor`
// built from this config) works with it as-is. No new serve-loop needed.

use crate::client_trust::ApprovedClients;
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
    signature_verification: SignatureVerification,
}

impl ApprovedFingerprintClientCertVerifier {
    fn new(approved: Arc<Mutex<ApprovedClients>>) -> Self {
        Self {
            approved,
            signature_verification: SignatureVerification::new(),
        }
    }
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
        let parsed = webpki::EndEntityCert::try_from(end_entity).map_err(|_error| {
            TlsError::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;
        let presented_fingerprint = Fingerprint::of(parsed.subject_public_key_info().as_ref());
        let is_approved = self
            .approved
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains(&presented_fingerprint);
        if is_approved {
            Ok(ClientCertVerified::assertion())
        } else {
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

/// Builds a `rustls::ServerConfig` presenting `identity`. **Requires** a
/// client certificate (mTLS on) and checks it against `approved` — see
/// `ApprovedFingerprintClientCertVerifier`. Fail-closed: an empty
/// `approved` set (the default until Milestone P's admin channel adds
/// something) rejects every client.
pub fn build_server_config(
    identity: &Identity,
    approved: Arc<Mutex<ApprovedClients>>,
) -> Result<ServerConfig, String> {
    let certificate = CertificateDer::from(identity.certificate_der.clone());
    let private_key = PrivateKeyDer::try_from(identity.private_key_der.clone())
        .map_err(|error| error.to_string())?;
    ServerConfig::builder()
        .with_client_cert_verifier(Arc::new(ApprovedFingerprintClientCertVerifier::new(
            approved,
        )))
        .with_single_cert(vec![certificate], private_key)
        .map_err(|error| error.to_string())
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

    #[test]
    fn builds_a_server_config_from_a_generated_identity() {
        let identity = protocol::tls::generate_self_signed_identity().unwrap();
        let approved = Arc::new(Mutex::new(ApprovedClients::new()));
        assert!(build_server_config(&identity, approved).is_ok());
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
        let verifier =
            ApprovedFingerprintClientCertVerifier::new(Arc::new(Mutex::new(approved_clients)));

        let end_entity = CertificateDer::from(identity.certificate_der);
        let result = verifier.verify_client_cert(&end_entity, &[], UnixTime::now());

        assert!(result.is_ok());
    }

    #[test]
    fn approved_fingerprint_client_cert_verifier_rejects_an_unapproved_fingerprint() {
        let identity = protocol::tls::generate_self_signed_identity().unwrap();
        // Empty — nothing approved, matching the fail-closed default before
        // Milestone P's admin channel ever inserts anything.
        let verifier = ApprovedFingerprintClientCertVerifier::new(Arc::new(Mutex::new(
            ApprovedClients::new(),
        )));

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
        let verifier =
            ApprovedFingerprintClientCertVerifier::new(Arc::new(Mutex::new(approved_clients)));

        let end_entity = CertificateDer::from(other_identity.certificate_der);
        let result = verifier.verify_client_cert(&end_entity, &[], UnixTime::now());

        assert!(result.is_err());
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
        let server_config = build_server_config(&identity, approved).unwrap();
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

        tokio::spawn(async move {
            let (tcp_stream, _peer) = listener.accept().await.unwrap();
            let tls_stream = acceptor.accept(tcp_stream).await.unwrap();
            serve_tcp_connection(
                tls_stream,
                registers,
                store,
                coils,
                coil_store,
                MemLayout::Abcd,
                Arc::new(String::new()),
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
    async fn rejects_a_connection_without_any_client_certificate() {
        let identity = protocol::tls::generate_self_signed_identity().unwrap();
        // Empty on purpose — this test is about presenting *no* certificate
        // at all, which fails regardless of what's approved.
        let approved = Arc::new(Mutex::new(ApprovedClients::new()));
        let server_config = build_server_config(&identity, approved).unwrap();
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
        let server_config = build_server_config(&identity, approved).unwrap();
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
