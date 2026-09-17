// Unifies TCP and RTU behind one "send this PDU, get a response PDU" call
// so write_confirmation/transaction_consumer/polling don't need to care
// which transport they're actually talking over. An enum rather than a
// trait: the two transports use different ADU types (TcpAdu carries a
// transaction_id RtuAdu has no use for) and there are exactly two concrete
// cases, known up front — no need for open-ended dynamic dispatch.

use protocol::adu::{RtuAdu, TcpAdu};
use protocol::rtu::frame_silence_for_baud_rate;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme};
use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_serial::{SerialPortBuilderExt, SerialStream};

pub enum Connection {
    Tcp {
        stream: TcpStream,
        next_transaction_id: u16,
    },
    Rtu {
        stream: SerialStream,
        frame_silence: Duration,
    },
    // Boxed: `TlsStream` is over 1KB (rustls's internal buffers), and Rust
    // sizes an enum to fit its largest variant — leaving it unboxed would
    // make every `Connection::Tcp`/`Connection::Rtu` pay that size too.
    Tls {
        stream: Box<TlsStream<TcpStream>>,
        next_transaction_id: u16,
    },
}

/// The `ServerCertVerifier` methods concerned with checking that a handshake
/// signature is cryptographically valid — i.e. that the peer really holds
/// the private key for the certificate it presented — as opposed to
/// *whether that certificate should be trusted*, which is a separate
/// decision each verifier below makes its own way. Shared because both
/// verifiers below need identical, real signature checking; only the trust
/// decision itself differs between them.
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

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_algorithms.supported_schemes()
    }
}

/// Accepts *any* server certificate without checking whether it should be
/// trusted.
///
/// **Insecure fallback, used only when no `--expect-server-fingerprint` was
/// given.** Its entire purpose is to prove the TLS transport and Modbus PDU
/// exchange work before any real trust policy exists — see
/// `PinnedFingerprintServerCertVerifier` for the real one (L3). Kept around
/// (not deleted now that L3 exists) so `tls+tcp://` still works for local
/// testing without first having to know the server's fingerprint.
#[derive(Debug)]
struct InsecureAcceptAnyServerCert {
    signature_verification: SignatureVerification,
}

impl InsecureAcceptAnyServerCert {
    fn new() -> Self {
        Self {
            signature_verification: SignatureVerification::new(),
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

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.signature_verification.supported_verify_schemes()
    }
}

/// Verifies the server's certificate by comparing its public-key fingerprint
/// against `expected_fingerprint`, pinned once out of band (the
/// `--expect-server-fingerprint` CLI flag) — this project's *only* real TLS
/// trust decision, matching CLAUDE.md's fingerprint-pinning design: no CA,
/// no hostname check, nothing else about the certificate is consulted.
#[derive(Debug)]
struct PinnedFingerprintServerCertVerifier {
    expected_fingerprint: protocol::tls::Fingerprint,
    signature_verification: SignatureVerification,
}

impl PinnedFingerprintServerCertVerifier {
    fn new(expected_fingerprint: protocol::tls::Fingerprint) -> Self {
        Self {
            expected_fingerprint,
            signature_verification: SignatureVerification::new(),
        }
    }
}

impl ServerCertVerifier for PinnedFingerprintServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let parsed = webpki::EndEntityCert::try_from(end_entity).map_err(|_error| {
            TlsError::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;
        let presented_fingerprint =
            protocol::tls::Fingerprint::of(parsed.subject_public_key_info().as_ref());
        if presented_fingerprint == self.expected_fingerprint {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(TlsError::General(format!(
                "server presented TLS fingerprint {presented_fingerprint}, expected {}",
                self.expected_fingerprint
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

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.signature_verification.supported_verify_schemes()
    }
}

impl Connection {
    pub async fn connect_tcp(address: &str) -> io::Result<Self> {
        let stream = TcpStream::connect(address).await?;
        Ok(Self::Tcp {
            stream,
            next_transaction_id: 0,
        })
    }

    /// Connects over TLS. If `expected_server_fingerprint` is given, the
    /// server's certificate is verified against it for real
    /// (`PinnedFingerprintServerCertVerifier`) and the connection fails if
    /// it doesn't match. If not given, falls back to the insecure K6a
    /// placeholder (`InsecureAcceptAnyServerCert`) — useful for local
    /// testing, but does not check the server's identity at all.
    pub async fn connect_tls(
        address: &str,
        expected_server_fingerprint: Option<protocol::tls::Fingerprint>,
    ) -> io::Result<Self> {
        let tcp_stream = TcpStream::connect(address).await?;

        let verifier: Arc<dyn ServerCertVerifier> = match expected_server_fingerprint {
            Some(fingerprint) => Arc::new(PinnedFingerprintServerCertVerifier::new(fingerprint)),
            None => Arc::new(InsecureAcceptAnyServerCert::new()),
        };
        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(config));

        // Sent as the TLS ClientHello's SNI value. Never consulted for trust
        // by either verifier above — this project's trust model is
        // fingerprint-only, never hostname-based — but a real value derived
        // from what the caller actually asked to connect to is still more
        // correct on the wire than an arbitrary placeholder.
        let host = address
            .rsplit_once(':')
            .map_or(address, |(host, _port)| host);
        let server_name = ServerName::try_from(host.to_string())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;

        let stream = connector
            .connect(server_name, tcp_stream)
            .await
            .map_err(io::Error::other)?;
        Ok(Self::Tls {
            stream: Box::new(stream),
            next_transaction_id: 0,
        })
    }

    /// `path` is the serial device (e.g. `/dev/ttyUSB0`); `frame_silence`
    /// (the gap that marks a frame boundary — see `protocol::rtu`) is
    /// derived from `baud_rate` per the Modbus spec, not configurable
    /// separately since it's not an independent physical parameter.
    ///
    /// Takes `handle` (rather than just assuming an ambient runtime like
    /// `TcpStream::connect` can) because tokio-serial registers the file
    /// descriptor with the reactor immediately at open time, not lazily on
    /// first use — so opening it needs an active runtime context even
    /// though this function itself isn't async.
    pub fn open_rtu(
        handle: &tokio::runtime::Handle,
        path: &str,
        baud_rate: u32,
    ) -> io::Result<Self> {
        let _guard = handle.enter();
        let stream = tokio_serial::new(path, baud_rate)
            .open_native_async()
            .map_err(|error| io::Error::other(error.to_string()))?;
        Ok(Self::Rtu {
            stream,
            frame_silence: frame_silence_for_baud_rate(baud_rate),
        })
    }

    /// Sends `pdu` under `unit_id` and returns the response PDU bytes,
    /// dispatching to whichever transport this connection actually is.
    pub async fn request(
        &mut self,
        unit_id: u8,
        pdu: Vec<u8>,
        timeout: Duration,
    ) -> io::Result<Vec<u8>> {
        match self {
            Connection::Tcp {
                stream,
                next_transaction_id,
            } => {
                *next_transaction_id = next_transaction_id.wrapping_add(1);
                let request = TcpAdu {
                    transaction_id: *next_transaction_id,
                    unit_id,
                    pdu,
                };
                let response = protocol::tcp::send_request(stream, request, timeout).await?;
                Ok(response.pdu)
            }
            Connection::Rtu {
                stream,
                frame_silence,
            } => {
                let request = RtuAdu { unit_id, pdu };
                let response =
                    protocol::rtu::send_request(stream, request, *frame_silence, timeout).await?;
                Ok(response.pdu)
            }
            Connection::Tls {
                stream,
                next_transaction_id,
            } => {
                *next_transaction_id = next_transaction_id.wrapping_add(1);
                let request = TcpAdu {
                    transaction_id: *next_transaction_id,
                    unit_id,
                    pdu,
                };
                let response = protocol::tcp::send_request(stream, request, timeout).await?;
                Ok(response.pdu)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::pdu::{ReadHoldingRegistersRequest, ReadHoldingRegistersResponse};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn tcp_connection_sends_a_request_and_returns_the_response_pdu() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();

        let server_task = tokio::spawn(async move {
            let (mut stream, _peer) = listener.accept().await.unwrap();
            let mut header = vec![0u8; 7];
            stream.read_exact(&mut header).await.unwrap();
            let mut pdu = vec![0u8; 5];
            stream.read_exact(&mut pdu).await.unwrap();

            let response_pdu = ReadHoldingRegistersResponse {
                register_values: vec![42],
            }
            .encode();
            let mut response = header;
            let length = (response_pdu.len() + 1) as u16;
            response[4..6].copy_from_slice(&length.to_be_bytes());
            response.extend_from_slice(&response_pdu);
            stream.write_all(&response).await.unwrap();
        });

        let mut connection = Connection::connect_tcp(&address).await.unwrap();
        let request_pdu = ReadHoldingRegistersRequest {
            starting_address: 40001,
            quantity: 1,
        }
        .encode();
        let response_pdu = connection
            .request(0x01, request_pdu, Duration::from_secs(1))
            .await
            .unwrap();

        assert_eq!(
            ReadHoldingRegistersResponse::decode(&response_pdu).unwrap(),
            ReadHoldingRegistersResponse {
                register_values: vec![42]
            }
        );
        server_task.await.unwrap();
    }

    // Minimal in-test TLS acceptor standing in for the real server-side TLS
    // support that doesn't exist yet (K6b) — proves K6a's client side works
    // against a real TLS handshake, not against `server`. Also returns the
    // identity's fingerprint so L3 tests can pin/mismatch against it.
    fn test_server_config() -> (rustls::ServerConfig, protocol::tls::Fingerprint) {
        let identity = protocol::tls::generate_self_signed_identity().unwrap();
        let fingerprint = protocol::tls::Fingerprint::of(&identity.public_key_der);
        let certificate = rustls::pki_types::CertificateDer::from(identity.certificate_der);
        let private_key = rustls::pki_types::PrivateKeyDer::try_from(identity.private_key_der)
            .expect("rcgen produces a valid PKCS#8 private key");
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate], private_key)
            .unwrap();
        (config, fingerprint)
    }

    #[tokio::test]
    async fn tls_connection_sends_a_request_and_returns_the_response_pdu() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let (server_config, _fingerprint) = test_server_config();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

        let server_task = tokio::spawn(async move {
            let (tcp_stream, _peer) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(tcp_stream).await.unwrap();

            let mut header = vec![0u8; 7];
            stream.read_exact(&mut header).await.unwrap();
            let mut pdu = vec![0u8; 5];
            stream.read_exact(&mut pdu).await.unwrap();

            let response_pdu = ReadHoldingRegistersResponse {
                register_values: vec![42],
            }
            .encode();
            let mut response = header;
            let length = (response_pdu.len() + 1) as u16;
            response[4..6].copy_from_slice(&length.to_be_bytes());
            response.extend_from_slice(&response_pdu);
            stream.write_all(&response).await.unwrap();
        });

        let mut connection = Connection::connect_tls(&address, None).await.unwrap();
        let request_pdu = ReadHoldingRegistersRequest {
            starting_address: 40001,
            quantity: 1,
        }
        .encode();
        let response_pdu = connection
            .request(0x01, request_pdu, Duration::from_secs(1))
            .await
            .unwrap();

        assert_eq!(
            ReadHoldingRegistersResponse::decode(&response_pdu).unwrap(),
            ReadHoldingRegistersResponse {
                register_values: vec![42]
            }
        );
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn tls_connection_succeeds_when_the_pinned_fingerprint_matches() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let (server_config, fingerprint) = test_server_config();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

        tokio::spawn(async move {
            let (tcp_stream, _peer) = listener.accept().await.unwrap();
            // The handshake completing at all (even with nothing read/written
            // afterwards) is enough to prove the pinned verifier accepted it.
            let _stream = acceptor.accept(tcp_stream).await.unwrap();
        });

        let result = Connection::connect_tls(&address, Some(fingerprint)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn tls_connection_fails_when_the_pinned_fingerprint_does_not_match() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let (server_config, _fingerprint) = test_server_config();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let wrong_fingerprint = protocol::tls::Fingerprint::of(b"not the real key");

        tokio::spawn(async move {
            let (tcp_stream, _peer) = listener.accept().await.unwrap();
            // The client is expected to abort the handshake once it sees the
            // mismatched fingerprint — a connection error here is fine too,
            // the assertion that matters is on the client side below.
            let _ = acceptor.accept(tcp_stream).await;
        });

        let result = Connection::connect_tls(&address, Some(wrong_fingerprint)).await;
        assert!(result.is_err());
    }
}
