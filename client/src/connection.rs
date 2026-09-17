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

/// Accepts *any* server certificate without checking whether it should be
/// trusted — it only checks that the handshake signature is cryptographically
/// valid for whatever certificate was presented (i.e. that the peer really
/// holds the private key for the certificate it showed), not that the
/// certificate itself is the right one to talk to.
///
/// **Temporary placeholder for milestone K6a.** Its entire purpose is to
/// prove the TLS transport and Modbus PDU exchange work before any real
/// trust policy exists — real server-fingerprint verification lands in L3.
/// Must never be reachable once L3 exists.
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

impl Connection {
    pub async fn connect_tcp(address: &str) -> io::Result<Self> {
        let stream = TcpStream::connect(address).await?;
        Ok(Self::Tcp {
            stream,
            next_transaction_id: 0,
        })
    }

    /// Connects over TLS. **Uses the insecure K6a placeholder verifier —
    /// does not actually check the server's identity yet** (see
    /// `InsecureAcceptAnyServerCert`); real fingerprint verification is L3.
    pub async fn connect_tls(address: &str) -> io::Result<Self> {
        let tcp_stream = TcpStream::connect(address).await?;

        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureAcceptAnyServerCert::new()))
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(config));

        // Sent as the TLS ClientHello's SNI value. Never consulted for trust
        // (the verifier above ignores it, and the real L3 verifier will too
        // — this project's trust model is fingerprint-only, never hostname-
        // based), but a real value derived from what the caller actually
        // asked to connect to is still more correct on the wire than an
        // arbitrary placeholder.
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
    // against a real TLS handshake, not against `server`.
    fn insecure_test_server_config() -> rustls::ServerConfig {
        let identity = protocol::tls::generate_self_signed_identity().unwrap();
        let certificate = rustls::pki_types::CertificateDer::from(identity.certificate_der);
        let private_key = rustls::pki_types::PrivateKeyDer::try_from(identity.private_key_der)
            .expect("rcgen produces a valid PKCS#8 private key");
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate], private_key)
            .unwrap()
    }

    #[tokio::test]
    async fn tls_connection_sends_a_request_and_returns_the_response_pdu() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(insecure_test_server_config()));

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

        let mut connection = Connection::connect_tls(&address).await.unwrap();
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
}
