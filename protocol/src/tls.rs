use std::fmt;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use pem::Pem;
use rcgen::{CertifiedKey, PublicKeyData, generate_simple_self_signed};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, SubjectPublicKeyInfoDer};

const CERTIFICATE_FILE_NAME: &str = "cert.pem";
const PRIVATE_KEY_FILE_NAME: &str = "key.pem";
const PUBLIC_KEY_FILE_NAME: &str = "public_key.pem";
const PRIVATE_KEY_FILE_MODE: u32 = 0o600;

/// A TLS identity: a certificate, the private key that signed it, and the
/// certificate's own public key — all as raw DER bytes. No CA is involved —
/// the certificate is self-signed, and every consumer of an `Identity` is
/// expected to trust it (or not) based on `fingerprint(&identity.public_key_der)`,
/// never based on certificate fields like Subject or validity period, which
/// are meaningless for a self-signed certificate the peer generated itself.
///
/// The public key is kept as its own field (SubjectPublicKeyInfo DER,
/// [RFC 5280 §4.1](https://tools.ietf.org/html/rfc5280#section-4.1)) rather
/// than derived on demand from `certificate_der`/`private_key_der`, so that
/// fingerprinting an `Identity` never needs an X.509 parser or a
/// private-key-to-public-key derivation step — both `rcgen` (generating) and
/// disk storage (loading) already produce/carry this value for free.
pub struct Identity {
    pub certificate_der: Vec<u8>,
    pub private_key_der: Vec<u8>,
    pub public_key_der: Vec<u8>,
}

/// Generates a fresh self-signed TLS identity. No subject alternative names
/// are set — trust is based purely on the certificate's public key
/// fingerprint (see `fingerprint`), so a hostname/IP-based name has no role
/// to play here.
pub fn generate_self_signed_identity() -> Result<Identity, rcgen::Error> {
    let CertifiedKey { cert, signing_key } = generate_simple_self_signed(Vec::<String>::new())?;
    Ok(Identity {
        certificate_der: cert.der().to_vec(),
        public_key_der: signing_key.subject_public_key_info(),
        private_key_der: signing_key.serialize_der(),
    })
}

/// Loads a TLS identity from `directory` (`cert.pem` + `key.pem` +
/// `public_key.pem`) if all three files already exist there, otherwise
/// generates a fresh self-signed one and persists it there so the same
/// identity is reused on every later call — an identity that changed on
/// every restart would make every previously pinned/approved fingerprint
/// (see the FUSE `client-trust/` design) stale.
pub fn load_or_generate_identity(directory: &Path) -> io::Result<Identity> {
    let certificate_path = directory.join(CERTIFICATE_FILE_NAME);
    let private_key_path = directory.join(PRIVATE_KEY_FILE_NAME);
    let public_key_path = directory.join(PUBLIC_KEY_FILE_NAME);

    if certificate_path.is_file() && private_key_path.is_file() && public_key_path.is_file() {
        load_identity(&certificate_path, &private_key_path, &public_key_path)
    } else {
        let identity = generate_self_signed_identity().map_err(io::Error::other)?;
        std::fs::create_dir_all(directory)?;
        save_identity(
            &identity,
            &certificate_path,
            &private_key_path,
            &public_key_path,
        )?;
        Ok(identity)
    }
}

fn load_identity(
    certificate_path: &Path,
    private_key_path: &Path,
    public_key_path: &Path,
) -> io::Result<Identity> {
    let certificate = CertificateDer::from_pem_file(certificate_path)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let private_key = PrivateKeyDer::from_pem_file(private_key_path)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let public_key = SubjectPublicKeyInfoDer::from_pem_file(public_key_path)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;

    Ok(Identity {
        certificate_der: certificate.to_vec(),
        private_key_der: private_key.secret_der().to_vec(),
        public_key_der: public_key.to_vec(),
    })
}

fn save_identity(
    identity: &Identity,
    certificate_path: &Path,
    private_key_path: &Path,
    public_key_path: &Path,
) -> io::Result<()> {
    let certificate_pem = pem::encode(&Pem::new("CERTIFICATE", identity.certificate_der.clone()));
    std::fs::write(certificate_path, certificate_pem)?;

    let public_key_pem = pem::encode(&Pem::new("PUBLIC KEY", identity.public_key_der.clone()));
    std::fs::write(public_key_path, public_key_pem)?;

    // The private key file, unlike the certificate/public key, is sensitive
    // material: created with 0600 directly (not chmod'd afterwards), so it
    // is never briefly readable at a wider permission than intended.
    let private_key_pem = pem::encode(&Pem::new("PRIVATE KEY", identity.private_key_der.clone()));
    let mut private_key_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(PRIVATE_KEY_FILE_MODE)
        .open(private_key_path)?;
    private_key_file.write_all(private_key_pem.as_bytes())
}

/// A SHA-256 fingerprint of a raw public key
/// ([`Identity::public_key_der`]). This — not the certificate as a whole —
/// is the only thing this project's TLS trust decisions are ever based on;
/// see `Identity`'s own documentation for why.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    pub fn of(public_key_der: &[u8]) -> Self {
        let digest = ring::digest::digest(&ring::digest::SHA256, public_key_der);
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(digest.as_ref());
        Fingerprint(bytes)
    }
}

/// Colon-separated lowercase hex, matching the conventional SSH/OpenSSL
/// fingerprint display (e.g. `3a:f2:9b:...`) — a technician comparing two
/// fingerprints by eye is the actual security boundary for pairing a new
/// device (see the `client-trust` design), so the format has to be exactly
/// this recognizable, not a novel one.
impl fmt::Display for Fingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, byte) in self.0.iter().enumerate() {
            if index > 0 {
                write!(formatter, ":")?;
            }
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Parses the `Display` format back — a technician pastes a fingerprint
/// they read off a device label or copied from another terminal into a CLI
/// argument (see the `--expect-server-fingerprint` flag), so this has to
/// accept exactly what `Display` produces.
impl std::str::FromStr for Fingerprint {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let mut bytes = [0u8; 32];
        let byte_strings: Vec<&str> = text.split(':').collect();
        if byte_strings.len() != bytes.len() {
            return Err(format!(
                "expected 32 colon-separated hex bytes, got {} in {text:?}",
                byte_strings.len()
            ));
        }
        for (index, byte_string) in byte_strings.iter().enumerate() {
            bytes[index] = u8::from_str_radix(byte_string, 16).map_err(|error| {
                format!("invalid hex byte {byte_string:?} in {text:?}: {error}")
            })?;
        }
        Ok(Fingerprint(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_non_empty_certificate_and_key() {
        let identity = generate_self_signed_identity().unwrap();

        assert!(!identity.certificate_der.is_empty());
        assert!(!identity.private_key_der.is_empty());
        assert!(!identity.public_key_der.is_empty());
    }

    #[test]
    fn generates_a_fresh_key_pair_every_call() {
        let first = generate_self_signed_identity().unwrap();
        let second = generate_self_signed_identity().unwrap();

        assert_ne!(first.certificate_der, second.certificate_der);
        assert_ne!(first.private_key_der, second.private_key_der);
        assert_ne!(first.public_key_der, second.public_key_der);
    }

    #[test]
    fn generates_and_persists_an_identity_on_first_call() {
        let directory = tempfile::tempdir().unwrap();

        let identity = load_or_generate_identity(directory.path()).unwrap();

        assert!(directory.path().join(CERTIFICATE_FILE_NAME).is_file());
        assert!(directory.path().join(PRIVATE_KEY_FILE_NAME).is_file());
        assert!(directory.path().join(PUBLIC_KEY_FILE_NAME).is_file());
        assert!(!identity.certificate_der.is_empty());
        assert!(!identity.private_key_der.is_empty());
        assert!(!identity.public_key_der.is_empty());
    }

    #[test]
    fn loads_the_same_identity_on_a_later_call() {
        let directory = tempfile::tempdir().unwrap();

        let first = load_or_generate_identity(directory.path()).unwrap();
        let second = load_or_generate_identity(directory.path()).unwrap();

        assert_eq!(first.certificate_der, second.certificate_der);
        assert_eq!(first.private_key_der, second.private_key_der);
        assert_eq!(first.public_key_der, second.public_key_der);
    }

    #[test]
    fn private_key_file_is_only_readable_by_its_owner() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        load_or_generate_identity(directory.path()).unwrap();

        let metadata = std::fs::metadata(directory.path().join(PRIVATE_KEY_FILE_NAME)).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, PRIVATE_KEY_FILE_MODE);
    }

    #[test]
    fn fingerprint_matches_known_sha256_vectors() {
        // Verified independently via `printf '' | sha256sum` / `printf 'abc' | sha256sum`,
        // not just re-deriving them from our own implementation.
        assert_eq!(
            Fingerprint::of(b"").to_string(),
            "e3:b0:c4:42:98:fc:1c:14:9a:fb:f4:c8:99:6f:b9:24:27:ae:41:e4:\
             64:9b:93:4c:a4:95:99:1b:78:52:b8:55"
        );
        assert_eq!(
            Fingerprint::of(b"abc").to_string(),
            "ba:78:16:bf:8f:01:cf:ea:41:41:40:de:5d:ae:22:23:b0:03:61:a3:\
             96:17:7a:9c:b4:10:ff:61:f2:00:15:ad"
        );
    }

    #[test]
    fn fingerprint_is_stable_and_key_specific() {
        let first = generate_self_signed_identity().unwrap();
        let second = generate_self_signed_identity().unwrap();

        assert_eq!(
            Fingerprint::of(&first.public_key_der),
            Fingerprint::of(&first.public_key_der)
        );
        assert_ne!(
            Fingerprint::of(&first.public_key_der),
            Fingerprint::of(&second.public_key_der)
        );
    }

    #[test]
    fn fingerprint_round_trips_through_display_and_from_str() {
        let fingerprint = Fingerprint::of(b"abc");
        let parsed: Fingerprint = fingerprint.to_string().parse().unwrap();
        assert_eq!(fingerprint, parsed);
    }

    #[test]
    fn fingerprint_from_str_rejects_wrong_byte_count() {
        assert!("3a:f2".parse::<Fingerprint>().is_err());
    }

    #[test]
    fn fingerprint_from_str_rejects_non_hex_bytes() {
        let too_short_but_right_count = vec!["zz"; 32].join(":");
        assert!(too_short_but_right_count.parse::<Fingerprint>().is_err());
    }
}
