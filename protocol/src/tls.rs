use std::fs::OpenOptions;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use pem::Pem;
use rcgen::{CertifiedKey, generate_simple_self_signed};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

const CERTIFICATE_FILE_NAME: &str = "cert.pem";
const PRIVATE_KEY_FILE_NAME: &str = "key.pem";
const PRIVATE_KEY_FILE_MODE: u32 = 0o600;

/// A TLS identity: a certificate and the private key that signed it, as raw
/// DER bytes. No CA is involved — the certificate is self-signed, and every
/// consumer of an `Identity` is expected to trust it (or not) based on its
/// public key fingerprint, never based on certificate fields like Subject or
/// validity period, which are meaningless for a self-signed certificate the
/// peer generated itself.
pub struct Identity {
    pub certificate_der: Vec<u8>,
    pub private_key_der: Vec<u8>,
}

/// Generates a fresh self-signed TLS identity. No subject alternative names
/// are set — trust is based purely on the certificate's public key
/// fingerprint (see `fingerprint` once it exists), so a hostname/IP-based
/// name has no role to play here.
pub fn generate_self_signed_identity() -> Result<Identity, rcgen::Error> {
    let CertifiedKey { cert, signing_key } = generate_simple_self_signed(Vec::<String>::new())?;
    Ok(Identity {
        certificate_der: cert.der().to_vec(),
        private_key_der: signing_key.serialize_der(),
    })
}

/// Loads a TLS identity from `directory` (`cert.pem` + `key.pem`) if both
/// files already exist there, otherwise generates a fresh self-signed one
/// and persists it there so the same identity is reused on every later call
/// — an identity that changed on every restart would make every previously
/// pinned/approved fingerprint (see the FUSE `client-trust/` design) stale.
pub fn load_or_generate_identity(directory: &Path) -> io::Result<Identity> {
    let certificate_path = directory.join(CERTIFICATE_FILE_NAME);
    let private_key_path = directory.join(PRIVATE_KEY_FILE_NAME);

    if certificate_path.is_file() && private_key_path.is_file() {
        load_identity(&certificate_path, &private_key_path)
    } else {
        let identity = generate_self_signed_identity().map_err(io::Error::other)?;
        std::fs::create_dir_all(directory)?;
        save_identity(&identity, &certificate_path, &private_key_path)?;
        Ok(identity)
    }
}

fn load_identity(certificate_path: &Path, private_key_path: &Path) -> io::Result<Identity> {
    let certificate = CertificateDer::from_pem_file(certificate_path)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let private_key = PrivateKeyDer::from_pem_file(private_key_path)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;

    Ok(Identity {
        certificate_der: certificate.to_vec(),
        private_key_der: private_key.secret_der().to_vec(),
    })
}

fn save_identity(
    identity: &Identity,
    certificate_path: &Path,
    private_key_path: &Path,
) -> io::Result<()> {
    let certificate_pem = pem::encode(&Pem::new("CERTIFICATE", identity.certificate_der.clone()));
    std::fs::write(certificate_path, certificate_pem)?;

    // The private key file, unlike the certificate, is sensitive material:
    // created with 0600 directly (not chmod'd afterwards), so it is never
    // briefly readable at a wider permission than intended.
    let private_key_pem = pem::encode(&Pem::new("PRIVATE KEY", identity.private_key_der.clone()));
    let mut private_key_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(PRIVATE_KEY_FILE_MODE)
        .open(private_key_path)?;
    private_key_file.write_all(private_key_pem.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_non_empty_certificate_and_key() {
        let identity = generate_self_signed_identity().unwrap();

        assert!(!identity.certificate_der.is_empty());
        assert!(!identity.private_key_der.is_empty());
    }

    #[test]
    fn generates_a_fresh_key_pair_every_call() {
        let first = generate_self_signed_identity().unwrap();
        let second = generate_self_signed_identity().unwrap();

        assert_ne!(first.certificate_der, second.certificate_der);
        assert_ne!(first.private_key_der, second.private_key_der);
    }

    #[test]
    fn generates_and_persists_an_identity_on_first_call() {
        let directory = tempfile::tempdir().unwrap();

        let identity = load_or_generate_identity(directory.path()).unwrap();

        assert!(directory.path().join(CERTIFICATE_FILE_NAME).is_file());
        assert!(directory.path().join(PRIVATE_KEY_FILE_NAME).is_file());
        assert!(!identity.certificate_der.is_empty());
        assert!(!identity.private_key_der.is_empty());
    }

    #[test]
    fn loads_the_same_identity_on_a_later_call() {
        let directory = tempfile::tempdir().unwrap();

        let first = load_or_generate_identity(directory.path()).unwrap();
        let second = load_or_generate_identity(directory.path()).unwrap();

        assert_eq!(first.certificate_der, second.certificate_der);
        assert_eq!(first.private_key_der, second.private_key_der);
    }

    #[test]
    fn private_key_file_is_only_readable_by_its_owner() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        load_or_generate_identity(directory.path()).unwrap();

        let metadata = std::fs::metadata(directory.path().join(PRIVATE_KEY_FILE_NAME)).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, PRIVATE_KEY_FILE_MODE);
    }
}
