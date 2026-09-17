use rcgen::{CertifiedKey, generate_simple_self_signed};

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
}
