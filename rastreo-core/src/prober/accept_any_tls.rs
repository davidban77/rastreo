use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as RustlsError, SignatureScheme};

/// Accepts every server certificate without validation. The probers fingerprint what a server
/// calls itself, they do not authenticate the server; skipping trust-chain checks is required
/// to reach servers with self-signed, expired, or otherwise untrusted certificates.
#[derive(Debug)]
pub(crate) struct AcceptAnyVerifier;

impl ServerCertVerifier for AcceptAnyVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_any_verifier_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<AcceptAnyVerifier>();
    }

    #[test]
    fn accepts_an_empty_certificate_chain() {
        let verifier = AcceptAnyVerifier;
        let end_entity = CertificateDer::from(vec![0x30, 0x00]);
        let result = verifier.verify_server_cert(
            &end_entity,
            &[],
            &ServerName::try_from("example.com").expect("server name"),
            &[],
            UnixTime::now(),
        );
        assert!(
            result.is_ok(),
            "the fingerprinting verifier trusts any cert"
        );
    }

    #[test]
    fn advertises_the_common_signature_schemes() {
        let schemes = AcceptAnyVerifier.supported_verify_schemes();
        assert!(schemes.contains(&SignatureScheme::ED25519));
        assert!(schemes.contains(&SignatureScheme::ECDSA_NISTP256_SHA256));
    }
}
