//! TLS config builder for the QUIC client.

use std::fs;
use std::sync::Arc;

use rustls::RootCertStore;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime, pem::PemObject};

pub fn build_client_config(
    insecure: bool,
    cafile: Option<&str>,
) -> anyhow::Result<Arc<rustls::ClientConfig>> {
    // Idempotent: returns Err if a provider is already installed (e.g. by the
    // edge in the same process during integration tests). Either way we end up
    // with a usable default.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots_owned());

    if let Some(path) = cafile {
        let pem = fs::read(path)?;
        for cert in CertificateDer::pem_slice_iter(&pem) {
            roots.add(cert?)?;
        }
    }

    let mut cfg = if insecure {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth()
    } else {
        rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth()
    };
    cfg.alpn_protocols = vec![relay_proto::ALPN.to_vec()];
    Ok(Arc::new(cfg))
}

fn webpki_roots_owned() -> Vec<rustls::pki_types::TrustAnchor<'static>> {
    webpki_roots::TLS_SERVER_ROOTS.to_vec()
}

#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        use rustls::SignatureScheme::*;
        vec![
            RSA_PKCS1_SHA256,
            RSA_PKCS1_SHA384,
            RSA_PKCS1_SHA512,
            ECDSA_NISTP256_SHA256,
            ECDSA_NISTP384_SHA384,
            ED25519,
            RSA_PSS_SHA256,
            RSA_PSS_SHA384,
            RSA_PSS_SHA512,
        ]
    }
}
