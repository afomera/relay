//! TLS helpers for the edge.
//!
//! Dev mode: we generate a self-signed wildcard cert at startup and write it
//! to the data dir so the CLI (with `--cafile`) can trust it.

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// Generate a self-signed cert valid for the given DNS names. Suitable for
/// `--dev` and integration tests only.
pub fn generate_dev_cert(
    sans: &[String],
) -> anyhow::Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    let key = rcgen::KeyPair::generate()?;
    let mut params = rcgen::CertificateParams::new(sans.to_vec())?;
    params.distinguished_name.push(rcgen::DnType::CommonName, "relay dev");
    let cert = params.self_signed(&key)?;
    let cert_der = cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    Ok((cert_der, key_der))
}
