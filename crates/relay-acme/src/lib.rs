//! ACME integration for relay.
//!
//! * Wildcard `*.<base>` via DNS-01 using any `relay-dns` provider.
//! * Custom customer domains via HTTP-01 (see `http01.rs`).
//! * Encrypted cert-key storage via `encrypt.rs` (AES-GCM-SIV).
//! * In-memory cert cache + rustls resolver in `resolver.rs`.
//! * Background renewal in `renewal.rs`.

pub mod encrypt;
pub mod http01;
pub mod issue;
pub mod renewal;
pub mod resolver;
pub mod store;

pub use encrypt::{decrypt_key, encrypt_key};
pub use http01::Http01Pending;
pub use issue::{IssueOptions, IssuedCert, issue_http01, issue_wildcard};
pub use renewal::RenewalWorker;
pub use resolver::CertResolver;
pub use store::{CertStore, DbCertStore};
