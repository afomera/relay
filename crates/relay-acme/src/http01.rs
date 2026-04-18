//! HTTP-01 ACME challenge responder.
//!
//! Used by the custom-domain flow (M6): a user CNAMEs their hostname to our
//! apex, and we serve `/.well-known/acme-challenge/<token>` on :80 with the
//! expected key-authorization.
//!
//! Shape is stubbed out — M6 wires it into the edge's HTTP listener.

use dashmap::DashMap;

#[derive(Default)]
pub struct Http01Pending {
    /// token → key-authorization
    entries: DashMap<String, String>,
}

impl Http01Pending {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn put(&self, token: &str, key_authorization: &str) {
        self.entries.insert(token.to_string(), key_authorization.to_string());
    }

    pub fn get(&self, token: &str) -> Option<String> {
        self.entries.get(token).map(|e| e.clone())
    }

    pub fn remove(&self, token: &str) {
        self.entries.remove(token);
    }
}
