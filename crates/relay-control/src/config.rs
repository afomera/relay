use std::net::SocketAddr;

#[derive(Clone, Debug)]
pub struct ControlConfig {
    pub bind_admin: SocketAddr,
    /// Base domain for the public service (tunnels domain).
    pub base_domain: String,
    /// Publicly-reachable URL of the control plane (for OAuth callbacks).
    /// e.g. `https://withrelay.dev`. Dev default: `http://127.0.0.1:7090`.
    pub public_url: String,
    /// Public URL scheme for tunnels (shown in the UI).
    pub tunnel_scheme: String,
    /// Optional port appended to rendered tunnel URLs. Set in dev where the
    /// edge HTTP listener isn't on :80; leave `None` in prod.
    pub tunnel_public_port: Option<u16>,

    pub github: Option<GithubOauthConfig>,

    /// 32-byte key, base64-encoded. Used for cookie signing + data-at-rest enc.
    pub data_key_b64: String,

    /// Dev mode — exposes a one-click `/auth/dev/login` so you can use the
    /// dashboard locally without a GitHub OAuth app. Never enable in prod.
    pub dev_mode: bool,

    /// Zone that Relay operates for ACME DNS-01 delegation. When set, users
    /// adding a wildcard custom domain are instructed to CNAME
    /// `_acme-challenge.<their-domain>` to `<slug>.<delegation_zone>`, and the
    /// DNS provider is expected to have write scope on this zone. When
    /// `None`, wildcard custom domains are disabled (the UI hides the toggle).
    pub acme_delegation_zone: Option<String>,
}

#[derive(Clone, Debug)]
pub struct GithubOauthConfig {
    pub client_id: String,
    pub client_secret: String,
    /// Scopes requested. `read:org` is added automatically when
    /// `allowed_orgs` is non-empty.
    pub scopes: String,
    /// If non-empty, only users who are members of at least one of these
    /// orgs may sign in. Case-insensitive. Common enterprise pattern:
    /// lock the dashboard to employees of `mycompany`.
    pub allowed_orgs: Vec<String>,
}

impl GithubOauthConfig {
    pub fn new(client_id: impl Into<String>, client_secret: impl Into<String>) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            scopes: "read:user user:email".into(),
            allowed_orgs: Vec::new(),
        }
    }

    pub fn effective_scopes(&self) -> String {
        if self.allowed_orgs.is_empty() || self.scopes.contains("read:org") {
            self.scopes.clone()
        } else {
            format!("{} read:org", self.scopes)
        }
    }
}
