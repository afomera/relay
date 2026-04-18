//! Local CLI config at `~/.config/relay/config.toml` (or per-OS equivalent).

use std::fs;
use std::path::PathBuf;

use directories::ProjectDirs;
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: Option<String>,
    pub token: Option<String>,
}

pub fn path() -> anyhow::Result<PathBuf> {
    // Reverse-DNS under `withrelay.dev` (the project's domain). On macOS this
    // resolves to `~/Library/Application Support/dev.withrelay.relay/`.
    let dirs = ProjectDirs::from("dev", "withrelay", "relay")
        .ok_or_else(|| anyhow::anyhow!("cannot resolve config dir"))?;
    Ok(dirs.config_dir().join("config.toml"))
}

/// Pre-0.0.5 config dir. Read-only fallback so existing users don't have to
/// re-login. Drop once we're comfortable nobody has state left here.
fn legacy_path() -> Option<PathBuf> {
    ProjectDirs::from("dev", "relay", "relay").map(|d| d.config_dir().join("config.toml"))
}

pub fn load() -> anyhow::Result<Config> {
    let p = path()?;
    if p.exists() {
        let txt = fs::read_to_string(&p)?;
        return Ok(toml::from_str(&txt)?);
    }
    if let Some(old) = legacy_path() {
        if old.exists() {
            let txt = fs::read_to_string(&old)?;
            return Ok(toml::from_str(&txt)?);
        }
    }
    Ok(Config::default())
}

pub fn save(cfg: &Config) -> anyhow::Result<()> {
    let p = path()?;
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&p, toml::to_string_pretty(cfg)?)?;
    Ok(())
}
