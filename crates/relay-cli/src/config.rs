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
    let dirs = ProjectDirs::from("dev", "relay", "relay")
        .ok_or_else(|| anyhow::anyhow!("cannot resolve config dir"))?;
    Ok(dirs.config_dir().join("config.toml"))
}

pub fn load() -> anyhow::Result<Config> {
    let p = path()?;
    if !p.exists() {
        return Ok(Config::default());
    }
    let txt = fs::read_to_string(&p)?;
    Ok(toml::from_str(&txt)?)
}

pub fn save(cfg: &Config) -> anyhow::Result<()> {
    let p = path()?;
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&p, toml::to_string_pretty(cfg)?)?;
    Ok(())
}
