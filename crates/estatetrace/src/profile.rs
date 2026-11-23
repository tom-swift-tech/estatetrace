use anyhow::{Context, Result};
use std::path::PathBuf;

pub fn profile_dir() -> Result<PathBuf> {
    let base = dirs::data_local_dir().context("LOCALAPPDATA unavailable")?;
    let dir = base.join("EstateTrace");
    std::fs::create_dir_all(&dir)?;
    std::fs::create_dir_all(dir.join("packs"))?;
    std::fs::create_dir_all(dir.join("themes"))?;
    std::fs::create_dir_all(dir.join("backups"))?;
    Ok(dir)
}
