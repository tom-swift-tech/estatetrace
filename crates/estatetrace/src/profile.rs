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

pub fn db_path() -> Result<PathBuf> {
    Ok(profile_dir()?.join("estatetrace.db"))
}

pub fn settings_path() -> Result<PathBuf> {
    Ok(profile_dir()?.join("settings.json"))
}