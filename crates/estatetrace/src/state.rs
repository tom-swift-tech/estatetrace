use crate::profile::profile_dir;
use anyhow::Result;
use estatetrace_core::SettingsDoc;
use sqlx::SqlitePool;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    pub profile: PathBuf,
    pub session_token: String,
    pub settings: Arc<RwLock<SettingsDoc>>,
    pub scan_lock: Arc<tokio::sync::Mutex<()>>,
}

impl AppState {
    pub async fn bootstrap() -> Result<Self> {
        Self::bootstrap_in(profile_dir()?).await
    }

    pub async fn bootstrap_in(profile: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&profile)?;
        std::fs::create_dir_all(profile.join("packs"))?;
        std::fs::create_dir_all(profile.join("themes"))?;
        std::fs::create_dir_all(profile.join("backups"))?;
        let pool = estatetrace_db::open_db(&profile.join("estatetrace.db")).await?;
        let settings = load_settings_from(&profile.join("settings.json"))?;
        let session_token = ensure_session_token(&pool).await?;
        Ok(Self {
            pool,
            profile,
            session_token,
            settings: Arc::new(RwLock::new(settings)),
            scan_lock: Arc::new(tokio::sync::Mutex::new(())),
        })
    }
}

fn load_settings_from(path: &Path) -> Result<SettingsDoc> {
    if path.exists() {
        let text = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&text).unwrap_or_default())
    } else {
        let s = SettingsDoc::default();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, serde_json::to_string_pretty(&s)?)?;
        Ok(s)
    }
}

pub async fn save_settings(state: &AppState) -> Result<()> {
    let path = state.profile.join("settings.json");
    let s = state.settings.read().await.clone();
    std::fs::write(&path, serde_json::to_string_pretty(&s)?)?;
    Ok(())
}

async fn ensure_session_token(pool: &SqlitePool) -> Result<String> {
    if let Some(t) = estatetrace_db::meta_get(pool, "session_token").await? {
        return Ok(t);
    }
    let token = Uuid::new_v4().to_string();
    estatetrace_db::meta_set(pool, "session_token", &token).await?;
    Ok(token)
}
