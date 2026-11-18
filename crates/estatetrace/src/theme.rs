use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThemeDoc {
    pub name: Option<String>,
    pub logo: Option<String>,
    pub header: Option<String>,
    pub sidebar: Option<String>,
    pub canvas: Option<String>,
    pub accent: Option<String>,
}

pub fn load_theme(path: &Path) -> Result<ThemeDoc> {
    let text = std::fs::read_to_string(path)?;
    Ok(serde_yaml::from_str(&text)?)
}

pub fn neutral_theme() -> ThemeDoc {
    ThemeDoc {
        name: Some("Neutral".into()),
        logo: None,
        header: Some("#1f2933".into()),
        sidebar: Some("#243b53".into()),
        canvas: Some("#f5f7fa".into()),
        accent: Some("#0b6e4f".into()),
    }
}

pub fn theme_css(theme: &ThemeDoc) -> String {
    format!(
        ":root {{\n  --et-header: {};\n  --et-sidebar: {};\n  --et-canvas: {};\n  --et-accent: {};\n}}\n",
        theme.header.as_deref().unwrap_or("#1f2933"),
        theme.sidebar.as_deref().unwrap_or("#243b53"),
        theme.canvas.as_deref().unwrap_or("#f5f7fa"),
        theme.accent.as_deref().unwrap_or("#0b6e4f"),
    )
}

pub fn theme_preview_payload(theme: &ThemeDoc) -> Value {
    json!({
        "theme": theme,
        "css": theme_css(theme),
        "preview": {
            "table_row": "sample production change",
            "nav_selection": "Change inbox",
            "button": "Apply theme"
        },
        "compliance_colors_preserved": true
    })
}