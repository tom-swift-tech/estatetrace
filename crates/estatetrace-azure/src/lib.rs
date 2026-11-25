//! Azure discovery and Resource Graph collection via Azure CLI.

mod collector;
mod discovery;

pub use collector::*;
pub use discovery::*;

#[cfg(test)]
mod diff_tests;

use anyhow::{anyhow, Context, Result};
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::process::Stdio;
use tokio::process::Command;
use tracing::warn;

pub async fn az_json<T: DeserializeOwned>(args: &[&str]) -> Result<T> {
    #[cfg(windows)]
    let mut command = {
        let mut command = Command::new("cmd.exe");
        command.arg("/D").arg("/S").arg("/C");
        command.arg("az.cmd");
        for arg in args {
            command.arg(arg);
        }
        command
    };
    #[cfg(not(windows))]
    let mut command = {
        let mut command = Command::new("az");
        command.args(args);
        command
    };

    let output = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .context("failed to spawn Azure CLI (is `az` on PATH?)")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("az {} failed: {stderr}", args.join(" ")));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.trim().is_empty() {
        return Err(anyhow!("az {} returned empty stdout", args.join(" ")));
    }
    serde_json::from_str(&stdout).with_context(|| format!("parse az output for {}", args.join(" ")))
}

pub async fn az_json_value(args: &[&str]) -> Result<Value> {
    az_json(args).await
}

pub async fn az_rest(uri: &str, method: &str, body: Option<&Value>) -> Result<Value> {
    let mut args = vec![
        "rest".to_string(),
        "--method".into(),
        method.into(),
        "--uri".into(),
        uri.into(),
        "-o".into(),
        "json".into(),
    ];
    if let Some(b) = body {
        args.push("--body".into());
        args.push(b.to_string());
    }
    let str_args: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    match az_json_value(&str_args).await {
        Ok(v) => Ok(v),
        Err(e) => {
            warn!("az rest failed: {e}");
            Err(e)
        }
    }
}

/// Access token for ARM via Azure CLI (used when calling Resource Graph directly).
pub async fn arm_access_token() -> Result<String> {
    #[derive(serde::Deserialize)]
    struct Tok {
        #[serde(rename = "accessToken")]
        access_token: String,
    }
    let t: Tok = az_json(&[
        "account",
        "get-access-token",
        "--resource",
        "https://management.azure.com/",
        "-o",
        "json",
    ])
    .await?;
    Ok(t.access_token)
}