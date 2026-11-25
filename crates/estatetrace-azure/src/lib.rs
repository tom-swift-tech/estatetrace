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
    // `az` on Windows is az.cmd. CreateProcess cannot run a batch file, so the
    // command goes through cmd.exe. Resource Graph bodies contain quotes and
    // `|`. cmd.exe does not use CreateProcess backslash quoting, so the whole
    // command line is one cmd-quoted string (see `cmd_quote`).
    #[cfg(windows)]
    let mut command = {
        use std::os::windows::process::CommandExt;
        let mut command = Command::new("cmd.exe");
        command.arg("/D").arg("/S").arg("/C");
        command.raw_arg(windows_cmd_command_line("az.cmd", args));
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

/// One cmd.exe command line. Arguments are quoted with cmd rules: internal
/// `"` becomes `""`, and `%` becomes `%%` so environment expansion cannot eat it.
/// The program stays unquoted when it is a plain token, so `cmd /S /C` does not
/// strip the first and last quote of the whole line.
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
pub(crate) fn windows_cmd_command_line(program: &str, args: &[&str]) -> String {
    let mut parts = Vec::with_capacity(1 + args.len());
    parts.push(if cmd_needs_quotes(program) {
        cmd_quote(program)
    } else {
        program.to_string()
    });
    for arg in args {
        parts.push(cmd_quote(arg));
    }
    parts.join(" ")
}

#[cfg_attr(not(any(windows, test)), allow(dead_code))]
fn cmd_needs_quotes(arg: &str) -> bool {
    arg.is_empty()
        || arg.chars().any(|c| {
            matches!(
                c,
                ' ' | '\t' | '"' | '&' | '|' | '<' | '>' | '^' | '%' | '(' | ')' | '@'
            )
        })
}

#[cfg_attr(not(any(windows, test)), allow(dead_code))]
pub(crate) fn cmd_quote(arg: &str) -> String {
    let mut out = String::from("\"");
    for c in arg.chars() {
        match c {
            '"' => out.push_str("\"\""),
            '%' => out.push_str("%%"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

/// True when every `|` sits inside a cmd quoted region. A pipe outside quotes
/// would be a pipeline, not an argument.
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
pub(crate) fn cmd_pipes_are_quoted(line: &str) -> bool {
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '"' {
            if quoted && chars.peek() == Some(&'"') {
                chars.next();
            } else {
                quoted = !quoted;
            }
        } else if c == '|' && !quoted {
            return false;
        }
    }
    !quoted && line.matches('"').count() % 2 == 0
}

#[cfg(test)]
mod cmd_quote_tests {
    use super::*;

    /// Split a command line produced by `cmd_quote`. `""` is an escaped quote.
    fn cmd_parse(line: &str) -> Vec<String> {
        let mut args = Vec::new();
        let mut cur = String::new();
        let mut chars = line.chars().peekable();
        let mut quoted = false;
        while let Some(c) = chars.next() {
            if quoted {
                if c == '"' {
                    if chars.peek() == Some(&'"') {
                        chars.next();
                        cur.push('"');
                    } else {
                        quoted = false;
                    }
                } else if c == '%' && chars.peek() == Some(&'%') {
                    chars.next();
                    cur.push('%');
                } else {
                    cur.push(c);
                }
            } else if c == '"' {
                quoted = true;
            } else if c == ' ' {
                if !cur.is_empty() {
                    args.push(std::mem::take(&mut cur));
                }
            } else {
                cur.push(c);
            }
        }
        if !cur.is_empty() {
            args.push(cur);
        }
        args
    }

    #[test]
    fn resource_graph_body_round_trips_with_pipes_inside_quotes() {
        let body = r#"{"subscriptions":["abc"],"query":"Resources | where subscriptionId =~ 'abc' | project id","options":{"$top":1000}}"#;
        let args = ["rest", "--method", "post", "--uri", "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01", "--body", body, "-o", "json"];
        let line = windows_cmd_command_line("az.cmd", &args);
        assert!(cmd_pipes_are_quoted(&line), "{line}");
        assert!(!line.starts_with('"'), "cmd /S would strip a leading quote");
        let parsed = cmd_parse(&line);
        assert_eq!(parsed[0], "az.cmd");
        assert_eq!(&parsed[1..], &args);
    }

    #[test]
    fn percent_and_quotes_are_cmd_literals() {
        let arg = r#"say "100%" & more"#;
        let line = windows_cmd_command_line("az.cmd", &[arg]);
        assert_eq!(cmd_parse(&line), vec!["az.cmd".to_string(), arg.to_string()]);
        assert!(line.contains("%%"));
        assert!(line.contains("\"\""));
    }
}