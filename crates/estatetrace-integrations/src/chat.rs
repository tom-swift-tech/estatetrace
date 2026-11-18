use crate::credentials::{delete_secret, read_secret, chat_account, store_secret};
use anyhow::{anyhow, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatConfig {
    pub gateway_url: String,
    pub deployment: String,
    pub api_version: Option<String>,
    /// Header carrying the BYOK key (key itself is in Credential Manager).
    pub header_name: String,
}

impl Default for ChatConfig {
    fn default() -> Self {
        Self {
            gateway_url: String::new(),
            deployment: String::new(),
            api_version: Some("2024-02-15-preview".into()),
            header_name: "Ocp-Apim-Subscription-Key".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovedChatContext {
    pub question: String,
    pub view_filters: Value,
    pub records: Vec<Value>,
    pub evidence_time: Option<String>,
    pub gaps: Vec<String>,
    pub include_ticket_notes: bool,
}

pub struct ChatClient {
    client: Client,
    pub config: ChatConfig,
    key: String,
}

impl ChatClient {
    pub fn connect(config: ChatConfig, key: String) -> Self {
        Self {
            client: Client::new(),
            config,
            key,
        }
    }

    pub fn from_stored(config: ChatConfig) -> Result<Self> {
        let key = read_secret(&chat_account(&config.gateway_url))?
            .ok_or_else(|| anyhow!("chat key not in credential store"))?;
        Ok(Self::connect(config, key))
    }

    pub fn save_credentials(config: &ChatConfig, key: &str) -> Result<()> {
        store_secret(&chat_account(&config.gateway_url), key)
    }

    pub fn disconnect(gateway_url: &str) -> Result<()> {
        delete_secret(&chat_account(gateway_url))
    }

    pub async fn test_synthetic(&self) -> Result<Value> {
        let ctx = ApprovedChatContext {
            question: "Reply with the word pong only.".into(),
            view_filters: json!({}),
            records: vec![],
            evidence_time: None,
            gaps: vec![],
            include_ticket_notes: false,
        };
        self.ask(&ctx).await
    }

    /// Send only approved fields. Credentials never appear in the payload.
    pub async fn ask(&self, ctx: &ApprovedChatContext) -> Result<Value> {
        let records: Vec<Value> = ctx
            .records
            .iter()
            .map(|r| redact_record(r, ctx.include_ticket_notes))
            .collect();

        let payload = json!({
            "messages": [
                {
                    "role": "system",
                    "content": "You are EstateTrace assistant. Answer only from the provided approved dashboard records. Do not invent tickets or resources. Mention gaps explicitly."
                },
                {
                    "role": "user",
                    "content": serde_json::to_string(&json!({
                        "question": ctx.question,
                        "view_filters": ctx.view_filters,
                        "records": records,
                        "evidence_time": ctx.evidence_time,
                        "gaps": ctx.gaps,
                    }))?
                }
            ],
            "temperature": 0.1,
        });

        let mut url = self.config.gateway_url.clone();
        if let Some(ver) = &self.config.api_version {
            if !url.contains("api-version") {
                let sep = if url.contains('?') { '&' } else { '?' };
                url = format!("{url}{sep}api-version={ver}");
            }
        }

        let resp = self
            .client
            .post(&url)
            .header(&self.config.header_name, &self.key)
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            return Err(anyhow!("chat gateway HTTP {status}"));
        }
        let parsed: Value = serde_json::from_str(&text).unwrap_or(json!({ "raw": text }));
        Ok(json!({
            "answer": extract_answer(&parsed),
            "records_sent": records.len(),
            "gaps": ctx.gaps,
            "view_filters": ctx.view_filters,
        }))
    }
}

fn redact_record(r: &Value, include_notes: bool) -> Value {
    let mut out = json!({
        "resource_id": r.get("resource_id"),
        "name": r.get("name"),
        "subscription_id": r.get("subscription_id"),
        "compliance": r.get("compliance"),
        "outcome": r.get("outcome"),
        "ticket_number": r.get("ticket_number"),
        "ticket_state": r.get("ticket_state"),
        "severity": r.get("severity"),
        "observation_time": r.get("observation_time"),
    });
    if include_notes {
        if let Some(obj) = out.as_object_mut() {
            obj.insert("ticket_description".into(), r.get("ticket_description").cloned().unwrap_or(Value::Null));
            obj.insert("work_notes".into(), r.get("work_notes").cloned().unwrap_or(Value::Null));
        }
    }
    out
}

fn extract_answer(v: &Value) -> String {
    v.pointer("/choices/0/message/content")
        .and_then(|c| c.as_str())
        .unwrap_or_else(|| v.get("answer").and_then(|a| a.as_str()).unwrap_or(""))
        .to_string()
}