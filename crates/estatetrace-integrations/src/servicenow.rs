use crate::credentials::{delete_secret, read_secret, snow_account, store_secret};
use anyhow::{anyhow, Context, Result};
use base64::Engine;
use chrono::{DateTime, Duration, TimeZone, Utc};
use chrono_tz::Tz;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use tracing::warn;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceNowConfig {
    pub instance_url: String,
    pub username: String,
    pub operating_scope_services: Vec<String>,
    pub operating_scope_assignment_groups: Vec<String>,
    pub high_priorities: Vec<String>,
    pub ongoing_incident_states: Vec<String>,
    pub refresh_interval_minutes: u64,
    pub operations_timezone: Option<String>,
}

impl Default for ServiceNowConfig {
    fn default() -> Self {
        Self {
            instance_url: String::new(),
            username: String::new(),
            operating_scope_services: vec![],
            operating_scope_assignment_groups: vec![],
            high_priorities: vec!["1".into(), "2".into()],
            ongoing_incident_states: vec![
                "1".into(),
                "2".into(),
                "3".into(),
                "New".into(),
                "In Progress".into(),
                "On Hold".into(),
            ],
            refresh_interval_minutes: 5,
            operations_timezone: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnTicket {
    pub sys_id: String,
    pub number: String,
    pub short_description: String,
    pub state: String,
    pub priority: Option<String>,
    pub assignment_group: Option<String>,
    pub service: Option<String>,
    pub configuration_item: Option<String>,
    pub planned_start: Option<DateTime<Utc>>,
    pub planned_end: Option<DateTime<Utc>>,
    pub actual_start: Option<DateTime<Utc>>,
    pub actual_end: Option<DateTime<Utc>>,
    pub opened_at: Option<DateTime<Utc>>,
    pub impact_start: Option<DateTime<Utc>>,
    pub link: String,
    pub implementation_outcome: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueSnapshot {
    pub refresh_instant: DateTime<Utc>,
    pub timezone: String,
    pub executed: Vec<SnTicket>,
    pub scheduled_today: Vec<SnTicket>,
    pub high_priority_incidents: Vec<SnTicket>,
    pub errors: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentChangeMatch {
    pub change: SnTicket,
    pub reasons: Vec<String>,
    pub elapsed_to_incident: Option<String>,
    pub match_kind: String,
}

pub struct ServiceNowClient {
    client: Client,
    pub config: ServiceNowConfig,
    password: String,
}

impl ServiceNowClient {
    pub fn connect(config: ServiceNowConfig, password: String) -> Self {
        Self {
            client: Client::new(),
            config,
            password,
        }
    }

    pub fn from_stored(config: ServiceNowConfig) -> Result<Self> {
        let password = read_secret(&snow_account(&config.instance_url))?
            .ok_or_else(|| anyhow!("ServiceNow password not in credential store"))?;
        Ok(Self::connect(config, password))
    }

    pub fn save_credentials(config: &ServiceNowConfig, password: &str) -> Result<()> {
        store_secret(&snow_account(&config.instance_url), password)
    }

    pub fn disconnect(instance_url: &str) -> Result<()> {
        delete_secret(&snow_account(instance_url))
    }

    pub async fn test_access(&self) -> Result<Value> {
        let chg = self
            .get_json("/api/now/table/change_request?sysparm_limit=1")
            .await
            .context("change_request access")?;
        let inc = self
            .get_json("/api/now/table/incident?sysparm_limit=1")
            .await
            .context("incident access")?;
        Ok(json!({
            "change_ok": chg.get("result").is_some(),
            "incident_ok": inc.get("result").is_some(),
            "priorities": self.config.high_priorities,
            "ongoing_states": self.config.ongoing_incident_states,
        }))
    }

    async fn get_json(&self, path: &str) -> Result<Value> {
        let url = format!(
            "{}{}",
            self.config.instance_url.trim_end_matches('/'),
            path
        );
        let auth = base64::engine::general_purpose::STANDARD
            .encode(format!("{}:{}", self.config.username, self.password));
        let resp = self
            .client
            .get(&url)
            .header("Authorization", format!("Basic {auth}"))
            .header("Accept", "application/json")
            .send()
            .await?;
        let status = resp.status();
        let text = resp.text().await?;
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            return Err(anyhow!("unauthorized or forbidden: {status}"));
        }
        if !status.is_success() {
            return Err(anyhow!("ServiceNow HTTP {status}: {text}"));
        }
        Ok(serde_json::from_str(&text)?)
    }

    pub async fn lookup_changes_for_ci(&self, ci_sys_id: &str) -> Result<Vec<SnTicket>> {
        let path = format!(
            "/api/now/table/change_request?sysparm_query=cmdb_ci={ci_sys_id}^ORcmdb_ci.sys_id={ci_sys_id}&sysparm_limit=50"
        );
        let data = self.get_json(&path).await?;
        Ok(parse_tickets(
            &self.config.instance_url,
            data.get("result").unwrap_or(&Value::Null),
            "change",
        ))
    }

    pub async fn refresh_queues(&self, now: DateTime<Utc>) -> Result<QueueSnapshot> {
        let tz_name = self
            .config
            .operations_timezone
            .clone()
            .unwrap_or_else(|| local_tz_name());
        let mut errors = HashMap::new();

        let executed = match self.fetch_executed(now).await {
            Ok(v) => v,
            Err(e) => {
                errors.insert("executed".into(), e.to_string());
                vec![]
            }
        };
        let scheduled_today = match self.fetch_scheduled_today(now, &tz_name).await {
            Ok(v) => v,
            Err(e) => {
                errors.insert("scheduled_today".into(), e.to_string());
                vec![]
            }
        };
        let high_priority_incidents = match self.fetch_high_priority_incidents().await {
            Ok(v) => v,
            Err(e) => {
                errors.insert("high_priority_incidents".into(), e.to_string());
                vec![]
            }
        };

        Ok(QueueSnapshot {
            refresh_instant: now,
            timezone: tz_name,
            executed: dedupe_tickets(executed),
            scheduled_today: dedupe_tickets(scheduled_today),
            high_priority_incidents: dedupe_tickets(high_priority_incidents),
            errors,
        })
    }

    async fn fetch_executed(&self, now: DateTime<Utc>) -> Result<Vec<SnTicket>> {
        let start = now - Duration::hours(48);
        // Inclusive 48h boundary: actual end >= start AND actual end <= now
        let query = format!(
            "work_end>={}^work_end<={}^state!=4",
            fmt_snow(start),
            fmt_snow(now)
        );
        // Also try common field names via OR in a second query if needed — use work_end as primary.
        let path = format!(
            "/api/now/table/change_request?sysparm_query={}&sysparm_limit=200",
            urlencoding_lite(&query)
        );
        let data = self.get_json(&path).await?;
        let mut tickets = parse_tickets(
            &self.config.instance_url,
            data.get("result").unwrap_or(&Value::Null),
            "change",
        );
        tickets.retain(|t| {
            t.actual_end
                .map(|e| e >= start && e <= now)
                .unwrap_or(false)
        });
        tickets.sort_by(|a, b| b.actual_end.cmp(&a.actual_end));
        Ok(self.filter_scope(tickets))
    }

    async fn fetch_scheduled_today(&self, now: DateTime<Utc>, tz_name: &str) -> Result<Vec<SnTicket>> {
        let (day_start, day_end) = local_day_bounds(now, tz_name);
        let query = format!(
            "start_date>={}^start_date<{}^state!=4",
            fmt_snow(day_start),
            fmt_snow(day_end)
        );
        let path = format!(
            "/api/now/table/change_request?sysparm_query={}&sysparm_limit=200",
            urlencoding_lite(&query)
        );
        let data = self.get_json(&path).await?;
        let mut tickets = parse_tickets(
            &self.config.instance_url,
            data.get("result").unwrap_or(&Value::Null),
            "change",
        );
        tickets.retain(|t| {
            let canceled = t.state.eq_ignore_ascii_case("canceled")
                || t.state.eq_ignore_ascii_case("cancelled")
                || t.state == "4";
            if canceled {
                return false;
            }
            t.planned_start
                .map(|s| s >= day_start && s < day_end)
                .unwrap_or(false)
        });
        tickets.sort_by(|a, b| a.planned_start.cmp(&b.planned_start));
        Ok(self.filter_scope(tickets))
    }

    async fn fetch_high_priority_incidents(&self) -> Result<Vec<SnTicket>> {
        let pri = self
            .config
            .high_priorities
            .iter()
            .map(|p| format!("priority={p}"))
            .collect::<Vec<_>>()
            .join("^OR");
        let path = format!(
            "/api/now/table/incident?sysparm_query=active=true^({pri})&sysparm_limit=200"
        );
        let data = self.get_json(&path).await?;
        let mut tickets = parse_tickets(
            &self.config.instance_url,
            data.get("result").unwrap_or(&Value::Null),
            "incident",
        );
        tickets.retain(|t| {
            let pri_ok = t
                .priority
                .as_ref()
                .map(|p| {
                    self.config
                        .high_priorities
                        .iter()
                        .any(|hp| hp.eq_ignore_ascii_case(p) || priority_label_match(hp, p))
                })
                .unwrap_or(false);
            let state_ok = !is_terminal_incident(&t.state)
                && (self.config.ongoing_incident_states.is_empty()
                    || self
                        .config
                        .ongoing_incident_states
                        .iter()
                        .any(|s| s.eq_ignore_ascii_case(&t.state)));
            pri_ok && state_ok
        });
        tickets.sort_by(|a, b| {
            let pa = priority_rank(a.priority.as_deref());
            let pb = priority_rank(b.priority.as_deref());
            pa.cmp(&pb).then_with(|| a.opened_at.cmp(&b.opened_at))
        });
        Ok(self.filter_scope(tickets))
    }

    fn filter_scope(&self, tickets: Vec<SnTicket>) -> Vec<SnTicket> {
        if self.config.operating_scope_services.is_empty()
            && self.config.operating_scope_assignment_groups.is_empty()
        {
            return tickets;
        }
        tickets
            .into_iter()
            .filter(|t| {
                let svc_ok = self.config.operating_scope_services.is_empty()
                    || t.service
                        .as_ref()
                        .map(|s| {
                            self.config
                                .operating_scope_services
                                .iter()
                                .any(|x| x.eq_ignore_ascii_case(s))
                        })
                        .unwrap_or(false);
                let grp_ok = self.config.operating_scope_assignment_groups.is_empty()
                    || t.assignment_group
                        .as_ref()
                        .map(|s| {
                            self.config
                                .operating_scope_assignment_groups
                                .iter()
                                .any(|x| x.eq_ignore_ascii_case(s))
                        })
                        .unwrap_or(false);
                // Within configured scope dimensions: match either when both set, else the set one.
                match (
                    self.config.operating_scope_services.is_empty(),
                    self.config.operating_scope_assignment_groups.is_empty(),
                ) {
                    (false, false) => svc_ok || grp_ok,
                    (false, true) => svc_ok,
                    (true, false) => grp_ok,
                    (true, true) => true,
                }
            })
            .collect()
    }

    /// INT-04: changes before an incident.
    pub async fn changes_before_incident(
        &self,
        incident: &SnTicket,
        lookback_hours: i64,
        now: DateTime<Utc>,
    ) -> Result<Value> {
        let (anchor, anchor_source) = match (incident.impact_start, incident.opened_at) {
            (Some(t), _) => (Some(t), Some("impact_start")),
            (None, Some(t)) => (Some(t), Some("opened_at_fallback")),
            (None, None) => (None, None),
        };

        if anchor.is_none() {
            return Ok(json!({
                "anchor": null,
                "anchor_source": null,
                "message": "Incident start unavailable.",
                "completed": [],
                "implementing_at_start": [],
            }));
        }
        let anchor = anchor.unwrap();
        let lookback_start = anchor - Duration::hours(lookback_hours);

        let query = format!(
            "work_end>={}^work_end<{}^ORwork_start<={}",
            fmt_snow(lookback_start),
            fmt_snow(anchor),
            fmt_snow(anchor)
        );
        let path = format!(
            "/api/now/table/change_request?sysparm_query={}&sysparm_limit=200",
            urlencoding_lite(&query)
        );

        let data = match self.get_json(&path).await {
            Ok(d) => d,
            Err(e) => {
                warn!("incident change lookup failed: {e}");
                return Ok(json!({
                    "anchor": anchor,
                    "anchor_source": anchor_source,
                    "coverage": "partial_or_denied",
                    "error": e.to_string(),
                    "completed": [],
                    "implementing_at_start": [],
                }));
            }
        };

        let tickets = self.filter_scope(parse_tickets(
            &self.config.instance_url,
            data.get("result").unwrap_or(&Value::Null),
            "change",
        ));
        let _ = now;
        Ok(classify_changes_before_incident(
            incident,
            &tickets,
            anchor,
            anchor_source,
            lookback_hours,
            self.config
                .operations_timezone
                .clone()
                .unwrap_or_else(local_tz_name),
        ))
    }
}

/// Pure INT-04 matcher for fixture tests (AC-10).
pub fn classify_changes_before_incident(
    incident: &SnTicket,
    tickets: &[SnTicket],
    anchor: DateTime<Utc>,
    anchor_source: Option<&str>,
    lookback_hours: i64,
    timezone: String,
) -> Value {
    let lookback_start = anchor - Duration::hours(lookback_hours);
    let mut completed: Vec<IncidentChangeMatch> = Vec::new();
    let mut overlapping: Vec<IncidentChangeMatch> = Vec::new();
    let mut seen = HashSet::new();

    for chg in tickets {
        if chg.actual_end.is_none() && chg.actual_start.is_none() {
            continue;
        }

        let mut reasons = Vec::new();
        if same_resource(incident, chg) {
            reasons.push("same_resource".into());
        }
        if same_service(incident, chg) {
            reasons.push("same_service".into());
        }
        if reasons.is_empty() {
            continue;
        }

        let make_match = |kind: &str, reasons: &[String]| IncidentChangeMatch {
            elapsed_to_incident: chg
                .actual_end
                .map(|e| format!("{}s", (anchor - e).num_seconds())),
            change: chg.clone(),
            reasons: reasons.to_vec(),
            match_kind: kind.into(),
        };

        if let Some(end) = chg.actual_end {
            if end >= lookback_start && end < anchor {
                if seen.insert(chg.sys_id.clone()) {
                    completed.push(make_match("completed", &reasons));
                } else if let Some(existing) =
                    completed.iter_mut().find(|m| m.change.sys_id == chg.sys_id)
                {
                    for r in &reasons {
                        if !existing.reasons.contains(r) {
                            existing.reasons.push(r.clone());
                        }
                    }
                }
            }
        }

        let overlap = match (chg.actual_start, chg.actual_end) {
            (Some(start), Some(end)) => start < anchor && end >= anchor,
            (Some(start), None) => {
                start < anchor
                    && chg
                        .implementation_outcome
                        .as_deref()
                        .map(|s| s.to_ascii_lowercase().contains("progress"))
                        .unwrap_or(false)
            }
            _ => false,
        };
        if overlap {
            let in_completed = completed.iter().position(|m| m.change.sys_id == chg.sys_id);
            let in_overlapping = overlapping.iter().any(|m| m.change.sys_id == chg.sys_id);
            if let Some(idx) = in_completed {
                if !completed[idx].reasons.iter().any(|r| r == "overlap") {
                    completed[idx].reasons.push("overlap".into());
                }
                if !in_overlapping {
                    let mut m = completed[idx].clone();
                    m.match_kind = "implementing_at_start".into();
                    overlapping.push(m);
                }
            } else if let Some(idx) = overlapping
                .iter()
                .position(|m| m.change.sys_id == chg.sys_id)
            {
                if !overlapping[idx].reasons.iter().any(|r| r == "overlap") {
                    overlapping[idx].reasons.push("overlap".into());
                }
            } else {
                overlapping.push(make_match("implementing_at_start", &reasons));
            }
        }
    }

    completed.sort_by(|a, b| b.change.actual_end.cmp(&a.change.actual_end));

    json!({
        "anchor": anchor,
        "anchor_source": anchor_source,
        "timezone": timezone,
        "lookback_hours": lookback_hours,
        "completed": completed,
        "implementing_at_start": overlapping,
        "coverage": "complete",
        "message": if completed.is_empty() && overlapping.is_empty() {
            "No matching changes"
        } else {
            ""
        }
    })
}

fn same_resource(inc: &SnTicket, chg: &SnTicket) -> bool {
    match (&inc.configuration_item, &chg.configuration_item) {
        (Some(a), Some(b)) if !a.is_empty() && a == b => true,
        _ => false,
    }
}

fn same_service(inc: &SnTicket, chg: &SnTicket) -> bool {
    match (&inc.service, &chg.service) {
        (Some(a), Some(b)) if !a.is_empty() && a.eq_ignore_ascii_case(b) => true,
        _ => false,
    }
}

fn parse_tickets(instance_url: &str, result: &Value, kind: &str) -> Vec<SnTicket> {
    let arr = result.as_array().cloned().unwrap_or_default();
    arr.into_iter()
        .filter_map(|row| {
            let sys_id = row.get("sys_id")?.as_str()?.to_string();
            let number = row
                .get("number")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let link = format!(
                "{}/{}",
                instance_url.trim_end_matches('/'),
                if kind == "incident" {
                    format!("incident.do?sys_id={sys_id}")
                } else {
                    format!("change_request.do?sys_id={sys_id}")
                }
            );
            Some(SnTicket {
                sys_id,
                number,
                short_description: row
                    .get("short_description")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                state: display_or_value(row.get("state")),
                priority: {
                    let s = display_or_value(row.get("priority"));
                    if s.is_empty() { None } else { Some(s) }
                },
                assignment_group: nested_display(row.get("assignment_group")),
                service: nested_display(row.get("business_service"))
                    .or_else(|| nested_display(row.get("service"))),
                configuration_item: nested_display(row.get("cmdb_ci")),
                planned_start: parse_snow_time(row.get("start_date")),
                planned_end: parse_snow_time(row.get("end_date")),
                actual_start: parse_snow_time(row.get("work_start")),
                actual_end: parse_snow_time(row.get("work_end")),
                opened_at: parse_snow_time(row.get("opened_at")),
                impact_start: parse_snow_time(row.get("u_impact_start"))
                    .or_else(|| parse_snow_time(row.get("impact_start"))),
                link,
                implementation_outcome: {
                    let s = display_or_value(
                        row.get("u_implementation_outcome")
                            .or_else(|| row.get("close_code")),
                    );
                    if s.is_empty() { None } else { Some(s) }
                },
            })
        })
        .collect()
}

fn display_or_value(v: Option<&Value>) -> String {
    match v {
        Some(Value::Object(m)) => m
            .get("display_value")
            .or_else(|| m.get("value"))
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        _ => String::new(),
    }
}

fn nested_display(v: Option<&Value>) -> Option<String> {
    let s = display_or_value(v);
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn parse_snow_time(v: Option<&Value>) -> Option<DateTime<Utc>> {
    let s = display_or_value(v);
    if s.is_empty() {
        return None;
    }
    DateTime::parse_from_rfc3339(&s)
        .ok()
        .map(|d| d.with_timezone(&Utc))
        .or_else(|| {
            chrono::NaiveDateTime::parse_from_str(&s, "%Y-%m-%d %H:%M:%S")
                .ok()
                .map(|n| Utc.from_utc_datetime(&n))
        })
}

fn fmt_snow(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%d %H:%M:%S").to_string()
}

fn dedupe_tickets(tickets: Vec<SnTicket>) -> Vec<SnTicket> {
    let mut seen = HashSet::new();
    tickets
        .into_iter()
        .filter(|t| seen.insert(t.sys_id.clone()))
        .collect()
}

fn is_terminal_incident(state: &str) -> bool {
    matches!(
        state.to_ascii_lowercase().as_str(),
        "resolved" | "closed" | "canceled" | "cancelled" | "6" | "7" | "8"
    )
}

fn priority_rank(p: Option<&str>) -> u8 {
    match p.unwrap_or("") {
        "1" | "p1" | "P1" | "Critical" => 0,
        "2" | "p2" | "P2" | "High" => 1,
        "3" | "p3" | "P3" => 2,
        _ => 9,
    }
}

fn priority_label_match(configured: &str, actual: &str) -> bool {
    let c = configured.to_ascii_lowercase();
    let a = actual.to_ascii_lowercase();
    c == a
        || (c == "1" && (a == "p1" || a == "critical"))
        || (c == "2" && (a == "p2" || a == "high"))
}

fn local_tz_name() -> String {
    // Best-effort: use system offset label; operators can override in settings.
    "local".into()
}

pub fn local_day_bounds(now: DateTime<Utc>, tz_name: &str) -> (DateTime<Utc>, DateTime<Utc>) {
    if let Ok(tz) = tz_name.parse::<Tz>() {
        let local = now.with_timezone(&tz);
        let day = local.date_naive();
        let start = tz
            .from_local_datetime(&day.and_hms_opt(0, 0, 0).unwrap())
            .single()
            .map(|d| d.with_timezone(&Utc));
        let end = tz
            .from_local_datetime(&day.and_hms_opt(0, 0, 0).unwrap())
            .single()
            .map(|d| (d + Duration::days(1)).with_timezone(&Utc));
        if let (Some(s), Some(e)) = (start, end) {
            return (s, e);
        }
    }
    // Fallback: UTC midnight
    let day = now.date_naive();
    let start = Utc.from_utc_datetime(&day.and_hms_opt(0, 0, 0).unwrap());
    (start, start + Duration::days(1))
}

fn urlencoding_lite(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            ' ' => "%20".into(),
            '=' => "%3D".into(),
            '^' => "%5E".into(),
            _ => format!("%{:02X}", c as u8),
        })
        .collect()
}

/// Pure queue membership helpers for AC-09 clock-frozen tests.
pub fn is_executed_in_last_48h(
    actual_end: Option<DateTime<Utc>>,
    refresh: DateTime<Utc>,
) -> bool {
    match actual_end {
        Some(end) => {
            let start = refresh - Duration::hours(48);
            end >= start && end <= refresh
        }
        None => false,
    }
}

pub fn is_scheduled_today(
    planned_start: Option<DateTime<Utc>>,
    state: &str,
    refresh: DateTime<Utc>,
    tz_name: &str,
) -> bool {
    if state.eq_ignore_ascii_case("canceled") || state.eq_ignore_ascii_case("cancelled") {
        return false;
    }
    let (day_start, day_end) = local_day_bounds(refresh, tz_name);
    planned_start
        .map(|s| s >= day_start && s < day_end)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Timelike;

    #[test]
    fn ac09_48h_inclusive_boundary() {
        let refresh = Utc.with_ymd_and_hms(2026, 3, 8, 12, 0, 0).unwrap();
        let exact = refresh - Duration::hours(48);
        let earlier = exact - Duration::seconds(1);
        assert!(is_executed_in_last_48h(Some(exact), refresh));
        assert!(!is_executed_in_last_48h(Some(earlier), refresh));
        assert!(!is_executed_in_last_48h(None, refresh));
    }

    #[test]
    fn ac09_dst_midnight_bounds() {
        // US Central DST spring forward 2026-03-08
        let refresh = Utc.with_ymd_and_hms(2026, 3, 8, 18, 0, 0).unwrap();
        let (start, end) = local_day_bounds(refresh, "America/Chicago");
        assert_eq!(start.hour(), 6); // CST midnight = 06:00 UTC
        assert!(end > start);
        let planned = start + Duration::hours(1);
        assert!(is_scheduled_today(Some(planned), "scheduled", refresh, "America/Chicago"));
        assert!(!is_scheduled_today(
            Some(start - Duration::seconds(1)),
            "scheduled",
            refresh,
            "America/Chicago"
        ));
    }

    fn ticket(
        sys_id: &str,
        number: &str,
        ci: Option<&str>,
        service: Option<&str>,
        actual_start: Option<DateTime<Utc>>,
        actual_end: Option<DateTime<Utc>>,
    ) -> SnTicket {
        SnTicket {
            sys_id: sys_id.into(),
            number: number.into(),
            short_description: number.into(),
            state: "closed".into(),
            priority: None,
            assignment_group: None,
            service: service.map(|s| s.into()),
            configuration_item: ci.map(|s| s.into()),
            planned_start: None,
            planned_end: None,
            actual_start,
            actual_end,
            opened_at: None,
            impact_start: None,
            link: format!("https://example.service-now.com/{number}"),
            implementation_outcome: None,
        }
    }

    #[test]
    fn ac10_same_resource_same_service_overlap_and_dedupe() {
        let impact = Utc.with_ymd_and_hms(2026, 6, 1, 12, 0, 0).unwrap();
        let incident = SnTicket {
            sys_id: "inc1".into(),
            number: "INC001".into(),
            short_description: "outage".into(),
            state: "2".into(),
            priority: Some("1".into()),
            assignment_group: None,
            service: Some("Payments".into()),
            configuration_item: Some("ci-app".into()),
            planned_start: None,
            planned_end: None,
            actual_start: None,
            actual_end: None,
            opened_at: Some(impact + Duration::hours(2)),
            impact_start: Some(impact),
            link: "https://example.service-now.com/INC001".into(),
            implementation_outcome: None,
        };

        let same_ci = ticket(
            "chg-ci",
            "CHG001",
            Some("ci-app"),
            Some("Other"),
            Some(impact - Duration::hours(50)),
            Some(impact - Duration::hours(48)),
        );
        let same_svc = ticket(
            "chg-svc",
            "CHG002",
            Some("ci-other"),
            Some("Payments"),
            Some(impact - Duration::minutes(40)),
            Some(impact - Duration::minutes(20)),
        );
        let both = ticket(
            "chg-both",
            "CHG003",
            Some("ci-app"),
            Some("Payments"),
            Some(impact - Duration::hours(3)),
            Some(impact - Duration::hours(1)),
        );
        let overlapping = ticket(
            "chg-overlap",
            "CHG004",
            Some("ci-app"),
            None,
            Some(impact - Duration::hours(1)),
            Some(impact + Duration::minutes(30)),
        );
        let planned_only = SnTicket {
            planned_start: Some(impact - Duration::hours(2)),
            planned_end: Some(impact - Duration::hours(1)),
            ..ticket("chg-plan", "CHG005", Some("ci-app"), None, None, None)
        };
        let unrelated = ticket(
            "chg-x",
            "CHG006",
            Some("ci-x"),
            Some("Billing"),
            Some(impact - Duration::hours(2)),
            Some(impact - Duration::hours(1)),
        );

        let result = classify_changes_before_incident(
            &incident,
            &[
                same_ci,
                same_svc,
                both,
                overlapping,
                planned_only,
                unrelated,
            ],
            impact,
            Some("impact_start"),
            48,
            "UTC".into(),
        );

        let completed = result["completed"].as_array().unwrap();
        let implementing = result["implementing_at_start"].as_array().unwrap();

        assert!(completed.iter().any(|m| {
            m["change"]["number"] == "CHG001"
                && m["reasons"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|r| r == "same_resource")
        }));
        assert!(completed.iter().any(|m| {
            m["change"]["number"] == "CHG002"
                && m["reasons"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|r| r == "same_service")
        }));
        let both_row = completed
            .iter()
            .find(|m| m["change"]["number"] == "CHG003")
            .expect("both reasons");
        let reasons = both_row["reasons"].as_array().unwrap();
        assert!(reasons.iter().any(|r| r == "same_resource"));
        assert!(reasons.iter().any(|r| r == "same_service"));
        // Nearest completed first (CHG002 at -20m, then CHG003 at -1h, then CHG001 at -48h)
        assert_eq!(completed[0]["change"]["number"], "CHG002");
        assert_eq!(completed[1]["change"]["number"], "CHG003");

        assert!(implementing.iter().any(|m| m["change"]["number"] == "CHG004"));
        assert!(!completed.iter().any(|m| m["change"]["number"] == "CHG005"));
        assert!(!completed.iter().any(|m| m["change"]["number"] == "CHG006"));
        assert_eq!(result["anchor_source"], "impact_start");
    }

    #[test]
    fn ac10_opened_at_fallback_when_impact_missing() {
        let opened = Utc.with_ymd_and_hms(2026, 6, 1, 14, 0, 0).unwrap();
        let incident = SnTicket {
            sys_id: "inc2".into(),
            number: "INC002".into(),
            short_description: "outage".into(),
            state: "2".into(),
            priority: Some("1".into()),
            assignment_group: None,
            service: None,
            configuration_item: Some("ci-app".into()),
            planned_start: None,
            planned_end: None,
            actual_start: None,
            actual_end: None,
            opened_at: Some(opened),
            impact_start: None,
            link: "https://example.service-now.com/INC002".into(),
            implementation_outcome: None,
        };
        let chg = ticket(
            "chg1",
            "CHG010",
            Some("ci-app"),
            None,
            Some(opened - Duration::hours(2)),
            Some(opened - Duration::hours(1)),
        );
        let result = classify_changes_before_incident(
            &incident,
            &[chg],
            opened,
            Some("opened_at_fallback"),
            48,
            "UTC".into(),
        );
        assert_eq!(result["anchor_source"], "opened_at_fallback");
        assert_eq!(result["completed"].as_array().unwrap().len(), 1);
    }
}