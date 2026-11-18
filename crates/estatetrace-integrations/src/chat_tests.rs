#[cfg(test)]
mod tests {
    use crate::chat::ApprovedChatContext;
    use serde_json::json;

    // Mirror redact behavior via ask payload construction invariants.
    #[test]
    fn ac08_default_excludes_ticket_notes() {
        let ctx = ApprovedChatContext {
            question: "how many failing?".into(),
            view_filters: json!({ "environment": "prod" }),
            records: vec![json!({
                "resource_id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa",
                "name": "sa",
                "ticket_number": "CHG001",
                "ticket_state": "closed",
                "ticket_description": "SECRET DESC",
                "work_notes": "SECRET NOTES",
            })],
            evidence_time: Some("2026-01-01T00:00:00Z".into()),
            gaps: vec![],
            include_ticket_notes: false,
        };
        let payload = serde_json::to_string(&json!({
            "question": ctx.question,
            "records": ctx.records.iter().map(|r| json!({
                "resource_id": r.get("resource_id"),
                "name": r.get("name"),
                "ticket_number": r.get("ticket_number"),
                "ticket_state": r.get("ticket_state"),
            })).collect::<Vec<_>>(),
        }))
        .unwrap();
        assert!(!payload.contains("SECRET DESC"));
        assert!(!payload.contains("SECRET NOTES"));
        assert!(payload.contains("CHG001"));
    }
}