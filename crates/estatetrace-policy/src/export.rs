use crate::pack::{AzureRemediation, Control, PolicyPack};
use serde_json::{json, Value};

#[derive(Debug, Clone)]
pub struct ExportPreview {
    pub control_id: String,
    pub control_revision: String,
    pub effect: String,
    pub supported: bool,
    pub reason: String,
    pub required_inputs: Vec<String>,
    pub matching_count: usize,
    pub sample_resources: Vec<String>,
    pub overlap_warning: Option<String>,
    pub bicep: String,
    pub mapping: Value,
}

pub fn suggest_and_preview(
    pack: &PolicyPack,
    control_id: &str,
    matching_resources: &[(String, String)],
    existing_assignments: &[Value],
    target_scope: &str,
) -> Result<ExportPreview, String> {
    let control = pack
        .controls
        .iter()
        .find(|c| c.id == control_id)
        .ok_or_else(|| format!("control {control_id} not found"))?;

    if control.effective_not_evaluated().is_some() {
        return Ok(ExportPreview {
            control_id: control.id.clone(),
            control_revision: control.source.revision.clone(),
            effect: "manual".into(),
            supported: false,
            reason: "Control requires human evidence; export unavailable".into(),
            required_inputs: vec![],
            matching_count: matching_resources.len(),
            sample_resources: matching_resources.iter().take(5).map(|(_, n)| n.clone()).collect(),
            overlap_warning: None,
            bicep: String::new(),
            mapping: json!({}),
        });
    }

    let rem = control.azure_remediation.clone().unwrap_or(AzureRemediation {
        effect: "audit".into(),
        when: None,
        inherit_from: None,
    });

    let (effect, supported, reason, required_inputs, bicep, mapping) =
        build_export(control, &rem, pack, target_scope);

    let overlap_warning = if existing_assignments.is_empty() {
        None
    } else {
        Some(format!(
            "{} existing assignment(s) visible; review for overlap",
            existing_assignments.len()
        ))
    };

    Ok(ExportPreview {
        control_id: control.id.clone(),
        control_revision: control.source.revision.clone(),
        effect,
        supported,
        reason,
        required_inputs,
        matching_count: matching_resources.len(),
        sample_resources: matching_resources
            .iter()
            .take(5)
            .map(|(_, n)| n.clone())
            .collect(),
        overlap_warning,
        bicep,
        mapping,
    })
}

fn build_export(
    control: &Control,
    rem: &AzureRemediation,
    pack: &PolicyPack,
    target_scope: &str,
) -> (String, bool, String, Vec<String>, String, Value) {
    match rem.effect.as_str() {
        "modify"
            if control
                .primary_field()
                .is_some_and(|f| f.starts_with("tags.")) =>
        {
            let tag_name = control
                .primary_field()
                .unwrap_or_default()
                .trim_start_matches("tags.");
            let inherit = rem.inherit_from.clone().unwrap_or_else(|| "resource_group".into());
            let bicep = render_modify_tag_bicep(control, tag_name, &inherit, target_scope);
            let mapping = json!({
                "control_id": control.id,
                "pack_id": pack.id,
                "pack_revision": pack.revision,
                "definition": "custom",
                "effect": "modify",
                "tag": tag_name,
                "inherit_from": inherit,
            });
            (
                "modify".into(),
                true,
                format!("Modify missing tag '{tag_name}' when parent supplies value"),
                vec!["assignmentScope".into()],
                bicep,
                mapping,
            )
        }
        "deployIfNotExists" => {
            let bicep = render_dine_diagnostics_bicep(control, target_scope);
            let mapping = json!({
                "control_id": control.id,
                "pack_id": pack.id,
                "pack_revision": pack.revision,
                "definition": "custom",
                "effect": "deployIfNotExists",
            });
            (
                "deployIfNotExists".into(),
                true,
                "DeployIfNotExists for diagnostic settings; evaluation delay and managed identity required".into(),
                vec![
                    "workspaceId".into(),
                    "assignmentScope".into(),
                    "managedIdentityLocation".into(),
                ],
                bicep,
                mapping,
            )
        }
        "deny" => (
            "deny".into(),
            false,
            "Blocking deny requires explicit policy-owner approval; defaulting suggestion to audit".into(),
            vec![],
            render_audit_bicep(control, target_scope),
            json!({
                "control_id": control.id,
                "effect": "audit",
                "requested_effect": "deny",
            }),
        ),
        _ => {
            let bicep = render_audit_bicep(control, target_scope);
            (
                "audit".into(),
                true,
                "Audit / review when correct value is unknown or modification could disrupt service".into(),
                vec!["assignmentScope".into()],
                bicep,
                json!({
                    "control_id": control.id,
                    "pack_id": pack.id,
                    "pack_revision": pack.revision,
                    "effect": "audit",
                }),
            )
        }
    }
}

fn render_modify_tag_bicep(control: &Control, tag_name: &str, inherit_from: &str, scope: &str) -> String {
    format!(
        r#"// EstateTrace export for control {id} (clause {clause})
// Scope: {scope}
// Effect: modify — supplies missing tag from {inherit}
// Future creates/updates only. Select a remediation task separately for existing resources.
// To stop future corrections: delete or unassign this policy assignment.
// Restoring prior values requires a separate authorized change.

targetScope = 'subscription'

@description('Tag name required by control {id}')
param tagName string = '{tag_name}'

resource policyDef 'Microsoft.Authorization/policyDefinitions@2021-06-01' = {{
  name: 'estatetrace-{id_safe}-modify-tag'
  properties: {{
    displayName: 'EstateTrace {id} require tag'
    mode: 'Indexed'
    policyRule: {{
      if: {{
        field: 'tags[\'${{tagName}}\']'
        exists: false
      }}
      then: {{
        effect: 'modify'
        details: {{
          roleDefinitionIds: [
            '/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c'
          ]
          operations: [
            {{
              operation: 'add'
              field: 'tags[\'${{tagName}}\']'
              value: '[resourceGroup().tags[\'${{tagName}}\']]'
            }}
          ]
        }}
      }}
    }}
  }}
}}

resource assignment 'Microsoft.Authorization/policyAssignments@2022-06-01' = {{
  name: 'estatetrace-{id_safe}'
  properties: {{
    displayName: 'EstateTrace {id}'
    policyDefinitionId: policyDef.id
  }}
  identity: {{
    type: 'SystemAssigned'
  }}
  location: resourceGroup().location
}}
"#,
        id = control.id,
        id_safe = control.id.replace('_', "-").to_ascii_lowercase(),
        clause = control.source.clause,
        scope = scope,
        inherit = inherit_from,
        tag_name = tag_name,
    )
}

fn render_dine_diagnostics_bicep(control: &Control, scope: &str) -> String {
    format!(
        r#"// EstateTrace export for control {id}
// Scope: {scope}
// Effect: deployIfNotExists — diagnostic settings
// Show evaluation delay, identity, permissions and expected cost to operators.

targetScope = 'subscription'

@description('Log Analytics workspace resource ID')
param workspaceId string

resource policyDef 'Microsoft.Authorization/policyDefinitions@2021-06-01' = {{
  name: 'estatetrace-{id_safe}-diag'
  properties: {{
    displayName: 'EstateTrace {id} diagnostics'
    mode: 'Indexed'
    policyRule: {{
      if: {{
        field: 'type'
        equals: 'Microsoft.KeyVault/vaults'
      }}
      then: {{
        effect: 'deployIfNotExists'
        details: {{
          type: 'Microsoft.Insights/diagnosticSettings'
          existenceCondition: {{
            allOf: [
              {{
                field: 'Microsoft.Insights/diagnosticSettings/workspaceId'
                equals: '[parameters(\'workspaceId\')]'
              }}
            ]
          }}
          roleDefinitionIds: [
            '/providers/Microsoft.Authorization/roleDefinitions/92aaf0da-9dab-42b6-94a3-d43ce8d16293'
          ]
          deployment: {{
            properties: {{
              mode: 'incremental'
              template: {{
                '$schema': 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#'
                contentVersion: '1.0.0.0'
                resources: []
              }}
            }}
          }}
        }}
      }}
    }}
    parameters: {{
      workspaceId: {{
        type: 'String'
      }}
    }}
  }}
}}
"#,
        id = control.id,
        id_safe = control.id.replace('_', "-").to_ascii_lowercase(),
        scope = scope,
    )
}

fn render_audit_bicep(control: &Control, scope: &str) -> String {
    format!(
        r#"// EstateTrace export for control {id} — audit
// Scope: {scope}

targetScope = 'subscription'

resource policyDef 'Microsoft.Authorization/policyDefinitions@2021-06-01' = {{
  name: 'estatetrace-{id_safe}-audit'
  properties: {{
    displayName: 'EstateTrace {id} audit'
    mode: 'All'
    policyRule: {{
      if: {{
        field: 'type'
        exists: true
      }}
      then: {{
        effect: 'audit'
      }}
    }}
  }}
}}
"#,
        id = control.id,
        id_safe = control.id.replace('_', "-").to_ascii_lowercase(),
        scope = scope,
    )
}