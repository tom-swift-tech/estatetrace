# Policy pack conversion prompt

You are converting an approved cloud policy document into an EstateTrace policy pack.

Inputs:
1. The EstateTrace JSON Schema (`policy_pack.schema.json`)
2. The evidence field catalog
3. The organization's policy DOCX or text

Output:
1. A YAML policy pack (`schema_version: 1`) with stable control IDs
2. A clause coverage report listing each clause as `automated_check`, `manual_evidence`, or `owner_question`
3. Example cases for pass, fail, and unknown where machine-checkable

Rules:
- Preserve clause location and document revision on every control
- Use only catalog fields and allowed operators
- Do not invent Azure write actions beyond suggested remediation metadata
- Keep quarterly restore tests and similar obligations even when Azure can only supply enrollment evidence (`manual: true`)
