# Rule Authoring Standards

These standards keep detections consistent, SOC-usable, and maintainable.

## Sigma Requirements
Each Sigma rule should include:
- `title`, `id` (UUID), `status`, `description`, `author`, `date`
- `logsource` (category + product)
- `detection` logic with readable selections + clear `condition`
- `falsepositives` (realistic cases)
- `level` (low/medium/high/critical)
- `tags` mapped to **MITRE ATT&CK**

## Severity (Sigma `level`)
- **critical**: very strong compromise indicator (e.g., LSASS dump patterns)
- **high**: strong suspicious behavior (mshta remote/script, WMI process create)
- **medium**: sometimes-admin activity; suspicious on endpoints (run keys, vaultcmd)
- **low**: weak/broad signals (avoid unless correlated)

## Log Sources
Recommended Windows telemetry:
- **Sysmon**: Event ID 1 (Process Create)
- **Security**: Event ID 4688 (Process Creation w/ command line)

Fields you should ensure exist in your pipeline:
- `Image`, `CommandLine`, `ParentImage`, `User`, `Computer`

## False Positive Strategy
Every rule should define:
- Known legit tools (SCCM/Intune/EDR agents/IR tooling)
- Expected enterprise automation patterns
- A tuning path:
  - Baseline normal parent processes per org
  - Allowlist signed binaries and management agents
  - Restrict certain detections to non-admin endpoints

## Detection Engineering Best Practices
- Prefer behavior-driven logic over fragile strings
- Keep rules readable; document assumptions
- Use filters for known enterprise tooling where needed
- Track tuning changes via commits (e.g., “reduce FP”, “add allowlist filter”)

## Atomic Red Team Validation Standard
For each ATT&CK-mapped Sigma detection:
- Run the relevant atomic test
- Confirm the rule fires with expected fields
- Document tuning applied and known FPs

## YARA Standards
- Include `meta`: description, author, date, reference, confidence
- Avoid single-string matches; require multiple indicators (`2 of`, `3 of`)
- Treat these as templates; refine with real samples + section/pe checks where possible
