# Detection Rule Repository (Sigma • YARA • Splunk SPL)

A **production-ready detection engineering repository** containing:
- **Sigma** rules for endpoint/SIEM detections (Windows process creation telemetry)
- **YARA** rules for malware/tooling identification
- **Splunk SPL** hunting queries to operationalize detections
- A **MITRE ATT&CK coverage matrix** to track technique coverage and gaps

---

## What’s in this repo

### Sigma (Behavior detections)
Sigma rules are organized by ATT&CK tactic areas:
- **Credential Access** (e.g., Mimikatz usage, LSASS dumping, Credential Manager access)
- **Execution / Defense Evasion** (e.g., encoded PowerShell, mshta, regsvr32 scrobj abuse)
- **Persistence** (scheduled tasks, registry run keys)
- **Lateral Movement** (PsExec, WMI remote execution)

These rules assume **Windows process creation telemetry**, such as:
- Sysmon Event ID 1 (Process Create), and/or
- Security Event ID 4688 (Process Creation with command line enabled)

### YARA (Static detections)
YARA rules are provided as **high-signal templates** for:
- Malware families (Emotet, QakBot)
- Tooling (Cobalt Strike, Mimikatz)

### Splunk (Hunting queries)
Starter SPL hunts are included to help you:
- Validate telemetry
- Hunt suspicious activity
- Convert Sigma logic into SIEM-native searches

---

## Repository Structure

```
detection-rules/
├── sigma/
│   ├── credential_access/
│   │   ├── mimikatz_execution.yml
│   │   ├── lsass_memory_dump.yml
│   │   └── credential_manager_access.yml
│   ├── execution/
│   │   ├── powershell_encoded_command.yml
│   │   ├── mshta_execution.yml
│   │   └── regsvr32_scrobj.yml
│   ├── persistence/
│   │   ├── scheduled_task_creation.yml
│   │   └── registry_run_keys.yml
│   └── lateral_movement/
│       ├── psexec_execution.yml
│       └── wmi_lateral_movement.yml
├── yara/
│   ├── malware/
│   │   ├── emotet_loader.yar
│   │   ├── cobalt_strike_beacon.yar
│   │   └── qakbot_strings.yar
│   └── tools/
│       └── mimikatz_strings.yar
├── splunk/
│   └── hunting_queries.spl
├── COVERAGE_MATRIX.md
├── RULE_AUTHORING_STANDARDS.md
└── PORTFOLIO_HIGHLIGHT.md
```

---

## Validation (Atomic Red Team)

For each technique-mapped Sigma rule, validate using Atomic Red Team:
1. Run the relevant atomic test for the technique (e.g., T1059.001, T1218.005, T1047).
2. Confirm your endpoint telemetry is collecting `Image`, `CommandLine`, `ParentImage`, `User`.
3. Ensure the rule triggers reliably, then tune filters/allowlists to reduce false positives.

**Tip:** Record validation notes as GitHub issues or commit messages (e.g., “tuned mshta rule to reduce FP from legacy app”).

---

## Tuning Guidance (False Positives)
Many techniques can be used by legitimate tooling (SCCM/Intune, admin scripts).
See **RULE_AUTHORING_STANDARDS.md** for baseline + allowlist strategies.

---

## MITRE ATT&CK Coverage
See **COVERAGE_MATRIX.md** for technique + software mapping.

---

## Roadmap
- Add Microsoft Sentinel **KQL** equivalents
- Add CI checks for Sigma/YARA linting
- Expand to Defense Evasion, C2, Exfiltration
- Add rule metadata: `severity`, `confidence`, `required_fields`

---

## Disclaimer
For defensive security research and education only. Test thoroughly before deploying in production environments.
