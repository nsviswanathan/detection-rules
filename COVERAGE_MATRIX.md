# MITRE ATT&CK Coverage Matrix

This matrix maps repository detections to **MITRE ATT&CK techniques** (and relevant **software IDs** for YARA).

## Technique Coverage (Sigma)

| Tactic | Rule File | Technique | ATT&CK ID |
|---|---|---|---|
| Credential Access | sigma/credential_access/mimikatz_execution.yml | OS Credential Dumping | T1003 |
| Credential Access | sigma/credential_access/lsass_memory_dump.yml | OS Credential Dumping: LSASS Memory | T1003.001 |
| Credential Access | sigma/credential_access/credential_manager_access.yml | Credentials from Password Stores: Windows Credential Manager | T1555.004 |
| Execution | sigma/execution/powershell_encoded_command.yml | Command and Scripting Interpreter: PowerShell | T1059.001 |
| Defense Evasion | sigma/execution/powershell_encoded_command.yml | Obfuscated/Compressed Files and Information | T1027 |
| Defense Evasion | sigma/execution/mshta_execution.yml | System Binary Proxy Execution: Mshta | T1218.005 |
| Defense Evasion | sigma/execution/regsvr32_scrobj.yml | System Binary Proxy Execution: Regsvr32 | T1218.010 |
| Persistence | sigma/persistence/scheduled_task_creation.yml | Scheduled Task/Job: Scheduled Task | T1053.005 |
| Persistence | sigma/persistence/registry_run_keys.yml | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | T1547.001 |
| Lateral Movement | sigma/lateral_movement/psexec_execution.yml | System Services: Service Execution | T1569.002 |
| Lateral Movement | sigma/lateral_movement/wmi_lateral_movement.yml | Windows Management Instrumentation | T1047 |

## Software Coverage (YARA)

| Rule File | Software | ATT&CK Software ID |
|---|---|---|
| yara/tools/mimikatz_strings.yar | Mimikatz | S0002 |
| yara/malware/emotet_loader.yar | Emotet | S0367 |
| yara/malware/cobalt_strike_beacon.yar | Cobalt Strike | S0154 |
| yara/malware/qakbot_strings.yar | QakBot | S0650 |

## Notes
- Sigma rules are **behavior-driven** and designed for SIEM/Sysmon/Security 4688 telemetry.
- YARA rules provide **static detection** templates for malware/tooling artifacts.
- Validate technique-based Sigma rules with **Atomic Red Team** where applicable.
