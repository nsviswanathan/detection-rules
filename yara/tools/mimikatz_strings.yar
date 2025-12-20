rule Mimikatz_Tool_Strings
{
  meta:
    description = "Detects Mimikatz tool strings (template)"
    author = "N SV"
    date = "2025-12-20"
    reference = "https://attack.mitre.org/software/S0002/"
    tool = "Mimikatz"
    confidence = "high"
  strings:
    $mz = { 4D 5A }
    $m1 = "mimikatz" ascii nocase
    $m2 = "sekurlsa::logonpasswords" ascii
    $m3 = "lsadump::sam" ascii
    $m4 = "privilege::debug" ascii
  condition:
    $mz at 0 and 2 of ($m*)
}
