rule Suspicious_Generic_Strings
{
    meta:
        description = "Detects common suspicious malware-related strings"
        level = "easy"

    strings:
        $a = "cmd.exe"
        $b = "powershell"
        $c = "CreateProcess"

    condition:
        any of them
}