rule AMSI_Bypass_Strings
{
    meta:
        description = "Detects common strings seen in AMSI bypass attempts"
        author = "YourName"
        level = "easy"

    strings:
        $a = "AmsiUtils" nocase
        $b = "amsiInitFailed" nocase
        $c = "System.Management.Automation" nocase

    condition:
        any of them
}