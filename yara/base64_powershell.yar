rule Base64_PowerShell_Command
{
    meta:
        description = "Detects PowerShell base64 encoding usage"
        level = "easy"

    strings:
        $ps1 = "-enc"
        $ps2 = "FromBase64String"

    condition:
        any of them
}