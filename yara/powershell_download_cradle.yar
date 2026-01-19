rule PowerShell_Download_Cradle
{
    meta:
        description = "Detects common PowerShell download cradle patterns"
        author = "YourName"
        level = "easy"

    strings:
        $a = "Invoke-WebRequest" nocase
        $b = "IEX" nocase
        $c = "DownloadString" nocase
        $d = "New-Object Net.WebClient" nocase

    condition:
        2 of them
}