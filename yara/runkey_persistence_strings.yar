rule RunKey_Persistence_Strings
{
    meta:
        description = "Detects registry Run key persistence-related strings"
        author = "YourName"
        level = "easy"

    strings:
        $a = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $b = "\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" nocase
        $c = "reg add" nocase

    condition:
        any of them
}