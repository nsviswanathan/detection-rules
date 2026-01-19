rule Schtasks_Persistence_Strings
{
    meta:
        description = "Detects schtasks creation patterns often used for persistence"
        author = "YourName"
        level = "easy"

    strings:
        $a = "schtasks" nocase
        $b = "/create" nocase
        $c = "/sc onlogon" nocase
        $d = "/ru SYSTEM" nocase

    condition:
        $a and ( $b or $c or $d )
}