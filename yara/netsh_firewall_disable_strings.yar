rule Netsh_Firewall_Disable_Strings
{
    meta:
        description = "Detects netsh commands that disable Windows Firewall"
        author = "YourName"
        level = "easy"

    strings:
        $a = "netsh" nocase
        $b = "advfirewall" nocase
        $c = "set allprofiles state off" nocase
        $d = "firewall set opmode disable" nocase

    condition:
        $a and ( $c or ( $b and $c ) or $d )
}