rule Encoded_Command_Generic
{
    meta:
        description = "Detects common encoded command flags used for obfuscation"
        author = "YourName"
        level = "easy"

    strings:
        $a = " -enc " nocase
        $b = " -encodedcommand " nocase
        $c = "FromBase64String" nocase
        $d = "base64," nocase

    condition:
        any of them
}