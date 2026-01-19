rule Linux_Reverse_Shell_Strings
{
    meta:
        description = "Detects common Linux reverse shell command patterns"
        author = "YourName"
        level = "easy"

    strings:
        $a = "/dev/tcp/" nocase
        $b = "bash -i" nocase
        $c = "nc -e" nocase
        $d = "mkfifo" nocase

    condition:
        any of them
}