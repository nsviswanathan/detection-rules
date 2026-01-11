rule Command_Shell_Execution
{
    meta:
        description = "Detects execution of Windows command shells"
        level = "easy"

    strings:
        $c1 = "cmd.exe"
        $c2 = "/c"
        $c3 = "/k"

    condition:
        2 of them
}