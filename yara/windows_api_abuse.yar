rule Windows_Process_Injection_APIs
{
    meta:
        description = "Detects common Windows APIs used in process injection"
        level = "easy"

    strings:
        $w1 = "VirtualAlloc"
        $w2 = "WriteProcessMemory"
        $w3 = "CreateRemoteThread"

    condition:
        2 of them
}