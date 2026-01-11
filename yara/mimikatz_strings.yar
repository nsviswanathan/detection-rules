rule Mimikatz_Indicators
{
    meta:
        description = "Detects common Mimikatz strings"
        level = "easy"

    strings:
        $m1 = "mimikatz"
        $m2 = "sekurlsa::logonpasswords"
        $m3 = "lsadump::sam"

    condition:
        any of them
}