rule Ransomware_Note_Detection
{
    meta:
        description = "Detects common ransomware ransom note phrases"
        level = "easy"

    strings:
        $r1 = "your files have been encrypted"
        $r2 = "bitcoin"
        $r3 = "contact us"

    condition:
        any of them
}