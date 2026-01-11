rule Certutil_Download_Abuse
{
    meta:
        description = "Detects certutil usage for file download"
        level = "easy"

    strings:
        $l1 = "certutil"
        $l2 = "-urlcache"
        $l3 = "http"

    condition:
        2 of them
}