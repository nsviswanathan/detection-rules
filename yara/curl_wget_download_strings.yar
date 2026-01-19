rule Curl_Wget_Download_Strings
{
    meta:
        description = "Detects curl/wget command usage commonly used to fetch payloads"
        author = "YourName"
        level = "easy"

    strings:
        $a = "curl " nocase
        $b = "wget " nocase
        $c = "http://" nocase
        $d = "https://" nocase

    condition:
        ( $a or $b ) and ( $c or $d )
}