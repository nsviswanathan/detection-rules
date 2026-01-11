rule Suspicious_HTTP_C2
{
    meta:
        description = "Detects basic HTTP-based command and control strings"
        level = "easy"

    strings:
        $h1 = "User-Agent:"
        $h2 = "POST /gate.php"
        $h3 = "GET /index.php"

    condition:
        any of them
}