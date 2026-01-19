rule Python_Exec_Eval_Obfuscation
{
    meta:
        description = "Detects common Python execution/obfuscation strings (exec/eval/base64)"
        author = "YourName"
        level = "easy"

    strings:
        $a = "exec(" nocase
        $b = "eval(" nocase
        $c = "base64" nocase
        $d = "b64decode" nocase

    condition:
        2 of them
}