rule Office_Macro_AutoExec_Strings
{
    meta:
        description = "Detects common Office macro auto-execution function names"
        author = "YourName"
        level = "easy"

    strings:
        $a = "AutoOpen" nocase
        $b = "Document_Open" nocase
        $c = "Workbook_Open" nocase
        $d = "AutoClose" nocase

    condition:
        any of them
}