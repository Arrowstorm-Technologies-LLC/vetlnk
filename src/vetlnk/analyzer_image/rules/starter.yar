/*
 * vetlnk starter YARA ruleset — a small set of coarse, illustrative rules for
 * detonation-mode static analysis. Not a substitute for a real threat-intel
 * feed; extend or replace with your own rules as needed.
 */

rule Suspicious_PE_High_Entropy_Section
{
    meta:
        description = "PE executable with characteristics common in packed/obfuscated malware"
    strings:
        $mz = { 4D 5A }
        $pe = "PE\x00\x00"
    condition:
        $mz at 0 and $pe
}

rule Embedded_PowerShell_Download_Cradle
{
    meta:
        description = "References PowerShell download-and-execute patterns"
    strings:
        $a = "IEX(New-Object" nocase
        $b = "DownloadString" nocase
        $c = "-EncodedCommand" nocase
        $d = "Invoke-Expression" nocase
    condition:
        any of them
}

rule Office_Macro_Auto_Exec
{
    meta:
        description = "OLE/Office document with auto-executing macro indicators"
    strings:
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }
        $auto1 = "Auto_Open" nocase
        $auto2 = "AutoOpen" nocase
        $auto3 = "Document_Open" nocase
    condition:
        $ole at 0 and any of ($auto1, $auto2, $auto3)
}

rule Double_Extension_Script
{
    meta:
        description = "Shell/interpreter script disguised behind a document-like name"
    strings:
        $shebang = "#!"
    condition:
        $shebang at 0
}
