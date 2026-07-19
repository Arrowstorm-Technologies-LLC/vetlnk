/*
 * vetlnk starter YARA ruleset — a small set of coarse, illustrative rules for
 * detonation-mode static analysis. Not a substitute for a real threat-intel
 * feed; extend or replace with your own rules as needed.
 *
 * Dropped the old "Double_Extension_Script" rule: it only checked for a
 * shebang at offset 0, which is just "any shell/interpreter script" (already
 * surfaced separately via analyze.py's magic-byte typing) and never actually
 * looked at the filename despite its name — vetlnk's non-YARA extension-vs-
 * magic-bytes mismatch check (see filetype.py) already covers that properly.
 */

import "math"
import "pe"

rule Suspicious_PE_High_Entropy
{
    meta:
        description = "PE executable whose overall image is high-entropy, typical of packed/encrypted payloads"
    condition:
        uint16(0) == 0x5A4D and pe.is_pe and math.entropy(0, filesize) >= 7.2
}

rule Suspicious_PE_Process_Injection_APIs
{
    meta:
        description = "PE references the classic VirtualAlloc(Ex)+WriteProcessMemory+CreateRemoteThread process-injection combo"
    strings:
        $valloc_ex = "VirtualAllocEx" ascii wide
        $valloc = "VirtualAlloc" ascii wide
        $wpm = "WriteProcessMemory" ascii wide
        $crt = "CreateRemoteThread" ascii wide
    condition:
        uint16(0) == 0x5A4D and ($valloc_ex or $valloc) and $wpm and $crt
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

rule LOLBin_Download_And_Execute
{
    meta:
        description = "References living-off-the-land binaries commonly abused to fetch/execute payloads"
    strings:
        $certutil = "certutil" nocase
        $decode = "-decode" nocase
        $urlcache = "-urlcache" nocase
        $mshta = "mshta.exe" nocase
        $regsvr = "regsvr32" nocase
        $http = "http" nocase
        $bitsadmin = "bitsadmin" nocase
    condition:
        ($certutil and ($decode or $urlcache)) or $mshta or ($regsvr and $http) or $bitsadmin
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

rule ELF_Reverse_Shell_Indicators
{
    meta:
        description = "ELF binary or script referencing common reverse-shell patterns"
    strings:
        $devtcp = "/dev/tcp/"
        $binsh_e = "/bin/sh -i"
        $nc_e = "nc -e"
        $mkfifo = "mkfifo"
    condition:
        any of them
}

rule Ransom_Note_Indicators
{
    meta:
        description = "Strings typical of a ransomware ransom note or extortion demand"
    strings:
        $s1 = "your files have been encrypted" nocase
        $s2 = "decrypt your files" nocase
        $s3 = ".onion"
        $btc = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/
    condition:
        2 of them
}

rule Obfuscated_Script_Base64_Payload
{
    meta:
        description = "Script with a long base64 blob alongside decode/execute keywords - common obfuscation"
    strings:
        $b64blob = /[A-Za-z0-9+\/]{200,}={0,2}/
        $fromb64 = "FromBase64String" nocase
        $b64decode = "base64.b64decode"
        $exec = /\beval\(/ nocase
        $iex = "IEX"
    condition:
        $b64blob and any of ($fromb64, $b64decode, $exec, $iex)
}
