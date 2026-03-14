/*
    ============================================================
    YARA Rules: Ransomware Encryption Behaviors
    Test ID: b4e0c5d8-3f9a-0e7b-4c1d-8a9b0c1d2e08
    MITRE ATT&CK: T1486 (Data Encrypted for Impact), T1491.001 (Internal Defacement)
    Author: F0RT1KA Detection Rules Generator
    Date: 2026-03-14
    ============================================================
    NOTE: These rules target the underlying attack technique behaviors inherent
    to ransomware — NOT test framework artifacts. They will catch real-world
    ransomware using these same TTPs.
    ============================================================
*/


/*
    ============================================================
    Rule: Ransom Note Content Patterns
    Technique: T1491.001 - Internal Defacement
    Confidence: High
    Description: Detects text files containing language characteristic of
                 ransomware demand notes. Matches across major ransomware families
                 based on common structural elements in ransom notes.
    ============================================================
*/
rule Ransomware_RansomNote_ContentPatterns {
    meta:
        description = "Detects text content with ransomware demand language and recovery instructions"
        author = "F0RT1KA Detection Rules Generator"
        date = "2026-03-14"
        test_id = "b4e0c5d8-3f9a-0e7b-4c1d-8a9b0c1d2e08"
        mitre_attack = "T1491.001"
        confidence = "high"
        reference = "https://attack.mitre.org/techniques/T1491/001/"

    strings:
        // Encryption notification language
        $enc1 = "your files have been encrypted" ascii wide nocase
        $enc2 = "all your files are encrypted" ascii wide nocase
        $enc3 = "your files are encrypted" ascii wide nocase
        $enc4 = "files were encrypted" ascii wide nocase
        $enc5 = "your documents, photos, databases" ascii wide nocase

        // Payment demand language
        $pay1 = "bitcoin" ascii wide nocase
        $pay2 = "BTC" ascii wide
        $pay3 = "ransom" ascii wide nocase
        $pay4 = "payment" ascii wide nocase
        $pay5 = "tor browser" ascii wide nocase
        $pay6 = ".onion" ascii wide nocase

        // Recovery instruction language
        $rec1 = "to decrypt" ascii wide nocase
        $rec2 = "to recover" ascii wide nocase
        $rec3 = "decryption key" ascii wide nocase
        $rec4 = "unique key" ascii wide nocase
        $rec5 = "contact us" ascii wide nocase
        $rec6 = "send us" ascii wide nocase

        // File affected scope language
        $scope1 = "important files" ascii wide nocase
        $scope2 = "documents, photos" ascii wide nocase
        $scope3 = "videos, music" ascii wide nocase

    condition:
        // Text file with at least one encryption notice + one payment indicator
        filesize < 100KB and
        (
            (1 of ($enc*)) and
            (1 of ($pay*)) and
            (1 of ($rec*))
        )
}


/*
    ============================================================
    Rule: Ransomware Executable - Cryptographic API and Mass File Operation Strings
    Technique: T1486 - Data Encrypted for Impact
    Confidence: Medium
    Description: Detects PE executables that combine cryptographic API imports
                 with strings associated with file traversal and encryption
                 extension patterns. This combination is characteristic of
                 ransomware payloads.
    ============================================================
*/
rule Ransomware_PE_CryptoAndFileOpsStrings {
    meta:
        description = "Detects PE files combining crypto API usage with bulk file operation patterns"
        author = "F0RT1KA Detection Rules Generator"
        date = "2026-03-14"
        test_id = "b4e0c5d8-3f9a-0e7b-4c1d-8a9b0c1d2e08"
        mitre_attack = "T1486"
        confidence = "medium"
        reference = "https://attack.mitre.org/techniques/T1486/"

    strings:
        // Cryptographic API imports/references
        $crypto1 = "CryptGenRandom" ascii wide
        $crypto2 = "BCryptGenRandom" ascii wide
        $crypto3 = "CryptEncrypt" ascii wide
        $crypto4 = "BCryptEncrypt" ascii wide
        $crypto5 = "AES" ascii wide
        $crypto6 = "CryptAcquireContext" ascii wide
        $crypto7 = "RtlGenRandom" ascii wide
        $crypto8 = "CryptImportKey" ascii wide

        // File traversal and enumeration patterns
        $ftrav1 = "FindFirstFileW" ascii wide
        $ftrav2 = "FindNextFileW" ascii wide
        $ftrav3 = "FindFirstFileExW" ascii wide

        // Common ransomware target extension strings
        $ext1 = ".docx" ascii wide nocase
        $ext2 = ".xlsx" ascii wide nocase
        $ext3 = ".pdf" ascii wide nocase
        $ext4 = ".jpg" ascii wide nocase
        $ext5 = ".pptx" ascii wide nocase
        $ext6 = ".csv" ascii wide nocase
        $ext7 = ".sql" ascii wide nocase
        $ext8 = ".bak" ascii wide nocase

        // Ransom note filename fragments
        $note1 = "README" ascii wide nocase
        $note2 = "DECRYPT" ascii wide nocase
        $note3 = "HOW_TO" ascii wide nocase
        $note4 = "RESTORE" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 20MB and
        (
            (2 of ($crypto*)) and
            (1 of ($ftrav*)) and
            (3 of ($ext*)) and
            (1 of ($note*))
        )
}


/*
    ============================================================
    Rule: Ransomware - Known Encryption Extension Patterns
    Technique: T1486 - Data Encrypted for Impact
    Confidence: Low-Medium (filename only)
    Description: Detects files with extensions associated with known ransomware
                 families or generic encryption extension patterns. Must be
                 combined with behavioral context — a single renamed file is
                 low signal but 10+ is high signal.
    ============================================================
*/
rule Ransomware_EncryptedFile_KnownExtensions {
    meta:
        description = "Detects files with extensions characteristic of ransomware-encrypted output"
        author = "F0RT1KA Detection Rules Generator"
        date = "2026-03-14"
        test_id = "b4e0c5d8-3f9a-0e7b-4c1d-8a9b0c1d2e08"
        mitre_attack = "T1486"
        confidence = "low"
        reference = "https://attack.mitre.org/techniques/T1486/"

    strings:
        // LockBit and variants
        $ext_lockbit = /\.(lockbit|lockbit2|lockbit3)$/i
        // REvil/Sodinokibi
        $ext_revil = /\.[a-z0-9]{5,10}$/
        // Ryuk
        $ext_ryuk = /\.RYK$/
        // BlackCat/ALPHV
        $ext_alphv = /\.(sykipot|zxz|basta)$/i
        // Conti
        $ext_conti = /\.CONTI$/i
        // Medusa
        $ext_medusa = /\.medusa$/i
        // BlackMatter
        $ext_blackmatter = /\.(blackmatter|dark)$/i
        // Generic — appended .encrypted or similar
        $ext_generic1 = /\.(encrypted|enc|crypt|locked|locked1|locked2)$/i
        $ext_generic2 = /\.(crypted|crptd|crypto)$/i

        // Original file content magic bytes that should NOT appear after encryption
        // Encrypted files typically lack standard headers — detect the ABSENCE
        // by checking that content starts with encrypted-looking random bytes
        $pdf_header = { 25 50 44 46 }    // %PDF
        $zip_header = { 50 4B 03 04 }    // PK..  (Office docs, zip)
        $ole_header = { D0 CF 11 E0 }    // OLE2 (old Office)
        $jpg_header = { FF D8 FF }        // JPEG

    condition:
        // File appears to be user document that lost its original header
        // (i.e., content was overwritten with ciphertext)
        filesize > 1KB and
        filesize < 500MB and
        not (
            uint32(0) == 0x46445025 or  // %PDF
            uint32(0) == 0x04034B50 or  // PK (zip/docx)
            uint32(0) == 0xE011CFD0 or  // OLE2
            uint16(0) == 0xD8FF         // JPEG
        ) and
        (1 of ($ext_lockbit, $ext_ryuk, $ext_alphv, $ext_conti, $ext_medusa, $ext_blackmatter, $ext_generic1, $ext_generic2))
}


/*
    ============================================================
    Rule: Ransomware Dropper - Embedded Ransom Note Template
    Technique: T1486, T1491.001
    Confidence: High
    Description: Detects PE executables with an embedded ransom note template.
                 Ransomware typically carries the ransom note as a string or
                 resource embedded in the binary, written to disk at runtime.
    ============================================================
*/
rule Ransomware_PE_EmbeddedRansomNoteTemplate {
    meta:
        description = "Detects PE files with embedded ransom note template text"
        author = "F0RT1KA Detection Rules Generator"
        date = "2026-03-14"
        test_id = "b4e0c5d8-3f9a-0e7b-4c1d-8a9b0c1d2e08"
        mitre_attack = "T1486, T1491.001"
        confidence = "high"
        reference = "https://attack.mitre.org/techniques/T1486/"

    strings:
        // Multi-language ransom note opening phrases embedded in binary
        $note_en1 = "All your files have been encrypted" ascii wide nocase
        $note_en2 = "Your personal files are encrypted" ascii wide nocase
        $note_en3 = "Your documents, photos, databases" ascii wide nocase
        $note_en4 = "You only have" ascii wide nocase

        // Payment instruction fragments
        $pay1 = "bitcoin address" ascii wide nocase
        $pay2 = "BTC wallet" ascii wide nocase
        $pay3 = "cryptocurrency" ascii wide nocase
        $pay4 = "tor2web" ascii wide nocase
        $pay5 = "tox id" ascii wide nocase

        // Ransom note filename strings that the binary writes
        $note_file1 = "README.txt" ascii wide nocase
        $note_file2 = "DECRYPT_FILES.txt" ascii wide nocase
        $note_file3 = "HOW_TO_DECRYPT" ascii wide nocase
        $note_file4 = "RESTORE_FILES" ascii wide nocase
        $note_file5 = "YOUR_FILES_ARE_ENCRYPTED" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        (
            (1 of ($note_en*)) and
            (1 of ($pay*)) and
            (1 of ($note_file*))
        )
}


/*
    ============================================================
    Rule: Ransomware - PowerShell Encryption Script Pattern
    Technique: T1486 - Data Encrypted for Impact (via T1059.001)
    Confidence: High
    Description: Detects PowerShell scripts that implement file encryption
                 loops over user directories. Script-based ransomware uses
                 .NET cryptography classes with Get-ChildItem traversal.
    ============================================================
*/
rule Ransomware_PowerShell_EncryptionScript {
    meta:
        description = "Detects PowerShell scripts implementing file encryption loops over user documents"
        author = "F0RT1KA Detection Rules Generator"
        date = "2026-03-14"
        test_id = "b4e0c5d8-3f9a-0e7b-4c1d-8a9b0c1d2e08"
        mitre_attack = "T1486"
        confidence = "high"
        reference = "https://attack.mitre.org/techniques/T1059/001/"

    strings:
        // .NET crypto class usage in PowerShell
        $crypto1 = "AesCryptoServiceProvider" ascii wide nocase
        $crypto2 = "RijndaelManaged" ascii wide nocase
        $crypto3 = "AesManaged" ascii wide nocase
        $crypto4 = "RSACryptoServiceProvider" ascii wide nocase
        $crypto5 = "CryptoStream" ascii wide nocase

        // File traversal for encryption
        $ftrav1 = "Get-ChildItem" ascii wide nocase
        $ftrav2 = "GetFiles" ascii wide nocase

        // Rename-Item or Move-Item for extension change
        $rename1 = "Rename-Item" ascii wide nocase
        $rename2 = "Move-Item" ascii wide nocase

        // Target file type filters
        $filter1 = "*.docx" ascii wide nocase
        $filter2 = "*.xlsx" ascii wide nocase
        $filter3 = "*.pdf" ascii wide nocase

        // Recursive directory traversal
        $recurse1 = "-Recurse" ascii wide nocase

        // Ransom note output
        $ransom1 = "Out-File" ascii wide nocase
        $ransom2 = "Set-Content" ascii wide nocase

    condition:
        filesize < 5MB and
        (
            (1 of ($crypto*)) and
            (1 of ($ftrav*)) and
            (1 of ($rename*)) and
            (2 of ($filter*))
        )
        or
        (
            (1 of ($crypto*)) and
            ($recurse1) and
            (1 of ($ransom*))
        )
}
