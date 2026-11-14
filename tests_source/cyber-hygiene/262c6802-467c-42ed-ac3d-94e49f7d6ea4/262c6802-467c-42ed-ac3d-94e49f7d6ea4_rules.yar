import "hash"

/*
    ============================================================
    YARA Rule: EMUDHRA_COMPROMISED_TLS_CA
    Test ID: 262c6802-467c-42ed-ac3d-94e49f7d6ea4
    MITRE ATT&CK: T1557
    Confidence: High
    Description: Exact compromised TLS intermediate certificates and their public keys.
    Author: F0RT1KA Detection Rules Generator
    Date: 2026-11-14
    ============================================================
    Coverage: SHA-256 of a standalone DER certificate, raw DER SPKI bytes embedded
    in DER/PKCS#7/other binary containers, and exact PEM lines spanning each SPKI.
    SPKI matches also identify newly forged certificates using a compromised key.
    False Positives: historically legitimate certificates and research collections.
    Tuning: alert on any match and review certificate provenance; do not exempt by
    filename, publisher, or directory. Presence alone is not chain acceptance.
*/
rule EMUDHRA_COMPROMISED_TLS_CA {
    meta:
        description = "Compromised eMudhra TLS intermediate DER certificates, PEM content, or SPKI bytes"
        author = "F0RT1KA"
        date = "2026-11-14"
        test_id = "262c6802-467c-42ed-ac3d-94e49f7d6ea4"
        mitre_attack = "T1557"
        confidence = "high"
        reference = "https://blog.cloudflare.com/emudhra-certificate-compromise"
        certificate_sha256 = "42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493 45A883F349AEDFD5F3A649B5498FFB121712BA8B448F3F2A91DBC5A766FCDDBE 98B896625C0C230ADEEC3EB2CF6AAD5001ECF9156A68644E82374CE5833BC25B 5F1DED4DD590AF74631290CF073B122A2AAC6A1FA479778A0BD43579BD832699 E7568FE6E12331F4FD7DE61DA4C7559D0F8EB192A218D4741A3BA75184333838 579480AEA166290BD3C643589E795FC0D0E54E86505D180F1DFF99EFD3199512 0164D7CEAE5BB909C272AF151FF44B1177AE9B47D9424B94F1D9558C30934D19 62B7F9868263F72F6911FC78CEAF72C1979158B7368BF648683BB2AA39B02E72 CB6E15165AC802E9B3F993F16C25D41F4E81C21EBDE71AE1B012AC00BF9C7C3F 7485B51C0ED192878FA1D2F948FB529AE1842CC5086C4B67F7BE5B2039DE9489 432EC25F0D28DE9006D97BF752F17BBB2CD41F669933FCB072D9A1148D0261F3 FD9D5C2DBBD4995AB69B8D50C439D9527B00529199C2FD01B2174EB58F07021F"
        spki_sha256 = "EBED6475C2C2D80FCB199F3FE8DD6E6B3CE60B77EB15D4E42C3DEC0C6F5B5105 43BFFA19D6EF651451F6841E019931E96F6F2EAEFF28AB4B6F1CE4576DE2717B E0254C7FCDC265E2F0F8A428DABB75AB4AE039B4872D62F5EE57F0877D5A8A41 49DD353DC2B919A3770645117D0E60C16115E7D1BC259EEFE734B00EA434FE5F 63ECEFEE431D49523BC1136C4E72D0206A477086CAF606CD5CF025686C109CF8 5C0660A2B164910D8FF589C18E14552E9E0EC237DCEFE2CB736D41A4811F81A0"

    strings:
        // Six compromised DER SubjectPublicKeyInfo values.
        $spki_dv_g3b = { 30 76 30 10 06 07 2A 86 48 CE 3D 02 01 06 05 2B 81 04 00 22 03 62 00 04 E7 9E D9 C0 4A 97 73 C4 73 5E 51 11 1D A8 5A C2 BD 5E 64 AB 37 4B 80 E1 2C BC 20 38 EC 1E 4F 0E 3B 81 2F C9 85 9E 1E 67 AF B0 4E 2F 8B C9 7F 74 85 BA 65 AA 91 1E E8 A4 E4 5B 62 D5 CC 03 D5 6B E6 78 B3 C3 8C B4 DC 93 7C A2 46 0E 23 84 53 C8 92 93 5D 29 D4 4F 91 E1 56 06 B6 3C CE DA B4 68 }
        $spki_ov_g3b = { 30 76 30 10 06 07 2A 86 48 CE 3D 02 01 06 05 2B 81 04 00 22 03 62 00 04 73 89 7A A0 EB 3C FD CA 8B 12 40 2F FA F0 AB C4 E1 21 2B AF 8D EE 77 8A C9 EE 2D 6D B8 3F AC 28 0C 5E 05 63 8A E7 A2 AC D7 1C 32 2A 8E 36 1C DE B9 F6 9C 43 02 B9 DD 8D 73 D1 CC 6C AA B2 CC 0A EE 4E 21 6C E9 79 DD 51 8A 4A F4 B6 26 E5 68 4C DD 65 80 37 ED 0C 85 4E 4C C1 2F 4C F8 64 6D 0D }
        $spki_ev_g3b = { 30 76 30 10 06 07 2A 86 48 CE 3D 02 01 06 05 2B 81 04 00 22 03 62 00 04 25 DB A8 5A 64 D3 97 DA 0B 10 52 E9 EA 54 6E 48 7B EF EA 9C 9D 9D 68 A0 C5 EA DC FE EF 75 A6 9B B5 D6 FC 01 F4 2B FB CA 6E B4 0B CD 64 C0 76 7E 36 FF D0 5D 97 A8 13 C5 AA 0C 6C 95 30 E7 9C F5 F0 86 64 68 F1 38 06 42 0A A5 C8 51 84 0B 1E 25 25 40 E7 90 E4 B6 54 C3 85 2E D6 4A F1 E8 65 7D }
        $spki_dv_g3c = { 30 76 30 10 06 07 2A 86 48 CE 3D 02 01 06 05 2B 81 04 00 22 03 62 00 04 3A 7A 78 62 C8 C4 4D 32 4D DD 69 03 3A 67 82 C0 EF EE FE 40 55 E6 8A 12 3F A0 37 1B A3 BD 91 94 51 4E E1 72 A4 33 E3 63 0F 02 BD 18 80 37 D9 E5 14 9F 9B 77 DB 94 A2 81 DF 98 7B 2F EA 88 8B 74 BD FE 8F DA 4C 10 99 EE 6C A1 95 66 FE 3E F0 E5 F6 B0 9A 55 6C CC 8B A5 05 61 DF 1B 2A 44 1D 01 }
        $spki_ov_g3c = { 30 76 30 10 06 07 2A 86 48 CE 3D 02 01 06 05 2B 81 04 00 22 03 62 00 04 13 82 51 CD 52 AC 92 98 C1 C8 AA D9 77 32 1D EB 97 E7 09 BD 0B 4C A0 AC A5 5D C8 AD 51 DC FC 9D 15 89 A1 59 7E 3A 51 20 E1 EF D6 31 C6 3E 18 35 CA CA E2 98 69 A6 2E 16 31 E8 A2 81 81 AB 56 61 6D C4 5D 91 8A BC 09 F3 AB 0E 63 CF 79 2A A4 DC ED 73 87 BE 37 BB A5 69 54 9F 1C 02 B2 70 ED 67 }
        $spki_ev_g3c = { 30 76 30 10 06 07 2A 86 48 CE 3D 02 01 06 05 2B 81 04 00 22 03 62 00 04 2D 56 E8 29 A6 FB 82 C6 4A 46 97 D9 60 AF 95 1E 90 67 AE 91 F9 26 D3 43 06 DA 48 A8 AA EB 78 69 B6 A6 7E 6D 27 42 6E 04 42 AA 03 B3 6E 19 88 DF F6 36 51 4E E1 CF 07 F5 BA 4B 3F F2 A0 66 45 AE 7D 31 D5 86 6A D3 1A A3 D2 46 EB 0B 31 77 EE 99 CB 75 66 C5 16 CE 74 80 8A 66 8F 91 F0 C4 7F CA }

        // Exact PEM content for the direct and Sectigo AAA certificate encodings.
        $pem_dv_g3b_direct_a = "AQYFK4EEACIDYgAE557ZwEqXc8RzXlERHahawr1eZKs3S4DhLLwgOOweTw47gS/J" ascii
        $pem_dv_g3b_direct_b = "hZ4eZ6+wTi+LyX90hbplqpEe6KTkW2LVzAPVa+Z4s8OMtNyTfKJGDiOEU8iSk10p" ascii
        $pem_dv_g3b_aaa_a = "IgNiAATnntnASpdzxHNeUREdqFrCvV5kqzdLgOEsvCA47B5PDjuBL8mFnh5nr7BO" ascii
        $pem_dv_g3b_aaa_b = "L4vJf3SFumWqkR7opORbYtXMA9Vr5nizw4y03JN8okYOI4RTyJKTXSnUT5HhVga2" ascii
        $pem_ov_g3b_direct_a = "BgUrgQQAIgNiAARziXqg6zz9yosSQC/68KvE4SErr43ud4rJ7i1tuD+sKAxeBWOK" ascii
        $pem_ov_g3b_direct_b = "56Ks1xwyKo42HN659pxDArndjXPRzGyqsswK7k4hbOl53VGKSvS2JuVoTN1lgDft" ascii
        $pem_ov_g3b_aaa_a = "IgNiAARziXqg6zz9yosSQC/68KvE4SErr43ud4rJ7i1tuD+sKAxeBWOK56Ks1xwy" ascii
        $pem_ov_g3b_aaa_b = "Ko42HN659pxDArndjXPRzGyqsswK7k4hbOl53VGKSvS2JuVoTN1lgDftDIVOTMEv" ascii
        $pem_ev_g3b_direct_a = "AQYFK4EEACIDYgAEJduoWmTTl9oLEFLp6lRuSHvv6pydnWigxerc/u91ppu11vwB" ascii
        $pem_ev_g3b_direct_b = "9Cv7ym60C81kwHZ+Nv/QXZeoE8WqDGyVMOec9fCGZGjxOAZCCqXIUYQLHiUlQOeQ" ascii
        $pem_ev_g3b_aaa_a = "IgNiAAQl26haZNOX2gsQUunqVG5Ie+/qnJ2daKDF6tz+73Wmm7XW/AH0K/vKbrQL" ascii
        $pem_ev_g3b_aaa_b = "zWTAdn42/9Bdl6gTxaoMbJUw55z18IZkaPE4BkIKpchRhAseJSVA55DktlTDhS7W" ascii
        $pem_dv_g3c_direct_a = "AQYFK4EEACIDYgAEOnp4YsjETTJN3WkDOmeCwO/u/kBV5ooSP6A3G6O9kZRRTuFy" ascii
        $pem_dv_g3c_direct_b = "pDPjYw8CvRiAN9nlFJ+bd9uUooHfmHsv6oiLdL3+j9pMEJnubKGVZv4+8OX2sJpV" ascii
        $pem_dv_g3c_aaa_a = "ACIDYgAEOnp4YsjETTJN3WkDOmeCwO/u/kBV5ooSP6A3G6O9kZRRTuFypDPjYw8C" ascii
        $pem_dv_g3c_aaa_b = "vRiAN9nlFJ+bd9uUooHfmHsv6oiLdL3+j9pMEJnubKGVZv4+8OX2sJpVbMyLpQVh" ascii
        $pem_ov_g3c_direct_a = "AQYFK4EEACIDYgAEE4JRzVKskpjByKrZdzId65fnCb0LTKCspV3IrVHc/J0ViaFZ" ascii
        $pem_ov_g3c_direct_b = "fjpRIOHv1jHGPhg1ysrimGmmLhYx6KKBgatWYW3EXZGKvAnzqw5jz3kqpNztc4e+" ascii
        $pem_ov_g3c_aaa_a = "ACIDYgAEE4JRzVKskpjByKrZdzId65fnCb0LTKCspV3IrVHc/J0ViaFZfjpRIOHv" ascii
        $pem_ov_g3c_aaa_b = "1jHGPhg1ysrimGmmLhYx6KKBgatWYW3EXZGKvAnzqw5jz3kqpNztc4e+N7ulaVSf" ascii
        $pem_ev_g3c_direct_a = "AgEGBSuBBAAiA2IABC1W6Cmm+4LGSkaX2WCvlR6QZ66R+SbTQwbaSKiq63hptqZ+" ascii
        $pem_ev_g3c_direct_b = "bSdCbgRCqgOzbhmI3/Y2UU7hzwf1uks/8qBmRa59MdWGatMao9JG6wsxd+6Zy3Vm" ascii
        $pem_ev_g3c_aaa_a = "IgNiAAQtVugppvuCxkpGl9lgr5UekGeukfkm00MG2kioqut4abamfm0nQm4EQqoD" ascii
        $pem_ev_g3c_aaa_b = "s24ZiN/2NlFO4c8H9bpLP/KgZkWufTHVhmrTGqPSRusLMXfumct1ZsUWznSAimaP" ascii

    condition:
        any of ($spki_*) or any of ($pem_*) or
        hash.sha256(0, filesize) == "42c4accd12c4f59597925e1a08a7a90102608543809308d50ec427e118ba1493" or
        hash.sha256(0, filesize) == "45a883f349aedfd5f3a649b5498ffb121712ba8b448f3f2a91dbc5a766fdddbe" or
        hash.sha256(0, filesize) == "98b896625c0c230adeec3eb2cf6aad5001ecf9156a68644e82374ce5833bc25b" or
        hash.sha256(0, filesize) == "5f1ded4dd590af74631290cf073b122a2aac6a1fa479778a0bd43579bd832699" or
        hash.sha256(0, filesize) == "e7568fe6e12331f4fd7de61da4c7559d0f8eb192a218d4741a3ba75184333838" or
        hash.sha256(0, filesize) == "579480aea166290bd3c643589e795fc0d0e54e86505d180f1dff99efd3199512" or
        hash.sha256(0, filesize) == "0164d7ceae5bb909c272af151ff44b1177ae9b47d9424b94f1d9558c30934d19" or
        hash.sha256(0, filesize) == "62b7f9868263f72f6911fc78ceaf72c1979158b7368bf648683bb2aa39b02e72" or
        hash.sha256(0, filesize) == "cb6e15165ac802e9b3f993f16c25d41f4e81c21ebde71ae1b012ac00bf9c7c3f" or
        hash.sha256(0, filesize) == "7485b51c0ed192878fa1d2f948fb529ae1842cc5086c4b67f7be5b2039de9489" or
        hash.sha256(0, filesize) == "432ec25f0d28de9006d97bf752f17bbb2cd41f669933fcb072d9a1148d0261f3" or
        hash.sha256(0, filesize) == "fd9d5c2dbbd4995ab69b8d50c439d9527b00529199c2fd01b2174eb58f07021f"
}

/*
    ============================================================
    YARA Rule: EMUDHRA_COMPROMISED_CODESIGN_CA
    Test ID: 262c6802-467c-42ed-ac3d-94e49f7d6ea4
    MITRE ATT&CK: T1553.002
    Confidence: High
    Description: Exact compromised code-signing intermediate certificates and keys.
    Author: F0RT1KA Detection Rules Generator
    Date: 2026-11-14
    ============================================================
    False Positives: historically legitimately signed files and research evidence.
    Tuning: inspect signature timestamp and provenance; a content match alone does
    not assert that WinVerifyTrust accepted the signature.
*/
rule EMUDHRA_COMPROMISED_CODESIGN_CA {
    meta:
        description = "Compromised eMudhra code-signing intermediate DER certificates, PEM content, or SPKI bytes"
        author = "F0RT1KA"
        date = "2026-11-14"
        test_id = "262c6802-467c-42ed-ac3d-94e49f7d6ea4"
        mitre_attack = "T1553.002"
        confidence = "high"
        reference = "https://blog.talosintelligence.com/compromised-intermediate-certificates/"
        certificate_sha256 = "9E39DE2881273ACC225A149C72BA3E0F51424963669AB633EE1DC7DF5DB067B4 A496E23AC0CAB8155FC9B117B97EAE368EFCBB9041AEC8804D5A308D2D01C2D8 4B2460A466F95FD40113BCDCCA2CEB29B3B093921DE45474DA7DF48874C630B1 84112972B8E59D14560AE7E7119654474AAD119990CF3722BFC1E3B91615E1FD"
        spki_sha256 = "EC4FFA1AD0AC88081314B7AAFFEF6A91F97CD57291BB5BA686C5415F5EB4F6B6 92C063D67E8F14DB71D288E11266FFDAF69CBF115F7BAB14F3BC2F68D25E0E30"

    strings:
        $spki_ov_cs_g3b = { 30 76 30 10 06 07 2A 86 48 CE 3D 02 01 06 05 2B 81 04 00 22 03 62 00 04 AA BB 0F B0 66 6A CF CF 01 FA D5 2B FC FD 4C 2B F2 CB 3C 34 97 DE 73 95 0E 58 19 B6 1F E6 95 09 87 41 C8 C4 91 43 9B 34 A0 43 1C AF FE 5B F9 B4 C1 C8 E8 AE 00 01 F9 F4 DC 8A D8 2C 59 F3 63 9E 96 CD 6C 3D 4D B0 CE FE C2 6C 3D 62 51 7B 37 76 13 72 74 3F 8E 8A DD 77 B1 00 64 F2 AB E5 E0 50 }
        $spki_ov_cs_g3c = { 30 76 30 10 06 07 2A 86 48 CE 3D 02 01 06 05 2B 81 04 00 22 03 62 00 04 B9 F0 E0 63 47 02 A6 9C A6 AA DD 44 3C FD 62 C4 1B 9B A4 B2 09 24 69 7D 79 74 E7 69 1A 12 6F B9 6A FB 3E 34 C2 FD 3B C5 F4 83 06 1F 26 5D C2 A5 84 36 34 73 23 51 04 36 B2 8F 04 F3 86 23 63 06 79 80 E2 50 3E 02 53 2D 65 46 23 5A 71 65 A2 59 A1 EF 49 6F 74 1B 5F DE E7 78 72 08 E4 B8 FA EF }

        $pem_ov_cs_g3b_direct_a = "K4EEACIDYgAEqrsPsGZqz88B+tUr/P1MK/LLPDSX3nOVDlgZth/mlQmHQcjEkUOb" ascii
        $pem_ov_cs_g3b_direct_b = "NKBDHK/+W/m0wcjorgAB+fTcitgsWfNjnpbNbD1NsM7+wmw9YlF7N3YTcnQ/jord" ascii
        $pem_ov_cs_g3b_aaa_a = "YgAEqrsPsGZqz88B+tUr/P1MK/LLPDSX3nOVDlgZth/mlQmHQcjEkUObNKBDHK/+" ascii
        $pem_ov_cs_g3b_aaa_b = "W/m0wcjorgAB+fTcitgsWfNjnpbNbD1NsM7+wmw9YlF7N3YTcnQ/jordd7EAZPKr" ascii
        $pem_ov_cs_g3c_direct_a = "BSuBBAAiA2IABLnw4GNHAqacpqrdRDz9YsQbm6SyCSRpfXl052kaEm+5avs+NML9" ascii
        $pem_ov_cs_g3c_direct_b = "O8X0gwYfJl3CpYQ2NHMjUQQ2so8E84YjYwZ5gOJQPgJTLWVGI1pxZaJZoe9Jb3Qb" ascii
        $pem_ov_cs_g3c_aaa_a = "IgNiAAS58OBjRwKmnKaq3UQ8/WLEG5uksgkkaX15dOdpGhJvuWr7PjTC/TvF9IMG" ascii
        $pem_ov_cs_g3c_aaa_b = "HyZdwqWENjRzI1EENrKPBPOGI2MGeYDiUD4CUy1lRiNacWWiWaHvSW90G1/e53hy" ascii

    condition:
        any of ($spki_*) or any of ($pem_*) or
        hash.sha256(0, filesize) == "9e39de2881273acc225a149c72ba3e0f51424963669ab633ee1dc7df5db067b4" or
        hash.sha256(0, filesize) == "a496e23ac0cab8155fc9b117b97eae368efcbb9041aec8804d5a308d2d01c2d8" or
        hash.sha256(0, filesize) == "4b2460a466f95fd40113bcdcca2ceb29b3b093921de45474da7df48874c630b1" or
        hash.sha256(0, filesize) == "84112972b8e59d14560ae7e7119654474aad119990cf3722bfc1e3b91615e1fd"
}
