' --- ACHILLES-PROMPTFLUX stage3 startup payload (benign) ---
' Persistence body for the Startup folder drop. Different variable
' naming scheme again from stages 1 and 2 — simulates yet another
' Gemini rewrite variant. Execution is NOT triggered by the test;
' this file only fires at the next user logon. The orchestrator
' cleans it up on every exit path before that can happen.

Dim qW5X, qY2Z, qA8B, qE3F
Dim pR1S, pT4U, pV6W
Dim fso, h

qW5X = Chr(65) & Chr(67) & Chr(72) & Chr(73) & Chr(76) & Chr(76) & Chr(69) & Chr(83)
qY2Z = Chr(45) & Chr(80) & Chr(82) & Chr(79) & Chr(77) & Chr(80) & Chr(84) & Chr(70) & Chr(76) & Chr(85) & Chr(88)
qA8B = Chr(45) & Chr(83) & Chr(84) & Chr(65) & Chr(71) & Chr(69) & Chr(51)
qE3F = Chr(45) & Chr(83) & Chr(84) & Chr(65) & Chr(82) & Chr(84) & Chr(85) & Chr(80)

pR1S = qW5X & Chr(45) & qY2Z & Chr(32) & qA8B & Chr(32) & qE3F

pT4U = Chr(99) & Chr(58) & Chr(92) & Chr(70) & Chr(48) & Chr(92)
pV6W = pT4U & Chr(112) & Chr(114) & Chr(111) & Chr(109) & Chr(112) & Chr(116) & Chr(102) & Chr(108) & Chr(117) & Chr(120) & Chr(95) & Chr(115) & Chr(116) & Chr(97) & Chr(103) & Chr(101) & Chr(51) & Chr(95) & Chr(115) & Chr(116) & Chr(97) & Chr(114) & Chr(116) & Chr(117) & Chr(112) & Chr(46) & Chr(116) & Chr(120) & Chr(116)

Set fso = CreateObject("Scripting.FileSystemObject")
If Not fso.FolderExists(pT4U) Then
    On Error Resume Next
    fso.CreateFolder(pT4U)
    On Error GoTo 0
End If

Set h = fso.CreateTextFile(pV6W, True)
h.WriteLine pR1S & Chr(32) & Chr(64) & Chr(32) & Now()
h.Close

WScript.Echo pR1S
