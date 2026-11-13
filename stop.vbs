Set oWMI = GetObject("winmgmts:")
Set col = oWMI.ExecQuery("SELECT * FROM Win32_Process WHERE Name='node.exe'")
For Each p In col
  If InStr(p.CommandLine, "launcher.mjs") > 0 Or InStr(p.CommandLine, "server.cjs") > 0 Or InStr(p.CommandLine, "bridge.mjs") > 0 Then
    p.Terminate
  End If
Next
WScript.Echo "Stopped AndroidReLive processes."
