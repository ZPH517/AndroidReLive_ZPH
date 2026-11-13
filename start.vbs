Set oShell = CreateObject("WScript.Shell")
oShell.Run "cmd /c node launcher.mjs > launcher.log 2>&1", 0, False
