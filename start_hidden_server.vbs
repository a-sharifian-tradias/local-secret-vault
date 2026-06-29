Set shell = CreateObject("WScript.Shell")

pythonExe = WScript.Arguments.Item(0)
vaultPy = WScript.Arguments.Item(1)

cmd = """" & pythonExe & """ """ & vaultPy & """ _serve"

shell.Run cmd, 0, False
