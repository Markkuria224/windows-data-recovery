$WshShell = New-Object -ComObject WScript.Shell
$desktop = [Environment]::GetFolderPath('Desktop')
$lnk = $WshShell.CreateShortcut((Join-Path $desktop 'Windows Data Recovery.lnk'))
$lnk.TargetPath = Join-Path $PSScriptRoot 'run_gui.bat'
$lnk.WorkingDirectory = $PSScriptRoot
$lnk.WindowStyle = 1
$lnk.Save()
Write-Output "Created shortcut on Desktop: $($lnk.TargetPath)"
