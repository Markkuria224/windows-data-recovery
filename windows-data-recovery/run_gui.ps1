# PowerShell launcher for the Recovery GUI
$script = Join-Path -Path $PSScriptRoot -ChildPath 'recovery_gui.py'
python $script
Read-Host -Prompt 'Press Enter to close'
