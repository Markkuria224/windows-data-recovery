# Windows Data Recovery MVP

This is a Windows-focused data recovery MVP for removable drives, HDDs, SSDs, and disk images.

The first version is intentionally safe and narrow:

- opens the source in read-only mode
- scans raw bytes for known file signatures
- estimates a recovery confidence percentage
- writes recovered files to a different output folder
- supports physical/logical Windows devices such as `\\.\E:` and ordinary image files

## Important limits

No software can guarantee recovery after data is overwritten. SSD recovery is especially limited because Windows and the SSD firmware may use TRIM, which can erase deleted blocks internally. If TRIM has already cleared the blocks, software cannot reconstruct the original content.

This MVP is best for:

- accidentally deleted files on USB drives, SD cards, and HDDs
- formatted FAT/exFAT/NTFS volumes where file content is still present
- disk images made from failing media

It is not a replacement for a hardware recovery lab when a drive is physically failing.

## Requirements

- Windows
- Python 3.11+ for the runnable MVP in `recovery_mvp.py`
- .NET 8 SDK or newer only if you want to build the C# native-app starting point
- Administrator terminal for scanning live drives

This workspace currently includes a runnable Python version because the local machine does not have `dotnet` on PATH.

## Build

```powershell
cd windows-data-recovery
python recovery_mvp.py --help
```

## List Drives

```powershell
python recovery_mvp.py list
```

## Scan a Drive

Run PowerShell as Administrator, then:

```powershell
python recovery_mvp.py scan --source "\\.\E:" --output "D:\Recovered"
```

Never save recovered files to the same drive being scanned.

## Scan a Disk Image

```powershell
python recovery_mvp.py scan --source "C:\images\usb.img" --output "D:\Recovered"
```

## Supported carving signatures

- JPEG
- PNG
- PDF
- ZIP-based Office documents: DOCX, XLSX, PPTX are recovered as ZIP containers in this MVP
- GIF

Future versions should add NTFS/FAT/exFAT metadata parsing, previews, a Windows GUI, and richer file validation.

## GUI (Desktop mode)

A lightweight Tkinter GUI wrapper is included as `recovery_gui.py` to make the tool feel like a desktop app.

- To run (recommended): open PowerShell and run:

```powershell
cd windows-data-recovery
python recovery_gui.py
```

- Quick launchers are provided:

	- `run_gui.bat` — double-click to launch the GUI with the default Python on PATH.
	- `run_gui.ps1` — PowerShell script to launch the GUI.

- Notes:
	- Scanning live devices such as `\\.\E:` requires Administrator privileges.
	- The GUI calls the same `scan_source(...)` logic, so behavior and safety checks are unchanged.
