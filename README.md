# MEmu Debloat & LauncherHijack Automation

![language](https://img.shields.io/badge/PowerShell-5%2B-5391FE?logo=powershell)
![os](https://img.shields.io/badge/OS-Windows-0078D6?logo=windows)
![status](https://img.shields.io/badge/status-beta-orange)
![version](https://img.shields.io/badge/version-v0.1.0-blue)

Automation helpers to debloat MEmu and set up LauncherHijack across all instances. This is an extension tool inspired by and built to automate steps from [TameemS’s debloat guide](https://gist.github.com/TameemS/603686cec857ff1f91e68607e374b0d8).

## Features
- Installs LauncherHijack APK to all instances
- Enables its accessibility service (merges with existing services; non-destructive)
- Debloats/limits MEmu stock apps (file removals when root allows; otherwise `pm disable-user`)
- Applies Windows hosts entries and Firewall IP blocks (from `memu_block.txt`)
- Installs your extra APKs from `Downloads\MEmu Download`

## Prerequisites
- Run PowerShell as Administrator.
- MEmu must be installed (memuc.exe discoverable under Program Files or on PATH).
- Internet access for auto-downloading LauncherHijack, or provide the APK locally.

## Quick start
1. Open an elevated PowerShell in this folder.
2. Run `setup-memu.ps1`.

Defaults
- Prefers `LauncherHijack-master\app\app-release.apk` if present; otherwise looks in `Downloads\MEmu Download`, else auto-downloads from GitHub.
- Extra APKs: place under your `Downloads\MEmu Download` folder (e.g., `C:\Users\<You>\Downloads\MEmu Download`).
[https://github.com/BaronKiko/LauncherHijack/tree/master](https://github.com/BaronKiko/LauncherHijack/releases)

## Shipping only this folder
- This `automation/` folder is sufficient to run on another machine if MEmu is installed.
- Firewall blocks: put `memu_block.txt` next to `setup-memu.ps1` (script also checks the parent workspace). You can start with `memu_block.example.txt` and rename it.
- Offline usage: include a LauncherHijack APK here or in `Downloads\MEmu Download`.

## Notes
- VMs are started and ADB waits are handled automatically.
- If the Windows hosts file is locked, a one-time startup task applies changes and triggers a reboot.
- Some builds keep `/system` read-only; the script falls back to disabling Microvirt packages instead of deleting files.

## Verify
See `VERIFY.md` for a quick checklist (accessibility enabled, APKs installed, hosts marker present, firewall rule created).

## Reference & Credits
- Debloating guide and original block lists: https://gist.github.com/TameemS/603686cec857ff1f91e68607e374b0d8
- LauncherHijack project and HELP: https://github.com/BaronKiko/LauncherHijack

Example of Powershell script:
<img width="1123" height="888" alt="image" src="https://github.com/user-attachments/assets/c5ef88ec-a5af-46f6-b91b-0f74af2603b1" />


## License
Add a license for your repository (e.g., MIT). If omitted, GitHub will show the project as unlicensed.


