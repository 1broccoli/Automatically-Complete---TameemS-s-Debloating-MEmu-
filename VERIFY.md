Post-setup verification steps

1) Hosts and firewall
- Open C:\\Windows\\System32\\drivers\\etc\\hosts and confirm the blocklist entries are appended under `# Added by setup-memu.ps1`.
- In Windows Defender Firewall > Advanced Settings > Outbound/Inbound Rules, confirm `memu_ip_to_fw_rule` exists and lists IPs from `memu_block.txt`.

2) Per-VM checks (repeat for each VM you use)
- Ensure the instance boots to Android.
- Open the app list and verify "Launcher Hijack" is installed.
- Settings > Accessibility: confirm "To detect home button press" (Launcher Hijack) is ON.
- Press Home and pick your preferred launcher in Launcher Hijack.

3) Optional guest debloat
- If the MEmu stock Guide/Launcher/Installer are still present and root is enabled, re-run `setup-memu.ps1` as Admin. Some systems need a second pass after root toggle and reboot.

4) Optional apps
- Any additional APKs placed in your Downloads folder under `MEmu Download` should be installed; check in the app drawer.
- If you provided `memu_block.txt`, the firewall rule `memu_ip_to_fw_rule` should exist (script looks in this folder and the parent workspace).
