# Python infostealer with Discord webhook exfiltration, Defender tampering and Startup persistence

Verdict: malicious.

## Indicators

### Malicious

| IOC | Type | Value | Context |
|---|---|---|---|
| Stealer | SHA-256 | e3c111174131c3ae127a168cac676ac5aee7f7d2adb81e8b46e256f4d59dd4c4 | PyInstaller `Xeno.exe`, Python 3.13, 72,759,992 B, unsigned; deletes itself with `%TEMP%\cleanup.bat` |
| Exfiltration | Discord webhook ID | 1527991852199055450 | API path `/api/webhooks/1527991852199055450/` used by the stealer `Xeno.exe` (SHA-256 of file e3c111174131c3ae127a168cac676ac5aee7f7d2adb81e8b46e256f4d59dd4c4) to send stolen data; the token is withheld |
| Crash log | File path | `%USERPROFILE%\Desktop\INE_CRASH.txt` | Start and crash log of the stealer `Xeno.exe` (SHA-256 of file e3c111174131c3ae127a168cac676ac5aee7f7d2adb81e8b46e256f4d59dd4c4) |
| Status file | File name | `defender_disabled.txt` | File name created by the stealer `Xeno.exe` (SHA-256 of file e3c111174131c3ae127a168cac676ac5aee7f7d2adb81e8b46e256f4d59dd4c4) |
| Status file | File name | `exclusion_added.txt` | File name created by the stealer `Xeno.exe` (SHA-256 of file e3c111174131c3ae127a168cac676ac5aee7f7d2adb81e8b46e256f4d59dd4c4) |
| Status file | File name | `harvest_full.zip` | File name created by the stealer `Xeno.exe` (SHA-256 of file e3c111174131c3ae127a168cac676ac5aee7f7d2adb81e8b46e256f4d59dd4c4) |
| Persistence | File name | `WindowsUpdate.exe` | Name of the copy of the stealer `Xeno.exe` (SHA-256 of file e3c111174131c3ae127a168cac676ac5aee7f7d2adb81e8b46e256f4d59dd4c4) that it places in the Startup folder |
| Archive | SHA-256 | de13381c11bf97a2360b82f6b4f6315f19bac5b1e7fe83e3b425404ffbfaa078 | `Xeno-v1.3.55.zip`; password `xeno`; holds `Xeno-v1.3.55/Xeno.exe` (SHA-256 of file e3c111174131c3ae127a168cac676ac5aee7f7d2adb81e8b46e256f4d59dd4c4) |
| Download | URL | https://www.mediafire.com/file/o6fcjf35xyng22b/Xeno-v1.3.55.zip/file | Served `Xeno-v1.3.55.zip` (SHA-256 of file de13381c11bf97a2360b82f6b4f6315f19bac5b1e7fe83e3b425404ffbfaa078), which holds `Xeno-v1.3.55/Xeno.exe` (SHA-256 of file e3c111174131c3ae127a168cac676ac5aee7f7d2adb81e8b46e256f4d59dd4c4) |
