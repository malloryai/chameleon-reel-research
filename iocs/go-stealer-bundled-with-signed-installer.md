# Go stealer with remote-access functions, bundled with a signed Xeno installer or a PySide6 decoy

Verdict: malicious.

## Indicators

### Malicious

| IOC | Type | Value | Context |
|---|---|---|---|
| Self-extractor | SHA-256 | 2f5104673cf0c09a0e14230c833033e12fa16227815e4ded89a68e733421fc9a | WinRAR SFX `Xeno-v1.3.55.exe`, 92,617,193 B; its SFX script runs the Go stealer `Xeno_1.3.55.exe` (SHA-256 of file dc30d128fe84cf7b01fb2c3d37e2e9f18f6a4214783192132864d5af7d382fdd) silently from `%TEMP%` beside the genuine signed Xeno 1.3.55 installer it also unpacks, also named `Xeno-v1.3.55.exe` |
| Stealer | SHA-256 | dc30d128fe84cf7b01fb2c3d37e2e9f18f6a4214783192132864d5af7d382fdd | `Xeno_1.3.55.exe`, Go 1.24.0, x86, UPX-packed, 3,591,680 B; launched from `%TEMP%\Xeno_1.3.55.exe` by the script of the WinRAR SFX `Xeno-v1.3.55.exe` (SHA-256 of file 2f5104673cf0c09a0e14230c833033e12fa16227815e4ded89a68e733421fc9a) beside the Xeno installer |
| Launcher | SHA-256 | a9a7a850015e67c65456dc004ab3fd1910e2c65d005708eb5a0786adafa851b3 | PyInstaller `ApexLoader.exe`, 57,792,700 B; its embedded Python bytecode copies `Loader.exe` (SHA-256 of file f25f5710e87b7f13b2e40a239faa1c0d3dc27b16d7e1d82c3a112a5a0cf0064a) and the GUI `Loader_2.0.exe` to `%TEMP%\LauncherPayload\`, starts `Loader.exe` without a window and shows the GUI |
| Stealer | SHA-256 | f25f5710e87b7f13b2e40a239faa1c0d3dc27b16d7e1d82c3a112a5a0cf0064a | `Loader.exe`, Go 1.22.0, x86, UPX-packed, 3,296,256 B; embedded in PyInstaller `ApexLoader.exe` (SHA-256 of file a9a7a850015e67c65456dc004ab3fd1910e2c65d005708eb5a0786adafa851b3), which copies it to `%TEMP%\LauncherPayload\` and starts it hidden |
| Archive | SHA-256 | 4e0953f59ef59340a33a40680e508d72cb171b8e7b2953bb1776f21eb0cde29a | `Xeno-v1.3.55.zip`; 92,422,106 B, no password; holds `Xeno-v1.3.55.exe` (SHA-256 of file 2f5104673cf0c09a0e14230c833033e12fa16227815e4ded89a68e733421fc9a) |
| Download | URL | https://www.mediafire.com/file/5vr8yjrww6tqakr/Xeno-v1.3.55.zip/file | Served `Xeno-v1.3.55.zip` (SHA-256 of file 4e0953f59ef59340a33a40680e508d72cb171b8e7b2953bb1776f21eb0cde29a), which holds `Xeno-v1.3.55.exe` (SHA-256 of file 2f5104673cf0c09a0e14230c833033e12fa16227815e4ded89a68e733421fc9a) |
| Archive | SHA-256 | cd418d02d5ea34932f2eec9914349850c1213073879ba0c517fa702895cc9b1d | `Apex.zip`; 62,759,166 B, password `apex`; holds `Apex/ApexLoader.exe` (SHA-256 of file a9a7a850015e67c65456dc004ab3fd1910e2c65d005708eb5a0786adafa851b3) |
| Download | URL | https://www.mediafire.com/file/i64tkgb7xbhf8qz/Apex.zip/file | Served `Apex.zip` (SHA-256 of file cd418d02d5ea34932f2eec9914349850c1213073879ba0c517fa702895cc9b1d), which holds `Apex/ApexLoader.exe` (SHA-256 of file a9a7a850015e67c65456dc004ab3fd1910e2c65d005708eb5a0786adafa851b3) |
