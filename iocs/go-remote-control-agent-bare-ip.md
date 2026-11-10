# Obfuscated Go remote-control agent with an appended bare-IP config and an embedded FFmpeg

Verdict: malicious.

## Indicators

Enrollment secret and client ID: withheld.

### Malicious

| IOC | Type | Value | Context |
|---|---|---|---|
| Remote-control agent | SHA-256 | cec2f9b0cae40d20521fa68c5d2b1f821870685d126da3347085b38cec835306 | `Inspiron_Launcher.exe`, obfuscated Go, 67,464,704 B, config block appended |
| C2 | IP:port | 102.208.217.10:8443 | HTTPS C2 address; from the config block appended to `Inspiron_Launcher.exe` (SHA-256 of file cec2f9b0cae40d20521fa68c5d2b1f821870685d126da3347085b38cec835306) |
| Archive | SHA-256 | b6ba19f0a6a8df8c134f742b16923e8c186238281e5a3998e5e3f440f333f4fb | `Inspiron_Executor.zip`; holds `Inspiron_Executor/Inspiron_Launcher.exe` (SHA-256 of file cec2f9b0cae40d20521fa68c5d2b1f821870685d126da3347085b38cec835306) |
| Download | URL | https://www.mediafire.com/file/pmhm0dogwnaibux/Inspiron_Executor.zip/file | Served `Inspiron_Executor.zip` (SHA-256 of file b6ba19f0a6a8df8c134f742b16923e8c186238281e5a3998e5e3f440f333f4fb), which holds `Inspiron_Executor/Inspiron_Launcher.exe` (SHA-256 of file cec2f9b0cae40d20521fa68c5d2b1f821870685d126da3347085b38cec835306) |
