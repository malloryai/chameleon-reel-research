# pkg-built Node.js dropper that adds Defender exclusions and XOR-decrypts an embedded x64 PE

Verdict: malicious.

## Indicators

### Malicious

| IOC | Type | Value | Context |
|---|---|---|---|
| Dropper | SHA-256 | 9628817b075509d0b3130ae201a855e6696020c1f8e102c4f56d330a42a38d4a | `Main.exe` in `XenoExecutor.rar` (SHA-256 of file 434f71a15882324249e410fe318d44f27c9715cb66e0f2bc14010fad11466e91), 116,966,143 B; carries a base64 PowerShell command that adds `$env:TEMP`, `C:\ProgramData`, `C:\ProgramData\Windows\Microsoft` and `C:\ProgramData\Microsoft\Windows` to Defender exclusions; `C:\ProgramData\Windows\Microsoft` is a folder Windows does not create |
| Dropper | SHA-256 | c347367b15699c7cb5ca9b5ff3fdd8bf5a799ad5159649252f464e70980eed0e | `MurderMystery.exe` in `MurderMysteryScript.rar` (SHA-256 of file 2ababff793be99a010fc5427c192fa963c85503cd8e4a116c583717555d0b4e7), 116,960,692 B; carries a base64 PowerShell command that adds `$env:TEMP`, `C:\ProgramData`, `C:\ProgramData\Windows\Microsoft` and `C:\ProgramData\Microsoft\Windows` to Defender exclusions; `C:\ProgramData\Windows\Microsoft` is a folder Windows does not create |
| Embedded PE | SHA-256 (payload) | e15f26965b0010219dc9fbffca5230b8a6a36f493d43af4d122000d46b1d5f50 | Decrypted from `Main.exe` (SHA-256 of file 9628817b075509d0b3130ae201a855e6696020c1f8e102c4f56d330a42a38d4a), 527,872 B |
| Embedded PE | SHA-256 (payload) | 11716de186bfa0d570804bdb0344cc71f964d464776320d78221013a58507a8c | Decrypted from `MurderMystery.exe` (SHA-256 of file c347367b15699c7cb5ca9b5ff3fdd8bf5a799ad5159649252f464e70980eed0e), 523,776 B |
| Archive | SHA-256 | 434f71a15882324249e410fe318d44f27c9715cb66e0f2bc14010fad11466e91 | `XenoExecutor.rar`; holds `Main.exe` (SHA-256 of file 9628817b075509d0b3130ae201a855e6696020c1f8e102c4f56d330a42a38d4a) |
| Download | URL | https://www.mediafire.com/file/jpv4k082aei82qf/XenoExecutor.rar/file | Served `XenoExecutor.rar` (SHA-256 of file 434f71a15882324249e410fe318d44f27c9715cb66e0f2bc14010fad11466e91), which holds `Main.exe` (SHA-256 of file 9628817b075509d0b3130ae201a855e6696020c1f8e102c4f56d330a42a38d4a) |
| Archive | SHA-256 | 2ababff793be99a010fc5427c192fa963c85503cd8e4a116c583717555d0b4e7 | `MurderMysteryScript.rar`; holds `MurderMystery.exe` (SHA-256 of file c347367b15699c7cb5ca9b5ff3fdd8bf5a799ad5159649252f464e70980eed0e) |
| Download | URL | https://www.mediafire.com/file/srjuvgb4bls6hhi/MurderMysteryScript.rar/file | Served `MurderMysteryScript.rar` (SHA-256 of file 2ababff793be99a010fc5427c192fa963c85503cd8e4a116c583717555d0b4e7), which holds `MurderMystery.exe` (SHA-256 of file c347367b15699c7cb5ca9b5ff3fdd8bf5a799ad5159649252f464e70980eed0e) |
