# MinGW dropper that installs itself under Windows Update names and drops a Monero miner

Verdict: malicious.

## Indicators

### Malicious

| IOC | Type | Value | Context |
|---|---|---|---|
| Dropper | SHA-256 | a569daf3a51cdf24c87e798fbd135592ef255d7bf3535ace559d0968640170f5 | `Loader 2.exe`, MinGW build |
| Install path | File path | `%LOCALAPPDATA%\Microsoft\Windows\Update\Loader 2.exe` | Install path used by the dropper `Loader 2.exe` (SHA-256 of file a569daf3a51cdf24c87e798fbd135592ef255d7bf3535ace559d0968640170f5); seen at runtime |
| Install path | File path | `%LOCALAPPDATA%\Microsoft\Windows\Update\MicrosoftUpdateHealth.exe` | Install path used by the dropper `Loader 2.exe` (SHA-256 of file a569daf3a51cdf24c87e798fbd135592ef255d7bf3535ace559d0968640170f5); seen at runtime |
| Install path | File path | `%LOCALAPPDATA%\Microsoft\Windows\Update\MicrosoftUpdateWorker.exe` | Install path used by the dropper `Loader 2.exe` (SHA-256 of file a569daf3a51cdf24c87e798fbd135592ef255d7bf3535ace559d0968640170f5); seen at runtime |
| Install path | File path | `%LOCALAPPDATA%\Microsoft\Windows\Update\rt\WinInetCache\dd.exe` | Install path used by the dropper `Loader 2.exe` (SHA-256 of file a569daf3a51cdf24c87e798fbd135592ef255d7bf3535ace559d0968640170f5); at runtime `dd.exe` started from here 2.4 s after the dropper |
| Payload path | File path | `%LOCALAPPDATA%\Microsoft_Corporation\WmiPrvSE.exe` | Payload path used by the dropper `Loader 2.exe` (SHA-256 of file a569daf3a51cdf24c87e798fbd135592ef255d7bf3535ace559d0968640170f5); seen at runtime |
| Archive | SHA-256 | d8a90e33d503aa697793cc44908c569550070050d90b8811a8faf8946eecd3e9 | `MetaLab.zip`; holds `MetaLab/Loader 2.exe` (SHA-256 of file a569daf3a51cdf24c87e798fbd135592ef255d7bf3535ace559d0968640170f5) |
| Download | URL | https://www.mediafire.com/file/95gh0xphgzjpesh/MetaLab.zip/file | Served `MetaLab.zip` (SHA-256 of file d8a90e33d503aa697793cc44908c569550070050d90b8811a8faf8946eecd3e9), which holds `MetaLab/Loader 2.exe` (SHA-256 of file a569daf3a51cdf24c87e798fbd135592ef255d7bf3535ace559d0968640170f5) |
| Archive | SHA-256 | d9513cef1c0e38d97dd50d7fd7ef0290e9bee4ecf1eb8d664659d9a220a6cb43 | `Mod Menu v2.7.zip`; holds `Mod Menu v2.7/Loader 2.exe` (SHA-256 of file a569daf3a51cdf24c87e798fbd135592ef255d7bf3535ace559d0968640170f5) |
| Download | URL | https://www.mediafire.com/file/aqtf046r024qrqn/Mod_Menu_v2.7.zip/file | Served `Mod Menu v2.7.zip` (SHA-256 of file d9513cef1c0e38d97dd50d7fd7ef0290e9bee4ecf1eb8d664659d9a220a6cb43), which holds `Mod Menu v2.7/Loader 2.exe` (SHA-256 of file a569daf3a51cdf24c87e798fbd135592ef255d7bf3535ace559d0968640170f5) |
| Archive | SHA-256 | e0236d02a318e3ddd56e5dc481e22ab5459debbec9c6c78cedfe22554103b772 | `Mod Menu v2.7.zip`; holds `Mod Menu v2.7/Loader 2.exe` (SHA-256 of file a569daf3a51cdf24c87e798fbd135592ef255d7bf3535ace559d0968640170f5) |
| Download | URL | https://www.mediafire.com/file/owtp3ye6h9veo3t/Mod%20Menu%20v2.7.zip/file | Served `Mod Menu v2.7.zip` (SHA-256 of file e0236d02a318e3ddd56e5dc481e22ab5459debbec9c6c78cedfe22554103b772), which holds `Mod Menu v2.7/Loader 2.exe` (SHA-256 of file a569daf3a51cdf24c87e798fbd135592ef255d7bf3535ace559d0968640170f5) |
| Archive | SHA-256 | f2ab09fc4791131b51a649c2e404174597b501cb1a19a4e6a4338100c434709a | `PlaySoft.zip`; holds `Playsoft/Loader 2.exe` (SHA-256 of file a569daf3a51cdf24c87e798fbd135592ef255d7bf3535ace559d0968640170f5) |
| Download | URL | https://www.mediafire.com/file/u1jn9is55ju5dvb/PlaySoft.zip/file | Served `PlaySoft.zip` (SHA-256 of file f2ab09fc4791131b51a649c2e404174597b501cb1a19a4e6a4338100c434709a), which holds `Playsoft/Loader 2.exe` (SHA-256 of file a569daf3a51cdf24c87e798fbd135592ef255d7bf3535ace559d0968640170f5) |

### Suspicious

| IOC | Type | Value | Context |
|---|---|---|---|
| Dropped executable | SHA-256 (payload) | 62dff0cf5917b57524122f8d040041857e7bd9a66bf9a1c49e69245281c529cd | Dropped by the dropper `Loader 2.exe` (SHA-256 of file a569daf3a51cdf24c87e798fbd135592ef255d7bf3535ace559d0968640170f5); 3,595,264 B; written as `%TEMP%\msdtc.exe` and `WmiPrvSE.exe`, started by `dd.exe`, starts PowerShell; at runtime the infection resolved a public Monero mining pool |
