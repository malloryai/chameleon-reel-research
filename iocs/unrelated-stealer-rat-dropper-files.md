# Six unrelated stealer, remote-control and dropper files from fake game-tool archives

Verdict: malicious.

## Indicators

### Malicious

| IOC | Type | Value | Context |
|---|---|---|---|
| Stealer | SHA-256 | 730b3baf63a97e313566bbdd026ebfcde96fa35c7f30b9d398ac08ece50540a0 | `NewLoader.exe`, .NET, `net.tcp` C2 |
| Stealer | SHA-256 | ee7d1349d4436bc6040aa448c6b0c7d297d3a9f6ce58ed90bced4d7b9e6dd483 | `UnlockAllTool.exe`, .NET, padded: 536,977,408 B, of which only the first 106,560 B are content and the rest is one 64-byte unit repeated |
| Stealer | SHA-256 (payload) | b9cd68685aff3e9e38f6c401f0d5a25f1c615bf48bcdf7f153e201011666a605 | `UnlockAllTool.exe` (SHA-256 of file ee7d1349d4436bc6040aa448c6b0c7d297d3a9f6ce58ed90bced4d7b9e6dd483) with the filler removed, 106,560 B |
| Stealer | SHA-256 | a893f6863c5e39a3397579d7b3ee7294f4bcba17a15a78db093927afb597391c | `Xeno.exe`, Go, with remote-control functions |
| Dropper | SHA-256 | bad56b6f841d48d8f84af2607176a12312b454956e492a79629f0540cd357844 | `Hack_Install.exe`; adds Defender exclusions |
| C2 | IP:port | 82.115.223.138:35316 | C2 address from the configuration of `NewLoader.exe` (SHA-256 of file 730b3baf63a97e313566bbdd026ebfcde96fa35c7f30b9d398ac08ece50540a0) |
| C2 | IP:port | 62.204.41.141:24758 | C2 address from the configuration of `UnlockAllTool.exe` (SHA-256 of file ee7d1349d4436bc6040aa448c6b0c7d297d3a9f6ce58ed90bced4d7b9e6dd483) |
| C2 | IPv4 | 144.31.12.162 | C2 address from the strings of the Go `Xeno.exe` (SHA-256 of file a893f6863c5e39a3397579d7b3ee7294f4bcba17a15a78db093927afb597391c) |
| Drop name | File name | `executavel_temporario.exe` | File name that `Hack_Install.exe` (SHA-256 of file bad56b6f841d48d8f84af2607176a12312b454956e492a79629f0540cd357844) gives to its embedded executable when it writes it to disk |
| Stealer | Imphash | 347f5c87243da517983cf28ef9192dbe | Import hash of `NewLoader.exe` (SHA-256 of file 730b3baf63a97e313566bbdd026ebfcde96fa35c7f30b9d398ac08ece50540a0) |
| Dropper | Imphash | bdcf6640dd39be2f9b3b5476d898a6dc | Import hash of `Hack_Install.exe` (SHA-256 of file bad56b6f841d48d8f84af2607176a12312b454956e492a79629f0540cd357844) |
| Archive | SHA-256 | 61903961e047efe55e476e0f2cc758324b6ca8569aecb6a8588e68a34c053f69 | `NewLoader.rar`; holds `NewLoader.exe` (SHA-256 of file 730b3baf63a97e313566bbdd026ebfcde96fa35c7f30b9d398ac08ece50540a0) |
| Download | URL | https://www.mediafire.com/file/eqftnii4luxz8at/NewLoader.rar/file | Served `NewLoader.rar` (SHA-256 of file 61903961e047efe55e476e0f2cc758324b6ca8569aecb6a8588e68a34c053f69), which holds `NewLoader.exe` (SHA-256 of file 730b3baf63a97e313566bbdd026ebfcde96fa35c7f30b9d398ac08ece50540a0) |
| Archive | SHA-256 | e8168ed82f65f4ac357a2ce7de0aa539a74d4f3ed07f3d8663231dc7b9e341d1 | `UnlockAllTool v3.zip`; holds `UnlockAllTool v3/UnlockAllTool.exe` (SHA-256 of file ee7d1349d4436bc6040aa448c6b0c7d297d3a9f6ce58ed90bced4d7b9e6dd483) |
| Download | URL | https://www.mediafire.com/file/vey7skj46dl2nu1/UnlockAllTool_v3.zip/file | Served `UnlockAllTool v3.zip` (SHA-256 of file e8168ed82f65f4ac357a2ce7de0aa539a74d4f3ed07f3d8663231dc7b9e341d1), which holds `UnlockAllTool v3/UnlockAllTool.exe` (SHA-256 of file ee7d1349d4436bc6040aa448c6b0c7d297d3a9f6ce58ed90bced4d7b9e6dd483) |
| Archive | SHA-256 | 29a76651483da178ab4e5bc355f5c0b35c2a58db12c4c3b70f6d88e2fba648d0 | `Hack.rar`; holds `Hack/Hack_Install.exe` (SHA-256 of file bad56b6f841d48d8f84af2607176a12312b454956e492a79629f0540cd357844) |
| Download | URL | https://www.mediafire.com/file/jnzpgas6s274qp4/Hack.rar/file | Served `Hack.rar` (SHA-256 of file 29a76651483da178ab4e5bc355f5c0b35c2a58db12c4c3b70f6d88e2fba648d0), which holds `Hack/Hack_Install.exe` (SHA-256 of file bad56b6f841d48d8f84af2607176a12312b454956e492a79629f0540cd357844) |
| Archive | SHA-256 | 942a8366624cbacb8a6164f438d54c628972aa1d6eb079dd19c97d7becc4a37e | `Xeno.rar`; holds `Xeno/Setup/Xeno.exe` (SHA-256 of file a893f6863c5e39a3397579d7b3ee7294f4bcba17a15a78db093927afb597391c) |
| Download | URL | https://www.mediafire.com/file/m5iq7q8czhaabx9/Xeno.rar/file | Served `Xeno.rar` (SHA-256 of file 942a8366624cbacb8a6164f438d54c628972aa1d6eb079dd19c97d7becc4a37e), which holds `Xeno/Setup/Xeno.exe` (SHA-256 of file a893f6863c5e39a3397579d7b3ee7294f4bcba17a15a78db093927afb597391c) |
| Archive | SHA-256 | 46eafb939395766e220e1c36f08336ae8aecab4a3d28b62ae1fff852e1d27bbf | `Xeno-v1.3.60.rar`; holds the loader `Xeno.dll` (SHA-256 of file d52f40f67256905d5f1ba20be94aba2048a50e4527f379783ca3b660da4a70c5) beside `Xeno-v1.3.60/Xeno-v1.3.60.exe` (SHA-256 of file 4a800b9da8b0bca037b8896a5b44bd3da41e4cb7184ef15da5c995c5c31b03ae) |
| Download | URL | https://www.mediafire.com/file/hibu3dh50bdr2tz/Xeno-v1.3.60.rar/file | Served `Xeno-v1.3.60.rar` (SHA-256 of file 46eafb939395766e220e1c36f08336ae8aecab4a3d28b62ae1fff852e1d27bbf), which holds the loader `Xeno.dll` (SHA-256 of file d52f40f67256905d5f1ba20be94aba2048a50e4527f379783ca3b660da4a70c5) beside `Xeno-v1.3.60/Xeno-v1.3.60.exe` (SHA-256 of file 4a800b9da8b0bca037b8896a5b44bd3da41e4cb7184ef15da5c995c5c31b03ae) |

### Suspicious

| IOC | Type | Value | Context |
|---|---|---|---|
| Defender-exclusion tool | SHA-256 | 4a800b9da8b0bca037b8896a5b44bd3da41e4cb7184ef15da5c995c5c31b03ae | `Xeno-v1.3.60.exe`; version information names `SmallDrop`; holds hidden PowerShell commands that add Defender exclusions |
| Remote-administration client | SHA-256 | 476b44206a0a4f380ae53096b40b978318e7f094c64c8d05cd8bb21ecd297fef | `Xeno.exe`, .NET; shipped as a game tool in `Xeno.zip` |
| Embedded executable | SHA-256 (payload) | c361b8c80cab4653bca725e691c2911f136c5ba29377a161785aa5a72f9b5e15 | Executable embedded in the dropper `Hack_Install.exe` (SHA-256 of file bad56b6f841d48d8f84af2607176a12312b454956e492a79629f0540cd357844), 2,628,608 B |
| Archive | SHA-256 | c757814317e5bea5b4f6954a16659caf022f480032688fdc37fb57d8844b307a | `Xeno.zip`; holds `Xeno.exe` (SHA-256 of file 476b44206a0a4f380ae53096b40b978318e7f094c64c8d05cd8bb21ecd297fef) |
| Download | URL | https://www.mediafire.com/file/n16rzjeuhw0nqu3/Xeno.zip/file | Served `Xeno.zip` (SHA-256 of file c757814317e5bea5b4f6954a16659caf022f480032688fdc37fb57d8844b307a), which holds `Xeno.exe` (SHA-256 of file 476b44206a0a4f380ae53096b40b978318e7f094c64c8d05cd8bb21ecd297fef) |
