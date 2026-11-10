# Native loader in a game mod-menu archive that runs an embedded .NET infostealer through AppLaunch.exe

Verdict: malicious.

## Indicators

### Malicious

| IOC | Type | Value | Context |
|---|---|---|---|
| Loader | SHA-256 | 8f9acbc5265493889f6d641e405891e9cf5ddaf7f96aa86ceffe474eae8195c0 | `websockets.dll` with the embedded stealer, 250,368 B |
| Archive | SHA-256 | 6d8244c170735a5a00d3bb3e542decdfdac4f269203f057cfa43f5bf8e2c0129 | `modest-menu_v0.9.7.zip`; 21,466,553 B, created 2023-01-04, video-stated password `modest`; holds `modest-menu_v0.9.7/websockets.dll` (SHA-256 of file 8f9acbc5265493889f6d641e405891e9cf5ddaf7f96aa86ceffe474eae8195c0) |
| Download | URL | https://www.mediafire.com/file/mp0op1ka2a7vs8v/modest-menu_v0.9.7.zip/file | Served `modest-menu_v0.9.7.zip` (SHA-256 of file 6d8244c170735a5a00d3bb3e542decdfdac4f269203f057cfa43f5bf8e2c0129), which holds `modest-menu_v0.9.7/websockets.dll` (SHA-256 of file 8f9acbc5265493889f6d641e405891e9cf5ddaf7f96aa86ceffe474eae8195c0) |
| C2 | IP:port | 82.115.223.45:81 | Stealer C2 decoded from the configuration of the .NET stealer embedded in `websockets.dll` (SHA-256 of file 8f9acbc5265493889f6d641e405891e9cf5ddaf7f96aa86ceffe474eae8195c0); decoded statically (Base64, XOR with a fixed key, Base64) |

### Suspicious

| IOC | Type | Value | Context |
|---|---|---|---|
| Loader | SHA-256 | d0ba3b68be583e4dc99d690c6183eb05de9b724d26134055c5a8cda3fe76b12e | `Launcher.exe`, 215,672 B; copied ESET signature, fake bank version info, shares an MSVC 9.0 build, the `AppLaunch.exe` path string, a large data section and a function-similarity cluster with `websockets.dll` (SHA-256 of file 8f9acbc5265493889f6d641e405891e9cf5ddaf7f96aa86ceffe474eae8195c0) |
| Loader | SHA-256 | 1a2a1bb7b9e81ea6444440482440414812789ae5089358f7edb06459791dc11e | `activate.exe`, 184,952 B; copied ESET signature, fake bank version info, shares an MSVC 9.0 build, the `AppLaunch.exe` path string, a large data section and a function-similarity cluster with `websockets.dll` (SHA-256 of file 8f9acbc5265493889f6d641e405891e9cf5ddaf7f96aa86ceffe474eae8195c0) |
| Loader | SHA-256 | 446b8b9f390aad1fb5ce6ce100402076c74fbc08d5891f29765f3aaff757cf5e | `Universal Loader.exe`, 268,920 B; copied ESET signature, fake bank version info, shares an MSVC 9.0 build, the `AppLaunch.exe` path string, a large data section and a function-similarity cluster with `websockets.dll` (SHA-256 of file 8f9acbc5265493889f6d641e405891e9cf5ddaf7f96aa86ceffe474eae8195c0) |
| Archive | SHA-256 | 3442066c7cbd4a20f08f912a15ade0f6e58fd4735b05a389d749595fb61a8080 | `Launcher.rar`; 2,093,566 B, created 2023-06-15, video-stated password `2023`; holds `Launcher.exe` (SHA-256 of file d0ba3b68be583e4dc99d690c6183eb05de9b724d26134055c5a8cda3fe76b12e) and `activate/activate.exe` (SHA-256 of file 1a2a1bb7b9e81ea6444440482440414812789ae5089358f7edb06459791dc11e) |
| Download | URL | https://www.mediafire.com/file/kjysst9gmrhx836/Launcher.rar/file | Served `Launcher.rar` (SHA-256 of file 3442066c7cbd4a20f08f912a15ade0f6e58fd4735b05a389d749595fb61a8080), which holds `Launcher.exe` (SHA-256 of file d0ba3b68be583e4dc99d690c6183eb05de9b724d26134055c5a8cda3fe76b12e) and `activate/activate.exe` (SHA-256 of file 1a2a1bb7b9e81ea6444440482440414812789ae5089358f7edb06459791dc11e) |
| Archive | SHA-256 | dccab2cd53fd507fa80061bf9fc609ca15a377e9573e3638cfb345d6be083d4c | `Universal Loader.rar`, 12,817,694 B; holds `Universal Loader/Universal Loader.exe` (SHA-256 of file 446b8b9f390aad1fb5ce6ce100402076c74fbc08d5891f29765f3aaff757cf5e) |
| Download | URL | https://mega.nz/folder/1S8Bnb5T#2uwi1R-tpS-_xSsR1JBL7w | MEGA folder link; the part after `#` is the folder key, which browsers do not send to the server. The folder serves `Universal Loader.rar` (SHA-256 of file dccab2cd53fd507fa80061bf9fc609ca15a377e9573e3638cfb345d6be083d4c), which holds `Universal Loader/Universal Loader.exe` (SHA-256 of file 446b8b9f390aad1fb5ce6ce100402076c74fbc08d5891f29765f3aaff757cf5e) |
