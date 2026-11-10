# Packed .NET stealer that checks in to nine rotating .biz domains

Verdict: malicious.

## Indicators

### Malicious

| IOC | Type | Value | Context |
|---|---|---|---|
| Stealer | SHA-256 | 5d4d3e3d41f56344ec1f3bc62cda2aed6433cd73ab44b2d71cc8adaa2a1a42e1 | x86 .NET, 338,944 B, unsigned. Named `YuQu Loader.exe`, `Aura.exe`, `Vanta.exe`, `Installer.exe` and `New Upd v1.1.0.exe` |
| C2 | Domain | whisperusz.biz | Check-in `POST /api` with body `act=life` by `YuQu Loader.exe` (SHA-256 of file 5d4d3e3d41f56344ec1f3bc62cda2aed6433cd73ab44b2d71cc8adaa2a1a42e1); seen in DNS and HTTP |
| C2 | Domain | fraggielek.biz | Check-in `POST /api` with body `act=life` by `YuQu Loader.exe` (SHA-256 of file 5d4d3e3d41f56344ec1f3bc62cda2aed6433cd73ab44b2d71cc8adaa2a1a42e1); seen in DNS and HTTP |
| C2 | Domain | grandiouseziu.biz | Check-in `POST /api` with body `act=life` by `YuQu Loader.exe` (SHA-256 of file 5d4d3e3d41f56344ec1f3bc62cda2aed6433cd73ab44b2d71cc8adaa2a1a42e1); seen in DNS and HTTP |
| C2 | Domain | littlenotii.biz | Check-in `POST /api` with body `act=life` by `YuQu Loader.exe` (SHA-256 of file 5d4d3e3d41f56344ec1f3bc62cda2aed6433cd73ab44b2d71cc8adaa2a1a42e1); seen in DNS and HTTP |
| C2 | Domain | marketlumpe.biz | Check-in `POST /api` with body `act=life` by `YuQu Loader.exe` (SHA-256 of file 5d4d3e3d41f56344ec1f3bc62cda2aed6433cd73ab44b2d71cc8adaa2a1a42e1); seen in DNS and HTTP |
| C2 | Domain | nuttyshopr.biz | Check-in `POST /api` with body `act=life` by `YuQu Loader.exe` (SHA-256 of file 5d4d3e3d41f56344ec1f3bc62cda2aed6433cd73ab44b2d71cc8adaa2a1a42e1); seen in DNS and HTTP |
| C2 | Domain | punishzement.biz | Check-in `POST /api` with body `act=life` by `YuQu Loader.exe` (SHA-256 of file 5d4d3e3d41f56344ec1f3bc62cda2aed6433cd73ab44b2d71cc8adaa2a1a42e1); seen in DNS and HTTP |
| C2 | Domain | spookycappy.biz | Check-in `POST /api` with body `act=life` by `YuQu Loader.exe` (SHA-256 of file 5d4d3e3d41f56344ec1f3bc62cda2aed6433cd73ab44b2d71cc8adaa2a1a42e1); seen in DNS and HTTP |
| C2 | Domain | truculengisau.biz | Check-in `POST /api` with body `act=life` by `YuQu Loader.exe` (SHA-256 of file 5d4d3e3d41f56344ec1f3bc62cda2aed6433cd73ab44b2d71cc8adaa2a1a42e1); seen in DNS and HTTP |
| Archive | SHA-256 | 7bc59124c00d4e0c19fb147b57192e285d60dbb7ea567f05114f443494c49e55 | `[1.1.0]-Aрр-UNC-x64.rar` (the two letters after the A are Cyrillic р); holds a nested `Release.rar` (SHA-256 of file 03f459085e960062634f47a51295232c26a820f27dfb4a2601b6504081fe5774) with the executable as `New Upd v1.1.0.exe` (SHA-256 of file 5d4d3e3d41f56344ec1f3bc62cda2aed6433cd73ab44b2d71cc8adaa2a1a42e1) and a `README.docx.lnk` shortcut; uploaded to MediaFire 2025-01-09 |
| Download | URL | https://www.mediafire.com/file/1qqlviakp9t7t02/%255B1.1.0%255D-A%25D1%2580%25D1%2580-UNC-x64.rar/file | Served `[1.1.0]-Aрр-UNC-x64.rar` (the р is Cyrillic; SHA-256 of file 7bc59124c00d4e0c19fb147b57192e285d60dbb7ea567f05114f443494c49e55), which holds a nested `Release.rar` (SHA-256 of file 03f459085e960062634f47a51295232c26a820f27dfb4a2601b6504081fe5774) with the executable as `New Upd v1.1.0.exe` (SHA-256 of file 5d4d3e3d41f56344ec1f3bc62cda2aed6433cd73ab44b2d71cc8adaa2a1a42e1) |
| Archive | SHA-256 | 03f459085e960062634f47a51295232c26a820f27dfb4a2601b6504081fe5774 | `Release.rar`, nested in `[1.1.0]-Aрр-UNC-x64.rar` (the р is Cyrillic; SHA-256 of file 7bc59124c00d4e0c19fb147b57192e285d60dbb7ea567f05114f443494c49e55); 21,111,102 B; holds `New Upd v1.1.0.exe` (SHA-256 of file 5d4d3e3d41f56344ec1f3bc62cda2aed6433cd73ab44b2d71cc8adaa2a1a42e1), the shortcut `README.docx.lnk` (SHA-256 of file 482c59b6d09277533c5c9c8753725feb8de42b2816adb631371787d308e50233) and an application tree of 341 other files |
| Archive | SHA-256 | 684dffb2cde2009276b44580c9bbc9130e449c8311dc65a51741ef3a72a2c8e8 | `Aura.rar`; uploaded to MediaFire 2025-01-09; holds `Aura.exe` (SHA-256 of file 5d4d3e3d41f56344ec1f3bc62cda2aed6433cd73ab44b2d71cc8adaa2a1a42e1) |
| Download | URL | https://www.mediafire.com/file/gmrv8ia19ackcbi/Aura.rar/file | Served `Aura.rar` (SHA-256 of file 684dffb2cde2009276b44580c9bbc9130e449c8311dc65a51741ef3a72a2c8e8), which holds `Aura.exe` (SHA-256 of file 5d4d3e3d41f56344ec1f3bc62cda2aed6433cd73ab44b2d71cc8adaa2a1a42e1) |
| Archive | SHA-256 | ec3c4df1436e997a02aacfd914d1893f07634a05bdf6ef60e888b81030a3a7c4 | `Installer.rar`; uploaded to MediaFire 2025-01-09; holds `Installer.exe` (SHA-256 of file 5d4d3e3d41f56344ec1f3bc62cda2aed6433cd73ab44b2d71cc8adaa2a1a42e1) |
| Download | URL | https://www.mediafire.com/file/9wg40t44ysg3gdw/Installer.rar/file | Served `Installer.rar` (SHA-256 of file ec3c4df1436e997a02aacfd914d1893f07634a05bdf6ef60e888b81030a3a7c4), which holds `Installer.exe` (SHA-256 of file 5d4d3e3d41f56344ec1f3bc62cda2aed6433cd73ab44b2d71cc8adaa2a1a42e1) |
| Archive | SHA-256 | 7a0dbe8c1e51b71d8e236f056cdda1f886fff57016af58d62273d5c6cc01ee62 | `Vanta.rar`; uploaded to MediaFire 2025-01-09; holds `Vanta.exe` (SHA-256 of file 5d4d3e3d41f56344ec1f3bc62cda2aed6433cd73ab44b2d71cc8adaa2a1a42e1) |
| Download | URL | https://www.mediafire.com/file/nbjzgq5kqhijju9/Vanta.rar/file | Served `Vanta.rar` (SHA-256 of file 7a0dbe8c1e51b71d8e236f056cdda1f886fff57016af58d62273d5c6cc01ee62), which holds `Vanta.exe` (SHA-256 of file 5d4d3e3d41f56344ec1f3bc62cda2aed6433cd73ab44b2d71cc8adaa2a1a42e1) |
| Archive | SHA-256 | bd6ca5c44c83c3085a2b48387f04b9a6fc3c6369c962ad19126e49095bd56ac4 | `YuQu Loader.rar`; uploaded to MediaFire 2025-01-09; holds `YuQu Loader.exe` (SHA-256 of file 5d4d3e3d41f56344ec1f3bc62cda2aed6433cd73ab44b2d71cc8adaa2a1a42e1) |
| Download | URL | https://www.mediafire.com/file/wk9m4h13vbplqh7/YuQu_Loader.rar/file | Served `YuQu Loader.rar` (SHA-256 of file bd6ca5c44c83c3085a2b48387f04b9a6fc3c6369c962ad19126e49095bd56ac4), which holds `YuQu Loader.exe` (SHA-256 of file 5d4d3e3d41f56344ec1f3bc62cda2aed6433cd73ab44b2d71cc8adaa2a1a42e1) |
