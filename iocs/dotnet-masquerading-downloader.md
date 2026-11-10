# Protected .NET downloader with Microsoft ODBC version info that loads a library from builder.pp.ru

Verdict: malicious.

## Indicators

### Malicious

| IOC | Type | Value | Context |
|---|---|---|---|
| Downloader | SHA-256 | b43495fa346b0471a27cbb6fc8d7b2677bd0ae4c20182611fe7a1280734789e3 | `Installer.exe` (`dd11.exe`), .NET x86, 44,544 B |
| Library host | Domain | builder.pp.ru | Resolved by DNS and connected to on TCP 443 at runtime by `Installer.exe` (SHA-256 of file b43495fa346b0471a27cbb6fc8d7b2677bd0ae4c20182611fe7a1280734789e3); this host name only, not its parent domain |
| Archive | SHA-256 | df6826b55fe489fc685ece9aae0072e31fe0a97be8724c16a74c751bb8132a9e | `Installer2.zip`; password `Sedones00`; holds `Installer.exe` (SHA-256 of file b43495fa346b0471a27cbb6fc8d7b2677bd0ae4c20182611fe7a1280734789e3) |
| Download | URL | https://www.mediafire.com/file/oi7jbuwrc6cgg3d/Installer2.zip/file | Served `Installer2.zip` (SHA-256 of file df6826b55fe489fc685ece9aae0072e31fe0a97be8724c16a74c751bb8132a9e), which holds `Installer.exe` (SHA-256 of file b43495fa346b0471a27cbb6fc8d7b2677bd0ae4c20182611fe7a1280734789e3) |
| Archive | SHA-256 | bda4bde84bce17cde95f096e9a894ad11fb71678abdaad07c42fd8f4b151e393 | `Installer.zip`; password `Sedones00`; holds `Installer.exe` (SHA-256 of file b43495fa346b0471a27cbb6fc8d7b2677bd0ae4c20182611fe7a1280734789e3) |
| Download | URL | https://www.mediafire.com/file/v8qtansx95w1mse/Installer.zip/file | Served `Installer.zip` (SHA-256 of file bda4bde84bce17cde95f096e9a894ad11fb71678abdaad07c42fd8f4b151e393), which holds `Installer.exe` (SHA-256 of file b43495fa346b0471a27cbb6fc8d7b2677bd0ae4c20182611fe7a1280734789e3) |
| Archive | SHA-256 | 630b5339d97d3956dbced2a80fce33bbbd980129e11c75916f76eecbd449a3f6 | `Installer4.zip`; password `Sedones00`; holds `Installer.exe` (SHA-256 of file b43495fa346b0471a27cbb6fc8d7b2677bd0ae4c20182611fe7a1280734789e3) |
| Download | URL | https://www.mediafire.com/file/dfky1h8k05187z7/Installer4.zip/file | Served `Installer4.zip` (SHA-256 of file 630b5339d97d3956dbced2a80fce33bbbd980129e11c75916f76eecbd449a3f6), which holds `Installer.exe` (SHA-256 of file b43495fa346b0471a27cbb6fc8d7b2677bd0ae4c20182611fe7a1280734789e3) |
| Archive | SHA-256 | 44f31d7d7e2f0fbdda965d882b06bfc1e8a02ea31f895b7d6a45113052543b31 | `Installer5.zip`; password `Sedones00`; holds `Installer.exe` (SHA-256 of file b43495fa346b0471a27cbb6fc8d7b2677bd0ae4c20182611fe7a1280734789e3) |
| Download | URL | https://www.mediafire.com/file/mfga1bi1o0ffwm5/Installer5.zip/file | Served `Installer5.zip` (SHA-256 of file 44f31d7d7e2f0fbdda965d882b06bfc1e8a02ea31f895b7d6a45113052543b31), which holds `Installer.exe` (SHA-256 of file b43495fa346b0471a27cbb6fc8d7b2677bd0ae4c20182611fe7a1280734789e3) |
