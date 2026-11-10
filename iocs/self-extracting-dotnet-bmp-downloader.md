# Zero-padded IExpress package that runs a .NET downloader for an XOR-encoded fake bitmap

Verdict: malicious.

## Indicators

### Malicious

| IOC | Type | Value | Context |
|---|---|---|---|
| IExpress package | SHA-256 | e9ce67be0ddb933a5c202ae0e94f74f816b2d437d3245a2380ba4ea2139bcab8 | `Installer.exe`, 711,025,824 B, 710,000,000 B of zero padding |
| Downloader | SHA-256 (payload) | 7316f32805ac85fc86b449e7b8791c3d978f800fed125e4b300970cbecd52f29 | `ROCKDE~3.EXE` (`rockdetailed.exe`), .NET, 382,726,912 B, from the cabinet of the IExpress package `Installer.exe` (SHA-256 of file e9ce67be0ddb933a5c202ae0e94f74f816b2d437d3245a2380ba4ea2139bcab8) |
| Payload | URL | https://atomm.com.br/.well-known/acme-challenge/bo/Pskfuvd.bmp | From the strings of the downloader `ROCKDE~3.EXE` (SHA-256 of payload 7316f32805ac85fc86b449e7b8791c3d978f800fed125e4b300970cbecd52f29); the file sits under `/.well-known/acme-challenge/` on an unrelated site, so only this URL is an indicator, not the domain |
| Archive | SHA-256 | ae28fdcc54ee4123f4b0fc37ae1d1d33e828bdb704e06d2114f56a4e655d6317 | `Installer.rar`; password `2022`; holds `Installer.exe` (SHA-256 of file e9ce67be0ddb933a5c202ae0e94f74f816b2d437d3245a2380ba4ea2139bcab8) |
| Short link | URL | https://bit.ly/3MvCmZa | Redirects to https://bitbucket.org/kyoto321/cookie/downloads/Installer.rar, which served `Installer.rar` (SHA-256 of file ae28fdcc54ee4123f4b0fc37ae1d1d33e828bdb704e06d2114f56a4e655d6317) |
| Short link | URL | https://bit.ly/3FVWBOf | Redirects to https://bitbucket.org/kyoto321/cookie/downloads/Installer.rar, which served `Installer.rar` (SHA-256 of file ae28fdcc54ee4123f4b0fc37ae1d1d33e828bdb704e06d2114f56a4e655d6317) |
| Download | URL | https://bitbucket.org/kyoto321/cookie/downloads/Installer.rar | Served `Installer.rar` (SHA-256 of file ae28fdcc54ee4123f4b0fc37ae1d1d33e828bdb704e06d2114f56a4e655d6317), which holds `Installer.exe` (SHA-256 of file e9ce67be0ddb933a5c202ae0e94f74f816b2d437d3245a2380ba4ea2139bcab8) |
