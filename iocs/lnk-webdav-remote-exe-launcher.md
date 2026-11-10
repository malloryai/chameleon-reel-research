# Shortcut with a Word icon that runs a program from a WebDAV share

Verdict: malicious.

## Indicators

### Malicious

| IOC | Type | Value | Context |
|---|---|---|---|
| Shortcut | SHA-256 | 482c59b6d09277533c5c9c8753725feb8de42b2816adb631371787d308e50233 | `README.docx.lnk` |
| WebDAV server | IP:port | 62.60.226.24:80 | Plain HTTP; WebDAV server that shortcut `README.docx.lnk` (SHA-256 of file 482c59b6d09277533c5c9c8753725feb8de42b2816adb631371787d308e50233) runs a program from |
| Remote payload | File path | `\\62.60.226.24@80\file\CatToolsMan.exe` | Run from the WebDAV share by shortcut `README.docx.lnk` (SHA-256 of file 482c59b6d09277533c5c9c8753725feb8de42b2816adb631371787d308e50233) |
| Archive | SHA-256 | 7bc59124c00d4e0c19fb147b57192e285d60dbb7ea567f05114f443494c49e55 | `[1.1.0]-Aрр-UNC-x64.rar` (the р is Cyrillic); holds `Release.rar`, which holds `README.docx.lnk` (SHA-256 of file 482c59b6d09277533c5c9c8753725feb8de42b2816adb631371787d308e50233) |
| Download | URL | https://www.mediafire.com/file/1qqlviakp9t7t02/%255B1.1.0%255D-A%25D1%2580%25D1%2580-UNC-x64.rar/file | Served `[1.1.0]-Aрр-UNC-x64.rar` (the р is Cyrillic; SHA-256 of file 7bc59124c00d4e0c19fb147b57192e285d60dbb7ea567f05114f443494c49e55), which holds `Release.rar`, which holds `README.docx.lnk` (SHA-256 of file 482c59b6d09277533c5c9c8753725feb8de42b2816adb631371787d308e50233) |
| Archive | SHA-256 | 03f459085e960062634f47a51295232c26a820f27dfb4a2601b6504081fe5774 | `Release.rar`; nested archive that holds shortcut `README.docx.lnk` (SHA-256 of file 482c59b6d09277533c5c9c8753725feb8de42b2816adb631371787d308e50233) |
