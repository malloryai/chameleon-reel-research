# .NET RAT with a loopback C2 address, credential theft and USB spreading

Verdict: malicious.

## Indicators

### Malicious

| IOC | Type | Value | Context |
|---|---|---|---|
| RAT | SHA-256 | f7aa830a43d79a5c20619e50978f9b71f3b7715e5c0216952fcfc14be75c7410 | `xen.exe`, .NET, 187,904 B |
| Archive | SHA-256 | fb6a06e0172c4bc87e152a2f1de804b290b4ea13196786bf889c9f167b0ab5d9 | `xen.rar`; 68,282 B, MediaFire creation date 2026-08-19, video-stated password `xenoexecutor`; holds `xen/xen.exe` (SHA-256 of file f7aa830a43d79a5c20619e50978f9b71f3b7715e5c0216952fcfc14be75c7410) |
| Download | URL | https://www.mediafire.com/file/r6tuddk1bu0olvk/xen.rar/file | Served `xen.rar` (SHA-256 of file fb6a06e0172c4bc87e152a2f1de804b290b4ea13196786bf889c9f167b0ab5d9), which holds `xen/xen.exe` (SHA-256 of file f7aa830a43d79a5c20619e50978f9b71f3b7715e5c0216952fcfc14be75c7410) |
| Installed copy | File name | `dllloadwin32.exe` | Name of the copy that the .NET RAT `xen.exe` (SHA-256 of file f7aa830a43d79a5c20619e50978f9b71f3b7715e5c0216952fcfc14be75c7410) installs; from its settings |
| Persistence | Run value name | `dllloadwin32` | Run value name used for persistence by the .NET RAT `xen.exe` (SHA-256 of file f7aa830a43d79a5c20619e50978f9b71f3b7715e5c0216952fcfc14be75c7410); from its settings |
| USB copy | File name | `VanToM.exe` | File name that the .NET RAT `xen.exe` (SHA-256 of file f7aa830a43d79a5c20619e50978f9b71f3b7715e5c0216952fcfc14be75c7410) writes with `.lnk` shortcuts to removable drives; from its strings |
