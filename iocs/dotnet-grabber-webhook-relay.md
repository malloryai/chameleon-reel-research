# .NET grabber for browser, Discord, Roblox and Minecraft data with exfiltration through a webhook relay

Verdict: malicious.

## Indicators

### Malicious

| IOC | Type | Value | Context |
|---|---|---|---|
| Grabber | SHA-256 | 658707c46d59a9fa66381766f47dd37f47895a4ac6bb1d16536bd62433148892 | .NET, 42,496 B; named `Bootstrapper.exe` and `output.exe` |
| Persistence | Run value name | `Mercurial Grabber` | Run value name used for persistence by the .NET grabber `Bootstrapper.exe` / `output.exe` (SHA-256 of file 658707c46d59a9fa66381766f47dd37f47895a4ac6bb1d16536bd62433148892) |
| User agent | User agent | `Mozilla/5.0 (Macintosh; Intel Mac OS X x.y; rv:42.0) Gecko/20100101 Firefox/42.0` | User agent literal in the .NET grabber `Bootstrapper.exe` / `output.exe` (SHA-256 of file 658707c46d59a9fa66381766f47dd37f47895a4ac6bb1d16536bd62433148892), with a literal `x.y`; this is the Firefox example string from MDN's `User-Agent` documentation, which no real browser sends and unrelated tools also copy |
| Archive | SHA-256 | 243825d65df708eb8e6d3f32b6cbaf3d67b36a6f26fdaca9b0df3b6aadabd2d8 | `Executor by hubguy.zip`; holds `Executor by hubguy/Bootstrapper.exe` (SHA-256 of file 658707c46d59a9fa66381766f47dd37f47895a4ac6bb1d16536bd62433148892) |
| Download | URL | https://www.mediafire.com/file/ixmk6a4gc5na0fs/Executor_by_hubguy.zip/file | Served `Executor by hubguy.zip` (SHA-256 of file 243825d65df708eb8e6d3f32b6cbaf3d67b36a6f26fdaca9b0df3b6aadabd2d8), which holds `Executor by hubguy/Bootstrapper.exe` (SHA-256 of file 658707c46d59a9fa66381766f47dd37f47895a4ac6bb1d16536bd62433148892) |
| Archive | SHA-256 | 138b3330c28bc569bffeeb110199f5d74a36acd88d4083cf1d800e8ba44ce544 | `Discord-image-logger.zip`; holds `Discord-image-logger/output.exe` (SHA-256 of file 658707c46d59a9fa66381766f47dd37f47895a4ac6bb1d16536bd62433148892) |
| Download | URL | https://www.mediafire.com/file/9loe4v9lx5zi0qp/Discord-image-logger.zip/file | Served `Discord-image-logger.zip` (SHA-256 of file 138b3330c28bc569bffeeb110199f5d74a36acd88d4083cf1d800e8ba44ce544), which holds `Discord-image-logger/output.exe` (SHA-256 of file 658707c46d59a9fa66381766f47dd37f47895a4ac6bb1d16536bd62433148892) |
