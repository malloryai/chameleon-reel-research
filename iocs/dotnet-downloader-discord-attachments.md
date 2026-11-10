# Small .NET downloaders that load a library from builder.pp.ru and feed it a Discord-hosted payload

Verdict: malicious.

## Indicators

### Malicious

| IOC | Type | Value | Context |
|---|---|---|---|
| Downloader | SHA-256 | 7ca831b75cb67c4fdd36a7202a429b89c158df52a0333749642de3b7dde0270f | `Install_.exe`, .NET x86, 16,592 B. In four `Install_` archives |
| Downloader | SHA-256 | 4908a11719fe299e43f90c7e5bbaf4bd15074926201c93c843f0ebb07439a356 | `TerrorInstaller.exe`, .NET x86, 15,976 B |
| Library | URL | https://builder.pp.ru/jetbaksaz.dll | In the IL of `Install_.exe` (SHA-256 of file 7ca831b75cb67c4fdd36a7202a429b89c158df52a0333749642de3b7dde0270f) |
| Library | URL | https://builder.pp.ru/qvuivhquwhuizqw.dll | In the IL of `TerrorInstaller.exe` (SHA-256 of file 4908a11719fe299e43f90c7e5bbaf4bd15074926201c93c843f0ebb07439a356) |
| Payload | URL | https://cdn.discordapp.com/attachments/871054001674805249/880500687383973988/rr.exe | In the IL of `Install_.exe` (SHA-256 of file 7ca831b75cb67c4fdd36a7202a429b89c158df52a0333749642de3b7dde0270f) |
| Payload | URL | https://cdn.discordapp.com/attachments/881630386839511083/881660379615342622/kexit99.exe | In the IL of `TerrorInstaller.exe` (SHA-256 of file 4908a11719fe299e43f90c7e5bbaf4bd15074926201c93c843f0ebb07439a356) |
| Archive | SHA-256 | a8b5f303ffdee03275d48f5542b2192a44ded7c685bb6341445ea5823091ceed | `Теrror.zip`; password `2021`; the name starts with Cyrillic Те; holds `TerrorInstaller.exe` (SHA-256 of file 4908a11719fe299e43f90c7e5bbaf4bd15074926201c93c843f0ebb07439a356) |
| Download | URL | https://www.mediafire.com/file/g3y1azf3q4549wk/%25D0%25A2%25D0%25B5rror.zip/file | Served `Теrror.zip` (Т and е are Cyrillic; SHA-256 of file a8b5f303ffdee03275d48f5542b2192a44ded7c685bb6341445ea5823091ceed), which holds `TerrorInstaller.exe` (SHA-256 of file 4908a11719fe299e43f90c7e5bbaf4bd15074926201c93c843f0ebb07439a356) |
| Archive | SHA-256 | d7092a4b6803512aa03a5404c288a2a6d7b1483b02eae1f1abb614c02e719630 | `Install_.zip`; password `Bseuzaq00`; holds `Install_.exe` (SHA-256 of file 7ca831b75cb67c4fdd36a7202a429b89c158df52a0333749642de3b7dde0270f) |
| Download | URL | https://www.mediafire.com/file/ido6td7l38b7v7e/Install_.zip/file | Served `Install_.zip` (SHA-256 of file d7092a4b6803512aa03a5404c288a2a6d7b1483b02eae1f1abb614c02e719630), which holds `Install_.exe` (SHA-256 of file 7ca831b75cb67c4fdd36a7202a429b89c158df52a0333749642de3b7dde0270f) |
| Archive | SHA-256 | e5fe7505e90d5e4e438a36a0b81ac1482334832b600e620206b38b040c26275a | `Install_3.zip`; password `Bseuzaq00`; holds `Install_.exe` (SHA-256 of file 7ca831b75cb67c4fdd36a7202a429b89c158df52a0333749642de3b7dde0270f) |
| Download | URL | https://www.mediafire.com/file/rak9n8ygkzcdlr3/Install_3.zip/file | Served `Install_3.zip` (SHA-256 of file e5fe7505e90d5e4e438a36a0b81ac1482334832b600e620206b38b040c26275a), which holds `Install_.exe` (SHA-256 of file 7ca831b75cb67c4fdd36a7202a429b89c158df52a0333749642de3b7dde0270f) |
| Archive | SHA-256 | e61f15252421cf0ed0e417d08a79701cbf82b7e68c3b564705a6e98002b1e1ef | `Install_4.zip`; password `Bseuzaq00`; holds `Install_.exe` (SHA-256 of file 7ca831b75cb67c4fdd36a7202a429b89c158df52a0333749642de3b7dde0270f) |
| Download | URL | https://www.mediafire.com/file/rqd7i7pupn5kbc5/Install_4.zip/file | Served `Install_4.zip` (SHA-256 of file e61f15252421cf0ed0e417d08a79701cbf82b7e68c3b564705a6e98002b1e1ef), which holds `Install_.exe` (SHA-256 of file 7ca831b75cb67c4fdd36a7202a429b89c158df52a0333749642de3b7dde0270f) |
| Archive | SHA-256 | 97ae99539bc7c3a04f91ed57706523dca1a1c64c616b81bc2d5a0cc61003f91c | `Install_6.zip`; password `Bseuzaq00`; holds `Install_.exe` (SHA-256 of file 7ca831b75cb67c4fdd36a7202a429b89c158df52a0333749642de3b7dde0270f) |
| Download | URL | https://www.mediafire.com/file/zomtblhl934wm4r/Install_6.zip/file | Served `Install_6.zip` (SHA-256 of file 97ae99539bc7c3a04f91ed57706523dca1a1c64c616b81bc2d5a0cc61003f91c), which holds `Install_.exe` (SHA-256 of file 7ca831b75cb67c4fdd36a7202a429b89c158df52a0333749642de3b7dde0270f) |
