# Byte-encoded loader DLL carrying an infostealer and a Chrome cookie helper

Verdict: malicious.

## Indicators

### Malicious

| IOC | Type | Value | Context |
|---|---|---|---|
| Encoded container | SHA-256 | ce25510ea0f625f87fc889c7e33ea8fb24b755d0015555295e2b56f80c12494f | `ErrorDetails.dll`, 527,360 B, no PE header |
| Loader DLL | SHA-256 (payload) | 7246b2ac48b019ab487abb37aebf824119db652cdeb791c8186b5833790bb082 | Decoded from `ErrorDetails.dll` (SHA-256 of file ce25510ea0f625f87fc889c7e33ea8fb24b755d0015555295e2b56f80c12494f); PE32, export `GetGameData`, TimeDateStamp 2024-10-10, 527,360 B |
| Infostealer | SHA-256 (payload) | cd7b86db186da598865100847e4cdf648802bb7bcad356f23cb2708f1efaf1b5 | Stored in the `.data` section of the loader DLL decoded from `ErrorDetails.dll` (SHA-256 of file ce25510ea0f625f87fc889c7e33ea8fb24b755d0015555295e2b56f80c12494f); PE32 executable, TimeDateStamp 2024-10-10, 314,368 B |
| Chrome cookie helper | SHA-256 (payload) | 29e7e1c1e1a7e5f26f6961d8036cdd04ee4557dec0a7dcadcd8e7651f5e53f43 | Embedded in the infostealer (SHA-256 of payload cd7b86db186da598865100847e4cdf648802bb7bcad356f23cb2708f1efaf1b5); PE32+ executable, TimeDateStamp 2024-09-29, 120,832 B |
| Infostealer | Imphash | 8e9e6de8c6aa184371108e1074479bb3 | Import hash of the infostealer (SHA-256 of payload cd7b86db186da598865100847e4cdf648802bb7bcad356f23cb2708f1efaf1b5) |
| Chrome cookie helper | Imphash | 259b0b4410b8a622569d646d1f3aca0f | Import hash of the Chrome cookie helper (SHA-256 of payload 29e7e1c1e1a7e5f26f6961d8036cdd04ee4557dec0a7dcadcd8e7651f5e53f43) |
| Archive | SHA-256 | c4d534e66b37455223b70b1e039713d28a7b6deb301423ffb87dfe10956dec54 | `Installer.zip`; holds `Instаller.zip` (the а is Cyrillic), which holds `Instаller/ErrorDetails.dll` (the а is Cyrillic; SHA-256 of file ce25510ea0f625f87fc889c7e33ea8fb24b755d0015555295e2b56f80c12494f) |
| Download | URL | https://www.mediafire.com/file/3h0xl8iw53v4qzb/Installer.zip/file | Served `Installer.zip` (SHA-256 of file c4d534e66b37455223b70b1e039713d28a7b6deb301423ffb87dfe10956dec54), which holds `Instаller.zip` (the а is Cyrillic), which holds `Instаller/ErrorDetails.dll` (the а is Cyrillic; SHA-256 of file ce25510ea0f625f87fc889c7e33ea8fb24b755d0015555295e2b56f80c12494f) |
