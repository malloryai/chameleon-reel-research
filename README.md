# CHAMELEON REEL research

Technical reports and indicators for malware distributed as fake game cheats, cracks and tools. The samples ship in archives, most of them password-protected and hosted on MediaFire, linked from YouTube videos.

Five clusters have full reports: unpacking, configuration and C2, protocol, capabilities, anti-analysis, crypto material and distribution. Another 31 indicator lists cover further clusters and single samples. Each full report opens with key findings and the infection chain, and closes with scope and method and indicators. Each indicator list opens with a verdict. Every file ends with a Malicious indicator table; some add a Suspicious table for indicators not proven malicious.

## Reports

- [Go loader and infostealer that reads its C2 address from a Polygon smart contract](reports/go-stealer-polygon-contract-c2.md)
- [Sideloaded fake libcurl.dll loader and native Windows RAT](reports/libcurl-sideload-native-rat.md)
- [Go loader that maps an in-memory infostealer with three hardcoded C2 servers and an Ethereum fallback](reports/go-loader-in-memory-stealer-ethereum-fallback.md)
- [Tampered Qt5Widgets.dll sideloaded by a signed TeamSpeak installer, with a .NET infostealer](reports/qt5widgets-sideload-dotnet-stealer.md)
- [Sandbox-aware loader that decrypts an x64 PE from a private PNG chunk and maps it in memory](reports/png-chunk-downloader-reflective-loader.md)

## Indicator lists

- [.NET RAT with a loopback C2 address, credential theft and USB spreading](iocs/dotnet-rat-loopback-config-credential-theft.md)
- [.NET grabber for browser, Discord, Roblox and Minecraft data with exfiltration through a webhook relay](iocs/dotnet-grabber-webhook-relay.md)
- [Bun single-file loaders, and one pkg build, that map an AES-encrypted PE into their own process](iocs/standalone-js-loader-in-memory-pe.md)
- [Byte-encoded loader DLL carrying an infostealer and a Chrome cookie helper](iocs/encoded-crypter-dll-stealer.md)
- [Electron installers with Defender-exclusion code that download and run a payload, three of them from 62.60.226.198](iocs/desktop-app-js-dropper-telegram.md)
- [Go stealer with a copied HTC signature that reports to a plain-HTTP .shop C2](iocs/go-plain-http-host-browser-stealer.md)
- [Go stealer with remote-access functions, bundled with a signed Xeno installer or a PySide6 decoy](iocs/go-stealer-bundled-with-signed-installer.md)
- [Infostealer that reads its C2 address from Telegram and Steam dead drops, with a hard-coded fallback](iocs/telegram-steam-deaddrop-stealer.md)
- [JScript loader that starts hidden PowerShell through WMI and loads a .NET assembly from Firebase Storage](iocs/jscript-wmi-hidden-powershell-loader.md)
- [Launchers that run an infostealer inside AppLaunch.exe and read its C2 from Telegram and Mastodon dead drops](iocs/hollowed-launcher-telegram-mastodon-deaddrop-stealer.md)
- [MinGW dropper that installs itself under Windows Update names and drops a Monero miner](iocs/update-themed-miner-dropper.md)
- [Native loader in a game mod-menu archive that runs an embedded .NET infostealer through AppLaunch.exe](iocs/mod-menu-embedded-dotnet-stealer.md)
- [Nim dropper that adds Defender exclusions and starts five to seven payloads from %TEMP%](iocs/defender-exclusion-multi-dropper.md)
- [Node.js loaders packed with nexe that add Defender exclusions and run payloads from a /richfamily/ C2 list](iocs/appended-js-loader-defender-exclusions.md)
- [Node.js single-executable dropper that fetches two password-protected ZIPs and runs their executables hidden](iocs/single-executable-js-zip-dropper.md)
- [NSIS stub that rebuilds a signed AutoIt interpreter and a compiled script from disguised pieces](iocs/disguised-batch-pieces-script-loader.md)
- [Obfuscated Go remote-control agent with an appended bare-IP config and an embedded FFmpeg](iocs/go-remote-control-agent-bare-ip.md)
- [Packed .NET stealer that checks in to nine rotating .biz domains](iocs/biz-domain-rotation-stealer-checkin.md)
- [pkg-built Node.js dropper that adds Defender exclusions and XOR-decrypts an embedded x64 PE](iocs/bytecode-js-dropper-encrypted-assets.md)
- [Protected .NET downloader with Microsoft ODBC version info that loads a library from builder.pp.ru](iocs/dotnet-masquerading-downloader.md)
- [Protected launchers in fake software archives run a .NET stealer that talks WCF to a hard-coded C2](iocs/protected-launchers-wcf-dotnet-stealer.md)
- [Python infostealer with Discord webhook exfiltration, Defender tampering and Startup persistence](iocs/python-stealer-discord-webhook.md)
- [Python infostealer with Telegram exfiltration and a cryptocurrency clipboard hijacker](iocs/python-stealer-telegram-clipper.md)
- [Self-signed Go uploader that posts to drrizon.click under a forged GitHub Host header](iocs/go-self-signed-forged-host-uploader.md)
- [Shortcut with a Word icon that runs a program from a WebDAV share](iocs/lnk-webdav-remote-exe-launcher.md)
- [Sideloaded Go DLL that unpacks an infostealer with Telegram and Steam dead drops](iocs/msedge-elf-sideload-deaddrop-stealer.md)
- [Six unrelated stealer, remote-control and dropper files from fake game-tool archives](iocs/unrelated-stealer-rat-dropper-files.md)
- [Small .NET downloaders shipped beside header-stripped .NET images](iocs/dotnet-downloader-header-stripped-payloads.md)
- [Small .NET downloaders that load a library from builder.pp.ru and feed it a Discord-hosted payload](iocs/dotnet-downloader-discord-attachments.md)
- [Native x64 downloaders that fetch and start executables over plain HTTP](iocs/http-exe-downloader.md)
- [Zero-padded IExpress package that runs a .NET downloader for an XOR-encoded fake bitmap](iocs/self-extracting-dotnet-bmp-downloader.md)

## Indicator conventions

- Each indicator table has the columns IOC (the item's role), Type, Value and Context, with one indicator per row.
- Indicators are live, not defanged. Do not click URLs or contact hosts outside a controlled environment.
- File hashes are SHA-256. The type `SHA-256 (payload)` marks a file recovered from inside another sample (decrypted, decoded, unpacked or extracted) rather than shipped as is.
- Each archive has an `Archive` row with its SHA-256, followed by a `Download` row for each URL that served it. File hosts and services named in URLs (for example MediaFire, MEGA, Bitbucket, bit.ly, Discord, Telegram, Steam, Mastodon, Firebase Storage, catbox) are legitimate; only the listed URLs are indicators, not their hosts. Archive names ending in `.zip` are file names, not domains.
- Certificate thumbprints and serials are colon-separated hex. Cryptographic material recovered from samples is written as space-separated lower-case byte pairs.
- Live access tokens found in samples are withheld.
- The reports make no family or actor attribution. Names that samples use for themselves appear only as observed strings.

## License

Indicators, meaning every file in `iocs/` and the Indicators section of each report, are dedicated to the public domain under [CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/): use them anywhere, including commercial feeds and blocklists, without attribution. All other text is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/): credit Mallory and link to this repository. See [LICENSE.md](LICENSE.md).
