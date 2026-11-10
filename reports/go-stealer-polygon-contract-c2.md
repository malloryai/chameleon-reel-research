# Go loader and infostealer that reads its C2 address from a Polygon smart contract

## Key findings

- A Go loader in fake game-cheat archives maps a native stealer into its own process.
- The stealer reads its C2 address from a Polygon contract and decrypts it with an AES-256 key that ships in every copy.
- It uploads encrypted records over HTTPS that accepts self-signed, expired and wrong-host certificates.
- It also injects a DLL into Chromium browsers to obtain App-Bound Encryption keys, then deletes the loader.
- In a contained run, it read the contract through one gateway, sent 13 upload records and deleted itself 11 s after start.

```
RAR archive on MediaFire (six names, ~168 MB each; links in YouTube videos)
 └─ <GameName>.exe  stage 1, Go 1.20.1 PE32+, 1,652,224 B, unsigned
     └─ decode 0x448C4-byte blob from .rdata (interleave, 0x92-v, Fibonacci XOR)
         └─ map stage 2 (280,772 B) into own process, RWX, call entry 0x14002c270
             ├─ gates: size/captcha, debugger, score > 4, mutex Global\E828AA27 -> ExitProcess(0)
             ├─ resolve: eth_call via 6 shuffled public Polygon gateways (5 usable)
             │     -> ABI string -> hex text -> IV || AES-256-CBC ciphertext -> "host:port"
             ├─ GET /health (body must contain "active"; else Sleep(60000), resolve again)
             ├─ modules: [MODULE:x] record -> AES-128-CBC -> base64 -> "data=" POST /<32-hex dir>/xoeml.pcon
             ├─ per browser: CreateProcessW(CREATE_SUSPENDED) -> ChaCha20 DLL -> remote thread at DllRegisterServer
             │     └─ DLL: IElevator COM -> "KEY:" / "ASTER_KEY:" / "DONE" over XOR-masked named pipe
             └─ "LogComplete" -> rename own file's data stream to ":x", delete -> ExitProcess(0)
```

## 1. Stage 1: Go loader

| Field | Value |
|---|---|
| File | SHA-256 of file 4889d808f3df9369ff0ac361c394606e4e1e58aaa9f97f387b1d9bf4c6e78671, 1,652,224 B |
| Format | PE32+ x64 GUI, entry RVA 0x5b540, TimeDateStamp 0, unsigned, not UPX-packed |
| Build | Go 1.20.1, module path `recorders`, `-trimpath` |
| Imports | kernel32.dll only, 40 functions; imphash f0ea7b7844bbc5bfa9bb32efdcea957c |

Own functions carry dictionary-word names, for example `main.Considering` (the decoder) and `main.Rehabilitation`, `main.Specially`, `main.Organization` and `main.Sustained` (PE mapping); the roles are inferred.

`main.main` (0x467d60) prepends the 4-byte header `b4 88 4f 65` to 0x448C0 bytes from `.rdata` file offset 0xcf530 (VA 0x4D0730). It decodes the resulting 0x448C4 bytes with seed 0x177993:

```python
def decode_stage2(enc: bytes, seed: int = 0x177993) -> bytes:
    h = (len(enc) + 1) // 2
    mixed = bytearray(len(enc))
    mixed[0::2] = enc[:h]            # first half -> even positions
    mixed[1::2] = enc[h:][::-1]      # reversed second half -> odd positions
    k = [seed & 0xFF, (seed * 7) & 0xFF]
    for i in range(2, len(enc)):
        k.append((k[i - 1] + k[i - 2] + i) & 0xFF)
    return bytes(((0x92 - b) & 0xFF) ^ k[i] for i, b in enumerate(mixed))

# enc = bytes([0xb4, 0x88, 0x4f, 0x65]) + loader[0xcf530:0xcf530 + 0x448c0]
```

The output (280,772 B, starting `MZ`) is stage 2. The loader maps it into RWX memory, at the preferred base or else at any base, then relocates it when needed, resolves its imports and calls its entry point. A failed allocation or relocation returns from `main.main` silently, which exits with code 0. The closures `main.main.func1` to `main.main.func9` only build and walk Go maps and slices filled with random values, and call no file or Windows API. Stage 1 links no `os` package, and its own functions call Windows only to allocate memory, resolve imports and call the entry point. It does not read sibling archive files.

## 2. Stage 2

Stage 2 runs inside the loader's process, so `GetModuleFileNameW(NULL)` returns the loader's path. This drives the size gate and self-deletion.

| Field | Value |
|---|---|
| Payload | SHA-256 of payload f778f27f3f34034bf600681199df5f64c7ec6bd6c238590b07e6c81795baaf52, 280,772 B |
| Format | PE32+ x64, image base 0x140000000, entry RVA 0x2c270; TimeDateStamp 2019-06-18T03:28:46Z |
| Imports | KERNEL32 56, USER32 2, the rest resolved at runtime; imphash 376a15e8b6beed6f11a458c96438cb35 |
| Overlay | 196 B at file offset 280,576 |

### 2.1 Strings, control flow and API resolution

Each string is stored encrypted in `.data` and decrypted in place on first use. Byte strings use `ror8((b[i] - (seed + 0x37*i)) & 0xFF, 3)`. UTF-16 strings use `ror16((w[i] - (seed - 0x61C9*i)) & 0xFFFF, 5)`. The last unit is forced to NUL. Each call site passes a seed immediate, of which only the low 8 bits (byte strings) or 16 bits (UTF-16 strings) are used; the table lists the effective values.

| VA | Seed | Plaintext |
|---|---|---|
| 0x14003e200 | 0x27 | contract address |
| 0x14003e278 | 0x62 | `0x862974de` |
| 0x14003e2a0 | 0x34 | AES-256 key as 64 hex characters |
| 0x14003e3a0, 0x14003e3d0 | -0x77, -0x0e | upload path (two identical copies) |
| 0x14003e370 | -0x1b | `jakoer228` |
| 0x14003e7e8 | -0x76e8 (wide) | `Global\E828AA27` |

`entry` is a flattened state machine: `state = next ^ 0x649618c1`, with a return after 1,000 iterations. It runs the following in order:

1. The four gates.
2. Resolve and `/health`.
3. The host report (`UserInformation`), retried until it succeeds.
4. `Environment`, `ProcessList` and `InstalledSoftware`.
5. Collection: `Clipboard` (state 0x50), then `Screenshot` and messengers (from state 0x11), the browser-key threads (state 0x1b) and extension wallets (state 0x45). Desktop wallets run in state 0x2b.
6. The file grabber, `LogComplete` and self-deletion.

The contained full run uploaded in this order: `UserInformation`, `Environment`, `ProcessList`, `InstalledSoftware`, `Clipboard`, `Screenshot`, the browser records, `FG_Downloads`, `LogComplete`.

Win32 calls go through wrappers that decrypt a DLL name and a function name, then cache the `GetProcAddress` result. The injection path adds a table of `ntdll.dll` system-call stubs keyed by 32-bit hashes. The hash is DJB2 (start 5381, multiplier 33) over the `Zw` export name, XORed with 0x0bd38755. For example, 0x29cf936e is `ZwAllocateVirtualMemory` and 0x318a81b4 is `ZwWriteVirtualMemory`.

### 2.2 Gates

Every gate ends in `ExitProcess(0)`.

- Size and captcha: if the module file is 200,000 to 400,000 bytes, stage 2 shows a topmost window titled `Reviera` (window class `CX`). It asks for a 6-character code from `ABCDEFGHJKLMNPQRSTUVWXYZ23456789` and exits on a wrong or empty answer. The module file is normally the 1,652,224-byte loader, so only a dumped stage 2 run on its own triggers this gate.
- Debugger: `IsDebuggerPresent`, `CheckRemoteDebuggerPresent` and the PEB `BeingDebugged` byte.
- Scoring: a score above 4 exits (table below).
- Mutex: `CreateMutexW(NULL, TRUE, L"Global\\E828AA27")`. A failed call or ERROR_ALREADY_EXISTS exits.

| Check | Condition | Points |
|---|---|---|
| Process names | ollydbg, x32dbg, x64dbg, windbg, ida, idaq, idaw, radare, ghidra, immunity, wireshark, fiddler, httpdebugger, charles, burp, mitmproxy, proxifier, procmon, procexp, pyw.exe, pythonw.exe, xenservice, qemu-ga, fakenet, dumpcap, rdpclip.exe | immediate exit |
| CPU | fewer than 2 cores or fewer than 4 logical processors, or a failed call | 5 |
| RAM | below 4 GiB, or a failed call | 5 |
| System drive | total at most 0x1DFFFFFFFF B (below 120 GiB); a failed call adds nothing | 4 |
| Display adapter | lower-cased DeviceString contains microsoft, vmware, virtualbox, array or adapter, or enumeration fails | 5 |
| User or computer name | johnson, miller, malware, maltest, johndoe, sandbox, virus, john doe, test user, sand box, wdagutilityaccount, bruno, george, harry johnson, test, sample, analysis, cuckoo, vmware, virtual | 5 |
| Uptime | below 600,000 ms | 1 |

Process names, the display adapter string and the user and computer names are lower-cased and then matched as substrings. For example, any user name containing `test` scores 5.

## 3. C2 resolver

Zero-address switch: if characters 2 to 4 of the compiled-in contract string are `000`, the resolver makes no RPC call. The caller then sleeps 60 s and retries forever. This sample's string starts `0x86A`, so the switch is off.

Gateway order: a six-entry index table is shuffled once per process with Fisher-Yates from the last slot down. The shuffle uses the LCG `x = x*0x41C64E6D + 0x3039` and takes `(x >> 16) % n`. The seed is `GetTickCount64 ^ PID ^ TID`, XORed with both halves of `QueryPerformanceCounter`. Attempt `n` uses `table[n]`, so one resolve tries each gateway at most once. The 1RPC host string carries a `/matic` path suffix. The whole string is passed to WinINet as the host name, so that entry never resolves and every round uses only the other five.

Request: `POST /` on port 443, with `Content-Type: application/json`, `User-Agent: Mozilla/5.0` and `Cache-Control: no-cache`, and this body:

`{"jsonrpc":"2.0","method":"eth_call","params":[{"to":"0x86A59863D1cf3a83c556bF16293A0b7EF33376aC","data":"0x862974de"},"latest"],"id":1}`

WinINet uses user agent `Mozilla/5.0`, a direct connection with no proxy, and 15 s timeouts. The flags are NO_CACHE_WRITE, SECURE, IGNORE_CERT_DATE_INVALID and IGNORE_CERT_CN_INVALID. An unknown CA is not ignored here, unlike in C2 requests.

Response: the `"result"` value is an ABI `string` whose content is hex text. The parser does not read the offset word. Counting hex digits after the `0x` prefix, it reads the length from digits 0x78 to 0x7F, requires 0 < length < 0x400, and hex-decodes from digit 0x80. The inner hex text decodes to 48 bytes: the IV (16), then the ciphertext (32). The parser finds the value by searching for the literal `"result":"` with no whitespace and reads to the next `"`; it does not parse JSON. A reply with `"result": "` was rejected on every attempt.

Decryption: AES-256-CBC with PKCS#7. The key is a hex string decoded from VA 0x14003e2a0 (file offset 0x3c0a0); there is no key derivation. Key and IV are in section 10. The plaintext is `bapesta.akjqdf.xyz:443`. The port follows the last `:`. A missing, non-numeric or zero port gives 443. The parent domain `akjqdf.xyz` was on `serverHold` at every RDAP reading from 2026-09-19 to 2026-11-06; its RDAP record last changed on 2026-05-04.

Loop: resolve, then `/health`. On failure, `Sleep(60000)` and repeat without limit. Port 443 turns TLS on, port 80 turns it off, and any other port keeps the previous setting (on by default). There is no fallback C2.

Observed at runtime: each process tried the five usable gateways in one fixed order, and the order differed between processes. A timed-out attempt lasts about 15 s, so rounds start about 140 s apart; with immediate rejected replies, all five are tried within about 50 ms and the next round starts 60 s later. The ClientHello offers TLS 1.3 and 1.2. In the full run the first gateway's reply was accepted, and the C2 host lookup followed 16 ms later.

## 4. C2 protocol

Request headers, the upload path and the record format were observed in the contained full run. Timeouts, TLS flags and the `false` reply are static.

| Item | `GET /health` | `POST /<dir>/xoeml.pcon` |
|---|---|---|
| Timeouts | 30 s | 120 s |
| TLS flags | SECURE, IGNORE_CERT_DATE_INVALID, IGNORE_CERT_CN_INVALID; security flags 0x3100 add IGNORE_UNKNOWN_CA | same, plus NO_CACHE_WRITE |
| Headers | `User-Agent`, `Host` only | `Content-Type: application/x-www-form-urlencoded`, `Cache-Control: no-cache` |
| Reply | must contain `active` | over 4 bytes starting `false`: close handles, `ExitProcess(0)` |

Both requests use user agent `Mozilla/5.0` and a direct connection. They accept certificates from an unknown CA, expired certificates and certificates for another host name; revocation and wrong-usage errors are not ignored. A fixed 32-character hex directory precedes `/xoeml.pcon`.

The upload record is:

`[MODULE:<name>]\nTraffic: jakoer228\nHWID: <MachineGuid or Unknown>\n---DATA---\n<data>`

The HWID is `MachineGuid` from `HKLM\SOFTWARE\Microsoft\Cryptography`. The record is encrypted with AES-128-CBC and PKCS#7 under a static key and IV (section 10), so identical records give identical ciphertext. The ciphertext is then base64-encoded, with `+`, `/` and `=` escaped as `%2B`, `%2F` and `%3D`, and sent as `data=<text>`. The AES S-box and round constants are stored XOR-masked with `(0x53*i + 0x7f) & 0xFF`. The stored S-box begins `1c ae 52 03 39 75 1e 01`, so S-box byte scans miss it.

Modules seen as upload labels: `UserInformation`, `Environment`, `ProcessList`, `InstalledSoftware`, `Clipboard`, `Screenshot` and `LogComplete` (body `complete`). The host report includes `Version Build: 1.0.0` and the constant placeholders `Country: Unknown` and `IP: 0.0.0.0`. Staged data sets are named `browser.bin`, `wallet.bin` and `dwallet.bin`.

The browser module adds `Browser_START` (body `total:<n>`), one `Browser_<i>of<n>` record per item and `Browser_END` (`sent:<i>,total:<n>`). The file grabber sent `FG_Downloads`. Browser and file data are `DEF1` blobs: `DEF1`, a 4-byte raw size, then a Windows Compression API XPRESS-Huffman buffer (magic `0A 51 E5 C0`, algorithm 4). These unpack to a `BRW1` container (profile files and `Local State`) or an `FGRB` container (count, then path, size and bytes per file).

Upload wrappers try 2 or 3 times, with a resolve between attempts. The host report retries without limit. A C2 outage therefore parks the client in 60 s sleeps.

## 5. Self-deletion

The last function opens the loader file with DELETE access and renames its default data stream to `:x` (FileRenameInformation). It then reopens the file, sets DeleteFile = 1 (FileDispositionInformation) and calls `ExitProcess(0)`. The call is `NtSetInformationFile`, resolved by name from `ntdll.dll` with `GetProcAddress`. In the contained full run the process exited with code 0 after 11 s and the loader file was gone.

## 6. Collection targets

All targets are decrypted strings. The contained full run took the host report, environment, process list, installed software, clipboard, a screenshot, one Chromium profile (cookies, login and web data, `Local State`) and files from Downloads.

| Category | Notable targets |
|---|---|
| Chromium extensions | 190 (ID, name) pairs: 164 wallets (MetaMask, Phantom, Coinbase, TrustWallet, OKX, Binance, Rabby, Keplr, TronLink, Tonkeeper) and 26 password managers and 2FA apps (1Password, Bitwarden, LastPass, KeePassXC, Authy, GoogleAuthenticator) |
| Chromium browsers | Chrome, Chrome Beta, Edge, Brave: `Cookies`, `Login Data`, `Web Data`; `Local State` key via `CryptUnprotectData`; App-Bound keys via the DLL; Yandex `Ya Passman Data`; a renamed `User Data` folder was still collected, so profiles are probably found by walking the browser folder (inferred) |
| Other browsers | Gecko `cookies.sqlite`, `logins.json`, `key3.db`, `key4.db`; Firefox extensions such as `browserextension@rainbow.me`; `EBWebView`, `CefCache` |
| Desktop wallets | Armory, Atomic, Electrum family, Exodus, Monero, Ledger Live, Trezor Suite, Wasabi, Zcash, Cake Wallet |
| Messengers, games | Telegram `tdata`, TOX, PSI+, PIDGIN, SESSION, ELEMENT, SLACK; eight Minecraft launchers, Steam, Roblox, EA Desktop |
| Other credentials | FileZilla, WinSCP, Cyberduck, FlashFXP, SmartFTP, CoreFTP; OpenVPN, WireGuard, NordVPN, ProtonVPN configs; Windows Credentials; password managers; Outlook; OBS; Sticky Notes |
| Files | Desktop, Documents, Downloads and cloud-sync folders; `.txt .md .csv .json .doc .docx .xls .xlsx .pdf .cfg .kdbx` |
| Host | host report, environment block, process list, installed software, screenshot, clipboard |

## 7. App-Bound Encryption key DLL

Stage 2 decrypts 0x3a00 bytes at VA 0x1400372c0 (file offset 0x35ac0) with ChaCha20 per RFC 8439, with the block counter starting at 0. Key and nonce are in section 10. ChaCha20 decryption with this key and nonce reproduces SHA-256 of payload 5443bf9862c1c0cf191c19d37727b2cc4780da1a206dd0698611ca79913616cb.

Per browser, stage 2 does the following:

1. Kill matching running processes.
2. Start the browser with `CreateProcessW` and CREATE_SUSPENDED.
3. Create the pipe server.
4. Write the flat DLL file image into the browser and set PAGE_EXECUTE_READ.
5. Start a remote thread at the `DllRegisterServer` export.
6. Run the pipe exchange, then terminate the browser.

The native calls go through the hash-resolved stubs `ZwAllocateVirtualMemory`, `ZwWriteVirtualMemory`, `ZwProtectVirtualMemory` (new protection 0x20), `ZwCreateThreadEx` and `ZwClose`. `DllRegisterServer` most likely maps the DLL itself, like a reflective loader (inferred).

| Field | Value |
|---|---|
| Payload | SHA-256 of payload 5443bf9862c1c0cf191c19d37727b2cc4780da1a206dd0698611ca79913616cb, 14,848 B, PE32+ x64 DLL |
| TimeDateStamp | 2026-03-04T22:42:18Z, 3 s after the contract deployment |
| Exports | internal name `msvcp140d.dll`; only export `DllRegisterServer` |
| Imports | imphash ced4e82be0e700c21c3771e8936ee102 with OLEAUT32 ordinals 6, 149 and 150 resolved to names (9b2b8f89090cbaaeb551302afb6f912b if left unresolved); `PeekNamedPipe`, `CryptStringToBinaryA`, `CoCreateInstance`, `CoSetProxyBlanket`; no network APIs |
| Constants | `edge-copilot`, `app_bound_encrypted_key`, `aster_app_bound_encrypted_key`, `KEY:`, `ASTER_KEY:`, `DONE`, pipe XOR key, unused copy of the ChaCha20 key and nonce, GUID-shaped value {F1B32785-6FBA-4FCF-9D55-7B8E7F157091} |

COM calls. The DLL has six `CoCreateInstance` call sites, using CLSCTX_LOCAL_SERVER. Each is followed by `CoSetProxyBlanket` with PKT_PRIVACY authentication, IMPERSONATE level and EOAC_DYNAMIC_CLOAKING, which the browsers' `IElevator` service requires. Two GUIDs are built on the stack: {17DF149F-BE61-447E-A305-522F55021B36} and {8F7B6792-784D-4047-845D-1782EFBEF205}.

The DLL is built to read `app_bound_encrypted_key` from `Local State` and base64-decode it with `CryptStringToBinaryA`, have the elevation service decrypt it, and return the result as `KEY:` and `ASTER_KEY:` messages. The values are probably upper-case hex, given the DLL's `0123456789ABCDEF` table (inferred). The targets are Chrome, Chrome Beta, Brave and Edge. The DLL matches a public open-source App-Bound proof of concept on four points: `ASTER_KEY:`, the blanket settings, a network-free DLL that answers over a pipe, and `edge-copilot`.

Pipe protocol. Stage 2 is the server. With `t = GetTickCount64()`, `u10 = (t ^ PID) & 0xffff` and `u11 = ((t >> 16) ^ TID) & 0xffff`. The pipe name is `\\.\pipe\` plus `wsprintfW(format, u10, u11)`:

| Browser label | Selector | Format 0 | Format 1 | Format 2 |
|---|---|---|---|---|
| `chrome`, `chrome-beta` | (u10 + u11) % 3 | `chrome.sync.%u.%u.%04X` | `chrome.nacl.%u_%04X` | `mojo.%u.%u.%04X.chrome` |
| `edge` | ((((PID << 8) ^ TID) & 0xffff) + u11) % 3 | `msedge.sync.%u.%u` | `msedge.crashpad_%u_%04X` | `LOCAL\msedge_%u` |
| other | none | `chromium.ipc.%u.%u` | | |

Formats with three specifiers receive only two arguments, so the last field takes whatever the third argument slot holds (inferred).

The pipe is created with `CreateNamedPipeW(name, 3, 6, 1, 0x1000, 0x1000, 5000, NULL)`. The server sends the browser label and reads replies for up to 59,999 ms. Both directions use `buf[i] ^= key[i & 7]` with the 8-byte pipe XOR key. The DLL answers with `KEY:<value>`, `ASTER_KEY:<value>`, then `DONE`. Stage 2's parser also accepts `ERROR:<text>`, but the DLL contains no such string.

## 8. Contract and on-chain footprint

The contract 0x86A59863D1cf3a83c556bF16293A0b7EF33376aC (Polygon PoS, chain ID 137) has 2,163 B of runtime code built with solc 0.8.20. It has exactly three functions:

- `0x862974de` returns slot 0, the hex-text blob.
- `0x7e172140` returns slot 1, the owner.
- `0x5fcf24bc` is the setter. Unless the caller is the owner, it reverts with `Only owner can call this function`. Otherwise it stores the string and emits LOG1.

Other selectors revert, and the owner cannot change.

The controller, 0xbc1a740152ca425d38d0a9fddf2c12b9fa9dbc41, deployed the contract with plain CREATE at nonce 609, in block 83,772,052 on 2026-03-04 at 22:42:15 UTC. The value was set in the constructor, and no setter call is recorded. On 2026-11-06 (block 96,812,047) the blob was still byte-identical to the 2026-09-19 reading. The controller still held 32.04 POL and can re-point the contract at any time.

The controller deployed 658 contracts from one template, with selectors randomised per build, so `0x862974de` is close to a per-build fingerprint (inferred).

## 9. Distribution

Six password-protected RAR archives on MediaFire, each about 168 MB, carry the same stage-1 file. Links come from YouTube videos. Each archive's password is its lower-case base name, for example `cs2skinchanger` for `Cs2SkinChanger.rar`. For each archive, at least one video that linked it gave the password.

`Cs2SkinChanger.rar` also contains genuine signed bait DLLs from Valve and Nvidia. It contains five PEs in which 0x00 bytes were replaced by 0x20 (`PE\x20\x20`): `AcXtrnal.dll`, `libavif-16.dll`, `libavresample-4.dll`, `libswscale-5.dll` and `vstdlib_s.dll`. It also holds two copies of a 52,428,800-byte blob, `i2j9S2Mrl3BV`, with entropy 7.994. The mangled PEs look like damaged copies of legitimate libraries (inferred).

## 10. Crypto material

| Value | Bytes | Location |
|---|---|---|
| Stage-1 seed | 0x177993 (imm32 `93 79 17 00`) | `main.main` 0x467db3 |
| Stage-1 header | `b4 88 4f 65` | `main.main` 0x467dcb |
| AES-256 key, C2 blob | `30 1c d0 6a 0d 9d 0d d6 b3 f8 bd 22 12 e2 4a 91 21 79 b9 e1 b8 94 5f f7 fa e0 da 9b 2d fe 7e f4` | stage 2 VA 0x14003e2a0, obfuscated hex text |
| AES-256 IV, C2 blob | `3f 17 d0 41 1c 7f c8 9c 3c 1b 53 d3 17 64 fc 32` | on-chain blob bytes 0-15 |
| AES-128 upload key | `36 ab 30 d8 72 d4 43 8c 0e a7 1b e5 a6 97 90 31` | stage 2 VA 0x1400371e0 |
| AES-128 upload IV | `d8 81 00 83 25 4e 1d f9 da 53 92 b2 43 32 75 cb` | stage 2 VA 0x1400371f0 |
| ChaCha20 key | `06 39 91 2d ad 92 56 56 3c 98 d3 17 4e 84 11 95 95 d0 a6 4a 29 ef ee 92 25 01 2e 41 c0 9b 50 49` | stage 2 VA 0x140037290 |
| ChaCha20 nonce | `b1 ab 32 d1 d7 89 d0 12 66 f1 47 fa` | stage 2 VA 0x1400372b0 |
| Pipe XOR key | `83 f4 5f a2 31 8f 06 22` | stage 2 VA 0x140037280; DLL offset 0x458 |

The upload key and IV decrypt all 13 records captured in the contained full run, each with valid PKCS#7 padding and the record format of section 4.

## 11. Scope and method

- **Samples:** one stage-1 sample, its in-memory second stage, one injected DLL, one Polygon contract, six distribution archives
- **Methods:** static analysis; contained Windows runs with the anti-analysis exits patched, against a local gateway and C2 simulator
- **Live checks:** read-only chain reads (2026-09-19, 2026-10-07, 2026-11-06); RDAP and DNS lookups of the C2 domain
- **Coverage:** Runtime observations cover the contract read, gateway requests, uploads of host, browser-file and Downloads data, and self-deletion. Browser launch, App-Bound DLL injection, the pipe exchange, upload retries, the `false` reply and wallet collection are described from static analysis of the code.

## Indicators

### Malicious

| IOC | Type | Value | Context |
|---|---|---|---|
| Stage 1 loader | SHA-256 | 4889d808f3df9369ff0ac361c394606e4e1e58aaa9f97f387b1d9bf4c6e78671 | SHA-256 of file 4889d808f3df9369ff0ac361c394606e4e1e58aaa9f97f387b1d9bf4c6e78671; Go 1.20.1 loader named 8BallPoolModMenu.exe, AmongUsModMenu.exe, Cs2Hack.exe, Cs2SkinChanger.exe, LOLSkinChanger.exe or ValorantSkinChanger.exe |
| Stage 2 stealer | SHA-256 (payload) | f778f27f3f34034bf600681199df5f64c7ec6bd6c238590b07e6c81795baaf52 | SHA-256 of payload f778f27f3f34034bf600681199df5f64c7ec6bd6c238590b07e6c81795baaf52; 280,772 B, unpacked in memory by the loader SHA-256 of file 4889d808f3df9369ff0ac361c394606e4e1e58aaa9f97f387b1d9bf4c6e78671 |
| Browser-key DLL | SHA-256 (payload) | 5443bf9862c1c0cf191c19d37727b2cc4780da1a206dd0698611ca79913616cb | SHA-256 of payload 5443bf9862c1c0cf191c19d37727b2cc4780da1a206dd0698611ca79913616cb; injected into Chromium browsers, 14,848 B, decrypted from stage 2 |
| Browser-key DLL | Imphash | ced4e82be0e700c21c3771e8936ee102 | Imphash of the DLL SHA-256 of payload 5443bf9862c1c0cf191c19d37727b2cc4780da1a206dd0698611ca79913616cb, with OLEAUT32 ordinals resolved to names |
| Browser-key DLL | Imphash | 9b2b8f89090cbaaeb551302afb6f912b | Imphash of the DLL SHA-256 of payload 5443bf9862c1c0cf191c19d37727b2cc4780da1a206dd0698611ca79913616cb, with OLEAUT32 ordinals left unresolved |
| Mutex | Mutex | `Global\E828AA27` | Single-instance mutex created by stage 2, SHA-256 of payload f778f27f3f34034bf600681199df5f64c7ec6bd6c238590b07e6c81795baaf52 |
| Traffic tag | Campaign tag | `jakoer228` | Fixed `Traffic:` value in every upload record and in the host report of stage 2, SHA-256 of payload f778f27f3f34034bf600681199df5f64c7ec6bd6c238590b07e6c81795baaf52 |
| C2 | Domain | bapesta.akjqdf.xyz | C2 host of stage 2, SHA-256 of payload f778f27f3f34034bf600681199df5f64c7ec6bd6c238590b07e6c81795baaf52; HTTPS on port 443; decrypted from the contract value read 2026-09-19, 2026-10-07 and 2026-11-06 |
| C2 parent domain | Domain | akjqdf.xyz | Parent of the C2 host of stage 2, SHA-256 of payload f778f27f3f34034bf600681199df5f64c7ec6bd6c238590b07e6c81795baaf52; registered 2026-02-07; in `serverHold` on 2026-09-19, 2026-10-07 and 2026-11-06, name servers still set |
| Liveness check | URL | https://bapesta.akjqdf.xyz/health | GET request by stage 2, SHA-256 of payload f778f27f3f34034bf600681199df5f64c7ec6bd6c238590b07e6c81795baaf52; the body must contain `active` |
| Upload URL | URL | https://bapesta.akjqdf.xyz/adb8a56294dadf33644cb54a090cb9f6/xoeml.pcon | POST target of every upload record from stage 2, SHA-256 of payload f778f27f3f34034bf600681199df5f64c7ec6bd6c238590b07e6c81795baaf52; the path is stored encoded in the file |
| C2 contract | Polygon contract | 0x86A59863D1cf3a83c556bF16293A0b7EF33376aC | Polygon PoS, chain ID 137; holds the encrypted C2 address read by stage 2, SHA-256 of payload f778f27f3f34034bf600681199df5f64c7ec6bd6c238590b07e6c81795baaf52 |
| Controller | Polygon address | 0xbc1a740152ca425d38d0a9fddf2c12b9fa9dbc41 | Deployer and controller of the contract 0x86A59863D1cf3a83c556bF16293A0b7EF33376aC read by stage 2, SHA-256 of payload f778f27f3f34034bf600681199df5f64c7ec6bd6c238590b07e6c81795baaf52; can change the C2 address at any time; still funded on 2026-11-06 |
| Archive | SHA-256 | 3a29128e28a7f27489c76e11733048e7b39770dc8f19fc21eb68f26ee00cdfb3 | 8BallPoolModMenu.rar, SHA-256 of file 3a29128e28a7f27489c76e11733048e7b39770dc8f19fc21eb68f26ee00cdfb3; password-protected RAR carrying the stage-1 loader |
| Download | URL | https://www.mediafire.com/file/gh9yehiz4bu11ri/8BallPoolModMenu.rar/file | MediaFire link serving 8BallPoolModMenu.rar, SHA-256 of file 3a29128e28a7f27489c76e11733048e7b39770dc8f19fc21eb68f26ee00cdfb3 |
| Archive | SHA-256 | 4a51ae0d6d458b4efc8422fde03c9a4d1e677282e1efbf9640536c23de85b2a3 | AmongUsModMenu.rar, SHA-256 of file 4a51ae0d6d458b4efc8422fde03c9a4d1e677282e1efbf9640536c23de85b2a3; password-protected RAR carrying the stage-1 loader |
| Download | URL | https://www.mediafire.com/file/bcjihx1xtowbh4s/AmongUsModMenu.rar/file | MediaFire link serving AmongUsModMenu.rar, SHA-256 of file 4a51ae0d6d458b4efc8422fde03c9a4d1e677282e1efbf9640536c23de85b2a3 |
| Archive | SHA-256 | b83514c6ebcee15742da68f159c82cd0e14680623499443cad61f19b3f75d43c | Cs2Hack.rar, SHA-256 of file b83514c6ebcee15742da68f159c82cd0e14680623499443cad61f19b3f75d43c; password-protected RAR carrying the stage-1 loader |
| Download | URL | https://www.mediafire.com/file/2o1epnrpd80oiv3/Cs2Hack.rar/file | MediaFire link serving Cs2Hack.rar, SHA-256 of file b83514c6ebcee15742da68f159c82cd0e14680623499443cad61f19b3f75d43c |
| Archive | SHA-256 | f75c49c0b6ea608944783e445c758f772161a1ac8089f6a15ec377c6b3180432 | Cs2SkinChanger.rar, SHA-256 of file f75c49c0b6ea608944783e445c758f772161a1ac8089f6a15ec377c6b3180432; password-protected RAR carrying the stage-1 loader |
| Download | URL | https://www.mediafire.com/file/dj751wxtrzci7m1/Cs2SkinChanger.rar/file | MediaFire link serving Cs2SkinChanger.rar, SHA-256 of file f75c49c0b6ea608944783e445c758f772161a1ac8089f6a15ec377c6b3180432 |
| Archive | SHA-256 | 295ef002d188e274e1306db31821c368adc1160cf0427adde3d0adc9c4734528 | LOLSkinChanger.rar, SHA-256 of file 295ef002d188e274e1306db31821c368adc1160cf0427adde3d0adc9c4734528; password-protected RAR carrying the stage-1 loader |
| Download | URL | https://www.mediafire.com/file/tbhps0s2g402w9h/LOLSkinChanger.rar/file | MediaFire link serving LOLSkinChanger.rar, SHA-256 of file 295ef002d188e274e1306db31821c368adc1160cf0427adde3d0adc9c4734528 |
| Archive | SHA-256 | 70b6d7b1c54ded9c09dab16c08ea85e3b227d8674a9d450bc7e0a5d0eddb6751 | ValorantSkinChanger.rar, SHA-256 of file 70b6d7b1c54ded9c09dab16c08ea85e3b227d8674a9d450bc7e0a5d0eddb6751; password-protected RAR carrying the stage-1 loader |
| Download | URL | https://www.mediafire.com/file/e3ee0rqpbcni0n9/ValorantSkinChanger.rar/file | MediaFire link serving ValorantSkinChanger.rar, SHA-256 of file 70b6d7b1c54ded9c09dab16c08ea85e3b227d8674a9d450bc7e0a5d0eddb6751 |
