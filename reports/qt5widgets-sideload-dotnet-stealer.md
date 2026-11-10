# Tampered Qt5Widgets.dll sideloaded by a signed TeamSpeak installer, with a .NET infostealer

## Key findings

- Fake game-cheat archives ship a tampered `Qt5Widgets.dll` and an encrypted manifest file, in 36 of 48 beside a renamed, signed TeamSpeak installer. The installer loads the DLL from its own folder.
- A patched jump runs a layered decryptor, then an implant that checks for a sandbox and for the user's country and language.
- The implant copies the manifest into a modified copy of the victim's own `System32\mshtml.dll`, decodes it with a single-byte XOR and runs it. The manifest unpacks itself into a Donut loader (inferred), which maps the final .NET stealer.
- The stealer talks to its C2 with AES-CBC frames over raw TCP. The server chooses what to collect, supplies Chrome App-Bound Encryption (ABE) shellcode and can send files and commands to run.
- All three manifests decrypt to the .NET stealer, with the same campaign GUID and bootstrap key but different C2 endpoints. The chain below is the first-generation build.

```
archive on MediaFire: <GameName>.exe (TeamSpeak installer) + Qt5Widgets.dll + manifest.json
 └─ installer loads Qt5Widgets.dll -> E9 patch -> code cave, 3 rolling-XOR layers
     └─ implant (26,315 B): 3 gates (crash on failure), exits for 10 countries and ru-RU
         └─ System32\mshtml.dll copied to amshtml.dll + RWX section; manifest.json copied in, XOR 0x08
             └─ manifest: 1 rolling-XOR layer -> Donut loader (inferred): Chaskey CTR, aPLib
                 └─ stage 5: x64 PE carrying the .NET stealer; exits on ru-RU
                     ├─ TCP 188.34.196.109:31078, then 2.28.37.159:24241
                     ├─ length || IV || AES-CBC; bootstrap key, then server session key
                     ├─ expiry 2026-10-06 21:00 UTC, checked after the first reply
                     └─ server-driven collection, ABE shellcode, run-file / PowerShell / cmd tasks
```

## 1. Distribution and host programs

All 48 archives carry one of three DLL builds. In 36, the DLL sits beside a renamed TeamSpeak installer that imports `Qt5Widgets.dll`. One installer build is in 33 first-generation archives, an older one in three second-generation archives. The other 12 archives hold an executable that does not import the DLL:

- `Among.zip` (7bb7e703), `Mm2 menu.zip` and `Valorant.zip`: an unsigned 32-bit Go executable, which cannot load these x64 DLLs.
- `Loader.zip`, `FlexMode.rar`, `GameMode.rar` and `SilentMode.rar`: a signed Notepad++ updater beside a `libcurl.dll`.
- `ValorantHack.rar` and `MurderMysteryScript.rar`: other executables.
- All three 9c7d1a81 archives: no TeamSpeak installer.

Encrypted manifests: one `manifest.json` (1,143,174 B) is in all 37 first-generation archives, including the four without a TeamSpeak installer. A different `manifest.json` (1,143,044 B) is in the three 9c7d1a81 archives. `Dependencies.manifest` (1,122,428 B) ships with 279c4c97. Each starts with byte 0xE8 and has entropy 7.9998 bits per byte.

The `Xen.zip` bundle holds 128 files, including about 48 MB of filler under `modules` and `locale_data`.

## 2. DLL tampering

| Build | Size | Authenticode | Patched function | Patch RVA | Bytes before -> after | Archives |
|---|---|---|---|---|---|---|
| First generation | 5,498,992 B | TeamSpeak Systems GmbH, digest mismatch | `QApplicationPrivate::QApplicationPrivate(int&,char**,int)` | 0xD303 | `48 83 c4 20 5b` -> `e9 4d cf 19 00` (to 0x1AA255) | 37 |
| Second generation 279c4c97 | 5,580,800 B | unsigned | `QApplicationPrivate::init()` | 0x137E9 | `ff 15 11 e8 33 00` -> `e9 8c 7b 19 00 00` (to 0x1AB37A) | 8 |
| Second generation 9c7d1a81 | 5,580,800 B | unsigned | `QApplication::QApplication(int&,char**,int)` | 0xF9E6 | `e8 d1 97 33 00` -> `e9 98 a6 24 00` (to 0x25A083) | 3 |

The first-generation signature is TeamSpeak Systems GmbH's (DigiCert SHA2 Assured ID Code Signing CA, valid 2020-11-04 to 2023-11-08), but its digest does not match the file. TimeDateStamps are 2020-11-06 05:24:44 UTC (first generation) and 2019-04-09 08:27:36 UTC (second).

In all three builds, `.text` is writable (0xE0000020; the genuine library has 0x60000020). The `.reloc` section is all zeros while DYNAMIC_BASE stays set. The first-generation DLL loads at its preferred base 0x180000000.

## 3. Code cave and implant

The first-generation cave spans RVA 0x1AA255 to 0x1B0924. Three chained layers follow. Each layer first calls a stub that repairs its own loop bytes: XOR and NOT in layer 1 (stub at 0x1B0925), XOR, ROR and ADD in layer 2, ROR and XOR in layer 3. A rolling-XOR loop then decrypts the rest of the cave. The 78,599 executed basic blocks are mostly the 78,576 loop iterations (0x66AB + 0x665A + 0x65EB). The first layer's loop:

```
mov  r8b, 0x4C          ; seed (first layer)
mov  rcx, 0x66AB        ; length
lea  rsi, [rip+9]
L: xor  byte [rsi+rcx], r8b
   add  r8b, byte [rsi+rcx]
   loop L
```

The result is a 26,315-byte implant (entry RVA 0x1ADE89) with no readable strings. It has flattened control flow and resolves APIs by walking the PEB and hashing names. Constants go through a decoder at RVA 0x1AF36E, called from 174 sites; the 143 sites that pass constant arguments were decoded:

```python
def dec(ecx, edx):
    edx = (edx + 0x162F0) & 0xFFFFFFFF
    d   = (~edx) & 0xFFFFFFFF
    r8  = (edx | 0xC408A890) & 0xDC38E890
    r9  = (d   | 0x18304000) & 0xDC38E890
    d   = ((d & 0x20800540) | r8) ^ ecx
    return ((((edx & 0x0347122F) | r9) ^ d) ^ 0x38B04540) & 0xFFFFFFFF
```

Everything after the add is bitwise, so testing all four bit combinations proves the decoder equals `ecx ^ (edx + 0x162F0)`. API names are hashed with plain Adler-32 (modulus 0xFFF1 from the decoder). It gives 0x1D5D0468 for `GetUserGeoID` and 0x73070947 for `GetUserDefaultUILanguage`.

## 4. Implant gates and locale exits

1. Bogus share: the implant loads `mpr.dll` and calls `WNetAddConnection2W` (RESOURCETYPE_DISK) for `{asAS}{{}W{}@kj21jjksaxjxa`, then `WNetGetResourceParentW`. It requires last-error values 67 (ERROR_BAD_NET_NAME) and 487 (ERROR_INVALID_ADDRESS), decoded as `dec(0x611F99,0x5FBCEA)` and `dec(0x612099,0x5FBE8E)`.
2. CPU count: `NumberOfProcessors` at PEB+0xB8 must be at least 3.
3. Refresh rate: through `CreatePipe` and `CreateProcessA` it runs `cmd /c powershell "Get-WmiObject Win32_VideoController | Select-Object -ExpandProperty CurrentRefreshRate"`. It reads the output as decimal digits and adds each CRLF-terminated line to a sum. A last line without CRLF is not counted, and digits are not validated. The gate passes if the sum over all display adapters is at least 20, so one ordinary monitor passes.

A failed gate feeds a wrong value into a computed jump. At gate 3 the implant calls the sum itself as an address, with MessageBox-shaped arguments. Without a display adapter the sum is 0 and the implant crashes with 0xC0000005 while executing address 0. An output of `19` crashes at 0x13, while `20`, or two lines of `10`, passes.

Next, `GetUserGeoID(GEOCLASS_NATION)` is compared with ten GeoIDs: 5 Azerbaijan, 7 Armenia, 29 Belarus, 130 Kyrgyzstan, 137 Kazakhstan, 152 Moldova, 203 Russia, 228 Tajikistan, 238 Turkmenistan and 247 Uzbekistan. On a match the implant calls `ExitProcess(501)`. It then calls `ExitProcess(502)` if `GetUserDefaultUILanguage` returns exactly 0x0419 (ru-RU). The first check uses the user's home location, not the interface language, so a host set to one of these countries exits even with an English interface. Ukraine (241), Georgia (88) and every other location go on. With the home location set to Russia and to Belarus, runs exited with code 501; with Ukraine, the run went on to load `amshtml.dll`.

## 5. manifest.json and the mshtml.dll carrier

The implant reads `\\?\<dir>\manifest.json`, builds the carrier described below and copies the file into the carrier's new section. From offset 1 it XORs every byte except 0x00 and 0x08 with 0x08, then calls the buffer. That is the implant's whole transform, and no Windows crypto API is involved. After the XOR, the first five bytes are a `call` (E8 rel32) to a stub 0x37 bytes before the end of the file. The stub repairs four dwords and jumps to offset 5. There, one rolling-XOR layer of the same kind as the cave's decrypts the rest. The first-generation layer has seed 0x2B and length 0x117125.

| Manifest | XOR | Tail stub | Stub repairs | Layer length |
|---|---|---|---|---|
| First generation, 1,143,174 B | 0x08 | 0x11714F | ror, sub, add, rol | 0x117125 |
| Beside 9c7d1a81, 1,143,044 B | 0x08 | 0x1170C9 | ror, not, xor, rol | 0x1170A3 |
| Beside 279c4c97, 1,122,428 B | 0x08 | 0x11203D | ror, not, xor, ror | 0x112018 |

The other two manifests decrypt with the same XOR key through to the loader's integrity check (section 6).

At runtime, `amshtml.dll` appeared in the bundle folder 1.3 to 2.4 s after launch. It is the victim's own `C:\Windows\System32\mshtml.dll` with rewritten headers and an added eighth section:

- Name `.text`, duplicating the existing section name.
- VA 0x0169A000, virtual size 0x01139186.
- Characteristics 0xE0000000 (read, write, execute) without the CNT_CODE flag.

On disk, the section holds a copy of the original `.text`. The implant loads the file with `LoadLibraryA`, copies the manifest into the section in memory and calls it there. The copy is 41,672,704 B and its hash follows the victim's Windows patch level, so it is not an indicator.

## 6. Stage 4: Donut loader

After the layer, the manifest calls over a context block into a loader. The block and the loader match the open-source Donut shellcode generator field for field. This identification is inferred from the structure. The fields are the instance length, master key, counter, IV, an API hash table, entropy mode 3 (encrypt), a MAC, the DLL list `ole32;oleaut32;wininet;mscoree;shell32` and an embedded module. The module has type 4 (unmanaged EXE) and is compressed with aPLib.

The instance is decrypted with Chaskey-LTS (16 rounds) in counter mode. APIs resolve as `H(lower-case DLL name) XOR H(export name)`, where `H` is Donut's Maru hash: a Merkle-Damgård construction over a 27-round Speck64/128-style cipher. Its seed is the instance IV, 0x042D307C42873E26 in the first generation. Donut's integrity check, a Maru hash of a decrypted signature field compared with a stored MAC, passes in all three builds. That validates every decryption step before it. Resolved APIs include `VirtualAlloc`, `VirtualProtect`, `RtlDecompressBuffer` and `NtContinue`. `NtTraceEvent` is looked up by name.

Stage 4 creates a 0x155000-byte section with `NtCreateSection`. It maps a read-write view (0x04), unmaps it and maps the section again with PAGE_EXECUTE_WRITECOPY (0x80). The read-write view most likely serves to write the image (inferred). It then sets per-range protections, including execute-read (0x20) on two ranges, and leaves the header page zeroed and read-only (0x02). Last, it loads `mscoree.dll`; at runtime `clr.dll` followed at 1,807 ms.

## 7. Stage 5 and the .NET stealer

Depacking the Donut module gives a complete x64 PE whose length equals the module's stated length. Stage 4 maps the first-generation PE as a 1,396,736-byte (0x155000) image and zeroes its first 0x1000-byte page, the header. The remaining 1,392,640 B, from offset 0x1000, hold three parts (offsets relative to that point):

- 0x0 to 0x2C200: a .NET assembly, at raw offset 0x400 of the PE.
- 0x2C400 to 0x68000: 244,736 B, mostly high-entropy. Exception data places eight functions here, 11,908 B in all, including the entry point, a 5-byte thunk. The rest is two high-entropy runs that nothing outside them references.
- 0x68000 to 0x154000: native code under a virtual-machine obfuscator.

| Manifest | Stage-5 PE | .NET assembly | .NET TimeDateStamp |
|---|---|---|---|
| First generation | c43f6c1c, 1,370,624 B | 89e6a5cc, 180,736 B | 2026-08-31 14:45:14 UTC |
| Beside 9c7d1a81 | 66ca1b60, 1,369,088 B | 923bc01c, 177,664 B | 2026-08-31 14:45:14 UTC |
| Beside 279c4c97 | 5c6fc701, 1,330,688 B | 055b7dbd, 142,848 B | 2026-07-29 04:04:17 UTC |

The first-generation .NET assembly from static decryption is identical to the one recovered from memory at runtime.

| Field | Value |
|---|---|
| Payload | SHA-256 of payload 89e6a5ccf6ddcb326983b2eac32d9ce0b9c4cbe0b1c0e3617a43a847d52efa1a, 180,736 B |
| Format | PE32+ CLI, AddressOfEntryPoint 0, TimeDateStamp 2026-08-31 14:45:14 UTC |
| Identity | assembly `box4`, module `box4.exe`, version 1.0.0.0 |
| Metadata | 117 types with random names; `#US` heap of 60 B holding only `WbemScripting.SWbemLocator`; one FieldRVA |

Strings are built inline from IL constants, for example `dup; ldc.i4; ldc.i4; xor; stelem` runs. Constant folding recovers all 173 string sites. A screen capture with a JPEG encoder is reachable; section 10 gives the condition.

## 8. Startup, configuration and expiry

`Main` runs only if WMI `Win32_OperatingSystem.MUILanguages` lacks `ru-RU` and the campaign GUID is 36 characters long. The configuration holds:

- Protocol version 3.
- Campaign GUID `3be7d45a-d61d-4fc6-978e-a14381b199cb`.
- Endpoints `188.34.196.109:31078` (stored as UTF-16 bytes) and `2.28.37.159:24241` (a char array).
- A 16-byte bootstrap key from the FieldRVA.
- Base date `2026-10-01T21:00:00Z`.

The client loops over both endpoints without limit and sleeps a random 5 to 10 s between rounds. In the run, it opened TCP to 188.34.196.109:31078 at 2,207 ms.

Hosting readings come from RDAP and BGP lookups on 2026-10-07 and from RDAP on 2026-11-05 for the second-generation addresses. On 2026-10-07 at 07:21 UTC, 188.34.196.109:31078 accepted connect-only TCP probes and 2.28.37.159:24241 timed out three times.

Expiry is the base date plus 5.0 days, 2026-10-06 21:00 UTC, on the local clock. The server time it receives is ignored. The check runs only after registration and the server's reply. An expired build then closes the connection and exits before collection. A run 13 h 32 m after expiry still connected and registered, as the code predicts.

The second-generation configurations share the campaign GUID, protocol version and bootstrap key with the first, but their endpoints differ:

| Item | First generation | Beside 9c7d1a81 | Beside 279c4c97 |
|---|---|---|---|
| Endpoints, in order | `188.34.196.109:31078`, `2.28.37.159:24241` | `91.98.226.140:63324`, `2.28.37.159:24241` | `167.233.240.6:35573`, `178.104.232.30:15766` |
| Campaign GUID | `3be7d45a-d61d-4fc6-978e-a14381b199cb` | same | same |
| Protocol version | 3 | 3 | 3 |
| Expiry base + offset | 2026-10-01 21:00 UTC + 5.0 d | 2026-10-01 21:00 UTC + 5.0 d | 2026-09-01 21:00 UTC + 5.0 d |
| Bootstrap key | FieldRVA | FieldRVA, same bytes | inline array, same bytes |
| `ru-RU` check in `Main` | yes | yes | yes |

The 279c4c97 assembly also hides some strings with a per-character XOR over stored literals.

## 9. C2 protocol

Frames are `uint32 LE length || IV (16) || AES-CBC ciphertext` with PKCS#7 and a fresh random IV. The 16-byte bootstrap key (AES-128) protects frames until the server's reply supplies a session key, whose length sets the AES key size.

A custom tagged serializer encodes the messages. Primitives use their .NET TypeCode as the tag (Int32 = 9, String = 18). Other tags are 0 null, 80 Guid, 81 byte[], 82 dictionary, 83 list, 84 object, 85 DateTime and 86 TimeSpan. Lengths are int32 LE.

- Registration: an object with four properties: int32 3, the GUID, one string that concatenates the WMI user name (`HOST\user`), the CPU name and any video-controller names, and 128 to 256 random bytes.
- Reply: the session key, the server time, and a byte array.
- Settings: two booleans. If the second is true, the stealer sends a full-screen JPEG (quality 70) right after the host profile. The first is never read.

The captured 324-byte registration frame has a length prefix of 320, the IV and 304 B of ciphertext. The bootstrap key decrypts it to 300 B that parse with nothing left over.

## 10. Collection

After registration, the stealer runs these steps in order:

1. Host profile: user, domain, OS version, architecture, time zone, video controllers, resolution, UI languages and CPU.
2. Screenshot, only if the server's second setting is true: the full screen at the WMI-reported resolution, as a JPEG at quality 70.
3. Discovery in Roaming and Local AppData to depth 3: `discord` and `tdata` folders, Chromium and Gecko profiles, and files with "wallet" in the name. It skips names with "backup" or "lock" and some extensions.
4. Chromium keys through the ABE bypass (section 12), then per-profile data. Server lists select the extensions.
5. An exchange covering `Local State`, Local Storage, server-chosen paths and Steam. Server lists pick what to send next.
6. Server tasks (section 11).
7. File grab from server-sent paths with include, exclude and size rules. Paths use tokens such as `$DOCUMENTS$`, `$ROAMING$` and `%recent%`.

Named targets include Chromium `Login Data`, `Cookies`, `Web Data`, `History` and extension storage, and Gecko `logins.json`, `key4.db` and `cookies.sqlite`. They also include Steam `loginusers.vdf`, `config.vdf` and `local.vdf`, and Telegram Desktop `tdata`. No wallet-extension IDs are hard-coded.

## 11. Server tasking

Each task has a type byte, a string and a byte array:

| Type | Action |
|---|---|
| 0 | Write the bytes to `%TEMP%\<new GUID as 32 hex digits>\<name>`. Run `.dll` as `rundll32 "<path>",EntryPoint` and `.ps1` as `powershell -ExecutionPolicy Bypass -File "<path>"`, both hidden. Open other files with `UseShellExecute`. |
| 1 | Start hidden PowerShell (`-NoProfile`, bitness matched to the OS) and write the string to its standard input. |
| 2 | Start hidden `cmd` and write the string to its standard input. |
| 3, 4 | No action. |
| 5 | `WebClient.DownloadString(<string>)`, then pipe the text into PowerShell as in type 1. |

The output handlers are empty, so results never go back to the server.

## 12. Chrome App-Bound Encryption bypass

The server sends two shellcode blobs and two PowerShell templates, one each for 32-bit and 64-bit. Per browser, with up to three tries, the stealer does the following:

1. Start the browser with CREATE_SUSPENDED, first with `--isolated`, then without.
2. Replace the UTF-16 marker `__AE_SHM_MARKER_` in the shellcode with a section name `Local\{GUID}`.
3. If bitness matches: create an RWX section with `NtCreateSection` and copy the shellcode in. Map it into the browser, queue it with `NtQueueApcThread` and call `NtResumeThread`.
4. Otherwise: fill `{process_id}`, `{thread_id}`, `{shell_array}` and `{shell_len}` in the template and run it with PowerShell of the matching bitness.
5. Exchange data over an 8,421,392-byte shared section. Post a path, then the encrypted key, with up to 10,000 ms to post each and up to 15,000 ms to wait for each reply. A reply of ASCII `0` to the path is a failure; a 32-byte reply to the key is the decrypted key.

The code handles `app_bound_encrypted_key` and `encrypted_key` and calls `CryptUnprotectData`.

## 13. Crypto material

| Value | Bytes | Location |
|---|---|---|
| Bootstrap AES-128 key | `7b 41 c3 30 b5 76 fa 8d 0c e9 09 c2 b1 e4 d1 50` | .NET FieldRVA 0x2048; same bytes in all three builds |
| Cave stub constants | XOR imm32 0x6431AFA4 and 0xC638E104 | stub at RVA 0x1B0925 |
| First cave layer | seed 0x4C, length 0x66AB | cave |
| Manifest XOR | 0x08 from offset 1; bytes 0x00 and 0x08 unchanged | implant |
| Manifest layer | seed 0x2B, length 0x117125 | first-generation manifest, offset 5 |
| Donut instance IV, Maru seed | 0x042D307C42873E26 (in memory `26 3e 87 42 7c 30 2d 04`) | first-generation Donut instance |

The bootstrap key decrypts the captured registration frame, and any other frame sent before the key switch.

## 14. Scope and method

- **Samples:** three tampered Qt5Widgets.dll builds, their three encrypted manifest files, the stages decrypted from all three manifests, 48 distribution archives
- **Methods:** static analysis; emulation; decompiled .NET source; contained runs of `Xen.zip` on Windows Server 2022 with a simulated network (2026-10-07, 2026-11-05); gate 3 refresh-rate output supplied through a PowerShell profile; RDAP and BGP lookups for hosting
- **Coverage:** The first-generation chain was run through to C2 check-in; the second-generation stages and configurations come from static decryption and decompiled code. Gates, locale exits, the C2 protocol, collection and server tasking come from code and emulation, with runs confirming the gate outcomes, the 501 exit and the C2 check-in.

## Indicators

### Malicious

| IOC | Type | Value | Context |
|---|---|---|---|
| Tampered DLL | SHA-256 | ae2c669940e2fdefd42d90fe644b9773abd68f8eefd8d7ed4c69dc69b4c507df | Qt5Widgets.dll, 5,498,992 B, broken TeamSpeak signature; in 37 archives |
| Tampered DLL | SHA-256 | 279c4c973059bbc86c06a1c076f53912a6eb4159e08e0f91ffed56c77777778f | Qt5Widgets.dll, 5,580,800 B, unsigned; in 8 archives |
| Tampered DLL | SHA-256 | 9c7d1a813bd9898579a4e50111bd421aebadeb722139062afc89c8bf0803e74f | Qt5Widgets.dll, 5,580,800 B, unsigned; in 3 archives |
| Encrypted manifest | SHA-256 | 3a3e50b8be1ae108aa73271fece6ad74a3a54965a49f238a3aaa4babcdf07f42 | `manifest.json`, 1,143,174 B; ships with Qt5Widgets.dll, SHA-256 of file ae2c669940e2fdefd42d90fe644b9773abd68f8eefd8d7ed4c69dc69b4c507df |
| Encrypted manifest | SHA-256 | ba7683080154c7aa226a624f6c7946065a6e679fa6742af27e449d34e87f3925 | `manifest.json`, 1,143,044 B; ships with Qt5Widgets.dll, SHA-256 of file 9c7d1a813bd9898579a4e50111bd421aebadeb722139062afc89c8bf0803e74f |
| Encrypted manifest | SHA-256 | f321146ce5c90b3f7189f1829805b7c29efdd615b18ea2b236ad77e516788f19 | `Dependencies.manifest`, 1,122,428 B; ships with Qt5Widgets.dll, SHA-256 of file 279c4c973059bbc86c06a1c076f53912a6eb4159e08e0f91ffed56c77777778f |
| Cave implant | SHA-256 (payload) | 69ad86d0ba016402353d9cd107c975308e061b49036c9c1ec98edd483a2f2950 | Decrypted from the code cave of Qt5Widgets.dll, SHA-256 of file ae2c669940e2fdefd42d90fe644b9773abd68f8eefd8d7ed4c69dc69b4c507df; 26,315 B, exists only in memory |
| Stage 5 | SHA-256 (payload) | c43f6c1c358295946cc84bf4f1b35972cb5ae7de32d4772042e690857c35bf54 | x64 PE carrying the .NET stealer, 1,370,624 B; unpacked from `manifest.json`, SHA-256 of file 3a3e50b8be1ae108aa73271fece6ad74a3a54965a49f238a3aaa4babcdf07f42 |
| Stage 5 | SHA-256 (payload) | 66ca1b6049b15f2ed29cb80055e208dd522c5c33484ffea7e8d1ac2f01d897f9 | x64 PE carrying the .NET stealer, 1,369,088 B; unpacked from `manifest.json`, SHA-256 of file ba7683080154c7aa226a624f6c7946065a6e679fa6742af27e449d34e87f3925 |
| Stage 5 | SHA-256 (payload) | 5c6fc70185731673c8a56890f1e281d8f07c4c72c55d6f6718e8c5a959e5fa0c | x64 PE carrying the .NET stealer, 1,330,688 B; unpacked from `Dependencies.manifest`, SHA-256 of file f321146ce5c90b3f7189f1829805b7c29efdd615b18ea2b236ad77e516788f19 |
| Infostealer | SHA-256 (payload) | 89e6a5ccf6ddcb326983b2eac32d9ce0b9c4cbe0b1c0e3617a43a847d52efa1a | .NET, assembly name `box4`, 180,736 B; carried in the stage-5 PE, SHA-256 of payload c43f6c1c358295946cc84bf4f1b35972cb5ae7de32d4772042e690857c35bf54 |
| Infostealer | SHA-256 (payload) | 923bc01c91da68413f16e9fb603d0d36ec2b3e7a22c6f362d1d216eee4b50c6b | .NET, 177,664 B; carried in the stage-5 PE, SHA-256 of payload 66ca1b6049b15f2ed29cb80055e208dd522c5c33484ffea7e8d1ac2f01d897f9 |
| Infostealer | SHA-256 (payload) | 055b7dbd085d0ff1f93665f7b51569a3818f68dd0a8c9fd6c91d3e4602d43da7 | .NET, 142,848 B; carried in the stage-5 PE, SHA-256 of payload 5c6fc70185731673c8a56890f1e281d8f07c4c72c55d6f6718e8c5a959e5fa0c |
| Campaign GUID | GUID | `3be7d45a-d61d-4fc6-978e-a14381b199cb` | Hard-coded in the .NET stealers SHA-256 of payload 89e6a5ccf6ddcb326983b2eac32d9ce0b9c4cbe0b1c0e3617a43a847d52efa1a, SHA-256 of payload 923bc01c91da68413f16e9fb603d0d36ec2b3e7a22c6f362d1d216eee4b50c6b and SHA-256 of payload 055b7dbd085d0ff1f93665f7b51569a3818f68dd0a8c9fd6c91d3e4602d43da7; sent with protocol version 3 in the registration frame |
| Patched copy | File name | `amshtml.dll` | `mshtml.dll` copy with a second `.text` section marked 0xE0000000, beside a game-named executable; written by the implant in Qt5Widgets.dll, SHA-256 of file ae2c669940e2fdefd42d90fe644b9773abd68f8eefd8d7ed4c69dc69b4c507df; its hash follows the host's Windows patch level |
| C2 | IP:port | 188.34.196.109:31078 | Primary C2 of the .NET stealer SHA-256 of payload 89e6a5ccf6ddcb326983b2eac32d9ce0b9c4cbe0b1c0e3617a43a847d52efa1a, raw TCP; Hetzner, Nuremberg, AS24940 |
| C2 | IP:port | 2.28.37.159:24241 | Secondary C2 of the .NET stealer SHA-256 of payload 89e6a5ccf6ddcb326983b2eac32d9ce0b9c4cbe0b1c0e3617a43a847d52efa1a, raw TCP; also the second endpoint of the .NET stealer SHA-256 of payload 923bc01c91da68413f16e9fb603d0d36ec2b3e7a22c6f362d1d216eee4b50c6b; Hetzner, Falkenstein, AS24940; range registered 2026-09-08 |
| C2 | IP:port | 91.98.226.140:63324 | First endpoint of the .NET stealer SHA-256 of payload 923bc01c91da68413f16e9fb603d0d36ec2b3e7a22c6f362d1d216eee4b50c6b; Hetzner, Nuremberg, AS24940; range registered 2025-10-15 |
| C2 | IP:port | 167.233.240.6:35573 | First endpoint of the .NET stealer SHA-256 of payload 055b7dbd085d0ff1f93665f7b51569a3818f68dd0a8c9fd6c91d3e4602d43da7; Hetzner, Nuremberg, AS24940; range registered 2026-07-01 |
| C2 | IP:port | 178.104.232.30:15766 | Second endpoint of the .NET stealer SHA-256 of payload 055b7dbd085d0ff1f93665f7b51569a3818f68dd0a8c9fd6c91d3e4602d43da7; Hetzner, Nuremberg, AS24940; range registered 2026-04-20 |
| Archive | SHA-256 | 7bb7e70398f3aa3a872ad158258fd070ac055c8e7bcaf1bf78510a21b9ed3d0f | `Among.zip`; 32-bit host executable; holds Qt5Widgets.dll, SHA-256 of file ae2c669940e2fdefd42d90fe644b9773abd68f8eefd8d7ed4c69dc69b4c507df |
| Download | URL | https://www.mediafire.com/file/7r6e4cdko40evua/Among.zip/file | Serves `Among.zip`, SHA-256 of file 7bb7e70398f3aa3a872ad158258fd070ac055c8e7bcaf1bf78510a21b9ed3d0f |
| Archive | SHA-256 | 88cda02be5fd58f45379f2fbfa3279351f0384d57030c7b5e1c8ef37c7afc7d9 | `Among.zip`; holds Qt5Widgets.dll, SHA-256 of file ae2c669940e2fdefd42d90fe644b9773abd68f8eefd8d7ed4c69dc69b4c507df |
| Download | URL | https://www.mediafire.com/file/u0e1znzpgqttc6q/Among.zip/file | Serves `Among.zip`, SHA-256 of file 88cda02be5fd58f45379f2fbfa3279351f0384d57030c7b5e1c8ef37c7afc7d9 |
| Archive | SHA-256 | 01843ecda7c87c688d5a40476674a64d8a062da7a753fe1bbf4a24607cbb130b | `AntiVCBanScript.zip`; holds Qt5Widgets.dll, SHA-256 of file ae2c669940e2fdefd42d90fe644b9773abd68f8eefd8d7ed4c69dc69b4c507df |
| Download | URL | https://www.mediafire.com/file/1ix31bi48g1ejm4/AntiVCBanScript.zip/file | Serves `AntiVCBanScript.zip`, SHA-256 of file 01843ecda7c87c688d5a40476674a64d8a062da7a753fe1bbf4a24607cbb130b |
| Archive | SHA-256 | e4867b586cf71d268d4a0341d6e7de12903d2c388d08b7df6b1e1cb553fdc222 | `BlockSpinScript.zip`; holds Qt5Widgets.dll, SHA-256 of file ae2c669940e2fdefd42d90fe644b9773abd68f8eefd8d7ed4c69dc69b4c507df |
| Download | URL | https://www.mediafire.com/file/t3hoio395c14feo/BlockSpinScript.zip/file | Serves `BlockSpinScript.zip`, SHA-256 of file e4867b586cf71d268d4a0341d6e7de12903d2c388d08b7df6b1e1cb553fdc222 |
| Archive | SHA-256 | 2dee1264ddec5c12d8301cf492928446c73b850c3b73596204ebb27f103f8f8b | `BloxFruitsScript.zip`; holds Qt5Widgets.dll, SHA-256 of file ae2c669940e2fdefd42d90fe644b9773abd68f8eefd8d7ed4c69dc69b4c507df |
| Download | URL | https://www.mediafire.com/file/k8pb1o9vs35vfni/BloxFruitsScript.zip/file | Serves `BloxFruitsScript.zip`, SHA-256 of file 2dee1264ddec5c12d8301cf492928446c73b850c3b73596204ebb27f103f8f8b |
| Archive | SHA-256 | ba78d6a2a30a8eba34d1e766801f8ce551a4a37cbf14e0d2c551bbf955d8c26d | `BrookhavenScript.zip`; holds Qt5Widgets.dll, SHA-256 of file ae2c669940e2fdefd42d90fe644b9773abd68f8eefd8d7ed4c69dc69b4c507df |
| Download | URL | https://www.mediafire.com/file/pgu8ojp7ne4jawh/BrookhavenScript.zip/file | Serves `BrookhavenScript.zip`, SHA-256 of file ba78d6a2a30a8eba34d1e766801f8ce551a4a37cbf14e0d2c551bbf955d8c26d |
| Archive | SHA-256 | ec34d90d868ba5b22187e62d4e7d04340dbc93df6e243bf77144f46bcd16fc10 | `Cs2Hack.zip`; holds Qt5Widgets.dll, SHA-256 of file ae2c669940e2fdefd42d90fe644b9773abd68f8eefd8d7ed4c69dc69b4c507df |
| Download | URL | https://www.mediafire.com/file/lgd6tbvf4npa1os/Cs2Hack.zip/file | Serves `Cs2Hack.zip`, SHA-256 of file ec34d90d868ba5b22187e62d4e7d04340dbc93df6e243bf77144f46bcd16fc10 |
| Archive | SHA-256 | 5fcdbace13016facf62cb8c8b39677dd62c51b49d460d5361c98d653b6173a57 | `Cs2SkinChanger.zip`; holds Qt5Widgets.dll, SHA-256 of file ae2c669940e2fdefd42d90fe644b9773abd68f8eefd8d7ed4c69dc69b4c507df |
| Download | URL | https://www.mediafire.com/file/dzsd1c0f3ff9t5u/Cs2SkinChanger.zip/file | Serves `Cs2SkinChanger.zip`, SHA-256 of file 5fcdbace13016facf62cb8c8b39677dd62c51b49d460d5361c98d653b6173a57 |
| Archive | SHA-256 | f4d07d1bf0e47805b3957527c7ab4e1d4680120ef6c050f288de66e4d9aa5009 | `Delt.zip`; holds Qt5Widgets.dll, SHA-256 of file ae2c669940e2fdefd42d90fe644b9773abd68f8eefd8d7ed4c69dc69b4c507df |
| Download | URL | https://www.mediafire.com/file/p3mfnlwgzn6rl90/Delt.zip/file | Serves `Delt.zip`, SHA-256 of file f4d07d1bf0e47805b3957527c7ab4e1d4680120ef6c050f288de66e4d9aa5009 |
| Archive | SHA-256 | 267523e4bbff53d87c1635d096675b02b1020e37bcab06ab004b102cc4c3b99c | `DrivingEmpireScript.zip`; holds Qt5Widgets.dll, SHA-256 of file ae2c669940e2fdefd42d90fe644b9773abd68f8eefd8d7ed4c69dc69b4c507df |
| Download | URL | https://www.mediafire.com/file/0e25dn3o0qh66ec/DrivingEmpireScript.zip/file | Serves `DrivingEmpireScript.zip`, SHA-256 of file 267523e4bbff53d87c1635d096675b02b1020e37bcab06ab004b102cc4c3b99c |
| Archive | SHA-256 | 9eeae5924a7a4af7bf005b9bf17e4bff3a5ab79a8c97ca8543e8a55105aa61e4 | `FischScript.zip`; holds Qt5Widgets.dll, SHA-256 of file ae2c669940e2fdefd42d90fe644b9773abd68f8eefd8d7ed4c69dc69b4c507df |
| Download | URL | https://www.mediafire.com/file/abcanpat41elbwe/FischScript.zip/file | Serves `FischScript.zip`, SHA-256 of file 9eeae5924a7a4af7bf005b9bf17e4bff3a5ab79a8c97ca8543e8a55105aa61e4 |
| Archive | SHA-256 | c6738f708ca400e9c13eb391c6ed21cc52f1f5b11cf8d659f015a154fa75e846 | `FivemModMenu.zip`; holds Qt5Widgets.dll, SHA-256 of file ae2c669940e2fdefd42d90fe644b9773abd68f8eefd8d7ed4c69dc69b4c507df |
| Download | URL | https://www.mediafire.com/file/f7i7amq73a64bp9/FivemModMenu.zip/file | Serves `FivemModMenu.zip`, SHA-256 of file c6738f708ca400e9c13eb391c6ed21cc52f1f5b11cf8d659f015a154fa75e846 |
| Archive | SHA-256 | 9efb6ca73fc38e775e254aca48247585d99cc073e02ff71b21b666d90cc7b562 | `FortniteMenu.zip`; holds Qt5Widgets.dll, SHA-256 of file ae2c669940e2fdefd42d90fe644b9773abd68f8eefd8d7ed4c69dc69b4c507df |
| Download | URL | https://www.mediafire.com/file/6lpq2g621o5ri90/FortniteMenu.zip/file | Serves `FortniteMenu.zip`, SHA-256 of file 9efb6ca73fc38e775e254aca48247585d99cc073e02ff71b21b666d90cc7b562 |
| Archive | SHA-256 | 46501cd364c814affb3b2fa1aaf87fc68d99d0927bd362595ef228ea8b4cf264 | `Forza6ModMenu.zip`; holds Qt5Widgets.dll, SHA-256 of file ae2c669940e2fdefd42d90fe644b9773abd68f8eefd8d7ed4c69dc69b4c507df |
| Download | URL | https://www.mediafire.com/file/57p0srdiylkr3y4/Forza6ModMenu.zip/file | Serves `Forza6ModMenu.zip`, SHA-256 of file 46501cd364c814affb3b2fa1aaf87fc68d99d0927bd362595ef228ea8b4cf264 |
| Archive | SHA-256 | 90959c6ec3bdd6f3859dd993eb56e7b6f3985b2dee6d92caec8f5ee6a1efb0ac | `FortniteSkinSwapper.zip`; holds Qt5Widgets.dll, SHA-256 of file ae2c669940e2fdefd42d90fe644b9773abd68f8eefd8d7ed4c69dc69b4c507df |
| Download | URL | https://www.mediafire.com/file/hcnaqkc6rmj11p5/FortniteSkinSwapper.zip/file | Serves `FortniteSkinSwapper.zip`, SHA-256 of file 90959c6ec3bdd6f3859dd993eb56e7b6f3985b2dee6d92caec8f5ee6a1efb0ac |
| Archive | SHA-256 | 017bd2895edba1c19fa917a6e9874f804f9109b9da343b5934d5f6211a348830 | `GenshinHack.zip`; holds Qt5Widgets.dll, SHA-256 of file ae2c669940e2fdefd42d90fe644b9773abd68f8eefd8d7ed4c69dc69b4c507df |
| Download | URL | https://www.mediafire.com/file/s9p6azd1vohx54f/GenshinHack.zip/file | Serves `GenshinHack.zip`, SHA-256 of file 017bd2895edba1c19fa917a6e9874f804f9109b9da343b5934d5f6211a348830 |
| Archive | SHA-256 | e24dca25218e71110d74881485c1c4b2c80151e57f869a7e7055a582cdcea39a | `GrowGarden2Script.zip`; holds Qt5Widgets.dll, SHA-256 of file ae2c669940e2fdefd42d90fe644b9773abd68f8eefd8d7ed4c69dc69b4c507df |
| Download | URL | https://www.mediafire.com/file/johsf79v46264rl/GrowGarden2Script.zip/file | Serves `GrowGarden2Script.zip`, SHA-256 of file e24dca25218e71110d74881485c1c4b2c80151e57f869a7e7055a582cdcea39a |
| Archive | SHA-256 | b18503cc223adb5faf118d97dd8727ef729132ad77e2e76051e444b0d86e5a2c | `JailbreakScript.zip`; holds Qt5Widgets.dll, SHA-256 of file ae2c669940e2fdefd42d90fe644b9773abd68f8eefd8d7ed4c69dc69b4c507df |
| Download | URL | https://www.mediafire.com/file/gty8eouxohyfdfp/JailbreakScript.zip/file | Serves `JailbreakScript.zip`, SHA-256 of file b18503cc223adb5faf118d97dd8727ef729132ad77e2e76051e444b0d86e5a2c |
| Archive | SHA-256 | f896b8c3e0b3cd2124f4218bc6c7d6307fc98fe85fceef046f1616cae02e493c | `KiddonsModMenu.zip`; holds Qt5Widgets.dll, SHA-256 of file ae2c669940e2fdefd42d90fe644b9773abd68f8eefd8d7ed4c69dc69b4c507df |
| Download | URL | https://www.mediafire.com/file/6bye9twk5i8jx5c/KiddonsModMenu.zip/file | Serves `KiddonsModMenu.zip`, SHA-256 of file f896b8c3e0b3cd2124f4218bc6c7d6307fc98fe85fceef046f1616cae02e493c |
| Archive | SHA-256 | dc37960b41d40d3fb287f9b1836938592611c40649af3edfeac7b2a994e0e524 | `KrnlExecutor.zip`; holds Qt5Widgets.dll, SHA-256 of file ae2c669940e2fdefd42d90fe644b9773abd68f8eefd8d7ed4c69dc69b4c507df |
| Download | URL | https://www.mediafire.com/file/1ndpveq6f9zfukf/KrnlExecutor.zip/file | Serves `KrnlExecutor.zip`, SHA-256 of file dc37960b41d40d3fb287f9b1836938592611c40649af3edfeac7b2a994e0e524 |
| Archive | SHA-256 | 2fe1c35cf71a1e4c4b16a6297dd2c985a5b6dc7eebbfbb311ca4487ae16cae89 | `Loader.zip`; Notepad++ updater host; holds Qt5Widgets.dll, SHA-256 of file ae2c669940e2fdefd42d90fe644b9773abd68f8eefd8d7ed4c69dc69b4c507df |
| Download | URL | https://www.mediafire.com/file/ksut4ouain796k1/Loader.zip/file | Serves `Loader.zip`, SHA-256 of file 2fe1c35cf71a1e4c4b16a6297dd2c985a5b6dc7eebbfbb311ca4487ae16cae89 |
| Download | URL | https://www.mediafire.com/file/cmvi8jue7qfzenx/Loader.zip/file | Serves `Loader.zip`, SHA-256 of file 2fe1c35cf71a1e4c4b16a6297dd2c985a5b6dc7eebbfbb311ca4487ae16cae89 |
| Download | URL | https://www.mediafire.com/file/tlmttormmycl44b/Loader.zip/file | Serves `Loader.zip`, SHA-256 of file 2fe1c35cf71a1e4c4b16a6297dd2c985a5b6dc7eebbfbb311ca4487ae16cae89 |
| Archive | SHA-256 | 0370ff3a6ff747cbbc1f674e48ee87717d87e39c635f5bbcc2ee4ce62ccc35fd | `Luna.zip`; holds Qt5Widgets.dll, SHA-256 of file ae2c669940e2fdefd42d90fe644b9773abd68f8eefd8d7ed4c69dc69b4c507df |
| Download | URL | https://www.mediafire.com/file/wa5i4f214bgaoge/Luna.zip/file | Serves `Luna.zip`, SHA-256 of file 0370ff3a6ff747cbbc1f674e48ee87717d87e39c635f5bbcc2ee4ce62ccc35fd |
| Archive | SHA-256 | 188e09d31a3ec9363811e427b0f94a94833d2613ac64375779a9b7ff0a44e3a3 | `MecchaChameleonCheats.zip`; holds Qt5Widgets.dll, SHA-256 of file ae2c669940e2fdefd42d90fe644b9773abd68f8eefd8d7ed4c69dc69b4c507df |
| Download | URL | https://www.mediafire.com/file/btkjgll5g5nvi58/MecchaChameleonCheats.zip/file | Serves `MecchaChameleonCheats.zip`, SHA-256 of file 188e09d31a3ec9363811e427b0f94a94833d2613ac64375779a9b7ff0a44e3a3 |
| Archive | SHA-256 | 56d1f3864dfd05a6aacde43893f6902bc65c3b6a8bdf3b7af830feed523607c1 | `MinecraftHackedClient.zip`; holds Qt5Widgets.dll, SHA-256 of file ae2c669940e2fdefd42d90fe644b9773abd68f8eefd8d7ed4c69dc69b4c507df |
| Download | URL | https://www.mediafire.com/file/shmxpq0camz8asx/MinecraftHackedClient.zip/file | Serves `MinecraftHackedClient.zip`, SHA-256 of file 56d1f3864dfd05a6aacde43893f6902bc65c3b6a8bdf3b7af830feed523607c1 |
| Archive | SHA-256 | 49dae28932581b3c3464a1ac031809cafe70b1ab3b33257084515aee77295139 | `Mm2 menu.zip`; 32-bit host executable; holds Qt5Widgets.dll, SHA-256 of file ae2c669940e2fdefd42d90fe644b9773abd68f8eefd8d7ed4c69dc69b4c507df |
| Download | URL | https://www.mediafire.com/file/wkmghxvvc409bnq/Mm2_menu.zip/file | Serves `Mm2 menu.zip`, SHA-256 of file 49dae28932581b3c3464a1ac031809cafe70b1ab3b33257084515aee77295139 |
| Archive | SHA-256 | 96ce40d6768fabf91accdce8172a5227c8f62ce64b5628e7650a638c9ad96b72 | `MurderMysteryScript.zip`; holds Qt5Widgets.dll, SHA-256 of file ae2c669940e2fdefd42d90fe644b9773abd68f8eefd8d7ed4c69dc69b4c507df |
| Download | URL | https://www.mediafire.com/file/10f1q5jt6kgsgh1/MurderMysteryScript.zip/file | Serves `MurderMysteryScript.zip`, SHA-256 of file 96ce40d6768fabf91accdce8172a5227c8f62ce64b5628e7650a638c9ad96b72 |
| Archive | SHA-256 | c0d5c5af09f060d889de1d9c4165e0f12cc2b166791481f7d9171a3194373657 | `RivalsScript.zip`; holds Qt5Widgets.dll, SHA-256 of file ae2c669940e2fdefd42d90fe644b9773abd68f8eefd8d7ed4c69dc69b4c507df |
| Download | URL | https://www.mediafire.com/file/w0zoku0v2p4dte7/RivalsScript.zip/file | Serves `RivalsScript.zip`, SHA-256 of file c0d5c5af09f060d889de1d9c4165e0f12cc2b166791481f7d9171a3194373657 |
| Archive | SHA-256 | 71be9d497fab0e3e1024f271ce6d389d6aa6094c054542ac8866818c5fc699fd | `RobloxMod.zip`; holds Qt5Widgets.dll, SHA-256 of file ae2c669940e2fdefd42d90fe644b9773abd68f8eefd8d7ed4c69dc69b4c507df |
| Download | URL | https://www.mediafire.com/file/vr211mr4p69a6rn/RobloxMod.zip/file | Serves `RobloxMod.zip`, SHA-256 of file 71be9d497fab0e3e1024f271ce6d389d6aa6094c054542ac8866818c5fc699fd |
| Archive | SHA-256 | 5c3d636ae9cc74832403d09f1dc504c333ae3d4e2102b907126ca3a197ea9a6b | `SniperArenaScript.zip`; holds Qt5Widgets.dll, SHA-256 of file ae2c669940e2fdefd42d90fe644b9773abd68f8eefd8d7ed4c69dc69b4c507df |
| Download | URL | https://www.mediafire.com/file/hej4ikfqb8rl5sy/SniperArenaScript.zip/file | Serves `SniperArenaScript.zip`, SHA-256 of file 5c3d636ae9cc74832403d09f1dc504c333ae3d4e2102b907126ca3a197ea9a6b |
| Archive | SHA-256 | f8d40514a3188a8b28642605bb9a93ce5d0e84b6f4c71fd9739ab41a0fb170d7 | `StealBrainrotScript.zip`; holds Qt5Widgets.dll, SHA-256 of file ae2c669940e2fdefd42d90fe644b9773abd68f8eefd8d7ed4c69dc69b4c507df |
| Download | URL | https://www.mediafire.com/file/462fs6jnr92kvu5/StealBrainrotScript.zip/file | Serves `StealBrainrotScript.zip`, SHA-256 of file f8d40514a3188a8b28642605bb9a93ce5d0e84b6f4c71fd9739ab41a0fb170d7 |
| Archive | SHA-256 | 5ad8c9b50892cf321d6b3a4696f4ea3fe9ce5423af02fadcbc98ed0d89a0180d | `StealEggScript.zip`; holds Qt5Widgets.dll, SHA-256 of file ae2c669940e2fdefd42d90fe644b9773abd68f8eefd8d7ed4c69dc69b4c507df |
| Download | URL | https://www.mediafire.com/file/1nqqbc1ltxt2ww5/StealEggScript.zip/file | Serves `StealEggScript.zip`, SHA-256 of file 5ad8c9b50892cf321d6b3a4696f4ea3fe9ce5423af02fadcbc98ed0d89a0180d |
| Archive | SHA-256 | 201d04e56d833b590c317c53b1b24547ae33edc04da519dbe7351585346443d7 | `Valorant.zip`; 32-bit host executable; holds Qt5Widgets.dll, SHA-256 of file ae2c669940e2fdefd42d90fe644b9773abd68f8eefd8d7ed4c69dc69b4c507df |
| Download | URL | https://www.mediafire.com/file/6j950xab213cl0l/Valorant.zip/file | Serves `Valorant.zip`, SHA-256 of file 201d04e56d833b590c317c53b1b24547ae33edc04da519dbe7351585346443d7 |
| Archive | SHA-256 | a5f30ef2cd8e11efbeaacc6db57c1721aac897d5d227a1bc946b3d7f93197863 | `ValorantHack.zip`; holds Qt5Widgets.dll, SHA-256 of file ae2c669940e2fdefd42d90fe644b9773abd68f8eefd8d7ed4c69dc69b4c507df |
| Download | URL | https://www.mediafire.com/file/zqoizb181qsq3py/ValorantHack.zip/file | Serves `ValorantHack.zip`, SHA-256 of file a5f30ef2cd8e11efbeaacc6db57c1721aac897d5d227a1bc946b3d7f93197863 |
| Archive | SHA-256 | 916137185a230871f35812e85b3d3751f706eb32e91ce00d1ad64d4047e18bd9 | `ValorantSkins.zip`; holds Qt5Widgets.dll, SHA-256 of file ae2c669940e2fdefd42d90fe644b9773abd68f8eefd8d7ed4c69dc69b4c507df |
| Download | URL | https://www.mediafire.com/file/clmcxaphv7yfe0z/ValorantSkins.zip/file | Serves `ValorantSkins.zip`, SHA-256 of file 916137185a230871f35812e85b3d3751f706eb32e91ce00d1ad64d4047e18bd9 |
| Archive | SHA-256 | 60c9b5f8c96715c1d6160f5164cbc84dac9a5bd13c19c0d8d30928f4ab153ec8 | `VolcanoExecutor.zip`; holds Qt5Widgets.dll, SHA-256 of file ae2c669940e2fdefd42d90fe644b9773abd68f8eefd8d7ed4c69dc69b4c507df |
| Download | URL | https://www.mediafire.com/file/5ui5szxcfbvluzf/VolcanoExecutor.zip/file | Serves `VolcanoExecutor.zip`, SHA-256 of file 60c9b5f8c96715c1d6160f5164cbc84dac9a5bd13c19c0d8d30928f4ab153ec8 |
| Archive | SHA-256 | e3b32ca107bf83568d0bd5dc572f9d5eee4454e308abf69509fd703971ab66bd | `VolleyballLegendsScript.zip`; holds Qt5Widgets.dll, SHA-256 of file ae2c669940e2fdefd42d90fe644b9773abd68f8eefd8d7ed4c69dc69b4c507df |
| Download | URL | https://www.mediafire.com/file/y4nkjdchgqqy6li/VolleyballLegendsScript.zip/file | Serves `VolleyballLegendsScript.zip`, SHA-256 of file e3b32ca107bf83568d0bd5dc572f9d5eee4454e308abf69509fd703971ab66bd |
| Archive | SHA-256 | 094af5299c6e521985f02119140a1e4b57f18fad7d8e00de1e8aa3540fd73272 | `Xen.zip`; password `xenoexecutor`; holds Qt5Widgets.dll, SHA-256 of file ae2c669940e2fdefd42d90fe644b9773abd68f8eefd8d7ed4c69dc69b4c507df |
| Download | URL | https://www.mediafire.com/file/kr4xtv7lsmet8ar/Xen.zip/file | Serves `Xen.zip`, SHA-256 of file 094af5299c6e521985f02119140a1e4b57f18fad7d8e00de1e8aa3540fd73272 |
| Archive | SHA-256 | bfa80b88601d8e238cca8b0756792ced643723d61c8c3abab0552a8e58d05985 | `AnimalHospitalScript.zip`; holds Qt5Widgets.dll, SHA-256 of file 279c4c973059bbc86c06a1c076f53912a6eb4159e08e0f91ffed56c77777778f |
| Download | URL | https://www.mediafire.com/file/77yvuutt4kwvoll/AnimalHospitalScript.zip/file | Serves `AnimalHospitalScript.zip`, SHA-256 of file bfa80b88601d8e238cca8b0756792ced643723d61c8c3abab0552a8e58d05985 |
| Archive | SHA-256 | 3fb91f9ee8798a3eb5b380bbb7c4cde1db33a884ef97596230207dcd6fae2779 | `FlexMode.rar`; Notepad++ updater host; holds Qt5Widgets.dll, SHA-256 of file 279c4c973059bbc86c06a1c076f53912a6eb4159e08e0f91ffed56c77777778f |
| Download | URL | https://www.mediafire.com/file/8wgfycm4x25ltpj/FlexMode.rar/file | Serves `FlexMode.rar`, SHA-256 of file 3fb91f9ee8798a3eb5b380bbb7c4cde1db33a884ef97596230207dcd6fae2779 |
| Archive | SHA-256 | ba4788f9356b93e2b98e3c9f5ce1ffcd4054463f2dd2d9ae52a9b438454b83ed | `GameMode.rar`; Notepad++ updater host; holds Qt5Widgets.dll, SHA-256 of file 279c4c973059bbc86c06a1c076f53912a6eb4159e08e0f91ffed56c77777778f |
| Download | URL | https://www.mediafire.com/file/8mwanqcxeppa24r/GameMode.rar/file | Serves `GameMode.rar`, SHA-256 of file ba4788f9356b93e2b98e3c9f5ce1ffcd4054463f2dd2d9ae52a9b438454b83ed |
| Archive | SHA-256 | 2ababff793be99a010fc5427c192fa963c85503cd8e4a116c583717555d0b4e7 | `MurderMysteryScript.rar`; no TeamSpeak host; holds Qt5Widgets.dll, SHA-256 of file 279c4c973059bbc86c06a1c076f53912a6eb4159e08e0f91ffed56c77777778f |
| Download | URL | https://www.mediafire.com/file/srjuvgb4bls6hhi/MurderMysteryScript.rar/file | Serves `MurderMysteryScript.rar`, SHA-256 of file 2ababff793be99a010fc5427c192fa963c85503cd8e4a116c583717555d0b4e7 |
| Archive | SHA-256 | 93ab446d364f85c62ab44ac8b7e34294381a7695cc55930177e815cea4816411 | `PetSimulatorScript.zip`; holds Qt5Widgets.dll, SHA-256 of file 279c4c973059bbc86c06a1c076f53912a6eb4159e08e0f91ffed56c77777778f |
| Download | URL | https://www.mediafire.com/file/wtx5xwer4yteau3/PetSimulatorScript.zip/file | Serves `PetSimulatorScript.zip`, SHA-256 of file 93ab446d364f85c62ab44ac8b7e34294381a7695cc55930177e815cea4816411 |
| Archive | SHA-256 | 8ca1cd37401795a7a66b951861364cfdbd6e533a397a051ba51b5f5372e98171 | `SilentMode.rar`; Notepad++ updater host; holds Qt5Widgets.dll, SHA-256 of file 279c4c973059bbc86c06a1c076f53912a6eb4159e08e0f91ffed56c77777778f |
| Download | URL | https://www.mediafire.com/file/49jdmb58tgvh59m/SilentMode.rar/file | Serves `SilentMode.rar`, SHA-256 of file 8ca1cd37401795a7a66b951861364cfdbd6e533a397a051ba51b5f5372e98171 |
| Archive | SHA-256 | db2be5eb8fcc084c8624ac718c7b17e33b73b04f36f7905269b67fe2bad67255 | `TheStrongestBattlegroundsScript.zip`; holds Qt5Widgets.dll, SHA-256 of file 279c4c973059bbc86c06a1c076f53912a6eb4159e08e0f91ffed56c77777778f |
| Download | URL | https://www.mediafire.com/file/wta3jwqe8z0z2t4/TheStrongestBattlegroundsScript.zip/file | Serves `TheStrongestBattlegroundsScript.zip`, SHA-256 of file db2be5eb8fcc084c8624ac718c7b17e33b73b04f36f7905269b67fe2bad67255 |
| Archive | SHA-256 | a5f479c26732fbab600fa9bc926f6eba082ff4c9f96489dc9fb98a09ec145883 | `ValorantHack.rar`; no TeamSpeak host; holds Qt5Widgets.dll, SHA-256 of file 279c4c973059bbc86c06a1c076f53912a6eb4159e08e0f91ffed56c77777778f |
| Download | URL | https://www.mediafire.com/file/sgt7vu0dv3vx230/ValorantHack.rar/file | Serves `ValorantHack.rar`, SHA-256 of file a5f479c26732fbab600fa9bc926f6eba082ff4c9f96489dc9fb98a09ec145883 |
| Archive | SHA-256 | 12d88135177e19e066a862c038a8dcb485e5e7dd519c31f7ac4f83f531c71c74 | `ARKNIGHT.zip`; no TeamSpeak host; holds Qt5Widgets.dll, SHA-256 of file 9c7d1a813bd9898579a4e50111bd421aebadeb722139062afc89c8bf0803e74f |
| Download | URL | https://www.mediafire.com/file/y5cvbx6b714rh99/ARKNIGHT.zip/file | Serves `ARKNIGHT.zip`, SHA-256 of file 12d88135177e19e066a862c038a8dcb485e5e7dd519c31f7ac4f83f531c71c74 |
| Archive | SHA-256 | 4c24b28ee7f116ae7567221e539019809f709ab2a38eac30acf70f1719ae2943 | `KiddonsModMenu.zip`; no TeamSpeak host; holds Qt5Widgets.dll, SHA-256 of file 9c7d1a813bd9898579a4e50111bd421aebadeb722139062afc89c8bf0803e74f |
| Download | URL | https://www.mediafire.com/file/xcqj6p0owi7tbgj/KiddonsModMenu.zip/file | Served `KiddonsModMenu.zip` at different times as SHA-256 of file 4c24b28ee7f116ae7567221e539019809f709ab2a38eac30acf70f1719ae2943 and SHA-256 of file 2415daf32170ec8814b864057fbd6639844e0f8a25dc6310d78108258c1f6530, both holding Qt5Widgets.dll, SHA-256 of file 9c7d1a813bd9898579a4e50111bd421aebadeb722139062afc89c8bf0803e74f |
| Archive | SHA-256 | 2415daf32170ec8814b864057fbd6639844e0f8a25dc6310d78108258c1f6530 | `KiddonsModMenu.zip`; no TeamSpeak host; holds Qt5Widgets.dll, SHA-256 of file 9c7d1a813bd9898579a4e50111bd421aebadeb722139062afc89c8bf0803e74f |
