# Sandbox-aware loader that decrypts an x64 PE from a private PNG chunk and maps it in memory

## Key findings

- A 98,304-byte unsigned x64 loader, shipped in five password-protected RAR archives on MediaFire under game-cheat names, downloads its next stage as a PNG from a temporary file host (`https://litter.catbox.moe/f26cev.png`).
- The next stage hides in the PNG's first `prVt` chunk. The loader checks a truncated HMAC-SHA256 tag, decrypts the rest with a static ChaCha20 key and maps the resulting x64 PE into its own process.
- Before the download it restores ntdll's code from `\KnownDlls`, removing user-mode hooks, and patches ETW, AMSI and `MiniDumpWriteDump`.
- It resolves APIs by hash and exits silently unless the host passes eight anti-analysis checks.

```
RAR archive on MediaFire (five lure names, ~148 MB each; links in YouTube videos)
 └─ <Lure>.exe  PE32+ x64 GUI, 98,304 B, unsigned
     ├─ resolve APIs: PEB module walk + export walk, 32-bit name hash
     ├─ gate: BeingDebugged, RDTSC, >= 4 CPUs, RAM > ~3.92 GiB, host/user hash list,
     │        debug port, CONTEXT check (no-op), Sleep(3905) skew   -> fail: ExitProcess(0)
     ├─ syscall-stub table -> copy clean ntdll .text from \KnownDlls -> patch EtwEventWrite, AmsiScanBuffer
     ├─ hide thread from debugger, DACL attempt, patch dbghelp!MiniDumpWriteDump
     ├─ WinINet GET https://litter.catbox.moe/f26cev.png  (user agent "Mozilla/5.0")
     ├─ PNG: first chunk of type "prVt" -> ciphertext || 16-byte tag
     ├─ HMAC-SHA256(key, ciphertext)[0:16] == tag -> ChaCha20(key, nonce, counter 0) in place
     └─ map x64 PE in own process: sections, relocations, imports, .pdata, protections,
        PEB image base swap, TLS callbacks, wipe MZ/PE signatures, call entry -> ExitProcess(0)
```

## 1. Sample

| Field | Value |
|---|---|
| File | SHA-256 of file 49457f4873d15debba87933ff93d9709c820d2e3ca35658af3cff7c26b62dda4, 98,304 B |
| Format | PE32+ x64 GUI, image base 0x140000000, entry RVA 0x1170, DllCharacteristics 0x160 |
| Build | TimeDateStamp 2026-02-15 22:01:10 UTC; no Rich header; no Authenticode signature; sections `.text .data .rdata .bss .idata .reloc .rsrc` |
| Static imports | 11 functions from KERNEL32, SHELL32 and USER32 (camouflage, section 2); imphash 2df38eecc876e0e71c0fa85ae90a47f9 |
| Version info | CompanyName `BrightView North Apps`, InternalName `ScreenshotFinder.exe`, FileVersion 5.5.1586.351, FileDescription `Backs up and restores screenshot finder with local storage` |
| Resources | 77,636 B (resource directory size), section entropy 7.897: icons, string table, version, manifest. The code resolves no resource API |

The entry point (0x140001170, labelled `start`) is the author's own code; there is no C runtime startup code. The sample has no symbols; function names such as `sandbox_gate` are analyst-assigned.

## 2. API resolution, strings and camouflage

Modules are found by walking `InLoadOrderModuleList` and hashing `BaseDllName`. Exports are found by walking the export table; forwarded exports are skipped. The hash lower-cases A to Z only:

```
h = 0x2AD9605F
for c in name:  h = 0x01E7238B * rol32(h ^ c, 5)      (mod 2^32)
return h ^ 0x7AEF6556                                 (empty string -> 0x50360509)
```

Module hashes: `kernel32.dll` 0xAC50EA7F, `ntdll.dll` 0x95ADBFE0, `advapi32.dll` 0x121E9BEB, `amsi.dll` 0xFF08A4E4. Apart from the payload's imports, the loader loads only `wininet.dll` and `dbghelp.dll`, through `LoadLibraryA`. The `advapi32.dll` and `amsi.dll` routines run only if those modules are already in the process.

Strings are stack-built and XOR-decoded just before use (keys in section 8); the URL is wiped after the download. The ChaCha20 constant and the SHA-256 tables are stored XORed with 0xF8350715, so byte scans for those standard constants miss the sample.

Camouflage: all 11 static imports are referenced only in 0x140004BE0, and five of them sit after its `ExitProcess(5)` call. That branch runs only if a `.data` dword masked with 0x1FF equals 30. The stored value is 0xB3803D5F (masked 0x15F), and no code in the sample writes it, so the branch does not run (inferred). Junk strings such as `%%s\\ipw72_31286.json` and `SOFTWARE\\xccxQ\\tag_93if` only feed a running sum in 0x140004A80 and 0x140004BE0.

## 3. Sandbox gate

`sandbox_gate` (0x140003700) runs eight checks in order. Any failure ends in `ExitProcess(0)` with no network activity.

| # | Check | Passes when | Function |
|---|---|---|---|
| 1 | PEB `BeingDebugged` | 0 | 0x140003510 |
| 2 | RDTSC around a 100-iteration loop | delta <= 0x7A11F (499,999) cycles | 0x140003660 |
| 3 | `GetSystemInfo` | `dwNumberOfProcessors` > 3 | 0x140003340 |
| 4 | `GlobalMemoryStatusEx` | `ullTotalPhys` > 0xFA9FFFFF (4,204,789,759 B, about 3.92 GiB) | 0x140003380 |
| 5 | `GetComputerNameA`, `GetUserNameA` | name hash not in the 14-entry table at 0x140006180 | 0x140003400 |
| 6 | `NtQueryInformationProcess(ProcessDebugPort)` | port 0, or the call fails | 0x140003540 |
| 7 | `NtGetContextThread(-2)` | 32 bytes at CONTEXT offset 0x350 are zero, or the call fails | 0x1400035C0 |
| 8 | `GetTickCount`, `Sleep(3905)`, `GetTickCount` | elapsed > 3,404 ms | 0x1400033D0 |

Check 5 uses the API hash, so matching is whole-string and case-insensitive. A name check is skipped if its API is missing or fails. Both name APIs are resolved only if `advapi32.dll` is already loaded when the API table is built; `GetComputerNameA` comes from kernel32 but sits behind the same test. The table includes `Johnson`, `miller`, `MALWARE`, `MALTEST`, `currentuser`, `SANDBOX`, `VIRUS`, `John Doe`, `WDAGUtilityAccount`, `bruno`, `george` and `Harry Johnson`. `bruno` and `miller` are inferred from exhaustive search: each is the only a-z preimage of six characters or fewer for its hash.

Check 7 sets ContextFlags to 0x10 and reads CONTEXT offsets 0x350 to 0x36F. In the x64 CONTEXT those bytes lie in `VectorRegister`, not in Dr0 to Dr7 (offsets 0x48 to 0x77). The check therefore cannot see hardware breakpoints (inferred from the documented CONTEXT layout).

A sandbox with fewer than four vCPUs, 4,204,789,759 B (about 3.92 GiB) or less of physical memory, accelerated sleeps or a listed name shows no network activity (inferred). That is not a benign result.

## 4. Defence tampering and self-protection

These steps run after the gate and before the download.

1. `build_syscall_table` (0x140003B40) finds the first executable section of the loaded ntdll and a `0F 05 C3` (`syscall; ret`) gadget in it. It collects up to 512 `Nt*` exports whose stub starts `4C 8B D1 B8`, stores (name hash, syscall number) pairs at 0x140007160 and sorts them by syscall number. If no gadget or stub is found, steps 2 to 4 are skipped.
2. `unhook_ntdll_knowndlls` (0x140003FF0) calls `NtOpenSection` on `\KnownDlls\ntdll.dll` and maps a read-only view. If the clean and loaded executable sections have equal virtual size, it sets the loaded `.text` to PAGE_EXECUTE_READWRITE, copies the clean bytes over it, restores the old protection and unmaps the view. This removes user-mode hooks in ntdll.
3. `patch_etweventwrite` (0x1400043E0) writes `31 c0 c3` (`xor eax, eax; ret`) to `ntdll!EtwEventWrite`.
4. `patch_amsiscanbuffer` (0x1400044C0) writes `b8 57 00 07 80 c3` (return E_INVALIDARG) to `amsi!AmsiScanBuffer`, only if `amsi.dll` is already loaded.
5. `hide_thread_from_debugger` (0x140003780) calls `NtSetInformationThread(-2, ThreadHideFromDebugger)`.
6. `harden_process_dacl` (0x1400038D0) builds an Everyone SID and a hand-made ACL with `AclSize` 8, then calls `AddAccessDeniedAce` with mask 0x450 (PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, PROCESS_DUP_HANDLE). An 8-byte ACL has no room for the ACE, so the call fails and `SetKernelObjectSecurity` is never reached (inferred from documented API behaviour). The intended deny-ACE is therefore most likely never applied.
7. The routine at 0x140003840 loads `dbghelp.dll`, resolves `MiniDumpWriteDump` (hash 0xA3C03592) and overwrites its first bytes with `31 c0 c3`. In-process minidump calls then fail. Dump tools running in their own process are not affected (inferred).

## 5. Stage-2 download

`http_download` (0x140004730) resolves `InternetOpenA`, `InternetOpenUrlA`, `InternetReadFile` and `InternetCloseHandle` from `wininet.dll`.

- `InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0)`: the system proxy setting applies, and the user agent is the bare string.
- `InternetOpenUrlA` with no extra headers and flags 0x84000200 (RELOAD, NO_CACHE_WRITE, NO_UI). No certificate-error flags are set.
- No HTTP status check. The body is read in 65,536-byte calls into a PAGE_READWRITE buffer that starts at 262,144 B and doubles when less than 64 KiB is free. Reading stops at the first failed or empty read.

The URL is `https://litter.catbox.moe/f26cev.png`. That host keeps uploads for at most 72 hours. There is no fallback URL and no retry.

## 6. PNG container and verification

`png_extract_chunk` (0x140004940) checks the 8-byte PNG signature (`89 50 4e 47 0d 0a 1a 0a`, stored at 0x1400061D0). It then walks chunks from offset 8 and returns the data of the first chunk whose type is `prVt`. The type is stored as the immediate 0x496B4F4D and XOR-decoded with 0x3D. Chunk CRCs are not checked, and `IHDR` or `IEND` is not required. Under PNG naming rules `prVt` is an ancillary, private, safe-to-copy chunk, so image viewers ignore it.

```
PNG signature  89 50 4e 47 0d 0a 1a 0a
chunk          length (4, big-endian) | type (4) | data (length) | CRC (4, unchecked)
"prVt" data    ciphertext (length - 16) | tag (16)
tag            HMAC-SHA256(key, ciphertext)[0:16]
plaintext      ChaCha20(key, nonce, counter 0) XOR ciphertext  ->  x64 PE
```

`start` copies the chunk data into a new PAGE_READWRITE buffer, zeroes and frees the download buffer, and verifies the tag with 0x140002D00. That routine is standard HMAC-SHA256 (ipad 0x36, opad 0x5c). It compares the first 16 bytes with an OR-accumulated XOR, so the compare is constant-time. On a mismatch the loader wipes its key copy, frees the buffer and exits with code 0. On a match, 0x140001DE0 decrypts the ciphertext in place with ChaCha20 per RFC 8439: 10 double rounds, a 32-bit block counter starting at 0 and a 96-bit nonce. One 32-byte key serves both the cipher and the MAC (encrypt-then-MAC).

0x140001DE0 produces reference ChaCha20 output for the stored key and nonce, and 0x140002D00 accepts `HMAC-SHA256(key, ciphertext)[0:16]` and rejects a tag with one bit flipped. Key and nonce are fixed, so any `prVt` payload served to this build decrypts with the values in section 8.

No bundled archive file contains a `prVt` chunk, and the loader resolves no file API.

## 7. In-memory PE loader

`reflective_load_and_run` (0x140003090) receives the plaintext and a table holding `VirtualAlloc`, `VirtualProtect`, `VirtualFree`, `LoadLibraryA`, `GetProcAddress` and `RtlAddFunctionTable`.

1. It requires `MZ`, `PE\0\0`, machine 0x8664 and more than 63 bytes. 32-bit payloads are rejected.
2. It allocates `SizeOfImage` as PAGE_READWRITE at any address; it does not try the preferred base. It copies the headers and each section's raw data, then zeroes the plaintext buffer.
3. It applies `IMAGE_REL_BASED_DIR64` relocations. A payload with no relocation directory fails, and the loader exits, unless the allocation happens to land at its preferred base.
4. It resolves imports by name or ordinal with `LoadLibraryA` and `GetProcAddress`. It uses the import lookup table, or the address table if that is absent. Any unresolved import aborts the load.
5. It registers the exception directory with `RtlAddFunctionTable`.
6. It sets section protections from the characteristics, from PAGE_NOACCESS up to PAGE_EXECUTE_READWRITE. The header page stays PAGE_READWRITE.
7. It sets `PEB->ImageBaseAddress` to the mapped image. It then calls each TLS callback as `(base, DLL_PROCESS_ATTACH, NULL)`. It allocates no TLS index and copies no TLS template.
8. It zeroes the `MZ` and `PE\0\0` signatures (anti-dump), then calls the entry point with no arguments, EXE-style.
9. When the entry point returns, it restores `PEB->ImageBaseAddress`. `start` then zeroes and frees the plaintext buffer, runs the camouflage routine 0x140004BE0 and calls `ExitProcess(0)`.

The payload runs on the loader's main thread inside the loader's process (`Cs2SkinChanger.exe` or another lure name). No child process, injection, file drop, registry write or persistence exists in the loader.

## 8. Crypto material

| Value | Bytes | Location |
|---|---|---|
| ChaCha20 key (also the HMAC-SHA256 key) | `6d a9 f3 d6 f9 c7 9d 56 43 da 31 06 69 8a c5 93 d2 cf 11 d1 8b 04 a6 99 55 e1 af 92 42 1e 1d 33` | `.rdata` VA 0x140006010, file offset 0x4410 |
| ChaCha20 nonce (IETF, 96-bit) | `bb 1b 88 94 cd 0f a4 e7 47 b6 05 7f` | `.rdata` VA 0x140006000, file offset 0x4400 |
| ChaCha20 initial counter | 0 | call at 0x14000142C |
| MAC | HMAC-SHA256 over the ciphertext, first 16 bytes kept | last 16 bytes of the `prVt` data |
| Constant mask | 0xF8350715 (`15 07 35 f8`) | ChaCha20 constant built in 0x140001DE0; SHA-256 initial values at 0x140006040 and round constants at 0x140006060 |
| URL XOR key | 0xae | stack string in `start`, loop at 0x1400012C0 |
| String XOR key | 0x3d | user agent, `wininet.dll`, `dbghelp.dll`, chunk type, `\KnownDlls\ntdll.dll` (low byte of each UTF-16 unit) |

The unmasked SHA-256 initial values and all 64 round constants equal the FIPS 180-4 values.

## 9. Distribution and related executables

Five RAR archives of about 148 MB each carry the loader under the lure names `Cs2SkinChanger`, `Cs2Hack`, `AmongUsModMenu`, `Forza6ModMenu` and `KiddonsModMenu`. They were uploaded to MediaFire on 2026-06-15 and 2026-06-16 and are linked from YouTube videos on three channels. Each archive opens with its lower-cased lure name as the password (for example `cs2skinchanger`), as stated in the linking videos. Each archive also holds three copies each of `libavcodec-62.dll`, `libavformat-62.dll`, `libavif-16.dll` (Valve Corp. certificates) and `GfnRuntimeSdk.dll` (Nvidia Corporation certificate). It also holds two 52,428,800-byte filler files and five random-named data files. The loader resolves no file API, so these files are bait or padding (inferred).

The same lure names were uploaded on 2026-06-09 and 2026-06-22, linked from an overlapping set of channels. Those archives carry two other executables instead of the loader:

| Field | 26 MB file | 11 MB file |
|---|---|---|
| Size | 26,009,096 B | 11,446,200 B |
| Version info | `Helix Point Crest Technologies Co.`, `Sleeping PC Environment Editor` | `SunTon Peak Software Inc.`, `Open Window Sync Local` |
| TimeDateStamp | 2019-02-06 | 2020-12-13 |
| Signature | self-signed, CN = product name, valid from 2026-06-09, DigiCert timestamp | self-signed, CN = product name, valid from 2026-06-22, Sectigo timestamp |
| Imports | one per DLL: `GetVersion`, `SendMessageW`, `CreateSolidBrush` | one per DLL: `GetVersion`, `AnimateWindow`, `CreatePen` |

Both keep `.text`, `.rdata` and `.data` as virtual-only sections and add three randomly named sections, one with entropy 7.75 or 7.83. This matches a commercial code-virtualising protector (inferred). Neither contains the loader's constants, key or nonce, which is expected under packing.

## 10. Scope and method

- **Samples:** one loader (five byte-identical copies), its five distribution archives, two packed executables from adjacent upload batches and their ten archives
- **Methods:** static analysis of the loader's code and stored bytes; isolated emulation of its cipher and MAC routines
- **Coverage:** The analysis covers the loader up to the hand-off to the decrypted second-stage PE, whose content is outside it. Loader behaviour is read from its code, with the cipher and MAC routines confirmed under emulation.

## Indicators

### Malicious

| IOC | Type | Value | Context |
|---|---|---|---|
| Loader | SHA-256 | 49457f4873d15debba87933ff93d9709c820d2e3ca35658af3cff7c26b62dda4 | PE32+ x64, 98,304 B, unsigned. Named Cs2SkinChanger.exe, Cs2Hack.exe, AmongUsModMenu.exe, Forza6ModMenu.exe or KiddonsModMenu.exe |
| Stage 2 | URL | https://litter.catbox.moe/f26cev.png | Download URL decoded from the code of the loader, SHA-256 of file 49457f4873d15debba87933ff93d9709c820d2e3ca35658af3cff7c26b62dda4; requested with user agent `Mozilla/5.0`; the loader expects an encrypted PE in a `prVt` chunk |
| Loader | Imphash | 2df38eecc876e0e71c0fa85ae90a47f9 | Imphash of the loader, SHA-256 of file 49457f4873d15debba87933ff93d9709c820d2e3ca35658af3cff7c26b62dda4 |
| Archive | SHA-256 | af97ceb362c313eaef03c1f719bbe319a94b7bdc7b65177aaee73302e9af1a4a | RAR archive `Cs2SkinChanger.rar` holding the loader as `Cs2SkinChanger.exe`, SHA-256 of file 49457f4873d15debba87933ff93d9709c820d2e3ca35658af3cff7c26b62dda4 |
| Download | URL | https://www.mediafire.com/file/6ifdz0c2qq8k4wo/Cs2SkinChanger.rar/file | MediaFire download of `Cs2SkinChanger.rar`, SHA-256 of file af97ceb362c313eaef03c1f719bbe319a94b7bdc7b65177aaee73302e9af1a4a |
| Archive | SHA-256 | a44d3f92005e7bc4f4ff92213ccebf3b1be8f645331d78b3ca607b8d785ac3a8 | RAR archive `Cs2Hack.rar` holding the loader as `Cs2Hack.exe`, SHA-256 of file 49457f4873d15debba87933ff93d9709c820d2e3ca35658af3cff7c26b62dda4 |
| Download | URL | https://www.mediafire.com/file/ayqvje6l31xl87o/Cs2Hack.rar/file | MediaFire download of `Cs2Hack.rar`, SHA-256 of file a44d3f92005e7bc4f4ff92213ccebf3b1be8f645331d78b3ca607b8d785ac3a8 |
| Archive | SHA-256 | 364e9e4d95b8df04e911fbb838bb05ff320de0ef515f50c9dceda5c5839511e4 | RAR archive `AmongUsModMenu.rar` holding the loader as `AmongUsModMenu.exe`, SHA-256 of file 49457f4873d15debba87933ff93d9709c820d2e3ca35658af3cff7c26b62dda4 |
| Download | URL | https://www.mediafire.com/file/pp6z1ubmxixyogc/AmongUsModMenu.rar/file | MediaFire download of `AmongUsModMenu.rar`, SHA-256 of file 364e9e4d95b8df04e911fbb838bb05ff320de0ef515f50c9dceda5c5839511e4 |
| Archive | SHA-256 | 5d1d2e359a23410162d0c31942b2f86c81d6b6afc0b9d8f07af171106272fdf0 | RAR archive `Forza6ModMenu.rar` holding the loader as `Forza6ModMenu.exe`, SHA-256 of file 49457f4873d15debba87933ff93d9709c820d2e3ca35658af3cff7c26b62dda4 |
| Download | URL | https://www.mediafire.com/file/y6ik8hdwn6ewuc2/Forza6ModMenu.rar/file | MediaFire download of `Forza6ModMenu.rar`, SHA-256 of file 5d1d2e359a23410162d0c31942b2f86c81d6b6afc0b9d8f07af171106272fdf0 |
| Archive | SHA-256 | eeb11d7c7124e851ba5110fda152a3acc7f4e2be82f5ee6f8828e551ef699e72 | RAR archive `KiddonsModMenu.rar` holding the loader as `KiddonsModMenu.exe`, SHA-256 of file 49457f4873d15debba87933ff93d9709c820d2e3ca35658af3cff7c26b62dda4 |
| Download | URL | https://www.mediafire.com/file/ztcq8vwwhhl0nsf/KiddonsModMenu.rar/file | MediaFire download of `KiddonsModMenu.rar`, SHA-256 of file eeb11d7c7124e851ba5110fda152a3acc7f4e2be82f5ee6f8828e551ef699e72 |

### Suspicious

| IOC | Type | Value | Context |
|---|---|---|---|
| Packed executable | SHA-256 | 208de02eff5e40eb46a6cafa857355b8292a7078531db690b6844f5a49445eb4 | Packed x64 executable, 26,009,096 B; shipped as `Cs2Hack.exe` and under the lure names `Cs2SkinChanger`, `AmongUsModMenu`, `Forza6ModMenu` and `KiddonsModMenu` in MediaFire RAR archives of the same names; version info company `Helix Point Crest Technologies Co.` |
| Signing certificate | Certificate SHA-256 | 8e:b8:b8:cb:66:a0:ca:f5:63:77:59:9d:dc:ac:3d:7c:32:99:f6:3c:02:da:e2:0e:c8:b3:4f:30:5a:70:58:96 | Self-signed certificate, CN `Sleeping PC Environment Editor`, on the packed executable with SHA-256 of file 208de02eff5e40eb46a6cafa857355b8292a7078531db690b6844f5a49445eb4 |
| Packed executable | SHA-256 | 22f3036d108d5c6b543b205e92ad90531efa2ce59158617daa4e9ba6c19692f1 | Packed x64 executable, 11,446,200 B; shipped as `Cs2Hack.exe` and under the lure names `Cs2SkinChanger`, `AmongUsModMenu`, `Forza6ModMenu` and `KiddonsModMenu` in MediaFire RAR archives of the same names; version info company `SunTon Peak Software Inc.` |
| Signing certificate | Certificate SHA-256 | c0:b7:04:a2:22:9a:73:f7:6f:2b:1c:c9:c6:49:97:38:0d:79:3a:4c:f1:2d:80:26:e6:dc:12:62:99:4c:bf:d6 | Self-signed certificate, CN `Open Window Sync Local`, on the packed executable with SHA-256 of file 22f3036d108d5c6b543b205e92ad90531efa2ce59158617daa4e9ba6c19692f1 |
| Archive | SHA-256 | 855de089cc6931252e7959e23268a6337da329abca22546912ff16d7c4c3db3a | RAR archive `Cs2Hack.rar` holding the packed executable with SHA-256 of file 208de02eff5e40eb46a6cafa857355b8292a7078531db690b6844f5a49445eb4 |
| Download | URL | https://www.mediafire.com/file/73c3s176786emqw/Cs2Hack.rar/file | MediaFire download of `Cs2Hack.rar`, SHA-256 of file 855de089cc6931252e7959e23268a6337da329abca22546912ff16d7c4c3db3a |
| Archive | SHA-256 | ac02692880ab836c25279d369957ad1072a953512e6533dd671222fccc56559e | RAR archive `KiddonsModMenu.rar` holding the packed executable with SHA-256 of file 208de02eff5e40eb46a6cafa857355b8292a7078531db690b6844f5a49445eb4 |
| Download | URL | https://www.mediafire.com/file/8t1egoap6l6z6kv/KiddonsModMenu.rar/file | MediaFire download of `KiddonsModMenu.rar`, SHA-256 of file ac02692880ab836c25279d369957ad1072a953512e6533dd671222fccc56559e |
| Archive | SHA-256 | 296c6c6a7ce77442c6a8489f9a848ea23fd13240e232266ba1aaf387bf526b19 | RAR archive `Cs2SkinChanger.rar` holding the packed executable with SHA-256 of file 208de02eff5e40eb46a6cafa857355b8292a7078531db690b6844f5a49445eb4 |
| Download | URL | https://www.mediafire.com/file/inlz8n4fpjb9vti/Cs2SkinChanger.rar/file | MediaFire download of `Cs2SkinChanger.rar`, SHA-256 of file 296c6c6a7ce77442c6a8489f9a848ea23fd13240e232266ba1aaf387bf526b19 |
| Archive | SHA-256 | a0d1b3477d0101405c66517f3ed2121e0c69e9bb431c5dca32a55054c1883e8d | RAR archive `Forza6ModMenu.rar` holding the packed executable with SHA-256 of file 208de02eff5e40eb46a6cafa857355b8292a7078531db690b6844f5a49445eb4 |
| Download | URL | https://www.mediafire.com/file/11b5o0153vh93x4/Forza6ModMenu.rar/file | MediaFire download of `Forza6ModMenu.rar`, SHA-256 of file a0d1b3477d0101405c66517f3ed2121e0c69e9bb431c5dca32a55054c1883e8d |
| Archive | SHA-256 | b598532dec99fe532c34e9176234a1a0e7c16573d7432ea99c45c27868634289 | RAR archive `AmongUsModMenu.rar` holding the packed executable with SHA-256 of file 208de02eff5e40eb46a6cafa857355b8292a7078531db690b6844f5a49445eb4 |
| Download | URL | https://www.mediafire.com/file/i13rjti8mnr783n/AmongUsModMenu.rar/file | MediaFire download of `AmongUsModMenu.rar`, SHA-256 of file b598532dec99fe532c34e9176234a1a0e7c16573d7432ea99c45c27868634289 |
| Archive | SHA-256 | a8a9d00397c23224e66672d50c47792dbd7ccc03dff9183c7b858578ce791acf | RAR archive `Cs2Hack.rar` holding the packed executable with SHA-256 of file 22f3036d108d5c6b543b205e92ad90531efa2ce59158617daa4e9ba6c19692f1 |
| Download | URL | https://www.mediafire.com/file/7113ibb1z1tafhk/Cs2Hack.rar/file | MediaFire download of `Cs2Hack.rar`, SHA-256 of file a8a9d00397c23224e66672d50c47792dbd7ccc03dff9183c7b858578ce791acf |
| Archive | SHA-256 | 56a698dca83c4e35a2ff45f78249868df242cb11749ebde42c9f3cb760104f8d | RAR archive `KiddonsModMenu.rar` holding the packed executable with SHA-256 of file 22f3036d108d5c6b543b205e92ad90531efa2ce59158617daa4e9ba6c19692f1 |
| Download | URL | https://www.mediafire.com/file/g6gzegiqkdgnyf9/KiddonsModMenu.rar/file | MediaFire download of `KiddonsModMenu.rar`, SHA-256 of file 56a698dca83c4e35a2ff45f78249868df242cb11749ebde42c9f3cb760104f8d |
| Archive | SHA-256 | 57f42c4aa9d1060adf5b2e9f758b640f49159bb34ba56537fea473afc4365f89 | RAR archive `Cs2SkinChanger.rar` holding the packed executable with SHA-256 of file 22f3036d108d5c6b543b205e92ad90531efa2ce59158617daa4e9ba6c19692f1 |
| Download | URL | https://www.mediafire.com/file/6h754wb0t57xhpi/Cs2SkinChanger.rar/file | MediaFire download of `Cs2SkinChanger.rar`, SHA-256 of file 57f42c4aa9d1060adf5b2e9f758b640f49159bb34ba56537fea473afc4365f89 |
| Archive | SHA-256 | a5410472aefdb0415129bdacca037a132a6a2928a1a932e90e9bec4381ecb006 | RAR archive `AmongUsModMenu.rar` holding the packed executable with SHA-256 of file 22f3036d108d5c6b543b205e92ad90531efa2ce59158617daa4e9ba6c19692f1 |
| Download | URL | https://www.mediafire.com/file/bdjj5xti81412va/AmongUsModMenu.rar/file | MediaFire download of `AmongUsModMenu.rar`, SHA-256 of file a5410472aefdb0415129bdacca037a132a6a2928a1a932e90e9bec4381ecb006 |
| Archive | SHA-256 | 069db97298b5fe4204ca6ce947a485c7c40cde535c694dba812be6d42d3c7af9 | RAR archive `Forza6ModMenu.rar` holding the packed executable with SHA-256 of file 22f3036d108d5c6b543b205e92ad90531efa2ce59158617daa4e9ba6c19692f1 |
| Download | URL | https://www.mediafire.com/file/kfmcio9ad12h4ig/Forza6ModMenu.rar/file | MediaFire download of `Forza6ModMenu.rar`, SHA-256 of file 069db97298b5fe4204ca6ce947a485c7c40cde535c694dba812be6d42d3c7af9 |
