# Node.js loaders packed with nexe that add Defender exclusions and run payloads from a /richfamily/ C2 list

Verdict: malicious.

## Indicators

### Malicious

| IOC | Type | Value | Context |
|---|---|---|---|
| Loader | SHA-256 | b63245d622f42aa1fba215a63db7fdc0590dbfbee20b565e9a67a684ea9b1cc7 | `CosmoLoader v4.exe`, 85,360,955 B, build ID `lsv0k5e7tq` |
| Loader | SHA-256 | ecf768cb4fb3564621ec8708969f0aa6fd13b278de1fd8715a4c926202e0ebf9 | `PlayTwo.exe`, 84,830,851 B, build ID `dr2grcraef` |
| Loader | SHA-256 | b9bd7fe1c4cde41c473efcdb001275cfc000de3db496a0f23d3cb6788963470c | `Installer.exe`, 77,627,561 B, build ID `q94yoygxkp` |
| C2 | URL | http://62.60.226.233:3000/richfamily/lsv0k5e7tq | Payload list, decoded statically from `CosmoLoader v4.exe` (SHA-256 of file b63245d622f42aa1fba215a63db7fdc0590dbfbee20b565e9a67a684ea9b1cc7), whose build ID is `lsv0k5e7tq` |
| C2 | URL | http://178.16.52.231:3000/richfamily/lsv0k5e7tq | Payload list, decoded statically from `CosmoLoader v4.exe` (SHA-256 of file b63245d622f42aa1fba215a63db7fdc0590dbfbee20b565e9a67a684ea9b1cc7), whose build ID is `lsv0k5e7tq` |
| C2 | URL | https://digitalservice365cloud.com:443/richfamily/lsv0k5e7tq | Payload list, decoded statically from `CosmoLoader v4.exe` (SHA-256 of file b63245d622f42aa1fba215a63db7fdc0590dbfbee20b565e9a67a684ea9b1cc7), whose build ID is `lsv0k5e7tq` |
| C2 | URL | https://mceenzie.sbs:443/richfamily/lsv0k5e7tq | Payload list, decoded statically from `CosmoLoader v4.exe` (SHA-256 of file b63245d622f42aa1fba215a63db7fdc0590dbfbee20b565e9a67a684ea9b1cc7), whose build ID is `lsv0k5e7tq` |
| C2 | URL | http://62.60.226.233:3000/richfamily/dr2grcraef | Payload list, decoded statically from `PlayTwo.exe` (SHA-256 of file ecf768cb4fb3564621ec8708969f0aa6fd13b278de1fd8715a4c926202e0ebf9), whose build ID is `dr2grcraef` |
| C2 | URL | http://178.16.52.231:3000/richfamily/dr2grcraef | Payload list, decoded statically from `PlayTwo.exe` (SHA-256 of file ecf768cb4fb3564621ec8708969f0aa6fd13b278de1fd8715a4c926202e0ebf9), whose build ID is `dr2grcraef` |
| C2 | URL | https://digitalservice365cloud.com:443/richfamily/dr2grcraef | Payload list, decoded statically from `PlayTwo.exe` (SHA-256 of file ecf768cb4fb3564621ec8708969f0aa6fd13b278de1fd8715a4c926202e0ebf9), whose build ID is `dr2grcraef` |
| C2 | URL | https://mceenzie.sbs:443/richfamily/dr2grcraef | Payload list, decoded statically from `PlayTwo.exe` (SHA-256 of file ecf768cb4fb3564621ec8708969f0aa6fd13b278de1fd8715a4c926202e0ebf9), whose build ID is `dr2grcraef` |
| C2 | URL | http://62.60.226.233:3000/richfamily/q94yoygxkp | Payload list, decoded statically from `Installer.exe` (SHA-256 of file b9bd7fe1c4cde41c473efcdb001275cfc000de3db496a0f23d3cb6788963470c), whose build ID is `q94yoygxkp` |
| C2 | URL | http://66.63.187.72:3000/richfamily/q94yoygxkp | Payload list, decoded statically from `Installer.exe` (SHA-256 of file b9bd7fe1c4cde41c473efcdb001275cfc000de3db496a0f23d3cb6788963470c), whose build ID is `q94yoygxkp` |
| C2 | URL | https://davpniktonevidit.cfd:443/richfamily/q94yoygxkp | Payload list, decoded statically from `Installer.exe` (SHA-256 of file b9bd7fe1c4cde41c473efcdb001275cfc000de3db496a0f23d3cb6788963470c), whose build ID is `q94yoygxkp` |
| C2 | URL | https://nupogodi.cfd:443/richfamily/q94yoygxkp | Payload list, decoded statically from `Installer.exe` (SHA-256 of file b9bd7fe1c4cde41c473efcdb001275cfc000de3db496a0f23d3cb6788963470c), whose build ID is `q94yoygxkp` |
| C2 | IP:port | 62.60.226.233:3000 | HTTP; host in the payload-list URLs of `CosmoLoader v4.exe` (SHA-256 of file b63245d622f42aa1fba215a63db7fdc0590dbfbee20b565e9a67a684ea9b1cc7), `PlayTwo.exe` (SHA-256 of file ecf768cb4fb3564621ec8708969f0aa6fd13b278de1fd8715a4c926202e0ebf9) and `Installer.exe` (SHA-256 of file b9bd7fe1c4cde41c473efcdb001275cfc000de3db496a0f23d3cb6788963470c); also takes `POST /log` |
| C2 | IP:port | 178.16.52.231:3000 | HTTP; host in the payload-list URLs of `CosmoLoader v4.exe` (SHA-256 of file b63245d622f42aa1fba215a63db7fdc0590dbfbee20b565e9a67a684ea9b1cc7) and `PlayTwo.exe` (SHA-256 of file ecf768cb4fb3564621ec8708969f0aa6fd13b278de1fd8715a4c926202e0ebf9); also takes `POST /log` |
| C2 | IP:port | 66.63.187.72:3000 | HTTP; host in the payload-list URLs of `Installer.exe` (SHA-256 of file b9bd7fe1c4cde41c473efcdb001275cfc000de3db496a0f23d3cb6788963470c); also takes `POST /log` |
| C2 | Domain | digitalservice365cloud.com | HTTPS on port 443; host in the payload-list URLs of `CosmoLoader v4.exe` (SHA-256 of file b63245d622f42aa1fba215a63db7fdc0590dbfbee20b565e9a67a684ea9b1cc7) and `PlayTwo.exe` (SHA-256 of file ecf768cb4fb3564621ec8708969f0aa6fd13b278de1fd8715a4c926202e0ebf9); also takes `POST /log` |
| C2 | Domain | mceenzie.sbs | HTTPS on port 443; host in the payload-list URLs of `CosmoLoader v4.exe` (SHA-256 of file b63245d622f42aa1fba215a63db7fdc0590dbfbee20b565e9a67a684ea9b1cc7) and `PlayTwo.exe` (SHA-256 of file ecf768cb4fb3564621ec8708969f0aa6fd13b278de1fd8715a4c926202e0ebf9); also takes `POST /log` |
| C2 | Domain | davpniktonevidit.cfd | HTTPS on port 443; host in the payload-list URLs of `Installer.exe` (SHA-256 of file b9bd7fe1c4cde41c473efcdb001275cfc000de3db496a0f23d3cb6788963470c); also takes `POST /log` |
| C2 | Domain | nupogodi.cfd | HTTPS on port 443; host in the payload-list URLs of `Installer.exe` (SHA-256 of file b9bd7fe1c4cde41c473efcdb001275cfc000de3db496a0f23d3cb6788963470c); also takes `POST /log` |
| Archive | SHA-256 | c4d534e66b37455223b70b1e039713d28a7b6deb301423ffb87dfe10956dec54 | `Installer.zip`; holds `Instаller.zip` (the а is Cyrillic), which holds `Instаller/Installer.exe` (the а is Cyrillic; SHA-256 of file b9bd7fe1c4cde41c473efcdb001275cfc000de3db496a0f23d3cb6788963470c) |
| Download | URL | https://www.mediafire.com/file/3h0xl8iw53v4qzb/Installer.zip/file | Served `Installer.zip` (SHA-256 of file c4d534e66b37455223b70b1e039713d28a7b6deb301423ffb87dfe10956dec54), which holds `Instаller.zip` (the а is Cyrillic), which holds `Instаller/Installer.exe` (the а is Cyrillic; SHA-256 of file b9bd7fe1c4cde41c473efcdb001275cfc000de3db496a0f23d3cb6788963470c) |
| Archive | SHA-256 | d47fc0adf8c37ab75a1a6e8132cfa7ad765db27137249114b9de2c2cbb9ba689 | `PlayTwo.zip`; holds `PlayTwo/PlayTwo.exe` (SHA-256 of file ecf768cb4fb3564621ec8708969f0aa6fd13b278de1fd8715a4c926202e0ebf9) |
| Download | URL | https://www.mediafire.com/file/5k8w71qji0qlfxu/PlayTwo.zip/file | Served `PlayTwo.zip` (SHA-256 of file d47fc0adf8c37ab75a1a6e8132cfa7ad765db27137249114b9de2c2cbb9ba689), which holds `PlayTwo/PlayTwo.exe` (SHA-256 of file ecf768cb4fb3564621ec8708969f0aa6fd13b278de1fd8715a4c926202e0ebf9) |
| Archive | SHA-256 | 4f0b5780032e515593d60acef41f858816183960b6896462950e519c6a6e29f5 | `Вооtstrapper-Win64.V8.10.zip` (В and о are Cyrillic); holds `Вооtstгаррег/CosmoLoader v4.exe` (В, о, г, а, р and е are Cyrillic; SHA-256 of file b63245d622f42aa1fba215a63db7fdc0590dbfbee20b565e9a67a684ea9b1cc7) |
| Download | URL | https://www.mediafire.com/file/gop85nobwniabxa/%25D0%2592%25D0%25BE%25D0%25BEtstrapper-Win64.V8.10.zip/file | Served `Вооtstrapper-Win64.V8.10.zip` (В and о are Cyrillic; SHA-256 of file 4f0b5780032e515593d60acef41f858816183960b6896462950e519c6a6e29f5), which holds `Вооtstгаррег/CosmoLoader v4.exe` (В, о, г, а, р and е are Cyrillic; SHA-256 of file b63245d622f42aa1fba215a63db7fdc0590dbfbee20b565e9a67a684ea9b1cc7) |
