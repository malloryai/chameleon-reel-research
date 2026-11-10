# Python infostealer with Telegram exfiltration and a cryptocurrency clipboard hijacker

Verdict: malicious.

## Indicators

### Malicious

| IOC | Type | Value | Context |
|---|---|---|---|
| Stealer | SHA-256 | d08d9722603dfc1d4d1fa16011d31c9c3034868ccb8ce2e28988d4f8ed28a533 | PyInstaller, Python 3.14, 19,927,380 B; named `NexusMods.exe` and `ValorantHack.exe` |
| Exfiltration | Telegram chat ID | 8740741178 | Chat ID used by the stealer `NexusMods.exe` / `ValorantHack.exe` (SHA-256 of file d08d9722603dfc1d4d1fa16011d31c9c3034868ccb8ce2e28988d4f8ed28a533) to send stolen data; the bot token is withheld |
| Clipper wallet | Bitcoin address | bc1qfpt6ljm7j2edsjn6f8aqst9qu6x55dgyfz30hw | Bitcoin address in the clipboard-hijacker address map of the stealer `NexusMods.exe` / `ValorantHack.exe` (SHA-256 of file d08d9722603dfc1d4d1fa16011d31c9c3034868ccb8ce2e28988d4f8ed28a533) |
| Clipper wallet | Ethereum address | 0x8e977c00EfeF0e3C9a044C0641e2648F7731425d | Ethereum address in the clipboard-hijacker address map of the stealer `NexusMods.exe` / `ValorantHack.exe` (SHA-256 of file d08d9722603dfc1d4d1fa16011d31c9c3034868ccb8ce2e28988d4f8ed28a533) |
| Clipper wallet | Tron address | TUCra7c48byL4xHfZWnXgmJDuPw9upTPz2 | Tron address in the clipboard-hijacker address map of the stealer `NexusMods.exe` / `ValorantHack.exe` (SHA-256 of file d08d9722603dfc1d4d1fa16011d31c9c3034868ccb8ce2e28988d4f8ed28a533) |
| Clipper wallet | Solana address | 5EWvLKWj66rsVwdoUjTygujjSfusEXfTRbhvS5TBi1My | Solana address in the clipboard-hijacker address map of the stealer `NexusMods.exe` / `ValorantHack.exe` (SHA-256 of file d08d9722603dfc1d4d1fa16011d31c9c3034868ccb8ce2e28988d4f8ed28a533) |
| Clipper wallet | Litecoin address | ltc1qfcrpmxw742lcef435526lwdqynt8ersmt4yha7 | Litecoin address in the clipboard-hijacker address map of the stealer `NexusMods.exe` / `ValorantHack.exe` (SHA-256 of file d08d9722603dfc1d4d1fa16011d31c9c3034868ccb8ce2e28988d4f8ed28a533) |
| Clipper wallet | XRP Ledger address | r3NVG9PDhSJfVRucvThWSPd1QJrv2cn2do | XRP Ledger address in the clipboard-hijacker address map of the stealer `NexusMods.exe` / `ValorantHack.exe` (SHA-256 of file d08d9722603dfc1d4d1fa16011d31c9c3034868ccb8ce2e28988d4f8ed28a533) |
| Clipper wallet | TON address | UQA4alhhvhTKqxxuvwCxrsRlCISmCk3mKPP0qEpLstrpmxBi | TON address in the clipboard-hijacker address map of the stealer `NexusMods.exe` / `ValorantHack.exe` (SHA-256 of file d08d9722603dfc1d4d1fa16011d31c9c3034868ccb8ce2e28988d4f8ed28a533) |
| Clipper wallet | Dogecoin address | DGf6iJd9bgStGdBH7vyuksWme6FAtnmpou | Dogecoin address in the clipboard-hijacker address map of the stealer `NexusMods.exe` / `ValorantHack.exe` (SHA-256 of file d08d9722603dfc1d4d1fa16011d31c9c3034868ccb8ce2e28988d4f8ed28a533) |
| Clipper wallet | Cardano address | addr1q9uadsqsuryljjmtsanfw3z8tswqad9wduvjz93kqphfnps0qn3dqcl2nka8fxyqxj9xtrxw7pjqxkuc5m2nphkfh78s4k93v7 | Cardano address in the clipboard-hijacker address map of the stealer `NexusMods.exe` / `ValorantHack.exe` (SHA-256 of file d08d9722603dfc1d4d1fa16011d31c9c3034868ccb8ce2e28988d4f8ed28a533) |
| Clipper wallet | Stellar address | GAMBLSPJJNCREW72ZDC2AOZJLD6RNOINXGOGLPIQP6N3A5UDOCZLEA44 | Stellar address in the clipboard-hijacker address map of the stealer `NexusMods.exe` / `ValorantHack.exe` (SHA-256 of file d08d9722603dfc1d4d1fa16011d31c9c3034868ccb8ce2e28988d4f8ed28a533) |
| Clipper wallet | Bitcoin Cash address | qz7ju086p20swahrreahg5f95hhgmuwczqhnn7pnpd | Bitcoin Cash address in the clipboard-hijacker address map of the stealer `NexusMods.exe` / `ValorantHack.exe` (SHA-256 of file d08d9722603dfc1d4d1fa16011d31c9c3034868ccb8ce2e28988d4f8ed28a533) |
| Clipper wallet | Sui address | 0x496c5addf166f6791a3eeb0b1d77fd6510f456256e43a9b1d0c4a88b314fd97e | Sui address in the clipboard-hijacker address map of the stealer `NexusMods.exe` / `ValorantHack.exe` (SHA-256 of file d08d9722603dfc1d4d1fa16011d31c9c3034868ccb8ce2e28988d4f8ed28a533) |
| Archive | SHA-256 | 93499be6f6e5c2e22e3f00f9da232e1ad3fcc30acf9559c3b1fe54ce9407c275 | `NexusMods.rar`; password `1930`; holds `NexusMods/NexusMods/NexusMods.exe` (SHA-256 of file d08d9722603dfc1d4d1fa16011d31c9c3034868ccb8ce2e28988d4f8ed28a533) |
| Download | URL | https://www.mediafire.com/file/jjkdue9h2jei15w/NexusMods.rar/file | Served `NexusMods.rar` (SHA-256 of file 93499be6f6e5c2e22e3f00f9da232e1ad3fcc30acf9559c3b1fe54ce9407c275), which holds `NexusMods/NexusMods/NexusMods.exe` (SHA-256 of file d08d9722603dfc1d4d1fa16011d31c9c3034868ccb8ce2e28988d4f8ed28a533) |
| Archive | SHA-256 | a5f479c26732fbab600fa9bc926f6eba082ff4c9f96489dc9fb98a09ec145883 | `ValorantHack.rar`; password `1930`; holds `ValorantHack/ValorantHack.exe` (SHA-256 of file d08d9722603dfc1d4d1fa16011d31c9c3034868ccb8ce2e28988d4f8ed28a533) |
| Download | URL | https://www.mediafire.com/file/sgt7vu0dv3vx230/ValorantHack.rar/file | Served `ValorantHack.rar` (SHA-256 of file a5f479c26732fbab600fa9bc926f6eba082ff4c9f96489dc9fb98a09ec145883), which holds `ValorantHack/ValorantHack.exe` (SHA-256 of file d08d9722603dfc1d4d1fa16011d31c9c3034868ccb8ce2e28988d4f8ed28a533) |
