# JScript loader that starts hidden PowerShell through WMI and loads a .NET assembly from Firebase Storage

Verdict: malicious.

## Indicators

### Malicious

| IOC | Type | Value | Context |
|---|---|---|---|
| JScript loader | SHA-256 | 13cc70951a1ce8cb502a8273d86f1ae98dad39790a50b2eda9cab59916b85dcc | `CS2HACK.js`, 656,828 B |
| Next stage | URL | https://firebasestorage.googleapis.com/v0/b/sadam-bda08.firebasestorage.app/o/traffic2%2Fcs2.png | `cs2.png`, next stage of `CS2HACK.js` (SHA-256 of file 13cc70951a1ce8cb502a8273d86f1ae98dad39790a50b2eda9cab59916b85dcc); the script adds `alt=media` and a download token; the token is withheld |
| Storage bucket | Firebase bucket | sadam-bda08.firebasestorage.app | Named in the next-stage URL path of `CS2HACK.js` (SHA-256 of file 13cc70951a1ce8cb502a8273d86f1ae98dad39790a50b2eda9cab59916b85dcc); the script contacts only the API host `firebasestorage.googleapis.com` |
| Archive | SHA-256 | 5ad936cb4c9629fed90db9cad261cbdc433c82dde0f13a053db4b9a42fd45cee | `CS2HACK.zip`; 31,901 B, one encrypted entry `CS2HACK/CS2HACK.js`; password `cs2hack`; holds `CS2HACK/CS2HACK.js` (SHA-256 of file 13cc70951a1ce8cb502a8273d86f1ae98dad39790a50b2eda9cab59916b85dcc) |
| Download | URL | https://www.mediafire.com/file/rgf7pgy34zqrri5/CS2HACK.zip/file | Served `CS2HACK.zip` (SHA-256 of file 5ad936cb4c9629fed90db9cad261cbdc433c82dde0f13a053db4b9a42fd45cee), which holds encrypted entry `CS2HACK/CS2HACK.js` |
