# Release signing

Each release's `SHA256SUMS.txt` is signed locally with
[minisign](https://jedisct1.github.io/minisign/). The secret key never goes to
CI. The public key is `crates/rosetun-core/keys/minisign.pub`. The signature is
`SHA256SUMS.txt.minisig`, with the trusted comment `rosetun <version>`.

`release.yml` creates the release as a draft. Then, on the machine that holds
the key (needs `gh`, logged in, and `minisign` on PATH):

```powershell
.\tools\release\Sign-RosetunRelease.ps1 -Version 0.7.0 -SecretKey <path to the secret key>
```

The script checks that `v<Version>` is a draft, downloads its `SHA256SUMS.txt`,
signs it (minisign asks for the key password), verifies the signature with the
public key, checks the trusted comment and uploads the `.minisig`. It does not
publish. Look at the draft, then publish it with
`gh release edit v<Version> --draft=false`, or run the script again with
`-Publish`. The key is never copied, printed or stored, and the temporary
folder is removed at the end.
