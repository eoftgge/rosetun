# Release signing

Each release's `SHA256SUMS.txt` is signed locally with
[minisign](https://jedisct1.github.io/minisign/). The secret key never goes to
CI. The public key is `crates/rosetun-core/keys/minisign.pub`. The signature is
`SHA256SUMS.txt.minisig`, with the trusted comment `rosetun <version>`.

`release.yml` creates the release as a draft. Then, on the machine that holds
the key (Windows or Linux; needs Python 3, `gh` logged in, and `minisign` on
PATH):

```sh
python3 tools/release/sign.py --version 0.7.0 --secret-key <path to the secret key>
```

On Windows, use `python` instead of `python3` if needed.

The script checks that `v<version>` is a draft, downloads its `SHA256SUMS.txt`,
signs it (minisign asks for the key password), verifies the signature with the
public key, checks that it is prehashed (`ED`) with the exact trusted comment,
and uploads the `.minisig`. It does not publish. Look at the draft, then publish
it with `gh release edit v<version> --draft=false`, or run the script again with
`--publish`. The key is never read, copied, printed or stored by the script, and
the temporary folder is removed at the end.
