# Forensic Evidence Archive

This directory preserves malicious artifacts from the axios npm supply chain attack (2026-03-31).

All files are password-protected zip archives (`infected`). **Do not extract outside an isolated environment.**

---

## npm Packages

Malicious npm package tarballs. Sourced from [DataDog/malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset).

| Package | File | SHA256 (tarball) |
|---------|------|-----------------|
| `axios@1.14.1` | `axios@1.14.1/axios-1.14.1.tgz` | `1b5d13dcb825751a72f7b557325809e4823c57163d9e400565108f2ad0a469d1` |
| `plain-crypto-js@4.2.1` | `plain-crypto-js@4.2.1/plain-crypto-js-4.2.1.tgz` | (see metadata.json) |

See each package directory for `metadata.json`, `sha256.txt`, and `sha1.txt`.

---

## Malware Payloads

Malicious binaries and scripts delivered by the `postinstall` hook. Each zip contains one file named by its SHA256 hash.

| SHA256 (payload) | Type | Zip size | Description |
|-----------------|------|----------|-------------|
| `e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09` | `.js` | 2 KB | Dropper — `setup.js` (executed by postinstall, self-deletes after) |
| `f7d335205b8d7b20208fb3ef93ee6dc817905dc3ae0c10a0b164f4e7d07121cd` | `.bat` | <1 KB | Windows stage-1 launcher |
| `e49c2732fb9861548208a78e72996b9c3c470b6b562576924bcc3a9fb75bf9ff` | `.bat` | <1 KB | Windows stage-2 launcher |
| `ed8560c1ac7ceb6983ba995124d5917dc1a00288912387a6389296637d5f815c` | `.ps1` | 3 KB | Windows PowerShell RAT |
| `6fbb418b08f8b0511dbac05fc942676d16fc632eccb99b9c72dc5c9300f3c14b` | `.ps1` | 3 KB | Windows PowerShell RAT (variant) |
| `8c8f5f095d65d3f33ce89a77dfbe84a79bb29d2e0073a57a23dcc014d0683c2e` | `.ps1` | 3 KB | Windows PowerShell RAT (variant) |
| `46f5eea70d536f7affe40409d7aaa5fa0009f0dc4538ba2867cb7569737db859` | `.ps1` | 3 KB | Windows PowerShell RAT (variant) |
| `617b67a8e1210e4fc87c92d1d1da45a2f311c08d26e89b12307cf583c900d101` | `.ps1` | 3 KB | Windows PowerShell RAT (variant) |
| `fcb81618bb15edfdedfb638b4c08a2af9cac9ecfa551af135a8402bf980375cf` | `.py` | 3 KB | Python RAT / credential stealer |
| `58401c195fe0a6204b42f5f90995ece5fab74ce7c69c67a24c61a057325af668` | `.gz` | 88 KB | Compressed payload (Linux) |
| `92ff08773995ebc8d55ec4b8e1a225d0d1e51efa4ef88b8849d0071230c9645a` | `.macho` | 154 KB | macOS RAT binary (Mach-O) |

### Zip SHA256 verification

| Zip filename (truncated) | SHA256 (zip) |
|--------------------------|-------------|
| `e10b1fa…e09.zip` | `b8d81f36a570c777031e6d94b06c7869fdbefce650b8e8a5c0aadb8a8606ae25` |
| `f7d3352…1cd.zip` | `eb2a2479f65559e18e98270448ac07c8b6a984b25dc73a76c602282ba84d1af5` |
| `e49c273…fff.zip` | `2e91401c1574f8bbb9c7857827c0a348f4e0d40dc97fa355ba08de91b73c731b` |
| `ed8560c…15c.zip` | `8883f7d801b8166092aab555d96651ed765485083ece1f29f707744eff550e15` |
| `6fbb418…14b.zip` | `1bb558486f1301504bfaf44e9c16268d9c81e50706755c05bcffd266292e44ce` |
| `8c8f5f0…c2e.zip` | `d9a43fd1853917b4cfc8b32792dbdebd8bf5feecd5aabd0e691d18021ce2f987` |
| `46f5eea…859.zip` | `0835820cf05e3bc29d7e10af3d0d7b079574b0c82c9acc4809e508877f1c5909` |
| `617b67a…101.zip` | `f5b7a0331d69e330f1474ead0eac7fec88c21cfc8a5a30520a0bb2e6844cfec2` |
| `fcb8161…3cf.zip` | `d7660e62d8263d76192d610e9873ec807a710642dd7ed89ba65ff39efbed060f` |
| `58401c1…668.zip` | `b872c39a0a5d97e7f0bcc99646cac920c9b3c2d7b871cae07998231f90736f24` |
| `92ff087…45a.zip` | `c15b5d68c52778593ad16ff4f52116e77404f3a045e88010fc8f0e5873d5951a` |

---

## Attack Timeline

| Time (UTC) | Event |
|-----------|-------|
| 2026-03-31 00:21 | `axios@1.14.1` published to npm |
| 2026-03-31 00:21–03:51 | **Attack window** — postinstall hook active |
| 2026-03-31 03:51 | Package removed / replaced with clean stub |

Any environment that ran `npm install` with a semver range resolving to `1.14.1` during the attack window should be considered compromised.
