# Security Policy

## Supported versions

`smb3-client` is pre-1.0 and currently maintained on a single line of releases.
Security fixes land on the latest published `0.x` minor; older minors are not
backported. Pin the exact version in your `package-lock.json` and upgrade
through patch releases as they ship.

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a vulnerability

**Do not open a public GitHub issue for suspected vulnerabilities.**

If you find a security issue, please report it privately to:

**euricojardim@gmail.com**

If you'd prefer GitHub's private reporting flow, use the *Report a vulnerability*
button on the [Security Advisories tab](../../security/advisories/new) of this
repository.

A good report includes:

- A short description of the issue and its impact.
- Steps to reproduce, ideally as a minimal code sample or pcap of relevant
  SMB2 frames.
- The version of `smb3-client` and Node.js you're running.
- Any suggested fix or mitigation, if you have one in mind.

You can expect:

- Acknowledgement within 5 business days.
- A triage assessment (severity, scope, planned action) within 14 days.
- Coordinated disclosure: a fix shipped before the issue is published.
- Credit in the release notes if you'd like.

## Threat model and known limitations

This library implements [MS-SMB2] from scratch. Some known properties of the
current implementation matter for security review:

### Authentication

- Only **NTLMv2** is supported, wrapped in a minimal SPNEGO layer. NTLMv2 has
  well-documented weaknesses: it is susceptible to relay attacks if the server
  is misconfigured (e.g. SMB signing not required), and offline cracking is
  feasible against weak passwords. For high-security environments use a server
  that enforces signing and rotate to strong, unique passwords.
- **Kerberos is out of scope.** If your environment requires Kerberos (or if
  NTLMv2 is disabled by group policy), this library will not authenticate.
- Password (or pre-computed NT hash) is held in memory for the lifetime of the
  `Client`. The hash is not zeroed on disconnect — Node and OS-level memory
  hygiene apply.

### Wire integrity

- **SMB2 message signing** is implemented and verified on every signed
  response (HMAC-SHA256 for 2.x dialects; AES-128-CMAC for 3.x). A signature
  mismatch fatally fails the connection.
- For SMB 3.1.1, the **pre-auth integrity hash** (SHA-512) is computed and fed
  into the signing-key derivation per spec.
- **SMB 3.x message encryption is not implemented.** All traffic above the
  signing layer is sent in cleartext. Treat the SMB connection itself as
  cleartext on the wire — anyone able to read the network can see file
  contents and metadata, even though they cannot tamper with messages
  undetected.
- **SMB 3.1.1 `EncryptionCapabilities` is advertised with zero ciphers** so
  the server does not select encryption. Servers that *require* encryption
  will refuse the connection.

### Cryptographic primitives

- All crypto uses Node's `node:crypto` (HMAC-SHA256, AES-128-CMAC built on
  AES-128-ECB, AES-128-ECB, SHA-512) **except** MD4 and RC4, which are
  hand-rolled in pure TypeScript.
- **MD4** is required only for NTLM password hashing (`MD4(UTF-16LE(password))`).
  It is broken as a general-purpose hash; we use it solely because the
  NTLMv2 protocol mandates it. The implementation has been validated against
  RFC 1320 and the canonical NTLMv2 test vector
  `ntowfV2("Password", "User", "Domain") = 0c868a40…2ef02e3f` (MS-NLMP
  §4.2.4.1.1).
- **RC4** is used only to wrap the 16-byte session key inside the NTLMSSP
  AUTHENTICATE message (`EncryptedRandomSessionKey`). Identical use to every
  other Windows-compatible NTLMv2 client.
- **AES-CMAC** is implemented per RFC 4493 and verified against all three
  RFC test vectors in unit tests.

### Path handling

- Public paths use forward slashes with the share name as the first segment.
  The path normalizer rejects:
  - `\\server\share` UNC syntax (caller can't pivot off the configured share).
  - Drive letters (`C:\…`).
  - Components equal to `..`.
- The library does not implement directory recursion for `rm`/`rmdir`. Caller
  walks the tree explicitly. This is by design and avoids accidental deletes.

### Out of scope (not vulnerabilities)

The following are explicitly not supported in v1; reports about their absence
will be filed as enhancement requests rather than security issues:

- SMB 3.x message encryption.
- Kerberos or any GSS mech other than NTLMSSP.
- Compound requests, leases, durable handles, multi-channel.
- DFS referrals.
- NetBIOS over TCP/139.
- Recursive `rm` / `rmdir`.

## Coordinated disclosure

We follow standard coordinated disclosure: please give us a reasonable window
to ship a fix before publishing details. Default 90 days from initial report,
extended by mutual agreement if a fix is in progress.

## Dependencies

`smb3-client` has **no runtime dependencies**. Build/test toolchain
(TypeScript, Vitest, ESLint, Prettier) is `devDependencies` only and never
ships in the published tarball.
