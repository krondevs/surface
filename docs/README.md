# Documentation

Start with the [README](../README.md) for installation and configuration. These
documents go deeper.

| Document | Read it when you want to… |
| --- | --- |
| [THREAT-MODEL.md](THREAT-MODEL.md) | know what Surface protects, against whom, and what it does not do |
| [CRYPTO.md](CRYPTO.md) | verify the primitives, key hierarchy, prologue binding and test vectors |
| [PROTOCOL.md](PROTOCOL.md) | implement or review the wire format, limits and versioning |
| [../SECURITY.md](../SECURITY.md) | report a vulnerability or check the scope and known limitations |

Status: all four documents are initial drafts, reviewed 2026-11-23. They track
the code in this repository and are expected to change as the protocol evolves.
Corrections are welcome as pull requests or issues.

Related material outside this directory:

- [README security model](../README.md#security-model) — operator-facing summary.
- [SURFACE Browser](https://github.com/krondevs/surface-browser) — official
  Chromium/Electron desktop client, a separate project with its own
  [security policy](https://github.com/krondevs/surface-browser/blob/main/SECURITY.md).
  It is published from its own repository; a local checkout can be kept in
  `surface-browser/`, which is not part of this repository.
