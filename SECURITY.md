# Security policy

Surface is networking and cryptography software. Security reports are welcome and
are taken seriously, but **Surface is a young project**: it has not been audited
by a third party and it does not provide anonymity. Read the
[threat model](docs/THREAT-MODEL.md) and the
[security model](README.md#security-model) before deploying it.

## Supported versions

| Version | Supported |
| --- | --- |
| `main` (development) | ✅ best effort |
| latest `1.x` release | ✅ security fixes |
| older releases | ❌ upgrade first |

Only the Go daemon in this repository is covered by this policy. The Electron
browser shell ([`krondevs/surface-browser`](https://github.com/krondevs/surface-browser)),
the Android wrapper (`android/`) and third-party dependencies have their own
scope notes below.

## Reporting a vulnerability

**Do not open a public issue for a vulnerability.**

Use GitHub's private vulnerability reporting on this repository:

1. Go to the **Security** tab → **Advisories** → **Report a vulnerability**.
2. Include the details listed below.

If private reporting is unavailable, open a public issue that only asks for a
private contact channel, and do not include exploit details.

Please include:

- affected version, commit or release tag, and platform,
- a description of the issue and the affected component
  (node, agent, client, discovery, proxy, E2E, packaging),
- reproduction steps or a proof of concept,
- the impact you believe it has (confidentiality, integrity, availability,
  deanonymization, privilege escalation, key compromise),
- any suggested fix or mitigation,
- whether you want to be credited, and under what name.

Never test against nodes, seeds or services you do not own. Denial of service,
traffic flooding, port scanning and social engineering are out of scope for
research conducted under this policy.

## What to expect

These are good-faith targets, not a contractual SLA:

| Step | Target |
| --- | --- |
| Acknowledgment | 7 days |
| Initial triage and severity assessment | 30 days |
| Fix or documented mitigation for high/critical issues | 90 days |
| Public advisory and credit | coordinated with the reporter |

If a report is valid but you disagree with the severity, the assessment will be
shared with the reasoning. If a report is out of scope, you will be told why.

## Scope

In scope:

- the transport handshake and session handling (`tunnel.go`, `sessions.go`),
- stream protocol v1/v2 (`protocol.go`, `node.go`),
- end-to-end encryption (`e2e.go`),
- identity, address derivation and certificate pinning (`identity.go`, `cert.go`),
- authorization and registry state (`registry.go`, `main.go`),
- local proxy implementations (`proxy.go`, `socks5.go`, `httpproxy.go`),
- clearnet and onion exit selection (`exit.go`, `exitproxy.go`),
- peer discovery and peer store (`discovery.go`, `peer.go`, `peerstore.go`,
  `peercache.go`),
- configuration handling and defaults (`settings.go`, `default_settings.json`),
- build, release and installer scripts (`scripts/`, `.github/workflows/`).

Out of scope for this repository:

- Chromium/Electron vulnerabilities and the browser shell: see the
  [SURFACE Browser security policy](https://github.com/krondevs/surface-browser/blob/main/SECURITY.md)
  and report those issues in
  [`krondevs/surface-browser`](https://github.com/krondevs/surface-browser/security).
- the Android app wrapper (Android platform issues; report the Go core here),
- vulnerabilities in upstream dependencies (report them upstream as well,
  `govulncheck` output is still useful),
- missing hardening that is already documented as a known limitation below,
- issues that require a compromised host, root access, or a malicious local
  user with access to the key directory,
- Tor, the operating system, or the network path outside Surface.

## Known limitations (not vulnerabilities)

These are design decisions or explicitly documented gaps. Reports about them
will be closed with a pointer to the
[threat model](docs/THREAT-MODEL.md). They are still worth opening as a design
discussion if you have a concrete proposal.

- **No anonymity.** Routing is single-hop. A node sees which service is
  contacted, the origin IP, timing and volume.
- **No traffic-analysis resistance.** No padding, cover traffic, batching or
  multi-hop routing yet.
- **The node is untrusted for `.surface` data, not for availability.** A node
  can drop, delay or refuse connections.
- **Clearnet plain HTTP is readable and modifiable by the node.** HTTPS protects
  content; the node always sees the destination host.
- **`node_auth: "none"` does not authenticate the node.** An active attacker can
  impersonate or redirect a node. `.surface` content stays confidential and
  bound to the agent key, but availability and clearnet exit selection are not
  protected. Use `node_auth: "pinned"` if that matters.
- **Open registration defaults.** With `allowed_agents`, `allowed_nodes` and the
  client key table empty, anyone can register an agent or connect a client.
  See [closing the network](README.md#security-model).
- **No per-service client authorization.** Knowing a `.surface` name is enough
  to reach the service; authorization happens at the node.
- **UDP, QUIC and ICMP are unsupported.** Only TCP `CONNECT` is proxied.
- **Peer discovery is seed-assisted gossip, not a DHT.** A seed can censor or
  eclipse discovery. Existing connections keep working if every seed is down.
- **Logs contain metadata.** Destination hosts and peer addresses appear in
  `surface.log`.

## Hardening checklist

For operators:

- expose only `9253/tcp` (and `9292/tcp` on loopback if you use `/healthz`),
- keep `proxy_listen` on loopback unless you intentionally run an open proxy,
- use `node_auth: "pinned"` for closed networks,
- set `allowed_agents` / `allowed_nodes` and authorize client keys,
- restrict outbound traffic with a firewall if the node is public
  (`exit_proxy`, DNS and Tor only),
- back up `identity/` and `keys/` with mode `0600`, and never commit them,
- run the daemon as an unprivileged user with a read-only filesystem except its
  data directory,
- rotate keys by creating a new identity directory and re-registering; there is
  no in-place rotation command yet.

For contributors:

- never log private keys, handshake secrets or decrypted payloads,
- fail closed on authentication, name-binding and prologue mismatch,
- use `crypto/rand` for anything security relevant (`math/rand` is used only for
  gossip jitter and peer shuffle),
- compare secrets with `crypto/subtle` (see `cert.go`),
- do not invent primitives: the E2E layer is Noise, the rest is ed25519,
  X25519 and TLS (`docs/CRYPTO.md`).

## Disclosure policy

- Fixes are developed privately and released with a coordinated advisory.
- Reporters are credited unless they ask otherwise.
- If a fix requires a protocol change, the advisory states the compatibility
  impact and the required rollout order (see `docs/PROTOCOL.md`).
- There is no bug bounty. Thanks and credit are the currency here.

## Security-relevant documentation

- [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) — assets, adversaries,
  mitigations and residual risk.
- [`docs/CRYPTO.md`](docs/CRYPTO.md) — primitives, key hierarchy, prologue
  binding, framing, test vectors.
- [`docs/PROTOCOL.md`](docs/PROTOCOL.md) — wire formats, limits and versioning.
- [`README.md#security-model`](README.md#security-model) — operator-facing
  summary.
- [SURFACE Browser](https://github.com/krondevs/surface-browser) — official
  desktop client, a separate attack surface with its own
  [security policy](https://github.com/krondevs/surface-browser/blob/main/SECURITY.md).
