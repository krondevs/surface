# Cryptography

This document describes every cryptographic operation Surface performs, where it
lives in the code, and what it does and does not protect. It exists so that
reviewers do not have to reverse-engineer the protocol, and so that
implementers can interoperate.

Surface does **not** invent cryptographic primitives. It composes ed25519,
X25519, TLS 1.2+ and the Noise Protocol Framework, using Go's standard library,
`golang.org/x/crypto`, `filippo.io/edwards25519` and `github.com/flynn/noise`.

| Primitive | Use | Implementation |
| --- | --- | --- |
| ed25519 | identities, node handshake signatures, peer message signatures, TLS certificate key | `crypto/ed25519` |
| X25519 | Noise static and ephemeral DH | `golang.org/x/crypto/curve25519` |
| ChaCha20-Poly1305 | Noise AEAD | `github.com/flynn/noise` |
| BLAKE2s | Noise hash | `github.com/flynn/noise` |
| SHA-256 | `.surface` name derivation, certificate key pinning | `crypto/sha256` |
| SHA-512 | ed25519 seed → X25519 scalar (libsodium-compatible) | `crypto/sha512` |
| TLS 1.2+ | transport between client/agent and node | `crypto/tls` |

The E2E handshake is **`Noise_NK_25519_ChaChaPoly_BLAKE2s`**. It is not a
custom protocol: it is the standard Noise NK pattern with the standard suite
(`e2e.go:65`).

## 1. Key hierarchy

| Key | File | Type | Purpose |
| --- | --- | --- | --- |
| Agent identity | `identity_dir/secret.key` (default `identity/secret.key`) | ed25519 private key (64 bytes) or seed (32 bytes) | Derives the `.surface` name; signs node handshakes; converts to the Noise static key |
| Client identity | `keys/client.key` | ed25519 | Authenticates the client to the node |
| Node identity | `keys/node.key` | ed25519 | Node authentication in discovery and `pinned` mode |
| Peer request key | `keys/peer.key` | ed25519 | Authenticates `peers_request` envelopes |
| Node TLS key | `certs/node.key` + `certs/node.crt` | ed25519 + self-signed X.509 | Transport only; a trust root only in `pinned` mode |

Keys are stored as raw bytes, created with mode `0600` in directories with mode
`0700` (`identity.go:20`). There is no passphrase, no OS keychain integration
and no HSM support. A file read is a key compromise.

Everyone can generate their own keys. There is no CA, no registration authority
and no key server.

## 2. Address derivation

A `.surface` name is a commitment to the agent's ed25519 public key:

```
sum  = SHA-256(ed25519_public_key)        // 32 bytes
id   = lowercase(base32_no_padding(sum[0:10]))   // 16 characters
name = id + ".surface"
```

Implementation: `DeriveName` in `identity.go:63`. Base32 uses the standard
alphabet (`A-Z2-7`) without padding, lowercased, so a name is 16 characters
plus `.surface`.

Consequences:

- Publishing a service requires only a key, no DNS and no port forwarding.
- Name squatting is impossible: the node rejects a registration whose name is
  not `DeriveName(pub)` (`node.go:154`).
- The name is a **public** hash of the key. It is not a secret and it does not
  hide the service from the relay.

### Test vector

Inputs and outputs, reproducible with any ed25519/SHA-256/base32 implementation:

```
seed        = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
public key  = 03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8
sha256[:10] = 56475aa75463474c0285
name        = kzdvvj2umnduyauf.surface
```

## 3. Node handshake (authentication)

Every client, agent and peer node connection starts with an ed25519
challenge-response over the TLS session (`peerHandshake` /
`readPeerHandshake`, `tunnel.go:58`):

1. Node → peer: 32 random bytes (`nonce`).
2. Peer → node: `ctype (1 byte) || ed25519_public_key (32) || signature (64)`
   where `signature = ed25519_sign(priv, nonce || ctype)`.
3. Node → peer: one status byte (`0` accepted, `2` rejected, `5` unknown
   connection type).

`ctype` values: `1` = agent registration, `2` = client request, `3` = node,
`4` = peer list. Including `ctype` in the signed message prevents a signature
for one role from being replayed as another.

Properties:

- The nonce is fresh per connection, so a captured signature is not replayable
  on a new connection.
- The message is not bound to the TLS channel (no exporter/`tls-unique`
  binding). This is safe under the assumption that the TLS endpoint is the
  node; it matters only if the TLS layer can be terminated by an attacker,
  which is exactly the `node_auth: "none"` case where the node is untrusted
  anyway. See [`THREAT-MODEL.md`](THREAT-MODEL.md), adversary A3.
- The node does not sign anything back at this layer. Node authentication is
  done by TLS pinning when enabled (`pinned`), or not at all (`none`).

## 4. Transport: TLS and pinning

`dialTLSAddr` (`tunnel.go:188`) and `startTunnelListener` (`node.go:103`):

- TLS minimum version: 1.2. No explicit maximum; Go negotiates TLS 1.3 when both
  sides support it.
- The node certificate is generated on first run: ed25519 key, self-signed,
  `IsCA: true`, valid 10 years, CN `surface-node`, `ServerAuth` EKU
  (`ensureTLSCert`, `node.go:399`).
- There is no CA and no hostname validation. Pinning is **public-key pinning**:
  `SHA-256(cert.RawSubjectPublicKeyInfo)` compared in constant time
  (`pinnedKeyFingerprint`, `verifyPinnedCertificateAny` in `cert.go`).
- Because pinning is SPKI-based, certificate expiry, subject and SAN are
  **ignored**. Pinning identifies a key, not a host.
- `InsecureSkipVerify` is always set, and verification is performed by the
  custom callback in `pinned` mode. In `none` mode there is no callback at all.

Two modes (`node_auth`):

| Mode | Node authenticated? | Data protection | Use |
| --- | --- | --- | --- |
| `none` (generated default) | No | `.surface` E2E; TLS only encrypts the hop | Open network, anyone can run a node |
| `pinned` | Yes, SPKI pin | `.surface` E2E plus authenticated relay | Closed network, `tls_skip_verify: false` |

**Footgun:** `tls_skip_verify: true` disables pinning even when
`node_auth: "pinned"`. The check is `if s.TLSSkipVerify || effectiveNodeAuth()
== "none"` (`tunnel.go:193`). Never enable it in a closed network.

## 5. End-to-end encryption (`.surface`)

### 5.1 Why NK

NK is a Noise pattern where the initiator knows the responder's static public
key in advance. That is exactly the Surface model: the client learns the agent
key from the node and verifies it against the name. NK gives:

- responder authentication to the initiator (the agent is who the name says),
- forward secrecy for the session from ephemeral DH,
- no client authentication at this layer (see 5.5).

### 5.2 Key conversion

The agent uses one ed25519 identity and derives its X25519 static key from it,
using the same conversion as libsodium's
`crypto_sign_ed25519_sk_to_curve25519`:

```
x25519_private = SHA-512(ed25519_seed)[0:32]     // X25519 clamps internally
x25519_public  = edwards25519.Point(pub).BytesMontgomery()
```

Implementation: `ed25519PrivateToX25519`, `ed25519PublicToX25519`,
`x25519Public` in `e2e.go`. `TestEd25519X25519Conversion` checks the pair.

Design note: the same ed25519 key is used for signatures (node handshake, peer
envelopes) and, via conversion, as the Noise static DH key. Cross-protocol key
reuse is a deliberate trade-off that keeps one identity per service. Domain
separation limits the risk: the handshake signs `nonce || ctype`, peer messages
sign `surface-peer-v1|<kind>|payload`, and the Noise prologue binds a distinct
string. A future version may split signing and DH keys.

### 5.3 Handshake and prologue

```
client                                              agent
  |  frame: Noise message 1 (e, es)                   |
  |-------------------------------------------------->|
  |  frame: Noise message 2 (e, ee)                   |
  |<--------------------------------------------------|
  |  transport frames (ChaCha20-Poly1305)             |
```

`Prologue = "surface-e2e-v1|" + name + "|" + decimal(port) + "|" + hex(ed25519_pub)`

The prologue is mixed into the Noise `InitializeSymmetric` step. It binds the
channel to:

- the E2E protocol version (`surface-e2e-v1`),
- the normalized service name,
- the virtual port requested,
- the exact agent ed25519 key.

A relay that redirects the stream to another service, another port, or its own
key produces a handshake failure. `TestNoisePrologueMismatchFails` and
`TestNoiseWrongAgentKeyFails` cover this. The prologue contains only public
data; it is not a secret.

The client also checks `DeriveName(pub) == name` before starting the handshake,
so the node cannot substitute a different valid key.

### 5.4 Framing

After the handshake, plaintext is split into 32 KiB chunks. Each chunk is
encrypted with `CipherState.Encrypt` and sent as:

```
+------------------------+------------------------------+
| length (4 bytes, BE)   | ciphertext (length bytes)    |
+------------------------+------------------------------+
```

- `length` must be in `1 .. 65551` (`noise.MaxMsgLen + 16`); `0` and larger
  values are rejected (`readFrame` in `e2e.go`).
- Handshake messages use the same framing.
- Reads are buffered per connection; partial frames are handled with
  `io.ReadFull`.
- Overhead per frame is 4 + 16 = 20 bytes.
- Nonces are managed by Noise: a 64-bit counter per direction, starting at 0.
  There is **no rekey** in the current implementation. Nonce exhaustion is not
  reachable in practice (2^64 messages), but long-lived connections are not
  rekeyed and there is no key update mechanism.

`TestNoiseHandshakeBidirectional` and `TestNoiseRelaySeesNoPlaintext` cover
bidirectional transport and relay opacity.

### 5.5 What E2E authenticates (and what it does not)

Authenticated: the agent key, the name, the port, and the integrity of every
byte. Confidentiality against the relay.

**Not authenticated: the client.** Any party that knows the name can complete
the handshake with the agent. Authorization happens earlier, at the node, by
key allowlist, and it is all-or-nothing: an authorized client can reach every
service registered on that node. Per-service client authorization is a roadmap
item, not a current feature.

Also not provided: padding, cover traffic, replay of application data
prevention beyond TCP semantics, or protection against an agent that
maliciously serves content (the application protocol is out of scope).

## 6. Peer discovery signatures

Peer messages are JSON envelopes (`peer.go`):

```
envelope = {"v":1,"payload":<json>,"sig":<ed25519 signature>}
signed   = "surface-peer-v1|" + kind + "|" + payload_bytes
kind     = announce | challenge | challenge_response | peers | peers_request
```

- The signature covers the exact payload bytes, so re-serializing changes the
  signature and invalidates it.
- `v` is fixed at 1; unknown versions are rejected.
- Frames are `length (4 bytes BE) || JSON`, maximum 64 KiB.
- Timestamps must be within ±5 minutes; challenges and announcements require a
  non-empty nonce.
- `announce` and `challenge_response` are verified against the claimed key.
  A peer listed in someone else's `peers` message is **not** trusted: the
  receiver performs its own callback challenge to the listed address and
  verifies the response with that peer's key (`verifyCallback`,
  `discovery.go:236`).
- A node that changes its key for a known address is ignored for that address
  (`rememberNodeKey`).

Replay notes: an `announce` can be replayed within the 5-minute window. The only
effect is that the receiver performs another callback verification; it cannot
create a trusted entry without a valid signature from the announced key.

### Test vector

Fixed seed `000102...1f`, payload exactly as below (no whitespace), kind
`announce`:

```
payload = {"type":"announce","public_key":"ed25519:03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8","port":9253,"timestamp":1700000000,"nonce":"00112233445566778899aabbccddeeff"}

signed  = surface-peer-v1|announce|{"type":"announce",...}

sig     = def8d55d8eb8d233a16ab670fbbbdae24e2b3ffaabd2570f145d3577fb0c48da5f8adac1e1932f6052c3c3cb8d0bd7864e28a6e134068fa447123bd87b5f06
```

The signature is deterministic for a given seed and message.

## 7. Randomness

- Key generation, nonces, TLS certificates and Noise ephemeral keys use
  `crypto/rand`.
- `math/rand` is used only for gossip jitter (`discovery.go:62`) and peer
  shuffle (`discovery.go:87`). Neither is security relevant.
- `randomID` (yamux session IDs) uses `crypto/rand`.

## 8. Failure behavior

The E2E path fails closed:

- A `.surface` request only proceeds when the agent registered `E2E: true`;
  otherwise the node returns `respE2EUnavailable` (`node.go:265`).
- A v1 (legacy) client talking to a new agent sends plaintext into the E2E
  handshake, which fails; plaintext never reaches the service
  (`TestNodeRejectsPlaintextSurface`).
- Any framing error, AEAD failure, prologue mismatch or key mismatch aborts
  the stream; there is no retry with weaker parameters.
- Invalid pinned certificates abort the TLS connection.

## 9. Limitations

- **No padding or traffic shaping.** Ciphertext length ≈ plaintext length + 20
  bytes per 32 KiB, visible to the relay.
- **No multi-hop.** One relay sees metadata and can deny service.
- **No key rotation or rekey.** Rotating an identity changes the `.surface`
  name.
- **No post-quantum algorithm.** X25519 and ed25519 are not PQ-resistant.
- **No secret storage protection.** Keys are plain files; host compromise is
  game over.
- **No formal verification.** The composition is standard, but the
  implementation has not been machine-checked or audited.
- **No client authentication in E2E.** See 5.5.

## 10. Rules for contributors

1. Do not add new primitives. If something is missing, use an established
   construction (Noise patterns, HPKE, TLS) and document the choice.
2. Never reuse a nonce with a key; let Noise manage nonces.
3. Bind every new channel to the service identity and purpose with a versioned
   prologue or domain-separation string.
4. Fail closed. Authentication or parsing errors must abort, never downgrade.
5. Compare secret material in constant time (`crypto/subtle`).
6. Add a test that proves the property, not just the happy path. If you change
   a byte on the wire, add or update a test vector in this document.
7. Never log secrets, decrypted buffers or Noise handshake material.

## 11. References

- Noise Protocol Framework, revision 34 —
  <https://noiseprotocol.org/noise.html>
- `flynn/noise` (Go implementation) —
  <https://github.com/flynn/noise>
- libsodium ed25519 → curve25519 conversion —
  `crypto_sign_ed25519_sk_to_curve25519`
- RFC 8032 (EdDSA), RFC 7748 (X25519), RFC 8439 (ChaCha20-Poly1305),
  RFC 8446 (TLS 1.3)

Implementation files: `identity.go`, `cert.go`, `tunnel.go`, `e2e.go`,
`protocol.go`, `peer.go`, `discovery.go`. Tests: `e2e_test.go`, `peer_test.go`,
`surface_test.go`.
