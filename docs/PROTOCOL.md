# Protocol

Wire-level description of the Surface protocol, as implemented in this
repository. It is intended for reviewers and for alternative implementations.
Cryptographic details are in [`CRYPTO.md`](CRYPTO.md); threats and guarantees in
[`THREAT-MODEL.md`](THREAT-MODEL.md).

Conventions:

- All integers are big-endian unless stated otherwise.
- `||` means concatenation.
- "Host" always means a normalized hostname: lowercase, no trailing dot
  (`NormalizeHost` in `identity.go`).
- Everything runs over TCP. There is no UDP, QUIC or ICMP support.

## 1. Layers

```
+-------------------------------------------------------+
| application (HTTP, SSH, ...)                           |
+-------------------------------------------------------+
| local proxy  SOCKS5 CONNECT / HTTP CONNECT / absolute  |   client only
+-------------------------------------------------------+
| stream protocol v2 (or legacy v1)                      |   client <-> node
+-------------------------------------------------------+
| TLS 1.2+                                               |
+-------------------------------------------------------+
| yamux multiplexing                                     |
+-------------------------------------------------------+
| ed25519 connection handshake                           |
+-------------------------------------------------------+
```

For `.surface` traffic, an additional end-to-end layer sits inside the yamux
stream between client and agent: Noise NK, then AEAD frames. The node relays
those bytes without parsing them.

Ports:

| Port | Default | Exposure |
| --- | --- | --- |
| `9253/tcp` | `tunnel_listen` | public (the only port that must be reachable) |
| `9252/tcp` | `proxy_listen` | loopback |
| `9292/tcp` | `health_listen` | loopback, `/healthz` |

## 2. Connection handshake

Applies to every connection to the node: agents, clients and peer nodes.

```
node                                                    peer
 |  nonce[32] (crypto/rand)                              |
 |------------------------------------------------------>|
 |  ctype[1] || ed25519_pub[32] || sig[64]               |
 |<------------------------------------------------------|
 |  status[1]                                            |
 |------------------------------------------------------>|
```

- `sig = ed25519_sign(peer_priv, nonce || ctype)`.
- The nonce is fresh per connection; replay of a signature on a new connection
  fails.
- Deadline: 15 s (`handshakeTimeout`).

`ctype` values (`tunnel.go:20`, `peer.go:20`):

| Value | Role | After the handshake |
| --- | --- | --- |
| `1` | agent registration | 4-byte length + registration JSON, then yamux |
| `2` | client | yamux, client opens streams |
| `3` | peer node (announce/challenge) | signed peer envelope |
| `4` | peer list request | signed peer envelope |

Status byte sent by the node:

| Value | Meaning |
| --- | --- |
| `0` | accepted |
| `2` | rejected (not authorized, or malformed) |
| `5` | unknown connection type |

The peer never receives a reason. A rejected connection is closed. The node
does not authenticate itself in this handshake; node authentication is TLS
pinning (`node_auth: "pinned"`) or nothing (`none`).

yamux roles:

- agent registration: node is the yamux **client** (opens streams to the
  agent), agent is the yamux **server** (accepts them),
- client connection: node is the yamux **server**, client is the yamux **client**.

yamux settings: keepalive enabled, interval 15 s, connection write timeout 30 s,
logs discarded.

## 3. Agent registration

After a `ctype = 1` handshake and `status = 0`:

```
+---------------------------+------------------------------+
| length (4 bytes, BE)      | JSON registration            |
+---------------------------+------------------------------+
```

`length` must be in `1 .. 65536`; larger or zero is rejected. JSON shape:

```json
{
  "name": "kzdvvj2umnduyauf.surface",
  "services": [
    { "virtual_port": 80, "alias": "blog" }
  ],
  "e2e": true,
  "protocol": 2
}
```

Rules enforced by the node (`node.go:154`):

- `name` must equal `DeriveName(pub)` of the handshake key, otherwise the
  connection is closed silently.
- `services` must be non-empty.
- Every `(name, virtual_port)` is upserted into the registry with the session
  ID and marked online.
- The agent must send `e2e: true` for `.surface` to be reachable; the node
  refuses to serve `.surface` from a session that did not declare E2E.
- The registration is last-write-wins per `(name, virtual_port)`.

Multiple identities are multiple registrations (one yamux session per identity
per node), grouped by `identity_dir` (`groupByIdentity` in `agent.go`).

## 4. Stream requests

A client opens a yamux stream and writes one request. Two versions are
supported by the node; clients always send v2.

### 4.1 v2 request

```
+------+---------+--------+-----------+--------+-------------+
| 0x00 | 0x02    | 0x02   | host_len  | host   | port (2 BE) |
+------+---------+--------+-----------+--------+-------------+
   ^      ^         ^
 marker  version   type=CONNECT
```

- `marker` is `0x00`. v1 requests can never start with `0x00` because a v1 host
  length of zero is invalid, so the versions are unambiguous.
- `host_len` is `1 .. 255`.
- The request carries no client identity; identity is the TLS/yamux session.

### 4.2 v1 request (legacy, read-only)

```
+-----------+--------+-------------+
| host_len  | host   | port (2 BE) |
+-----------+--------+-------------+
```

A v1 request has no E2E metadata. The node serves clearnet through the normal
exit, and `.surface` is forwarded to the agent as plaintext, where the E2E
handshake fails and the stream is closed. Plaintext never reaches the service.

### 4.3 Response

```
+--------+---------+--------------------+-------------------+
| status | flags   | agent_pub[32]      | e2e_version[1]    |
+--------+---------+--------------------+-------------------+
```

- `flags` and the rest are only present when `status == 0`.
- `flags & 0x01` means E2E is in use. When set, `agent_pub` (ed25519) and
  `e2e_version` follow.
- Status codes (`protocol.go:20`):

| Code | Name | Meaning |
| --- | --- | --- |
| `0` | `respOK` | stream established |
| `1` | `respNotFound` | unknown service, offline session, or unreachable clearnet target |
| `2` | `respE2EUnavailable` | the agent did not register E2E; `.surface` refused |
| `3` | `respBadRequest` | invalid key or stream setup |
| `4` | `respExitUnavailable` | `.onion` requested and Tor is unavailable, or exit failure |

After `respOK`, the stream becomes a raw byte pipe (clearnet) or the Noise
channel (`.surface`). The node does not send further metadata.

### 4.4 Routing decisions at the node

| Destination | Behavior |
| --- | --- |
| `*.surface`, v2 | registry lookup by `(name, port)`; require an online E2E session; open a yamux stream to the agent; write the 2-byte virtual port; reply `respOK` + agent key; relay |
| `*.surface`, v1 | open the agent stream, write the virtual port, relay plaintext; the agent's Noise responder fails and closes |
| `*.onion` | `onion_proxy` only (SOCKS5). No direct fallback. Failure → `respExitUnavailable` |
| everything else | `exit_proxy` if configured, else direct. Failure → `respNotFound` (or `respExitUnavailable` for onion) |

These status codes are v2 only. A v1 stream has no response header: it is
served if possible and simply closed on failure.

Client-side validation after `respOK` for `.surface` (`multinode.go:289`):

1. the response must have the E2E flag,
2. `e2e_version` must be `1`,
3. `DeriveName(agent_pub)` must equal the requested name,
4. the Noise NK handshake must succeed with the prologue that binds version,
   name, port and agent key.

Any failure closes the stream and the client tries the next node.

### 4.5 Virtual port

The node writes the requested virtual port to the agent stream as 2 bytes,
unencrypted but inside TLS and the yamux session, **before** the E2E handshake:

```
+---------------------+
| virtual_port (2 BE) |
+---------------------+
```

The Noise prologue also includes the port, so a relay that rewrites these two
bytes causes a prologue mismatch. The port is therefore authenticated by the
E2E layer, not by the 2-byte field.

## 5. End-to-end layer

See [`CRYPTO.md`](CRYPTO.md) for full detail. Summary:

```
client                                  node                         agent
  |-- v2 request ----------------------->|                             |
  |<-- respOK, flags, pub, ver ----------|                             |
  |                                     |-- yamux stream + vport ---->|
  |-- Noise msg1 (frame) ---------------|---------------------------->|
  |<-- Noise msg2 (frame) --------------|<----------------------------|
  |== AEAD frames (4-byte length) ======|============================>|
```

- Pattern: `Noise_NK_25519_ChaChaPoly_BLAKE2s`.
- Prologue: `surface-e2e-v1|name|port|hex(ed25519_pub)`.
- Framing: `length (4 BE) || ciphertext`, `1 <= length <= 65551`.
- Plaintext chunks: 32 KiB.

## 6. Peer discovery

Peer discovery is optional (`peer_discovery`, default `true`) and runs after
the `ctype = 3` or `ctype = 4` handshake. Messages are JSON envelopes wrapped
in a length-prefixed frame.

### 6.1 Envelope

```
+--------------------------+---------------------------+
| length (4 bytes, BE)     | {"v":1,"payload":...,"sig":...}
+--------------------------+---------------------------+
```

- `length` is `1 .. 65536`.
- `payload` and `sig` are base64 in JSON (`[]byte` encoding).
- `v` must be `1`.
- `sig = ed25519_sign(priv, "surface-peer-v1|" + kind + "|" + payload_bytes)`.
- `kind` is supplied out of band and is not transmitted; the verifier must know
  which message it expects.

### 6.2 Messages

| Kind | Direction | Fields |
| --- | --- | --- |
| `announce` | node → seed/peer | `type`, `public_key`, `addresses[]` or `port`, `timestamp`, `nonce`, `capabilities[]` |
| `peers` | any → any | `type`, `node_public_key`, `timestamp`, `peers[]` |
| `challenge` | verifier → target | `type`, `nonce`, `timestamp` |
| `challenge_response` | target → verifier | `type`, `public_key`, `address`, `nonce`, `timestamp` |
| `peers_request` | client/agent → node | `type`, `limit`, `timestamp` |

`PeerInfo` entries: `public_key`, `address`, `last_seen`, `source`.

### 6.3 Announce and verification flow

1. A node announces to each seed: signed `announce` with its key, a fresh nonce
   and a timestamp, plus either `addresses` or its tunnel port.
2. The receiver derives the address: explicit `addresses[0]` if present,
   otherwise the source IP of the connection + the announced port.
3. The receiver calls back the address, sends a random `challenge`, and requires
   a valid `challenge_response` signed by the **announced** key, echoing the
   nonce and carrying a fresh timestamp.
4. On success the peer is stored as `verified` with a 7-day TTL; on failure the
   failure counter is incremented and the entry is shortened to 1 hour.
5. The receiver answers with a signed `peers` list (up to 64 entries for an
   announce).
6. Nodes gossip to up to 3 random verified peers per round. Clients and agents
   use `peers_request` and merge the signed response.

Address validation (`normalizePeerAddr` in `peer.go:203`):

- must be `literal_ip:port` (no hostnames),
- rejects loopback, private, link-local, multicast, unspecified and CGNAT
  (`100.64.0.0/10`) addresses,
- `peer_allow_private: true` disables the public-IP requirement for private
  clusters. It also lets peer lists point at internal ranges.

Additional rules:

- timestamps must be within ±5 minutes,
- an address that changes its node key is ignored for that address,
- peer lists are not trusted transitively: every listed peer needs its own
  callback before it is stored,
- peer-DB row cap 5000, list cap 200, at most 5 callbacks per merge,
- per-IP rate limits: announcements 30 s, peer list requests 20 s.

### 6.4 Discovery limits

This is seed-assisted gossip, not a DHT. If every seed is unreachable, existing
peers cached in `peer_cache_file` keep working and configured `node_addrs`
remain usable, but new nodes cannot announce themselves.

## 7. Local proxy

`proxy_listen` (default `127.0.0.1:9252`) auto-detects the protocol by the
first byte: `0x05` means SOCKS5, anything else is parsed as HTTP.

SOCKS5 (`socks5.go`):

- greeting: version 5, method `0x00` (no auth) only; the server replies
  `05 00`,
- supports `CONNECT` only (`CMD 0x01`); other commands get reply `0x07`,
- address types: IPv4 (`0x01`), domain (`0x03`), IPv6 (`0x04`),
- reply is always `05 00 00 01 0.0.0.0:0` on success, `05 05 ...` on failure.

HTTP (`httpproxy.go`):

- `CONNECT host:port` (default port 443) → `200 Connection Established`,
- absolute-URI requests (`GET http://host/path`) → forwarded, default port 80,
- `Proxy-Connection` and `Proxy-Authorization` headers are stripped,
- failures return `502 Bad Gateway`.

The local proxy has no authentication. Keep it on loopback. DNS for `.surface`
must be resolved by the proxy, so browsers need "proxy DNS when using SOCKS v5".

Aliases are expanded client-side before the request is sent: `aliases` maps
`name.surface` to another `name.surface` (`multinode.go:245`).

The official [SURFACE Browser](https://github.com/krondevs/surface-browser)
configures Chromium to use this proxy and additionally disables HTTP/3, local
DNS prefetch and non-proxied WebRTC UDP so no traffic escapes the proxy. It is a
consumer of this protocol, not a separate implementation: the Go client still
owns the SOCKS5 listener and the E2E handshake.

## 8. Limits and timeouts

| Parameter | Value | Where |
| --- | --- | --- |
| Connection handshake deadline | 15 s | `handshakeTimeout` |
| Registration JSON size | 1 .. 65536 bytes | `readRegistration` |
| TLS minimum version | 1.2 | `dialTLSAddr`, `startTunnelListener` |
| TLS dial timeout | 15 s | `dialTLSAddr` |
| Exit dial timeout | 30 s | `internet.DialTarget` |
| yamux keepalive | 15 s | `yamuxConfig` |
| yamux write timeout | 30 s | `yamuxConfig` |
| E2E plaintext chunk | 32 KiB | `e2eChunk` |
| E2E frame max | 65551 bytes | `e2eMaxFrame` |
| Peer frame max | 64 KiB | `peerFrameMax` |
| Peer timestamp skew | ±5 min | `peerTimestampSkew` |
| Peer list per response | 200 | `peerListMax` |
| Peer DB rows | 5000 | `peerDBMax` |
| Peer TTL | 7 days | `peerTTL` |
| Peer connect / I/O / announce timeout | 15 s / 10 s / 30 s | `peer.go` |
| Peer refresh minimum | 30 s (default 300 s) | `PeerManager.Run`, `PeerDiscovery.Run` |
| Agent reconnect delay | 5 s, fixed | `agentNodeLoop` |
| Client node reconnect backoff | 1 s → 16 s, exponential | `MultiNodeDialer.maintain` |
| Heartbeat / sweeper | 15 s (`heartbeat_seconds`) | `node.runSweeper` |
| Health server read header timeout | 5 s | `health.go` |

`heartbeat_timeout_seconds` is parsed, defaulted and documented, but it is not
enforced anywhere in the current code. Session liveness relies on yamux
keepalive and TCP. Treat it as reserved.

## 9. Versioning and compatibility

Independent version axes:

| Axis | Current | Negotiation |
| --- | --- | --- |
| Stream protocol | 2 (v1 readable) | first byte marker |
| E2E version | 1 | `e2e_version` byte in the response, and the prologue prefix |
| Peer protocol | 1 | envelope `v` field |
| Registration | `protocol: 2`, `e2e: true` | agent-declared, node-enforced |

Rules:

- Adding a new stream request type or response flag must not change the meaning
  of existing bytes.
- A new E2E version must use a new prologue prefix (`surface-e2e-v2|...`) and be
  negotiated explicitly; never silently downgrade.
- Unknown peer envelope versions are rejected, not ignored.
- Rollout order for protocol changes: seeds first, then nodes, then agents and
  clients. Documented in the README for the v2 rollout; keep the same discipline.

Current compatibility matrix:

| Client | Node | Result |
| --- | --- | --- |
| v2 | v2 | full: `.surface` E2E, clearnet, onion |
| v1 | v2 | clearnet only; `.surface` fails closed |
| v2 | v1 | `.surface` unavailable (old node answers status 5 / no E2E flag); clearnet may work |

## 10. Interoperability notes

- Do not assume JSON key order in peer payloads; signatures cover the exact
  bytes received, so verify before re-marshalling.
- Host normalization is part of the protocol: `EXAMPLE.surface.` and
  `example.surface` are the same name.
- The `.surface` name is 16 lowercase base32 characters plus `.surface`.
- Implementations must fail closed on any E2E or name-binding error.
- Test vectors for name derivation, prologue and peer signatures are in
  [`CRYPTO.md`](CRYPTO.md).

Reference implementation: this repository (`main.go` is the CLI entry point).
