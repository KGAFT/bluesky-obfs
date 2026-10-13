# bluesky-obfs

Make any `TcpStream` wrapped in a tokio `Framed` look like a legitimate HTTPS connection to a website of your choice.

> [!WARNING]
> A server running this codec acts as a reverse proxy to the website it emulates (the *cover site*). Anyone who connects without authenticating is relayed to the real cover site. The optional rate limiter (`FakeCodecRateLimiterCfg`) keeps one connection from pushing too much traffic through the cover site. Even so, I recommend you also implement a blacklist for clients that fail the handshake repeatedly. `setup_stream` returns `false` on every failed handshake, so that's a natural place to count failures.

## How it works

1. **Cover handshake.** The client uses an HTTP client that can reproduce the TLS fingerprints of many real browsers [`wreq`](https://crates.io/crates/wreq). 
It makes a real browser request (Firefox fingerprint by default) to the cover site, e.g. `https://www.google.com/`. 
The request goes through a local setup proxy and then over the TCP connection to the obfs server.
The server relays the TLS session to the real cover site. Passive observers and active probers therefore see a real TLS handshake with a real certificate.
2. **Injected authentication.** While the cover session runs, `Spake2Injector` inserts messages into the TLS application-data records: `ClientHello`/`ClientBegin` from the client and `ServerHello`/`ServerBegin` from the server.
They are encrypted with a key derived from a shared *public password*, and they carry:
   - a SPAKE2 password-authenticated key exchange, using a per-client login and password from a credential provider;
   - key-confirmation tags bound to a transcript of the whole handshake;
   - a timestamp and nonce. The server's `ReplayGuard` uses them to reject replayed hellos.

   If a peer does not authenticate, the server stays in cover mode and keeps relaying to the real site, so a probe sees the same behaviour as from the real site.
3. **Codec.** Once SPAKE2 completes, both sides derive session keys from the shared secret and the transcript. `FakeCodec` then works as a `tokio_util` `Encoder`/`Decoder`: each payload is AEAD-sealed, padded, and framed as a TLS application-data record.
4. **Shaping.** Record sizes come from a `ConnectionPattern` captured from real traffic to the cover site, with random padding when no captured size is close enough. `DelayGenerator` adds random delays during the handshake. On the server, an optional rate limiter (`FakeCodecRateLimiterCfg`) bounds how far a client's traffic can drift from the pattern.


The crate is a library named `bsobfs`.

### Features

| Feature         | Default | Description |
|-----------------|---------|-------------|
| `debug-logging` | off     | Turns on `dbg_log!` output on the connection path. Leave it off in production: a release build writes nothing to stderr about connections. |

```sh
cargo build --features debug-logging
```

## Traffic patterns

`PatternStore::load_or_capture` reads `cli_pattern.bin` and `serv_pattern.bin` from the working directory. If they are missing, it captures new ones: it makes a real request to the cover site through a local proxy on port `9999` and records the size and order of the TLS records in each direction.

The pattern files are specific to one cover site and are git-ignored. Delete them to capture again, and use the same pair on the client and the server.

## Using the library

The main entry point is `FakeCodec`. Configure it with `FakeCodecCfg` and run `setup_stream` on a connected TCP stream. If setup succeeds, wrap the stream in `Framed`:

```rust
use bsobfs::codec::fake_codec::{FakeCodec, FakeCodecCfg};
use tokio_util::codec::Framed;

let mut codec = FakeCodec::new(cfg);
if codec.setup_stream(&mut tcp).await {
    let mut framed = Framed::new(tcp, codec);
    // send/receive Bytes through `framed`
} else {
    // failed handshake: count it towards a blacklist
}
```

Main `FakeCodecCfg` fields:

| Field | Purpose |
|-------|---------|
| `pattern` | `ConnectionPattern` for this side's outgoing traffic |
| `public_password` | 32-byte key shared by all clients of a server; protects the injected handshake messages |
| `credentials` | `CredentialsSide::Client(..)` or `CredentialsSide::Server(..)`: your credential provider |
| `target_sni` / `target_sni_connection_dest` | Cover site URL and `host:port` |
| `target_browser` | `wreq` emulation profile, e.g. `Emulation::Firefox151` |
| `setup_proxy_port` | Local port for the client's setup proxy during the handshake |
| `server_id` | Server identity mixed into SPAKE2; must match on both sides |
| `message_padding_size`, `max_adjusted_padding_derivation_percent` | Padding behaviour |
| `allowed_delays`, `long_delay_secs` | Timing jitter |
| `rate_limiter` | Optional server-side shaping limits |
| `replay_guard` | Server-side `Arc<ReplayGuard>`, shared by all connections |
| `handshake_timeout` | Upper bound on `setup_stream` |

Credentials come from two traits you implement:

```rust
#[async_trait]
pub trait ClientCredentialProvider: Send + Sync + 'static {
    /// Returns (login, password).
    async fn get_client_credentials(&self) -> Option<(Vec<u8>, Vec<u8>)>;
}

#[async_trait]
pub trait ServerCredentialProvider: Send + Sync + 'static {
    /// Return None for unknown logins, or if `time_in_auth_ms` is not newer
    /// than the last successful auth for this login (replay).
    async fn get_client_password(&self, client_identity: &str, time_in_auth_ms: u64) -> Option<Vec<u8>>;
}
```

## Examples

`examples/` contains a runnable server and client, configured through environment variables:

| Example | What it does |
|---------|--------------|
| `capture_pattern` | Captures (or loads) the cover site's pattern files and prints the record-size histogram |
| `server` | Accepts connections, authenticates them, and relays each tunnel to the `host:port` the client asks for |
| `client` | Connects to the server, opens a local HTTP `CONNECT` proxy for one session, and reconnects when the session ends |

```sh
# 1. Capture the pattern once, then copy cli_pattern.bin / serv_pattern.bin to both hosts
COVER_HOST=www.example.com cargo run --release --example capture_pattern

# 2. Server
LISTEN=0.0.0.0:443 PUBLIC_PASSWORD=HelloPassword \
    cargo run --release --example server

# 3. Client
SERVER=203.0.113.10:443 PUBLIC_PASSWORD=HelloPassword \
LOGIN=client PASSWORD=HelloPasswordForHandshake \
    cargo run --release --example client

# 4. Use it
curl -x http://127.0.0.1:9985 https://example.com/
```

| Variable | Used by | Default |
|----------|---------|---------|
| `COVER_HOST` | all | `www.example.com` for `server` and `client`, `www.pinterest.com` for `capture_pattern` |
| `PUBLIC_PASSWORD` | server, client | `HelloPassword` (hashed with SHA-256 into the 32-byte key) |
| `LISTEN` | server | `0.0.0.0:443` |
| `RATE_LIMIT` | server | off; `1` enables `FakeCodecRateLimiterCfg` |
| `SERVER` | client | required |
| `LOGIN` / `PASSWORD` | client | `client` / `HelloPasswordForHandshake` |
| `LOCAL_PROXY_PORT` | client | `9985` |

The examples add one convention of their own: the first tunnel message is the destination `host:port` as UTF-8. Server users are hard-coded in `InMemoryUsers` in `examples/server.rs`. Replace that with a lookup against your own store.

Limitations:

- Only TLS traffic can pass (HTTPS through `CONNECT`), because the local proxy frames TLS records.
- `ProxyInterface` accepts one client per bind, so the client serves one session at a time.
- With the rate limiter on, the server rejected a legitimate client during the handshake in local testing. That's why it's opt-in in the example.

## Tests

```sh
cargo test
```

Several tests make real network connections (for example, to `www.google.com` and the cover site), so they need internet access.
