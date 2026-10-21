# WIP Relay

A self-hosted relay server. When several machines take turns on the same Git repository, it carries each device's working-tree state to the others, so a user knows before writing that another machine still has uncommitted changes. It never uploads file content and never holds content keys.

[中文说明](README.md)

> [!NOTE]
> This project is implemented by AI, with the ideas, requirements and judgement provided by a human. Scope, trade-offs and acceptance criteria are decided by the human; code, documentation and tests are written by AI.

## What it does

- Accepts and stores signed state records from devices, and serves them to other devices in the same channel.
- Keeps channels and devices, handling registration, revocation and retirement.
- Verifies request signatures and time windows, and rejects replays.
- Sets deadlines on headers, bodies, responses and idle connections, so slow connections cannot hold resources indefinitely.

It does not understand Git and never touches file content: a record holds only a device, a sequence number and ciphertext, and even file paths are encrypted.

## What it does not do

- It does not sync content, resolve conflicts, replicate across relays, or manage accounts.
- It does not push notifications; every read is initiated by a client.

## Quick start

Go 1.27 or newer is required, or take a binary from the release page.

```bash
wip-relay init --config wip-relay.toml
wip-relay serve --config wip-relay.toml
```

`init` writes a sample configuration and generates a registration credential. The credential is shown only once, and the server stores only its digest. Once all devices are registered, set `[registration] enabled` to `false` in the configuration and run `wip-relay reload` to apply it.

Releases are single static binaries with no external runtime dependencies. Only publicly signed HTTPS and pinned self-signed certificates are allowed by default; plaintext and certificate-error tolerance must be configured explicitly, and the program never downgrades on its own.

## Deployment notes

- Put it behind a reverse proxy, or enable HTTPS directly.
- Expose only the necessary port; give the data directory minimal permissions and back it up regularly.
- Run it as an unprivileged user.
- Behind a reverse proxy, the source-address dimension sees the proxy's address, so rate limiting by real source belongs at the proxy. The server neither parses nor trusts forwarded headers.

## Using it together

WIP Relay can be paired with the [Vault WIP](https://github.com/y1chu666/vault-wip) plugin: the plugin collects working-tree state, and the relay carries it to other devices in the same channel.

The relay itself is not tied to Obsidian. The protocol is public, see [Protocol](docs/protocol.md); any client that implements it can connect, including for Git repositories unrelated to notes.

## Version compatibility

Starting with `0.2.0` this repository uses record format v2, which is not compatible with v1 in `0.1.0`. A relay does not parse record content, but it does take part in record signature verification, so it must be upgraded whenever a client changes the format; the two sides should be used in matching versions.

## Documentation

The design documents are written in Chinese:

- [Protocol](docs/protocol.md)
- [Server](docs/server.md)
- [Testing](docs/testing.md)

Design and plugin documents live in the [Vault WIP repository](https://github.com/y1chu666/vault-wip).

## License

Released under the Apache License 2.0; the full text is in [LICENSE](LICENSE). You may use, modify, and redistribute it, including commercially, as long as the license text travels with it and modified files are marked as changed. The software comes as is, without warranty of any kind.
