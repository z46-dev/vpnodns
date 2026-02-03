# VPN over DNS

DNS packets carry VPN traffic by encoding payloads into DNS question names (client to server) and TXT answers (server to client). The code keeps packets within DNS wire limits by fragmenting/reassembling, and uses EDNS0 to allow larger UDP responses. There is no encryption layer; traffic and handshake data are sent in the clear.

## How it works
- Client opens a TUN interface, reads IP packets, base32-encodes them into DNS query names, and sends UDP queries to the server. Large payloads are split across multiple DNS queries.
- Server listens on UDP for DNS, decodes query-name fragments, reassembles payloads, and writes packets to its TUN. Replies from the internet are queued and returned as TXT records when the client polls.
- Handshake messages (ClientHello/ServerHello/Finished) exist but credentials are not validated and no keys are derived. The handshake is informational only and for future expansion.
- Fragmentation keeps encoded names ≤255 bytes on the fly. Responses use EDNS0 with a 4096-byte UDP size.

## Current limitations
- Handshake metadata is still observable on the wire (not full TLS).
- Multi-client support is still basic and expects each client to use its own tunnel IP.

## Usage
Build or run the packages so both main and config files are included.

Server (run as root to create TUN and configure NAT):
```bash
go run ./server
```

Client (run as root to create TUN):
```bash
go run ./client -server 10.255.37.136:53535
```

Useful flags:
- Server auth + sessions: `-username`, `-password`, `-session-ttl`, `-queue-size`
- Client responsiveness: `-poll-min`, `-poll-max`

Server and client usernames/passwords must match.

## Improvements included

- Handshake credentials are now enforced on server (`ClientHello` can be rejected).
- Server keeps per-session outbound queues and routes packets to the matching session by tunnel destination IP.
- Server can piggyback queued `ServerData` on normal ACK responses, reducing pure-poll overhead.
- Client polling now uses adaptive backoff (`poll-min`..`poll-max`) for better idle CPU/traffic behavior.
- Added session key derivation and AES-GCM encryption for `ClientData`/`ServerData` payloads.
- Added handshake proof verification (client and server proofs + finished proof).
- Added replay/out-of-order protection window on server message sequences (duplicates are dropped).

## Systemd installer

Install helper script and unit templates are included:

```bash
sudo ./scripts/install_systemd.sh
```

Files:
- `systemd/vpnodns-server.service`
- `systemd/vpnodns-client.service`
- `scripts/install_systemd.sh`

You can override runtime flags in:
- `/etc/default/vpnodns-server`
- `/etc/default/vpnodns-client`

## Future goals

- Add encryption and integrity (e.g. TLS-like handshake, AEAD).
- Support multiple clients with proper isolation.
- Improve performance with polling, some things can be sent back as in client data acks.
- CI/CD for tests/builds
- Installer script for Systemd service setup
- Abstraction to allow this to run over other protocols (e.g. DHCP, TFTP, Minecraft Protocol, etc)
