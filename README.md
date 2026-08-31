# VPN over DNS

DNS packets carry VPN traffic by encoding payloads into DNS question names (client to server) and TXT answers (server to client). The code keeps packets within DNS wire limits by fragmenting/reassembling, and uses EDNS0 to allow larger UDP responses. There is no encryption layer; traffic and handshake data are sent in the clear.

## How it works
- Client opens a TUN interface, reads IP packets, base32-encodes them into DNS query names, and sends UDP queries to the server. Large payloads are split across multiple DNS queries.
- Server listens on UDP for DNS, decodes query-name fragments, reassembles payloads, and writes packets to its TUN. Replies from the internet are queued and returned as TXT records when the client polls.
- Handshake messages (ClientHello/ServerHello/Finished) exist but credentials are not validated and no keys are derived. The handshake is informational only and for future expansion.
- Fragmentation keeps encoded names ≤255 bytes on the fly. Responses use EDNS0 with a 4096-byte UDP size.

## Current limitations
- No encryption or integrity protection.
- Username/password is not enforced; the server always accepts.
- Designed for a single client path; the server queue is shared and there is no per-client isolation.

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

## Future goals

- Add encryption and integrity (e.g. TLS-like handshake, AEAD).
- Support multiple clients with proper isolation.
- Improve performance with polling, some things can be sent back as in client data acks.
- CI/CD for tests/builds
- Installer script for Systemd service setup
- Proper keepalive and connection management, including timeouts and retransmissions.
- Abstraction to allow this to run over other protocols (e.g. DHCP, TFTP, Minecraft Protocol, etc)