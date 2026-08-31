# VPN over DNS

DNS packets carry VPN traffic by encoding payloads into DNS question names (client to server) and TXT answers (server to client). The code keeps packets within DNS wire limits by fragmenting/reassembling, and uses EDNS0 to allow larger UDP responses. Passwords are authenticated with an HMAC challenge proof, and post-handshake tunnel messages are encrypted with AES-256-GCM.

## How it works
- Client opens a TUN interface, reads IP packets, base32-encodes them into DNS query names, and sends UDP queries to the server. Large payloads are split across multiple DNS queries.
- Server listens on UDP for DNS, decodes query-name fragments, reassembles payloads, and writes packets to its TUN. Replies from the internet are queued and returned as TXT records when the client polls.
- The client proves knowledge of its password with an HMAC over a fresh nonce. Both peers derive a per-session key from the password and fresh client/server nonces, then verify key possession with the Finished message.
- Client data, polling, server data, and acknowledgements use AES-256-GCM. Message type, session ID, and sequence number are authenticated as additional data.
- Each direction enforces a 64-message replay window. Sessions expire after five idle minutes or 24 total hours, and traffic keys rotate deterministically every 1,024 sequence numbers.
- Fragmentation keeps encoded names ≤255 bytes on the fly. Responses use EDNS0 with a 4096-byte UDP size.

## Current limitations
- The client does not automatically re-handshake after the server's 24-hour absolute session expiry.
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

- Automatically reconnect and establish a fresh session after absolute expiry or prolonged transport failure.
- Support multiple clients with proper isolation.
- Improve performance with polling, some things can be sent back as in client data acks.
- CI/CD for tests/builds
- Installer script for Systemd service setup
- Proper keepalive and connection management, including timeouts and retransmissions.
- Abstraction to allow this to run over other protocols (e.g. DHCP, TFTP, Minecraft Protocol, etc)
