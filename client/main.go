package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"
	"slices"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/miekg/dns"

	"github.com/z46-dev/go-logger"
	"github.com/z46-dev/vpnodns/shared"
	"github.com/z46-dev/vpnodns/tun"
)

var log *logger.Logger = logger.NewLogger().SetPrefix("[client]", logger.BoldBlue).IncludeTimestamp()

type clientSession struct {
	id          uint32
	established atomic.Bool
	key         atomic.Pointer[[32]byte]
}

func main() {
	var cfg clientConfig = parseClientConfig()
	var err error

	if err = runClient(cfg); err != nil {
		log.Errorf("client error: %v\n", err)
		os.Exit(1)
	}
}

func runClient(cfg clientConfig) (err error) {
	var (
		ctx    context.Context
		cancel context.CancelFunc
	)

	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	go waitForSignal(cancel)

	if cfg.pollMin <= 0 {
		cfg.pollMin = 75 * time.Millisecond
	}
	if cfg.pollMax < cfg.pollMin {
		cfg.pollMax = cfg.pollMin
	}

	var dnsClient *dns.Client = &dns.Client{
		Net:          "udp",
		UDPSize:      4096,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		Dialer: &net.Dialer{
			Timeout: 5 * time.Second,
		},
	}

	var tunIf *tun.Interface
	if tunIf, err = tun.Open(cfg.ifaceName); err != nil {
		return fmt.Errorf("open TUN: %w", err)
	}

	defer tunIf.Close()
	log.Statusf("client TUN ready: %s\n", tunIf.Name())

	if err = tun.Setup(tunIf.Name(), cfg.ifaceCIDR, cfg.ifaceMTU, cfg.routes); err != nil {
		return fmt.Errorf("configure TUN: %w", err)
	}

	var sessionID uint32 = randomUint32()
	var session *clientSession = &clientSession{id: sessionID}
	var lastSeq uint32
	if lastSeq, err = performHandshake(ctx, dnsClient, session, cfg.domain, cfg.serverAddr, cfg.username, cfg.password); err != nil {
		return fmt.Errorf("handshake failed: %w", err)
	}

	var seq uint32 = lastSeq
	var nextSeq func() uint32 = func() uint32 {
		return atomic.AddUint32(&seq, 1)
	}

	go forwardClientTraffic(ctx, tunIf, dnsClient, cfg.serverAddr, cfg.domain, session, nextSeq)
	go pollServer(ctx, tunIf, dnsClient, cfg.serverAddr, cfg.domain, session, nextSeq, cfg.pollMin, cfg.pollMax)

	<-ctx.Done()
	log.Basicf("client shutting down\n")
	return
}

func performHandshake(ctx context.Context, dnsClient *dns.Client, session *clientSession, domain, serverAddr, username, password string) (seq uint32, err error) {
	var clientHello shared.ClientHello
	if clientHello, err = shared.NewClientHello(username, password, []shared.CipherSuite{
		shared.CipherSuiteCHACHA20POLY1305,
		shared.CipherSuiteAES256GCM,
		shared.CipherSuiteAES128GCM,
	}); err != nil {
		err = fmt.Errorf("build client hello: %w", err)
		return
	}

	var msg shared.Message
	if msg, err = clientHello.ToMessage(session.id, 1); err != nil {
		err = fmt.Errorf("encode client hello: %w", err)
		return
	}

	var serverMsg shared.Message
	if serverMsg, err = sendMessage(ctx, dnsClient, serverAddr, domain, session, msg, shared.MessageTypeServerHello); err != nil {
		return
	}

	var hello shared.ServerHello
	if hello, err = shared.ParseServerHello(serverMsg); err != nil {
		return
	}

	if !hello.Accepted {
		err = fmt.Errorf("server rejected handshake: %s", hello.RejectionReason)
		return
	}

	if !shared.VerifyServerHelloProof(hello, password, session.id, clientHello.Nonce) {
		err = fmt.Errorf("server hello proof verification failed")
		return
	}

	var sessionKey []byte
	if sessionKey, err = shared.DeriveSessionKey(password, session.id, clientHello.Nonce, hello.Nonce); err != nil {
		return
	}
	session.setKey(sessionKey)

	var finished shared.Finished = shared.NewFinished(sessionKey, session.id)
	var finishMsg shared.Message
	if finishMsg, err = finished.ToMessage(session.id, 2); err != nil {
		err = fmt.Errorf("encode finished: %w", err)
		return
	}

	var resp shared.Message
	if resp, err = sendMessage(ctx, dnsClient, serverAddr, domain, session, finishMsg, shared.MessageTypeServerAck); err != nil {
		return
	}

	session.established.Store(true)
	seq = resp.Sequence
	return
}

func waitForSignal(cancel context.CancelFunc) {
	var sigCh chan os.Signal = make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	<-sigCh
	cancel()
}

func randomUint32() (value uint32) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		value = uint32(time.Now().UnixNano())
		return
	}
	value = binary.BigEndian.Uint32(b[:])
	return
}

func sendMessage(ctx context.Context, dnsClient *dns.Client, serverAddr, domain string, session *clientSession, msg shared.Message, expect ...shared.MessageType) (resp shared.Message, err error) {
	if shouldEncryptClientMessage(msg.Type) {
		if !session.established.Load() {
			err = fmt.Errorf("session not established")
			return
		}
		var key []byte
		var ok bool
		if key, ok = session.sessionKey(); !ok {
			err = fmt.Errorf("missing session key for %v", msg.Type)
			return
		}
		if msg, err = shared.EncryptMessagePayload(msg, key, shared.TrafficClientToServer); err != nil {
			return
		}
	}

	var fragments []shared.Message
	if fragments, err = shared.SplitMessageForQuery(msg, domain); err != nil {
		return
	}

	for idx, frag := range fragments {
		var query *dns.Msg
		if query, err = shared.EncodeQuery(frag, domain); err != nil {
			return
		}

		ensureEDNS(query, uint16(dnsClient.UDPSize))

		var dnsResp *dns.Msg
		if dnsResp, _, err = dnsClient.ExchangeContext(ctx, query, serverAddr); err != nil {
			return
		}

		if resp, err = shared.DecodeTXTResponse(dnsResp); err != nil {
			return
		}

		if idx < len(fragments)-1 {
			if resp.Type != shared.MessageTypeServerAck {
				err = fmt.Errorf("expected ack for part %d, got %v", frag.Part, resp.Type)
				return
			}
			continue
		}
	}

	if len(expect) > 0 && !typeAllowed(resp.Type, expect) {
		err = fmt.Errorf("unexpected response type %v", resp.Type)
		return
	}

	if shouldDecryptServerMessage(resp.Type) {
		if !session.established.Load() {
			err = fmt.Errorf("received encrypted server message before session establishment")
			return
		}
		var key []byte
		var ok bool
		if key, ok = session.sessionKey(); !ok {
			err = fmt.Errorf("missing session key for server message %v", resp.Type)
			return
		}
		if resp, err = shared.DecryptMessagePayload(resp, key, shared.TrafficServerToClient); err != nil {
			return
		}
	}
	return
}

func typeAllowed(t shared.MessageType, allowed []shared.MessageType) (ok bool) {
	ok = slices.Contains(allowed, t)
	return
}

func ensureEDNS(m *dns.Msg, size uint16) {
	if size == 0 {
		size = 4096
	}

	if opt := m.IsEdns0(); opt != nil {
		if opt.UDPSize() < size {
			opt.SetUDPSize(size)
		}
		return
	}

	m.SetEdns0(size, false)
}

func forwardClientTraffic(ctx context.Context, tunIf *tun.Interface, dnsClient *dns.Client, serverAddr, domain string, session *clientSession, nextSeq func() uint32) {
	var buf []byte = make([]byte, 2000)
	for {
		var (
			n   int
			err error
		)

		n, err = tunIf.Read(buf)
		if err != nil {
			log.Warningf("client tun read error: %v\n", err)
			return
		}

		var pkt []byte = append([]byte(nil), buf[:n]...)
		if shared.IsMulticast(pkt) {
			continue
		}

		var seq uint32 = nextSeq()
		var msg shared.Message = shared.Message{
			Type:      shared.MessageTypeClientData,
			SessionID: session.id,
			Sequence:  seq,
			Payload:   pkt,
		}

		var resp shared.Message
		if resp, err = sendMessage(ctx, dnsClient, serverAddr, domain, session, msg, shared.MessageTypeServerAck, shared.MessageTypeServerData); err != nil {
			log.Warningf("client send data seq=%d err: %v\n", seq, err)
			continue
		}

		handleServerMessage(tunIf, resp)
		log.Basicf("client tx %d bytes (%s)\n", n, shared.PacketSummary(pkt))
	}
}

func pollServer(ctx context.Context, tunIf *tun.Interface, dnsClient *dns.Client, serverAddr, domain string, session *clientSession, nextSeq func() uint32, pollMin, pollMax time.Duration) {
	var interval time.Duration = pollMin
	var timer *time.Timer = time.NewTimer(interval)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}

		var seq uint32 = nextSeq()
		var msg shared.Message = shared.Message{
			Type:      shared.MessageTypeClientPoll,
			SessionID: session.id,
			Sequence:  seq,
		}

		var resp shared.Message
		var err error
		if resp, err = sendMessage(ctx, dnsClient, serverAddr, domain, session, msg, shared.MessageTypeServerData, shared.MessageTypeServerAck); err != nil {
			log.Warningf("client poll seq=%d err: %v\n", seq, err)
			interval = minDuration(pollMax, interval*2)
			timer.Reset(interval)
			continue
		}

		if handleServerMessage(tunIf, resp) {
			interval = pollMin
		} else {
			interval = minDuration(pollMax, interval+pollMin)
		}

		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(interval)
	}
}

func handleServerMessage(tunIf *tun.Interface, resp shared.Message) (wrote bool) {
	if resp.Type != shared.MessageTypeServerData || len(resp.Payload) == 0 {
		return false
	}

	if shared.IsMulticast(resp.Payload) {
		return false
	}

	if _, err := tunIf.Write(resp.Payload); err != nil {
		log.Warningf("client write tun error: %v\n", err)
		return false
	}
	log.Basicf("client rx %d bytes (%s)\n", len(resp.Payload), shared.PacketSummary(resp.Payload))
	return true
}

func minDuration(a, b time.Duration) (d time.Duration) {
	if a < b {
		return a
	}
	return b
}

func shouldEncryptClientMessage(msgType shared.MessageType) (encrypt bool) {
	return msgType == shared.MessageTypeClientData
}

func shouldDecryptServerMessage(msgType shared.MessageType) (decrypt bool) {
	return msgType == shared.MessageTypeServerData
}

func (s *clientSession) setKey(key []byte) {
	if len(key) != 32 {
		return
	}
	var fixed [32]byte
	copy(fixed[:], key)
	s.key.Store(&fixed)
}

func (s *clientSession) sessionKey() (key []byte, ok bool) {
	var fixed *[32]byte = s.key.Load()
	if fixed == nil {
		return nil, false
	}
	return append([]byte(nil), fixed[:]...), true
}
