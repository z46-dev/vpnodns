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

func main() {
	var (
		cfg clientConfig = parseClientConfig()
		err error
	)

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

	var (
		dnsClient *dns.Client = &dns.Client{
			Net:          "udp",
			UDPSize:      4096,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
			Dialer: &net.Dialer{
				Timeout: 5 * time.Second,
			},
		}
		tunIf *tun.Interface
	)

	if tunIf, err = tun.Open(cfg.ifaceName); err != nil {
		err = fmt.Errorf("open TUN: %w", err)
		return
	}

	defer tunIf.Close()
	log.Statusf("client TUN ready: %s\n", tunIf.Name())

	if err = tun.Setup(tunIf.Name(), cfg.ifaceCIDR, cfg.ifaceMTU, cfg.routes); err != nil {
		err = fmt.Errorf("configure TUN: %w", err)
		return
	}

	var (
		sessionID, lastSeq uint32 = randomUint32(), 0
		sessionKey         []byte
	)

	if lastSeq, sessionKey, err = performHandshake(ctx, dnsClient, sessionID, cfg.domain, cfg.serverAddr, cfg.username, cfg.password); err != nil {
		err = fmt.Errorf("handshake failed: %w", err)
		return
	}

	var (
		seq          uint32               = lastSeq
		serverReplay *shared.ReplayWindow = new(shared.ReplayWindow)
		nextSeq      func() uint32        = func() uint32 {
			return atomic.AddUint32(&seq, 1)
		}
	)

	go forwardClientTraffic(ctx, tunIf, dnsClient, cfg.serverAddr, cfg.domain, sessionID, sessionKey, serverReplay, nextSeq)
	go pollServer(ctx, tunIf, dnsClient, cfg.serverAddr, cfg.domain, sessionID, sessionKey, serverReplay, nextSeq)

	<-ctx.Done()
	log.Basicf("client shutting down\n")
	return
}

func performHandshake(ctx context.Context, dnsClient *dns.Client, sessionID uint32, domain, serverAddr, username, password string) (seq uint32, sessionKey []byte, err error) {
	var clientHello shared.ClientHello
	if clientHello, err = shared.NewClientHello(username, password, []shared.CipherSuite{
		shared.CipherSuiteAES256GCM,
	}); err != nil {
		err = fmt.Errorf("build client hello: %w", err)
		return
	}

	var msg shared.Message
	if msg, err = clientHello.ToMessage(sessionID, 1); err != nil {
		err = fmt.Errorf("encode client hello: %w", err)
		return
	}

	var serverMsg shared.Message
	if serverMsg, err = sendMessage(ctx, dnsClient, serverAddr, domain, msg, shared.MessageTypeServerHello); err != nil {
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

	if hello.SelectedCipher != shared.CipherSuiteAES256GCM {
		err = fmt.Errorf("server selected unsupported cipher %q", hello.SelectedCipher)
		return
	}

	if sessionKey, err = shared.DeriveSessionKey(password, clientHello.Nonce, hello.Nonce); err != nil {
		return
	}

	var proof []byte
	if proof, err = shared.FinishedProof(sessionKey); err != nil {
		return
	}

	var (
		finished  shared.Finished = shared.Finished{Proof: proof}
		finishMsg shared.Message
	)

	if finishMsg, err = finished.ToMessage(sessionID, 2); err != nil {
		err = fmt.Errorf("encode finished: %w", err)
		return
	}

	var resp shared.Message
	if resp, err = sendMessage(ctx, dnsClient, serverAddr, domain, finishMsg, shared.MessageTypeServerAck); err != nil {
		return
	}

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
		var fallback [8]byte
		binary.BigEndian.PutUint64(fallback[:], uint64(time.Now().UnixNano()))
		value = binary.BigEndian.Uint32(fallback[4:])
		return
	}

	value = binary.BigEndian.Uint32(b[:])
	return
}

func sendMessage(ctx context.Context, dnsClient *dns.Client, serverAddr, domain string, msg shared.Message, expect ...shared.MessageType) (resp shared.Message, err error) {
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

	var opt *dns.OPT
	if opt = m.IsEdns0(); opt != nil {
		if opt.UDPSize() < size {
			opt.SetUDPSize(size)
		}

		return
	}

	m.SetEdns0(size, false)
}

func forwardClientTraffic(ctx context.Context, tunIf *tun.Interface, dnsClient *dns.Client, serverAddr, domain string, sessionID uint32, sessionKey []byte, serverReplay *shared.ReplayWindow, nextSeq func() uint32) {
	var buf []byte = make([]byte, 2000)

	for {
		var (
			n   int
			err error
		)

		if n, err = tunIf.Read(buf); err != nil {
			log.Warningf("client tun read error: %v\n", err)
			return
		}

		var pkt []byte = append([]byte(nil), buf[:n]...)
		if shared.IsMulticast(pkt) {
			continue
		}

		var (
			seq uint32         = nextSeq()
			msg shared.Message = shared.Message{
				Type:      shared.MessageTypeClientData,
				SessionID: sessionID,
				Sequence:  seq,
				Payload:   pkt,
			}
		)

		if msg, err = shared.SealMessage(sessionKey, msg); err != nil {
			log.Warningf("client encrypt data seq=%d err: %v\n", seq, err)
			continue
		}

		var response shared.Message
		if response, err = sendMessage(ctx, dnsClient, serverAddr, domain, msg, shared.MessageTypeServerAck); err != nil {
			log.Warningf("client send data seq=%d err: %v\n", seq, err)
			continue
		}

		if _, err = shared.OpenMessage(sessionKey, response); err != nil {
			log.Warningf("client authenticate ack seq=%d err: %v\n", seq, err)
			continue
		}

		if !serverReplay.Accept(response.Sequence) {
			log.Warningf("client rejected replayed ack seq=%d\n", response.Sequence)
			continue
		}

		log.Basicf("client tx %d bytes (%s)\n", n, shared.PacketSummary(pkt))
	}
}

func pollServer(ctx context.Context, tunIf *tun.Interface, dnsClient *dns.Client, serverAddr, domain string, sessionID uint32, sessionKey []byte, serverReplay *shared.ReplayWindow, nextSeq func() uint32) {
	var ticker *time.Ticker = time.NewTicker(300 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		var (
			seq uint32         = nextSeq()
			msg shared.Message = shared.Message{
				Type:      shared.MessageTypeClientPoll,
				SessionID: sessionID,
				Sequence:  seq,
			}
			resp shared.Message
			err  error
		)

		if msg, err = shared.SealMessage(sessionKey, msg); err != nil {
			log.Warningf("client encrypt poll seq=%d err: %v\n", seq, err)
			continue
		}

		if resp, err = sendMessage(ctx, dnsClient, serverAddr, domain, msg, shared.MessageTypeServerData, shared.MessageTypeServerAck); err != nil {
			log.Warningf("client poll seq=%d err: %v\n", seq, err)
			continue
		}

		if resp.Type != shared.MessageTypeServerData || len(resp.Payload) == 0 {
			if _, err = shared.OpenMessage(sessionKey, resp); err != nil {
				log.Warningf("client authenticate poll ack seq=%d err: %v\n", seq, err)
			} else if !serverReplay.Accept(resp.Sequence) {
				log.Warningf("client rejected replayed poll ack seq=%d\n", resp.Sequence)
			}

			continue
		}

		if resp, err = shared.OpenMessage(sessionKey, resp); err != nil {
			log.Warningf("client decrypt poll response seq=%d err: %v\n", seq, err)
			continue
		}

		if !serverReplay.Accept(resp.Sequence) {
			log.Warningf("client rejected replayed response seq=%d\n", resp.Sequence)
			continue
		}

		if shared.IsMulticast(resp.Payload) {
			continue
		}

		if _, err = tunIf.Write(resp.Payload); err != nil {
			log.Warningf("client write tun error: %v\n", err)
			continue
		}

		log.Basicf("client rx %d bytes (%s)\n", len(resp.Payload), shared.PacketSummary(resp.Payload))
	}
}
