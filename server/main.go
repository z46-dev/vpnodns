package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"

	"github.com/z46-dev/go-logger"
	"github.com/z46-dev/vpnodns/shared"
	"github.com/z46-dev/vpnodns/tun"
)

var log *logger.Logger = logger.NewLogger().SetPrefix("[server]", logger.BoldGreen).IncludeTimestamp()

func main() {
	var cfg serverConfig = parseServerConfig()
	var err error

	if err = runServer(cfg); err != nil {
		log.Errorf("server error: %v\n", err)
		os.Exit(1)
	}
}

func runServer(cfg serverConfig) (err error) {
	var (
		ctx    context.Context
		cancel context.CancelFunc
	)

	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	go waitForSignal(cancel)

	var tunIf *tun.Interface
	if tunIf, err = tun.Open(cfg.ifaceName); err != nil {
		return fmt.Errorf("open TUN: %w", err)
	}
	defer tunIf.Close()

	log.Statusf("server TUN ready: %s\n", tunIf.Name())
	if err = tun.Setup(tunIf.Name(), cfg.ifaceCIDR, cfg.ifaceMTU, cfg.routes); err != nil {
		return fmt.Errorf("configure TUN: %w", err)
	}

	var uplink string = cfg.natIface
	if uplink == "" {
		if uplink, err = tun.DetectDefaultIface(); err != nil {
			return fmt.Errorf("detect uplink: %w", err)
		}
	}

	log.Basicf("using uplink interface for NAT: %s\n", uplink)
	if err = tun.DisableRPFilter(tunIf.Name()); err != nil {
		log.Warningf("disable rp_filter on %s: %v\n", tunIf.Name(), err)
	}
	if err = tun.DisableRPFilter(uplink); err != nil {
		log.Warningf("disable rp_filter on %s: %v\n", uplink, err)
	}

	tun.EnforceRPFilterZeroUntil(tunIf.Name(), ctx.Done(), 250*time.Millisecond)
	tun.EnforceRPFilterZeroUntil(uplink, ctx.Done(), 250*time.Millisecond)

	if err = tun.SetupNAT(uplink, tunIf.Name()); err != nil {
		return fmt.Errorf("configure NAT on %s: %w", uplink, err)
	}
	tun.LogNATState(log, uplink, tunIf.Name())

	var sessions *sessionManager = newSessionManager(cfg.queueSize, cfg.sessionTTL)
	sessions.StartJanitor(ctx)

	var wg sync.WaitGroup
	wg.Go(func() {
		queueServerTraffic(tunIf, sessions)
	})

	var assembler *shared.Reassembler = shared.NewReassembler()
	var mux *dns.ServeMux = dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		if err := handleQuery(w, r, cfg, assembler, tunIf, sessions); err != nil {
			log.Warningf("query error: %v\n", err)
			dns.HandleFailed(w, r)
		}
	})

	var server dns.Server = dns.Server{
		Addr:         cfg.listenAddr,
		Net:          "udp",
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		UDPSize:      4096,
	}

	go func() {
		log.Statusf("DNS server listening on %s for %s\n", cfg.listenAddr, cfg.domain)
		if err := server.ListenAndServe(); err != nil {
			log.Errorf("serve DNS: %v\n", err)
			cancel()
		}
	}()

	<-ctx.Done()
	_ = server.Shutdown()
	wg.Wait()
	log.Basicf("server shutting down\n")
	return
}

func handleQuery(w dns.ResponseWriter, r *dns.Msg, cfg serverConfig, assembler *shared.Reassembler, tunIf *tun.Interface, sessions *sessionManager) (err error) {
	var msg shared.Message

	if msg, err = shared.DecodeQuery(r, cfg.domain); err != nil {
		return
	}

	var complete bool
	if msg, complete, err = assembler.Add(msg); err != nil {
		return
	}

	if !complete {
		var ack shared.Message = shared.Message{
			Type:       shared.MessageTypeServerAck,
			SessionID:  msg.SessionID,
			Sequence:   msg.Sequence,
			TotalParts: msg.TotalParts,
			Part:       msg.Part,
		}
		var resp *dns.Msg
		if resp, err = shared.EncodeTXTResponse(ack, r); err != nil {
			return
		}
		setResponseEDNS(resp, r)
		err = w.WriteMsg(resp)
		return
	}

	log.Basicf("received %v seq=%d len=%d parts=%d\n", msg.Type, msg.Sequence, len(msg.Payload), msg.TotalParts)
	switch msg.Type {
	case shared.MessageTypeClientHello:
		var clientHello shared.ClientHello
		if clientHello, err = shared.ParseClientHello(msg); err != nil {
			return
		}

		log.Basicf("client hello user=%s suites=%v\n", clientHello.Username, clientHello.CipherSuites)
		var accepted bool = validateCredentials(cfg, clientHello)
		var serverNonce []byte
		if serverNonce, err = randomBytes(32); err != nil {
			return
		}

		if accepted {
			sessions.Register(msg.SessionID)
			if !sessions.AcceptClientSequence(msg.SessionID, msg.Sequence) {
				err = fmt.Errorf("duplicate handshake seq=%d", msg.Sequence)
				return
			}
			var sessionKey []byte
			if sessionKey, err = shared.DeriveSessionKey(cfg.password, msg.SessionID, clientHello.Nonce, serverNonce); err != nil {
				return
			}
			sessions.SetSessionKey(msg.SessionID, sessionKey)
		}

		var respMsg shared.Message
		respMsg, err = shared.ServerHello{
			Accepted:          accepted,
			SelectedCipher:    chooseCipher(clientHello.CipherSuites),
			Nonce:             serverNonce,
			Proof:             shared.ComputeServerHelloProof(cfg.password, msg.SessionID, clientHello.Nonce, serverNonce),
			RejectionReason:   rejectionReason(accepted),
			SupportsFragments: true,
		}.ToMessage(msg.SessionID, msg.Sequence+1)

		if err != nil {
			return
		}

		var resp *dns.Msg
		if resp, err = shared.EncodeTXTResponse(respMsg, r); err != nil {
			return
		}

		setResponseEDNS(resp, r)
		err = w.WriteMsg(resp)
		return

	case shared.MessageTypeFinished:
		if !sessions.AcceptClientSequence(msg.SessionID, msg.Sequence) {
			err = fmt.Errorf("replayed/out-of-window seq=%d for session=%d", msg.Sequence, msg.SessionID)
			return
		}
		var key []byte
		var ok bool
		if key, ok = sessions.SessionKey(msg.SessionID); !ok {
			err = fmt.Errorf("missing session key for %d", msg.SessionID)
			return
		}

		var finished shared.Finished
		if finished, err = shared.ParseFinished(msg); err != nil {
			return
		}
		if !shared.VerifyFinished(finished, key, msg.SessionID) {
			err = fmt.Errorf("invalid finished proof")
			return
		}
		sessions.MarkEstablished(msg.SessionID)

		var respMsg shared.Message = shared.Message{Type: shared.MessageTypeServerAck, SessionID: msg.SessionID, Sequence: msg.Sequence + 1}
		return writeResponseMessage(w, r, respMsg)

	case shared.MessageTypeClientData:
		if !sessions.AcceptClientSequence(msg.SessionID, msg.Sequence) {
			err = fmt.Errorf("replayed/out-of-window seq=%d for session=%d", msg.Sequence, msg.SessionID)
			return
		}
		if !sessions.IsEstablished(msg.SessionID) {
			err = fmt.Errorf("client data before handshake completion")
			return
		}

		var sessionKey []byte
		var ok bool
		if sessionKey, ok = sessions.SessionKey(msg.SessionID); !ok {
			err = fmt.Errorf("missing session key for %d", msg.SessionID)
			return
		}
		if msg, err = shared.DecryptMessagePayload(msg, sessionKey, shared.TrafficClientToServer); err != nil {
			return
		}

		if shared.IsMulticast(msg.Payload) {
			err = writeAck(w, r, msg)
			return
		}

		var srcIP net.IP
		srcIP, _, _ = shared.PacketSrcDst(msg.Payload)
		sessions.BindClientIP(msg.SessionID, srcIP)

		if _, err = tunIf.Write(msg.Payload); err != nil {
			err = fmt.Errorf("write tun: %w", err)
			return
		}

		log.Basicf("server rx %d bytes (%s)\n", len(msg.Payload), shared.PacketSummary(msg.Payload))
		return writeDataOrAck(w, r, msg, sessions)

	case shared.MessageTypeClientPoll:
		if !sessions.AcceptClientSequence(msg.SessionID, msg.Sequence) {
			err = fmt.Errorf("replayed/out-of-window seq=%d for session=%d", msg.Sequence, msg.SessionID)
			return
		}
		if !sessions.IsEstablished(msg.SessionID) {
			err = fmt.Errorf("client poll before handshake completion")
			return
		}
		return writeDataOrAck(w, r, msg, sessions)

	default:
		err = fmt.Errorf("unhandled message type %d", msg.Type)
		return
	}
}

func chooseCipher(suites []shared.CipherSuite) (suite shared.CipherSuite) {
	if len(suites) == 0 {
		suite = shared.CipherSuiteCHACHA20POLY1305
		return
	}

	suite = suites[0]
	return
}

func waitForSignal(cancel context.CancelFunc) {
	var sigCh chan os.Signal = make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	<-sigCh
	cancel()
}

func writeAck(w dns.ResponseWriter, req *dns.Msg, msg shared.Message) (err error) {
	var respMsg shared.Message = shared.Message{
		Type:      shared.MessageTypeServerAck,
		SessionID: msg.SessionID,
		Sequence:  msg.Sequence + 1,
	}

	var resp *dns.Msg
	if resp, err = shared.EncodeTXTResponse(respMsg, req); err != nil {
		return
	}

	setResponseEDNS(resp, req)
	err = w.WriteMsg(resp)
	return
}

func writeDataOrAck(w dns.ResponseWriter, req *dns.Msg, msg shared.Message, sessions *sessionManager) (err error) {
	var (
		respMsg shared.Message
		pkt     []byte
		ok      bool
	)

	if pkt, ok = sessions.Dequeue(msg.SessionID); ok && len(pkt) > 0 && !shared.IsMulticast(pkt) {
		respMsg = shared.Message{
			Type:      shared.MessageTypeServerData,
			SessionID: msg.SessionID,
			Sequence:  msg.Sequence + 1,
			Payload:   pkt,
		}
		var sessionKey []byte
		if sessionKey, ok = sessions.SessionKey(msg.SessionID); ok {
			if respMsg, err = shared.EncryptMessagePayload(respMsg, sessionKey, shared.TrafficServerToClient); err != nil {
				return
			}
		}
		log.Basicf("server tx queued packet seq=%d len=%d (%s)\n", msg.Sequence, len(pkt), shared.PacketSummary(pkt))
	} else {
		respMsg = shared.Message{
			Type:      shared.MessageTypeServerAck,
			SessionID: msg.SessionID,
			Sequence:  msg.Sequence + 1,
		}
	}

	return writeResponseMessage(w, req, respMsg)
}

func writeResponseMessage(w dns.ResponseWriter, req *dns.Msg, msg shared.Message) (err error) {
	var resp *dns.Msg
	if resp, err = shared.EncodeTXTResponse(msg, req); err != nil {
		return
	}

	setResponseEDNS(resp, req)
	err = w.WriteMsg(resp)
	return
}

func validateCredentials(cfg serverConfig, hello shared.ClientHello) (accepted bool) {
	var expectedUser string = strings.TrimSpace(cfg.username)
	var expectedPass string = strings.TrimSpace(cfg.password)
	if expectedUser == "" && expectedPass == "" {
		return true
	}

	if hello.Username != expectedUser {
		return false
	}

	return shared.VerifyClientHelloProof(hello, expectedPass)
}

func rejectionReason(accepted bool) (reason string) {
	if accepted {
		return ""
	}
	return "invalid credentials"
}

func queueServerTraffic(tunIf *tun.Interface, sessions *sessionManager) {
	var buf []byte = make([]byte, 2000)
	for {
		var (
			n   int
			err error
		)

		n, err = tunIf.Read(buf)
		if err != nil {
			log.Warningf("server tun read error: %v\n", err)
			return
		}

		var pkt []byte = append([]byte(nil), buf[:n]...)
		if shared.IsMulticast(pkt) {
			continue
		}

		if sessions.EnqueueByPacket(pkt) {
			log.Basicf("server queued %d bytes for client (%s)\n", len(pkt), shared.PacketSummary(pkt))
		} else {
			log.Warningf("server drop outbound (no matching session) %s\n", shared.PacketSummary(pkt))
		}
	}
}

func setResponseEDNS(resp, req *dns.Msg) {
	const serverCap = 4096
	var size uint16 = uint16(serverCap)
	if opt := req.IsEdns0(); opt != nil && opt.UDPSize() > 0 && opt.UDPSize() < size {
		size = opt.UDPSize()
	}

	resp.SetEdns0(size, false)
}

func randomBytes(length int) (data []byte, err error) {
	if length <= 0 {
		return []byte{}, nil
	}

	data = make([]byte, length)
	if _, err = rand.Read(data); err != nil {
		err = fmt.Errorf("generate random bytes: %w", err)
		return
	}

	return
}
