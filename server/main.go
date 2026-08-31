package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
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
	var (
		cfg serverConfig = parseServerConfig()
		err error
	)

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
		err = fmt.Errorf("open TUN: %w", err)
		return
	}

	defer tunIf.Close()

	log.Statusf("server TUN ready: %s\n", tunIf.Name())
	if err = tun.Setup(tunIf.Name(), cfg.ifaceCIDR, cfg.ifaceMTU, cfg.routes); err != nil {
		err = fmt.Errorf("configure TUN: %w", err)
		return
	}

	var uplink string = cfg.natIface
	if uplink == "" {
		if uplink, err = tun.DetectDefaultIface(); err != nil {
			err = fmt.Errorf("detect uplink: %w", err)
			return
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
		err = fmt.Errorf("configure NAT on %s: %w", uplink, err)
		return
	}

	tun.LogNATState(log, uplink, tunIf.Name())

	var (
		outbound chan []byte = make(chan []byte, 64)
		wg       sync.WaitGroup
	)

	wg.Go(func() {
		queueServerTraffic(tunIf, outbound)
	})

	var (
		assembler *shared.Reassembler = shared.NewReassembler()
		mux       *dns.ServeMux       = dns.NewServeMux()
	)

	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		var err error
		if err = handleQuery(w, r, cfg.domain, assembler, tunIf, outbound); err != nil {
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
		var err error
		if err = server.ListenAndServe(); err != nil {
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

func handleQuery(w dns.ResponseWriter, r *dns.Msg, domain string, assembler *shared.Reassembler, tunIf *tun.Interface, outbound chan []byte) (err error) {
	var msg shared.Message

	if msg, err = shared.DecodeQuery(r, domain); err != nil {
		return
	}

	var complete bool
	if msg, complete, err = assembler.Add(msg); err != nil {
		return
	}

	if !complete {
		var (
			ack shared.Message = shared.Message{
				Type:       shared.MessageTypeServerAck,
				SessionID:  msg.SessionID,
				Sequence:   msg.Sequence,
				TotalParts: msg.TotalParts,
				Part:       msg.Part,
			}
			resp *dns.Msg
		)

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

		var respMsg shared.Message
		respMsg, err = shared.ServerHello{
			Accepted:          true,
			SelectedCipher:    chooseCipher(clientHello.CipherSuites),
			Nonce:             []byte("server-nonce"),
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
		var (
			respMsg shared.Message = shared.Message{Type: shared.MessageTypeServerAck, SessionID: msg.SessionID, Sequence: msg.Sequence + 1}
			resp    *dns.Msg
		)

		if resp, err = shared.EncodeTXTResponse(respMsg, r); err != nil {
			return
		}

		setResponseEDNS(resp, r)
		err = w.WriteMsg(resp)
		return

	case shared.MessageTypeClientData:
		if shared.IsMulticast(msg.Payload) {
			err = writeAck(w, r, msg)
			return
		}

		if _, err = tunIf.Write(msg.Payload); err != nil {
			err = fmt.Errorf("write tun: %w", err)
			return
		}

		log.Basicf("server rx %d bytes (%s)\n", len(msg.Payload), shared.PacketSummary(msg.Payload))

		var (
			respMsg shared.Message = shared.Message{Type: shared.MessageTypeServerAck, SessionID: msg.SessionID, Sequence: msg.Sequence + 1}
			resp    *dns.Msg
		)

		if resp, err = shared.EncodeTXTResponse(respMsg, r); err != nil {
			return
		}

		setResponseEDNS(resp, r)
		err = w.WriteMsg(resp)
		return

	case shared.MessageTypeClientPoll:
		select {
		case pkt := <-outbound:
			if len(pkt) == 0 {
				err = writeAck(w, r, msg)
				return
			}

			if shared.IsMulticast(pkt) {
				err = writeAck(w, r, msg)
				return
			}

			var respMsg shared.Message = shared.Message{
				Type:      shared.MessageTypeServerData,
				SessionID: msg.SessionID,
				Sequence:  msg.Sequence + 1,
				Payload:   pkt,
			}

			log.Basicf("server poll seq=%d -> tx %d bytes to client (%s)\n", msg.Sequence, len(pkt), shared.PacketSummary(pkt))
			var resp *dns.Msg
			if resp, err = shared.EncodeTXTResponse(respMsg, r); err != nil {
				return
			}

			setResponseEDNS(resp, r)
			err = w.WriteMsg(resp)
			return
		default:
			err = writeAck(w, r, msg)
			return
		}

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
	var (
		respMsg shared.Message = shared.Message{
			Type:      shared.MessageTypeServerAck,
			SessionID: msg.SessionID,
			Sequence:  msg.Sequence + 1,
		}
		resp *dns.Msg
	)

	if resp, err = shared.EncodeTXTResponse(respMsg, req); err != nil {
		return
	}

	setResponseEDNS(resp, req)
	err = w.WriteMsg(resp)
	return
}

func queueServerTraffic(tunIf *tun.Interface, outbound chan []byte) {
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

		enqueueOutbound(outbound, pkt)
		log.Basicf("server observed inbound for client (%s)\n", shared.PacketSummary(pkt))
	}
}

func setResponseEDNS(resp, req *dns.Msg) {
	const serverCap = 4096

	var (
		size uint16 = uint16(serverCap)
		opt  *dns.OPT
	)

	if opt = req.IsEdns0(); opt != nil && opt.UDPSize() > 0 && opt.UDPSize() < size {
		size = opt.UDPSize()
	}

	resp.SetEdns0(size, false)
}

func enqueueOutbound(outbound chan []byte, pkt []byte) {
	select {
	case outbound <- pkt:
		log.Basicf("server queued %d bytes for client (%s)\n", len(pkt), shared.PacketSummary(pkt))
	default:
		select {
		case <-outbound:
		default:
		}

		select {
		case outbound <- pkt:
			log.Basicf("server queued %d bytes for client (%s)\n", len(pkt), shared.PacketSummary(pkt))
		default:
			log.Warningf("server drop outbound (queue full) %s\n", shared.PacketSummary(pkt))
		}
	}
}
