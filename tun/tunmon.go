package tun

import (
	"fmt"

	"github.com/z46-dev/go-logger"
	"github.com/z46-dev/vpnodns/shared"
)

// Monitor begins monitoring the TUN interface for incoming packets
// Useful for debugging...
func Monitor(tunIf *Interface, prefix string) {
	go func() {
		var (
			log *logger.Logger = logger.NewLogger().SetPrefix(fmt.Sprintf("[%s]", prefix), logger.BoldCyan).IncludeTimestamp()
			buf [2000]byte
			n   int
			err error
		)

		for {
			if n, err = tunIf.Read(buf[:]); err != nil {
				log.Errorf("TUN read error: %v\n", err)
				return
			}

			log.Basicf("TUN rx %d bytes (%s)\n", n, shared.PacketSummary(buf[:n]))
		}
	}()
}
