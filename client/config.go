package main

import (
	"flag"
	"strings"
)

type (
	routeFlag    []string
	clientConfig struct {
		serverAddr string
		domain     string
		ifaceName  string
		ifaceCIDR  string
		ifaceMTU   int
		routes     []string
		username   string
		password   string
	}
)

func parseClientConfig() (cfg clientConfig) {
	var (
		routeList routeFlag
	)

	var (
		serverAddr *string = flag.String("server", "127.0.0.1:53535", "DNS server address (host:port)")
		domain     *string = flag.String("domain", "vpn.internal", "Authoritative domain handled by the VPN server")
		ifaceName  *string = flag.String("iface", "dns1", "Name for the client TUN interface")
		ifaceCIDR  *string = flag.String("iface-cidr", "10.44.0.2/30", "CIDR to assign to client TUN interface")
		ifaceMTU   *int    = flag.Int("iface-mtu", 1400, "MTU for the client TUN interface")
		username   *string = flag.String("username", "demo", "Username for handshake")
		password   *string = flag.String("password", "demo", "Password for handshake")
	)

	flag.Var(&routeList, "route", "Route to add via the client TUN (repeatable, e.g. -route 10.0.0.0/24)")
	flag.Parse()

	cfg = clientConfig{
		serverAddr: *serverAddr,
		domain:     *domain,
		ifaceName:  *ifaceName,
		ifaceCIDR:  *ifaceCIDR,
		ifaceMTU:   *ifaceMTU,
		routes:     routeList,
		username:   *username,
		password:   *password,
	}

	return
}

func (r *routeFlag) String() (result string) {
	result = strings.Join(*r, ",")
	return
}

func (r *routeFlag) Set(val string) (err error) {
	var cleaned string = strings.TrimSpace(val)
	if cleaned != "" {
		*r = append(*r, cleaned)
	}

	return
}
