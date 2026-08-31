package main

import (
	"flag"
	"strings"
)

type (
	routeFlag    []string
	serverConfig struct {
		listenAddr, domain, ifaceName, ifaceCIDR, natIface string
		ifaceMTU                                           int
		routes                                             []string
	}
)

func parseServerConfig() (cfg serverConfig) {
	var (
		routeList routeFlag
	)

	var (
		listenAddr *string = flag.String("listen", ":53535", "Address to listen for DNS queries on")
		domain     *string = flag.String("domain", "vpn.internal", "Domain to serve VPN DNS responses for")
		ifaceName  *string = flag.String("iface", "dns0", "Name for the server TUN interface")
		ifaceCIDR  *string = flag.String("iface-cidr", "10.44.0.1/30", "CIDR to assign to server TUN interface")
		ifaceMTU   *int    = flag.Int("iface-mtu", 1400, "MTU for the server TUN interface")
		natIface   *string = flag.String("nat-iface", "", "Uplink interface to NAT client traffic through (default: auto-detect)")
	)

	flag.Var(&routeList, "route", "Route to add via the server TUN (repeatable, e.g. -route 10.0.0.0/24)")
	flag.Parse()

	cfg = serverConfig{
		listenAddr: *listenAddr,
		domain:     *domain,
		ifaceName:  *ifaceName,
		ifaceCIDR:  *ifaceCIDR,
		ifaceMTU:   *ifaceMTU,
		natIface:   *natIface,
		routes:     routeList,
	}

	return
}

func (r *routeFlag) String() (result string) {
	result = strings.Join(*r, ",")
	return
}

func (r *routeFlag) Set(val string) (err error) {
	var cleaned string = strings.TrimSpace(val)
	if cleaned == "" {
		return
	}

	*r = append(*r, cleaned)
	return
}
