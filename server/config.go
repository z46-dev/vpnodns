package main

import (
	"flag"
	"strings"
	"time"
)

type serverConfig struct {
	listenAddr string
	domain     string
	ifaceName  string
	ifaceCIDR  string
	ifaceMTU   int
	natIface   string
	routes     []string
	username   string
	password   string
	sessionTTL time.Duration
	queueSize  int
}

func parseServerConfig() (cfg serverConfig) {
	var (
		routeList routeFlag
	)

	var listenAddr *string = flag.String("listen", ":53535", "Address to listen for DNS queries on")
	var domain *string = flag.String("domain", "vpn.internal", "Domain to serve VPN DNS responses for")
	var ifaceName *string = flag.String("iface", "dns0", "Name for the server TUN interface")
	var ifaceCIDR *string = flag.String("iface-cidr", "10.44.0.1/30", "CIDR to assign to server TUN interface")
	var ifaceMTU *int = flag.Int("iface-mtu", 1400, "MTU for the server TUN interface")
	var natIface *string = flag.String("nat-iface", "", "Uplink interface to NAT client traffic through (default: auto-detect)")
	var username *string = flag.String("username", "demo", "Required client username")
	var password *string = flag.String("password", "demo", "Required client password")
	var sessionTTL *time.Duration = flag.Duration("session-ttl", 2*time.Minute, "Expire inactive client sessions after this duration")
	var queueSize *int = flag.Int("queue-size", 128, "Per-session outbound packet queue size")

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
		username:   *username,
		password:   *password,
		sessionTTL: *sessionTTL,
		queueSize:  *queueSize,
	}

	return
}

type routeFlag []string

func (r *routeFlag) String() string {
	return strings.Join(*r, ",")
}

func (r *routeFlag) Set(val string) error {
	var cleaned string = strings.TrimSpace(val)
	if cleaned == "" {
		return nil
	}
	*r = append(*r, cleaned)
	return nil
}
