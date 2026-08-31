//go:build linux

package tun

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/z46-dev/go-logger"
)

var log *logger.Logger

func init() {
	log = logger.NewLogger().SetPrefix("[tun/net_linux]", logger.BoldRed).IncludeTimestamp()
}

// Setup configures an existing TUN interface with a given CIDR, MTU, and routes.
// It will return an error if any step fails.
func Setup(iface, cidr string, mtu int, routes []string) (err error) {
	if iface == "" {
		err = fmt.Errorf("interface name required")
		return
	}

	var (
		ctx    context.Context
		cancel context.CancelFunc
	)

	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if mtu > 0 {
		if err = run(ctx, "ip", "link", "set", "dev", iface, "mtu", fmt.Sprint(mtu)); err != nil {
			err = fmt.Errorf("set mtu: %w", err)
			return
		}
	}

	if cidr != "" {
		if err = run(ctx, "ip", "addr", "replace", cidr, "dev", iface); err != nil {
			err = fmt.Errorf("assign cidr: %w", err)
			return
		}
	}

	if err = run(ctx, "ip", "link", "set", "dev", iface, "up"); err != nil {
		err = fmt.Errorf("bring up iface: %w", err)
		return
	}

	for _, route := range routes {
		route = strings.TrimSpace(route)
		if route == "" {
			continue
		}

		if err = run(ctx, "ip", "route", "replace", route, "dev", iface); err != nil {
			err = fmt.Errorf("add route %s: %w", route, err)
			return
		}
	}

	return
}

// run executes a command with arguments and returns an error if it fails.
func run(ctx context.Context, cmd string, args ...string) (err error) {
	var (
		c   *exec.Cmd
		out []byte
	)

	c = exec.CommandContext(ctx, cmd, args...)
	if out, err = c.CombinedOutput(); err != nil {
		err = fmt.Errorf("%s %v: %v (%s)", cmd, args, err, strings.TrimSpace(string(out)))
	}

	return
}

// DetectDefaultIface returns the interface name used for the system default route.
// It returns an error if the default route cannot be determined.
func DetectDefaultIface() (iface string, err error) {
	var (
		ctx    context.Context
		cancel context.CancelFunc
		out    []byte
		fields []string
	)

	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if out, err = exec.CommandContext(ctx, "ip", "route", "show", "default").Output(); err != nil {
		err = fmt.Errorf("detect default route: %w", err)
		return
	}

	fields = strings.Fields(string(out))
	for i := range len(fields) {
		if fields[i] == "dev" && i+1 < len(fields) {
			iface = fields[i+1]
			return
		}
	}

	err = fmt.Errorf("no default interface found in %q", strings.TrimSpace(string(out)))
	return
}

// SetupNAT enables IPv4 forwarding, adds MASQUERADE on the uplink, and allows forwarding between the TUN and uplink.
func SetupNAT(uplink, inside string) (err error) {
	var (
		ctx                  context.Context
		cancel               context.CancelFunc
		insideCIDR, uplinkIP string
	)

	if uplink == "" || inside == "" {
		err = fmt.Errorf("uplink and inside interfaces required for NAT")
		return
	}

	log.Basicf("configuring NAT: inside=%s uplink=%s\n", inside, uplink)
	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err = run(ctx, "sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		return
	}

	if insideCIDR, err = ifaceIPv4CIDR(ctx, inside); err != nil {
		log.Warningf("nat debug: lookup %s cidr: %v\n", inside, err)
		err = nil
	}

	if insideCIDR != "" {
		warnOverlappingSubnet(log, inside, insideCIDR)
	}

	if uplinkIP, err = ifacePrimaryIPv4(ctx, uplink); err != nil {
		log.Warningf("nat debug: lookup %s ipv4: %v\n", uplink, err)
		err = nil
	}

	// NAT outbound
	if err = ensureRule(ctx, "nat", []string{"-A", "POSTROUTING", "-o", uplink, "-j", "MASQUERADE"}); err != nil {
		return
	}

	log.Basicf("nat rule: masquerade -> %s\n", uplink)
	if insideCIDR != "" {
		if err = ensureRule(ctx, "nat", []string{"-A", "POSTROUTING", "-s", insideCIDR, "-j", "MASQUERADE"}); err != nil {
			return
		}

		log.Basicf("nat rule: masquerade %s -> any uplink\n", insideCIDR)
		if uplinkIP != "" {
			if err = ensureRule(ctx, "nat", []string{"-A", "POSTROUTING", "-s", insideCIDR, "-o", uplink, "-j", "SNAT", "--to-source", uplinkIP}); err != nil {
				return
			}

			log.Basicf("nat rule: snat %s -> %s\n", insideCIDR, uplinkIP)
		}
	}

	// Forward client -> uplink
	if err = ensureRule(ctx, "filter", []string{"-A", "FORWARD", "-i", inside, "-o", uplink, "-j", "ACCEPT"}); err != nil {
		return
	} else {
		log.Basicf("nat rule: forward %s -> %s\n", inside, uplink)
	}

	// Forward client -> any uplink (covers mis-detected interface, e.g. tunnels)
	if err = ensureRule(ctx, "filter", []string{"-A", "FORWARD", "-i", inside, "-j", "ACCEPT"}); err != nil {
		return
	} else {
		log.Basicf("nat rule: forward %s -> any\n", inside)
	}

	// Forward uplink -> client (established)
	if err = ensureRule(ctx, "filter", []string{"-A", "FORWARD", "-i", uplink, "-o", inside, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"}); err != nil {
		return
	} else {
		log.Basicf("nat rule: forward established %s -> %s\n", uplink, inside)
	}

	// Forward any -> client (established) to catch non-default uplinks
	if err = ensureRule(ctx, "filter", []string{"-A", "FORWARD", "-o", inside, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"}); err != nil {
		return
	}

	log.Basicf("nat rule: forward established any -> %s\n", inside)
	return
}

// DisableRPFilter disables reverse path filtering for the given interface and the default setting to allow asymmetric routing (common with TUN).
func DisableRPFilter(iface string) (err error) {
	var (
		ctx    context.Context
		cancel context.CancelFunc
	)

	if iface == "" {
		err = fmt.Errorf("iface required for rp_filter")
		return
	}

	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Write all/default and the specific iface to 0, with verification/retries.
	for _, target := range []string{"all", "default", iface} {
		if err = setRPFilter(target, 0); err != nil {
			return
		}
	}

	// Re-assert several times in case something flips it back (seen on some distros)
	const attempts = 40
	for i := range attempts {
		var val string

		val, err = output(ctx, "sysctl", "-n", "net.ipv4.conf."+iface+".rp_filter")
		if err != nil {
			err = fmt.Errorf("read back rp_filter: %w", err)
			return
		}

		if val = strings.TrimSpace(val); val == "0" {
			return
		}

		log.Warningf("rp_filter for %s is %s (expected 0), reapplying (attempt %d/%d)\n", iface, val, i+1, attempts)
		if err = setRPFilter(iface, 0); err != nil {
			return
		}

		time.Sleep(50 * time.Millisecond)
	}

	err = fmt.Errorf("rp_filter for %s stayed non-zero", iface)
	return
}

// EnforceRPFilterZero periodically forces rp_filter to 0 for the given iface for the specified duration.
// This defends against services that flip rp_filter back to strict mode after we set it.
func EnforceRPFilterZero(iface string, duration time.Duration) {
	if iface == "" || duration <= 0 {
		return
	}

	var stop <-chan time.Time = time.After(duration)
	go func() {
		var err error

		for {
			select {
			case <-stop:
				return
			default:
			}

			if err = setRPFilter("all", 0); err != nil {
				log.Warningf("rp_filter enforce all: %v\n", err)
			}

			if err = setRPFilter("default", 0); err != nil {
				log.Warningf("rp_filter enforce default: %v\n", err)
			}

			if err = setRPFilter(iface, 0); err != nil {
				log.Warningf("rp_filter enforce %s: %v\n", iface, err)
			}

			time.Sleep(200 * time.Millisecond)
		}
	}()
}

// EnforceRPFilterZeroUntil keeps rp_filter at 0 for all/default/iface until stop is signaled.
// Useful when the OS keeps restoring strict mode after we disable it (common on some distros).
func EnforceRPFilterZeroUntil(iface string, stop <-chan struct{}, interval time.Duration) {
	if iface == "" || stop == nil {
		return
	}

	if interval <= 0 {
		interval = 250 * time.Millisecond
	}

	go func() {
		var t *time.Ticker = time.NewTicker(interval)
		defer t.Stop()

		var err error
		for {
			select {
			case <-stop:
				return
			case <-t.C:
			}

			for _, target := range []string{"all", "default", iface} {
				if err = setRPFilter(target, 0); err != nil {
					log.Warningf("rp_filter enforce %s: %v\n", target, err)
					continue
				}
			}

			var val []byte
			if val, err = os.ReadFile("/proc/sys/net/ipv4/conf/" + iface + "/rp_filter"); err == nil && strings.TrimSpace(string(val)) != "0" {
				log.Warningf("rp_filter for %s flipped back to %s; reasserting\n", iface, strings.TrimSpace(string(val)))
				if err = setRPFilter(iface, 0); err != nil {
					log.Warningf("rp_filter enforce %s: %v\n", iface, err)
				}
			}
		}
	}()
}

// ensureRule checks if an iptables rule exists, and adds it if not.
// It returns an error if the check or addition fails.
func ensureRule(ctx context.Context, table string, rule []string) (err error) {
	if err = exec.CommandContext(ctx, "iptables", append([]string{"-t", table, "-C"}, rule[1:]...)...).Run(); err == nil {
		return
	}

	err = run(ctx, "iptables", append([]string{"-t", table}, rule...)...)
	return
}

// LogNATState prints a snapshot of forwarding and firewall state to aid debugging.
func LogNATState(logger *logger.Logger, uplink, inside string) {
	var (
		ctx    context.Context
		cancel context.CancelFunc
	)

	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	logger.Basicf("nat debug: uplink=%s inside=%s\n", uplink, inside)

	logSysctl(ctx, logger, "net.ipv4.conf.all.rp_filter")
	logSysctl(ctx, logger, "net.ipv4.ip_forward")
	logSysctl(ctx, logger, "net.ipv4.conf.default.rp_filter")

	if uplink != "" {
		logSysctl(ctx, logger, "net.ipv4.conf."+uplink+".rp_filter")
	}

	if inside != "" {
		logSysctl(ctx, logger, "net.ipv4.conf."+inside+".rp_filter")
	}

	logCmdOutput(ctx, logger, "nat debug: iptables nat POSTROUTING", "iptables", "-t", "nat", "-S", "POSTROUTING")
	logCmdOutput(ctx, logger, "nat debug: iptables FORWARD", "iptables", "-S", "FORWARD")
	logCmdOutput(ctx, logger, "nat debug: iptables -v nat POSTROUTING", "iptables", "-t", "nat", "-L", "POSTROUTING", "-v", "-n")
	logCmdOutput(ctx, logger, "nat debug: iptables -v FORWARD", "iptables", "-L", "FORWARD", "-v", "-n")
}

// logSysctl retrieves and logs the value of a sysctl key.
func logSysctl(ctx context.Context, logger *logger.Logger, key string) {
	var (
		val string
		err error
	)

	val, err = output(ctx, "sysctl", "-n", key)
	if err != nil {
		logger.Errorf("nat debug: %s error: %v\n", key, err)
		return
	}

	logger.Basicf("nat debug: %s=%s\n", key, strings.TrimSpace(val))
}

// logCmdOutput runs a command and logs its output.
func logCmdOutput(ctx context.Context, logger *logger.Logger, prefix, cmd string, args ...string) {
	var (
		out string
		err error
	)

	if out, err = output(ctx, cmd, args...); err != nil {
		logger.Errorf("%s error: %v\n", prefix, err)
		return
	}

	logger.Basicf("%s:\n%s\n", prefix, strings.TrimSpace(out))
}

// output runs a command and returns its combined output as a string.
// It returns an error if the command fails.
func output(ctx context.Context, cmd string, args ...string) (out string, err error) {
	var (
		c *exec.Cmd
		b []byte
	)

	c = exec.CommandContext(ctx, cmd, args...)
	b, err = c.CombinedOutput()
	out = string(b)
	return
}

// setRPFilter sets the rp_filter value for the given interface.
// It verifies the setting and retries several times if needed.
// Returns an error if it cannot set the value correctly.
func setRPFilter(iface string, value int) (err error) {
	if iface == "" {
		err = fmt.Errorf("iface required")
		return
	}

	const attempts = 5
	var (
		target, want string = "/proc/sys/net/ipv4/conf/" + iface + "/rp_filter", strconv.Itoa(value)
		lastErr      error
	)

	for range attempts {
		if err = os.WriteFile(target, []byte(want), 0644); err != nil {
			lastErr = err
			time.Sleep(50 * time.Millisecond)
			continue
		}

		var buf []byte
		if buf, err = os.ReadFile(target); err != nil {
			lastErr = err
			time.Sleep(50 * time.Millisecond)
			continue
		}

		if strings.TrimSpace(string(buf)) == want {
			return
		}

		lastErr = fmt.Errorf("unexpected rp_filter value %q (wrote %s)", strings.TrimSpace(string(buf)), want)
		time.Sleep(50 * time.Millisecond)
	}

	err = fmt.Errorf("set rp_filter %s: %w", target, lastErr)
	return
}

var inetRegexp = regexp.MustCompile(`inet (\S+)`)

// ifaceIPv4CIDR returns the primary IPv4 CIDR assigned to the given interface.
// It returns an error if the CIDR cannot be determined.
func ifaceIPv4CIDR(ctx context.Context, iface string) (cidr string, err error) {
	var out []byte

	if iface == "" {
		err = fmt.Errorf("iface required")
		return
	}

	if out, err = exec.CommandContext(ctx, "ip", "-o", "-4", "addr", "show", "dev", iface).Output(); err != nil {
		return
	}

	var m []string = inetRegexp.FindStringSubmatch(string(out))
	if len(m) < 2 {
		err = fmt.Errorf("no inet line in %q", strings.TrimSpace(string(out)))
		return
	}

	cidr = m[1]
	return
}

// ifacePrimaryIPv4 returns the primary IPv4 address assigned to the given interface.
// It returns an error if the IP cannot be determined.
func ifacePrimaryIPv4(ctx context.Context, iface string) (ip string, err error) {
	var out []byte

	if iface == "" {
		err = fmt.Errorf("iface required")
		return
	}

	if out, err = exec.CommandContext(ctx, "ip", "-o", "-4", "addr", "show", "dev", iface).Output(); err != nil {
		return
	}

	var fields []string = strings.Fields(string(out))
	for i := range fields {
		if fields[i] == "inet" && i+1 < len(fields) {
			ipCIDR := fields[i+1]
			ip = strings.SplitN(ipCIDR, "/", 2)[0]
			return
		}
	}

	err = fmt.Errorf("no ipv4 found in %q", strings.TrimSpace(string(out)))
	return
}

// warnOverlappingSubnet logs when another interface already has an IP inside the given subnet.
// When server and client live in the same network namespace this can cause replies to stay local
// (never hitting the TUN/userland path), making it look like forwarding is broken.
func warnOverlappingSubnet(logger *logger.Logger, iface, cidr string) {
	if logger == nil || cidr == "" {
		return
	}

	var (
		network *net.IPNet
		err     error
		ifaces  []net.Interface
	)

	if _, network, err = net.ParseCIDR(cidr); err != nil {
		logger.Errorf("nat debug: parse cidr %s: %v\n", cidr, err)
		return
	}

	if ifaces, err = net.Interfaces(); err != nil {
		logger.Errorf("nat debug: list interfaces: %v\n", err)
		return
	}

	for _, ifc := range ifaces {
		if ifc.Name == iface {
			continue
		}

		var (
			addrs []net.Addr
			ip    net.IP
		)

		if addrs, err = ifc.Addrs(); err != nil {
			logger.Errorf("nat debug: list addrs for %s: %v\n", ifc.Name, err)
			continue
		}

		for _, addr := range addrs {
			ip = nil
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip == nil || ip.To4() == nil {
				continue
			}

			if network.Contains(ip) {
				logger.Warningf("subnet %s also present on %s (%s); client and server in same namespace will keep replies local\n", network.String(), ifc.Name, ip.String())
			}
		}
	}
}
