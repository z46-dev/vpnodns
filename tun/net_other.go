//go:build !linux

package tun

import (
	"fmt"
	"time"

	"github.com/z46-dev/go-logger"
)

// Setup reports that network configuration is currently Linux-only.
func Setup(_ string, _ string, _ int, _ []string) (err error) {
	err = fmt.Errorf("TUN network setup is only supported on Linux")
	return
}

// DetectDefaultIface reports that default-interface detection is currently Linux-only.
func DetectDefaultIface() (iface string, err error) {
	err = fmt.Errorf("default interface detection is only supported on Linux")
	return
}

// SetupNAT reports that NAT configuration is currently Linux-only.
func SetupNAT(_ string, _ string) (err error) {
	err = fmt.Errorf("NAT setup is only supported on Linux")
	return
}

// DisableRPFilter reports that reverse-path filter configuration is Linux-only.
func DisableRPFilter(_ string) (err error) {
	err = fmt.Errorf("reverse-path filter configuration is only supported on Linux")
	return
}

// EnforceRPFilterZero is a no-op outside Linux.
func EnforceRPFilterZero(_ string, _ time.Duration) {}

// EnforceRPFilterZeroUntil is a no-op outside Linux.
func EnforceRPFilterZeroUntil(_ string, _ <-chan struct{}, _ time.Duration) {}

// LogNATState is a no-op outside Linux.
func LogNATState(_ *logger.Logger, _ string, _ string) {}
