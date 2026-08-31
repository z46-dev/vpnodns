//go:build linux

package tun

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNilInterfaceMetadata(t *testing.T) {
	var iface *Interface = new(Interface)
	assert.Empty(t, iface.Name())
	assert.NoError(t, iface.Close())
}

func TestNetworkHelpersRejectMissingInterfaces(t *testing.T) {
	var (
		ctx context.Context = context.Background()
		err error
	)

	assert.Error(t, Setup("", "", 0, nil))
	assert.Error(t, SetupNAT("", ""))
	assert.Error(t, DisableRPFilter(""))
	_, err = ifaceIPv4CIDR(ctx, "")
	assert.Error(t, err)
	_, err = ifacePrimaryIPv4(ctx, "")
	assert.Error(t, err)
	assert.Error(t, setRPFilter("", 0))
}

func TestEnforceRPFilterNoopInputs(t *testing.T) {
	EnforceRPFilterZero("", time.Second)
	EnforceRPFilterZero("iface", 0)
	EnforceRPFilterZeroUntil("", make(chan struct{}), time.Second)
	EnforceRPFilterZeroUntil("iface", nil, time.Second)
}
