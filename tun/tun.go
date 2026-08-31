package tun

import (
	"github.com/songgao/water"
)

// Wrapper for the water TUN interface
type Interface struct {
	iface *water.Interface
}

// Open creates a TUN device using the water library
// If name is empty, a system-assigned name will be used
// Returns the TUN interface or an error
func Open(name string) (iface *Interface, err error) {
	var config water.Config = water.Config{
		DeviceType: water.TUN,
	}

	if name != "" {
		configureName(&config, name)
	}

	iface = &Interface{}
	iface.iface, err = water.New(config)
	return
}

// Name returns the name of the TUN interface
func (i *Interface) Name() (name string) {
	if i.iface != nil {
		name = i.iface.Name()
	}

	return
}

// Close closes the TUN interface
// Returns an error if any
func (i *Interface) Close() (err error) {
	if i.iface != nil {
		err = i.iface.Close()
	}

	return
}

// Read reads data from the TUN interface into p
// Returns the number of bytes read and an error if any
func (i *Interface) Read(p []byte) (n int, err error) {
	n, err = i.iface.Read(p)
	return
}

// Write writes data from p to the TUN interface
// Returns the number of bytes written and an error if any
func (i *Interface) Write(p []byte) (n int, err error) {
	n, err = i.iface.Write(p)
	return
}
