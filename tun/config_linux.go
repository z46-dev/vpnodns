//go:build linux

package tun

import "github.com/songgao/water"

// configureName applies the requested Linux interface name.
func configureName(config *water.Config, name string) {
	config.PlatformSpecificParams = water.PlatformSpecificParams{Name: name}
}
