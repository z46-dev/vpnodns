//go:build !linux

package tun

import "github.com/songgao/water"

// configureName leaves naming to water on platforms without Linux naming support.
func configureName(_ *water.Config, _ string) {}
