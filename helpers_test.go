// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package knx_test

import (
	"testing"
	"time"

	"github.com/cB-Sigma/knx"
	knxsim "github.com/cB-Sigma/knx-sim/sim"
)

func startSim(t *testing.T) *knxsim.Server { return startSimWith(t, knxsim.Options{}) }

func startSimWith(t *testing.T, o knxsim.Options) *knxsim.Server {
	t.Helper()
	s, err := knxsim.StartWith(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func secureSim(t *testing.T, timeout time.Duration) *knxsim.Server {
	return startSimWith(t, knxsim.Options{Secure: &knxsim.SecureConfig{
		Users: map[byte]string{2: "tunnel-pass"}, DeviceAuth: "gateway-auth",
		Serial: [6]byte{0x00, 0xC5, 0x01, 0x02, 0x03, 0x04}, SessionTimeout: timeout}})
}

func ga(t *testing.T, s string) knx.GroupAddress {
	t.Helper()
	g, err := knx.ParseGroupAddress(s)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func enc(t *testing.T, dpt string, v any) []byte {
	t.Helper()
	d, err := knx.ParseDPT(dpt)
	if err != nil {
		t.Fatal(err)
	}
	b, err := d.Encode(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// eventually polls cond until it holds or the time is up.
func eventually(t *testing.T, within time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
