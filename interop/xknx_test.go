// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package interop runs xknx 3.20.0 (MIT, github.com/XKNX/xknx), Home
// Assistant's KNX library, in a container built from ./xknx against the
// simulated gateway of knx-sim: description, tunnelling over UDP and TCP,
// KNX IP Secure tunnelling with a keyring the simulator wrote, group
// writes, reads and indications. The tests are skipped unless
// SIGMA_KNX_INTEROP=1 is set and Docker is running.
package interop

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/cB-Sigma/knx"
	"github.com/cB-Sigma/knx-sim/sim"
)

const image = "sigma-knxsim-xknx:3.20.0"

func needDocker(t *testing.T) {
	t.Helper()
	if os.Getenv("SIGMA_KNX_INTEROP") != "1" {
		t.Skip("set SIGMA_KNX_INTEROP=1 to run the interop tests (needs Docker)")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skip("docker is not running")
	}
	if exec.Command("docker", "image", "inspect", image).Run() == nil {
		return
	}
	if out, err := exec.Command("docker", "build", "-q", "-t", image, "xknx").CombinedOutput(); err != nil {
		t.Fatalf("docker build: %v\n%s", err, out)
	}
}

// hostIPv4 is the host's IPv4 address as containers see it.
func hostIPv4(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("docker", "run", "--rm", "--add-host=host.docker.internal:host-gateway", "--entrypoint", "getent",
		image, "ahostsv4", "host.docker.internal").CombinedOutput()
	if f := strings.Fields(string(out)); err == nil && len(f) > 0 {
		return f[0]
	}
	t.Fatalf("host address: %v %s", err, out)
	return ""
}

// startSim serves the simulator on every interface (UDP and TCP on the
// same port number), so that the container can reach it.
func startSim(t *testing.T, sec *sim.SecureConfig) (*sim.Server, int) {
	t.Helper()
	l, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	s, err := sim.StartWith(sim.Options{Listen: fmt.Sprintf("0.0.0.0:%d", port), TCP: true, ListenTCP: fmt.Sprintf("0.0.0.0:%d", port), Secure: sec})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	temp, _ := knx.ParseGroupAddress("1/2/3")
	v, _ := knx.DPT{Main: 9, Sub: 1}.Encode(21.5)
	s.Set(temp, v)
	return s, port
}

// client runs client.py; onLine sees each output line as it arrives.
func client(t *testing.T, stdin []byte, onLine func(string), args ...string) []string {
	t.Helper()
	cmd := exec.Command("docker", append([]string{"run", "--rm", "-i", "--add-host=host.docker.internal:host-gateway", image}, args...)...)
	cmd.Stdin = bytes.NewReader(stdin)
	r, w := io.Pipe()
	cmd.Stdout, cmd.Stderr = w, w
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait(); _ = w.Close() }()
	var lines []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		lines = append(lines, sc.Text())
		if onLine != nil {
			onLine(sc.Text())
		}
	}
	if err := <-done; err != nil {
		t.Errorf("xknx client: %v\n%s", err, strings.Join(lines, "\n"))
	}
	return lines
}

func has(lines []string, prefix string) bool {
	return slices.ContainsFunc(lines, func(l string) bool { return strings.HasPrefix(l, prefix) })
}

// TestXknxDescription: xknx's description request (what its gateway
// scanner and secure set-up use) reads the simulator's description.
func TestXknxDescription(t *testing.T) {
	needDocker(t)
	_, port := startSim(t, nil)
	lines := client(t, nil, nil, "search", hostIPv4(t), fmt.Sprint(port))
	if !has(lines, "GATEWAY Sigma KNX simulator 1.1.255 tunnelling tcp") {
		t.Errorf("xknx saw %q", lines)
	}
}

// tunnelTest runs the xknx client against the simulator and checks what
// both sides saw.
func tunnelTest(t *testing.T, s *sim.Server, keyring []byte, args ...string) {
	t.Helper()
	other, _ := knx.ParseGroupAddress("2/0/1")
	lines := client(t, keyring, func(l string) {
		if strings.HasPrefix(l, "READ ") {
			s.Inject(other, []byte{0x01}, true)
			s.Inject(other, []byte{0x0C, 0x1A}, false)
		}
	}, args...)
	t.Logf("xknx: %q", lines)
	if !has(lines, "CONNECTED ") || !has(lines, "DONE") {
		t.Fatalf("xknx did not finish: %q", lines)
	}
	if !has(lines, "READ 1/2/3 0c33") {
		t.Errorf("xknx read of 1/2/3 (21.5 °C): %q", lines)
	}
	if !has(lines, "TELEGRAM 2/0/1 GroupValueWrite 01") || !has(lines, "TELEGRAM 2/0/1 GroupValueWrite 0c1a") {
		t.Errorf("indications: %q", lines)
	}
	var writes []string
	for _, w := range s.Writes() {
		writes = append(writes, fmt.Sprintf("%s % x", w.GA, w.Data))
	}
	if !slices.Contains(writes, "1/1/7 01") || !slices.Contains(writes, "1/1/8 80") {
		t.Errorf("the simulator received %q", writes)
	}
	if !slices.Contains(s.Reads(), knx.GroupAddress(0x0A03)) {
		t.Errorf("reads %v", s.Reads())
	}
}

// TestXknxTunnelUDP: xknx tunnels over UDP (route back, as through NAT).
func TestXknxTunnelUDP(t *testing.T) {
	needDocker(t)
	s, port := startSim(t, nil)
	tunnelTest(t, s, nil, "udp", hostIPv4(t), fmt.Sprint(port))
}

// TestXknxTunnelTCP: xknx tunnels over TCP (KNXnet/IP core v2).
func TestXknxTunnelTCP(t *testing.T) {
	needDocker(t)
	s, port := startSim(t, nil)
	tunnelTest(t, s, nil, "tcp", hostIPv4(t), fmt.Sprint(port))
	if n := s.TCPAcks(); n != 0 {
		t.Errorf("xknx sent %d TUNNELLING_ACKs over TCP", n)
	}
}

// TestXknxSecureTunnel: xknx reads a keyring the simulator wrote and runs
// a KNX IP Secure tunnel to the simulator with it.
func TestXknxSecureTunnel(t *testing.T) {
	needDocker(t)
	s, port := startSim(t, &sim.SecureConfig{Users: map[byte]string{2: "tunnel-pass"}, DeviceAuth: "gateway-auth",
		Serial: [6]byte{0x00, 0xC5, 0x01, 0x02, 0x03, 0x04}})
	kr := sim.ETSKeyring(sim.KeyringOptions{Project: "Demo", Password: "keyring-pass", Host: "1.1.255", DeviceAuth: "gateway-auth",
		Tunnels: []sim.KeyringTunnel{{Address: "1.1.251", UserID: 2, Password: "tunnel-pass"}}})
	tunnelTest(t, s, kr, "secure", hostIPv4(t), fmt.Sprint(port), "2", "keyring-pass")
	if s.Sessions() == 0 {
		t.Error("no secure session was authenticated")
	}
}

// TestXknxReadsSimKeyring: xknx checks the signature of a keyring the
// simulator wrote and decrypts the same tunnel password, device
// authentication code and management password.
func TestXknxReadsSimKeyring(t *testing.T) {
	needDocker(t)
	kr := sim.ETSKeyring(sim.KeyringOptions{Project: "Demo", Password: "keyring-pass", Host: "1.1.255", DeviceAuth: "gateway-auth",
		Tunnels: []sim.KeyringTunnel{{Address: "1.1.251", UserID: 2, Password: "tunnel-pass"}, {Address: "1.1.252", UserID: 3, Password: "other-pass"}}})
	lines := client(t, kr, nil, "keyring", "keyring-pass")
	t.Logf("xknx: %q", lines)
	for _, want := range []string{
		"PROJECT Demo",
		"INTERFACE 1.1.251 1.1.255 2 tunnel-pass",
		"INTERFACE 1.1.252 1.1.255 3 other-pass",
		"DEVICE 1.1.255 gateway-auth",
	} {
		if !has(lines, want) {
			t.Errorf("xknx did not print %q", want)
		}
	}
}

// TestXknxprojectReadsSimProjects: xknxproject reads the project exports
// the simulator writes, plain, ETS 5-protected and ETS 6-protected, with
// the same group addresses, names and datapoint types.
func TestXknxprojectReadsSimProjects(t *testing.T) {
	needDocker(t)
	ranges := []sim.ETSRange{
		{Name: "Living Room", Groups: []sim.ETSGroup{
			{Address: "1/2/3", Name: "Temperature", DPT: "DPST-9-1", Read: "Enabled", Write: "Disabled"},
			{Address: "1/1/7", Name: "Ceiling light", DPT: "DPST-1-1", Write: "Enabled"},
		}},
		{Name: "Meter", Groups: []sim.ETSGroup{{Address: "3/0/1", Name: "Power", DPT: "DPST-14-56"}}},
	}
	for _, tc := range []struct {
		name string
		o    sim.ETSProjectOptions
	}{
		{"plain", sim.ETSProjectOptions{Name: "Home"}},
		{"ets5 protected", sim.ETSProjectOptions{Name: "Home", Password: "geheim"}},
		{"ets6 protected", sim.ETSProjectOptions{Name: "Home", Password: "geheim", ETS6: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.o.Ranges = ranges
			pw := tc.o.Password
			if pw == "" {
				pw = "-"
			}
			lines := client(t, sim.ETSProject(tc.o), nil, "project", pw)
			t.Logf("xknxproject: %q", lines)
			for _, want := range []string{"PROJECT Home", "GA 1/2/3 9.1 Temperature", "GA 1/1/7 1.1 Ceiling light", "GA 3/0/1 14.56 Power"} {
				if !has(lines, want) {
					t.Errorf("xknxproject did not print %q", want)
				}
			}
		})
	}
}
