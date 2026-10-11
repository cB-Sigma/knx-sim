// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Command knxsim serves a simulated KNXnet/IP tunnelling gateway, so a
// KNX client can be tried without an installation: it answers search and
// description requests, accepts tunnels over UDP and, with -tcp, over TCP,
// optionally inside a KNX IP Secure session (-secure-password), and holds
// a small demo installation:
//
//	1/2/3  living room temperature  9.001   (reported every -report)
//	1/1/7  living room light        1.001
//	1/1/8  living room dimmer       5.001
//	3/0/1  meter power              14.056
//	3/0/2  meter energy             13.010
//
// For example:
//
//	knxsim -listen 127.0.0.1:3671
//	knxsim -listen 127.0.0.1:3671 -tcp 127.0.0.1:3671 -secure-password tunnel-pass \
//	       -keyring home.knxkeys -project home.knxproj
//
// -project writes an ETS project export of the demo installation and
// -keyring a keyring export for the secure tunnel (password
// -keyring-password), so ETS import can be tried end to end. All
// passwords are demo values.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cB-Sigma/knx"
	"github.com/cB-Sigma/knx-sim/sim"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, nil); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "knxsim:", err)
		os.Exit(1)
	}
}

// demo is the simulated installation: group address, ETS name, ETS
// datapoint type, range, and the value the bus starts with.
var demo = []struct {
	ga, name, dpt, rng string
	value              []byte
}{
	{"1/2/3", "Temperature", "DPST-9-1", "Living Room", nil},
	{"1/1/7", "Light", "DPST-1-1", "Living Room", []byte{0}},
	{"1/1/8", "Dimmer", "DPST-5-1", "Living Room", []byte{0}},
	{"3/0/1", "Power", "DPST-14-56", "Meter", nil},
	{"3/0/2", "Energy", "DPST-13-10", "Meter", nil},
}

// run serves until ctx ends. ready, when not nil, receives the server once
// it listens.
func run(ctx context.Context, args []string, out io.Writer, ready func(*sim.Server)) error {
	fs := flag.NewFlagSet("knxsim", flag.ContinueOnError)
	fs.SetOutput(out)
	listen := fs.String("listen", "127.0.0.1:3671", "UDP address of the gateway")
	tcp := fs.String("tcp", "", "also serve KNXnet/IP over TCP on this address")
	user := fs.Int("secure-user", 2, "tunnelling user id of the secure tunnel")
	password := fs.String("secure-password", "", "run KNX IP Secure on the TCP endpoint with this user password (implies -tcp, default 127.0.0.1:3671)")
	deviceAuth := fs.String("device-auth", "gateway-auth", "device authentication code of the secure gateway")
	report := fs.Duration("report", 10*time.Second, "temperature report interval (0: none)")
	project := fs.String("project", "", "write an ETS project export (.knxproj) of the demo installation to this file")
	keyring := fs.String("keyring", "", "write an ETS keyring export (.knxkeys) for the secure tunnel to this file")
	keyringPassword := fs.String("keyring-password", "keyring-pass", "password of the keyring export")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *user < 1 || *user > 127 {
		return fmt.Errorf("-secure-user %d is not 1..127", *user)
	}
	o := sim.Options{Listen: *listen, ListenTCP: *tcp, TCP: *tcp != ""}
	if *password != "" {
		if o.ListenTCP == "" {
			o.ListenTCP = "127.0.0.1:3671"
		}
		o.Secure = &sim.SecureConfig{Users: map[byte]string{byte(*user): *password}, DeviceAuth: *deviceAuth,
			Serial: [6]byte{0x00, 0xC5, 0x01, 0x02, 0x03, 0x04}}
	}
	if *keyring != "" && *password == "" {
		return errors.New("-keyring needs -secure-password (the keyring holds the secure tunnel)")
	}

	if *project != "" {
		rs := map[string]*sim.ETSRange{}
		var ranges []*sim.ETSRange
		for _, d := range demo {
			r := rs[d.rng]
			if r == nil {
				r = &sim.ETSRange{Name: d.rng}
				rs[d.rng] = r
				ranges = append(ranges, r)
			}
			r.Groups = append(r.Groups, sim.ETSGroup{Address: d.ga, Name: d.name, DPT: d.dpt})
		}
		po := sim.ETSProjectOptions{Name: "Demo"}
		for _, r := range ranges {
			po.Ranges = append(po.Ranges, *r)
		}
		if err := os.WriteFile(*project, sim.ETSProject(po), 0o644); err != nil {
			return err
		}
	}
	if *keyring != "" {
		kr := sim.ETSKeyring(sim.KeyringOptions{Project: "Demo", Password: *keyringPassword, Host: "1.1.255",
			DeviceAuth: *deviceAuth, Tunnels: []sim.KeyringTunnel{{Address: "1.1.251", UserID: *user, Password: *password}}})
		if err := os.WriteFile(*keyring, kr, 0o600); err != nil {
			return err
		}
	}

	s, err := sim.StartWith(o)
	if err != nil {
		return err
	}
	defer s.Close()
	temp := 21.0
	for _, d := range demo {
		g, _ := knx.ParseGroupAddress(d.ga)
		v := d.value
		if v == nil {
			dpt, _ := knx.ParseDPT(d.dpt)
			x := 0.0
			if d.ga == "1/2/3" {
				x = temp
			}
			v, _ = dpt.Encode(x)
		}
		s.Set(g, v)
	}
	fmt.Fprintf(out, "knxsim: gateway on udp %s", s.Addr())
	if t := s.TCPAddr(); t != "" {
		fmt.Fprintf(out, ", tcp %s", t)
		if o.Secure != nil {
			fmt.Fprintf(out, " (KNX IP Secure, user %d)", *user)
		}
	}
	fmt.Fprintln(out)
	if ready != nil {
		ready(s)
	}

	var tick <-chan time.Time
	if *report > 0 {
		t := time.NewTicker(*report)
		defer t.Stop()
		tick = t.C
	}
	g, _ := knx.ParseGroupAddress("1/2/3")
	dpt := knx.DPT{Main: 9, Sub: 1}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick:
			temp += 0.5
			if temp > 24 {
				temp = 20
			}
			v, _ := dpt.Encode(temp)
			s.Inject(g, v, false)
		}
	}
}
