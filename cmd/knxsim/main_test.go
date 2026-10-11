// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cB-Sigma/knx"
	"github.com/cB-Sigma/knx-sim/sim"
)

// The runner writes a project and keyring that belong together: a client
// that takes the secure tunnel's credentials from the keyring connects,
// hears the temperature reports and switches the light named in the
// project.
func TestRunner(t *testing.T) {
	dir := t.TempDir()
	proj, kr := filepath.Join(dir, "demo.knxproj"), filepath.Join(dir, "demo.knxkeys")
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan *sim.Server, 1)
	done := make(chan error, 1)
	var out bytes.Buffer
	go func() {
		done <- run(ctx, []string{"-listen", "127.0.0.1:0", "-tcp", "127.0.0.1:0", "-secure-password", "tunnel-pass",
			"-report", "50ms", "-project", proj, "-keyring", kr}, &out, func(s *sim.Server) { ready <- s })
	}()
	var s *sim.Server
	select {
	case s = <-ready:
	case err := <-done:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("the runner did not start")
	}
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()

	raw, _ := os.ReadFile(proj)
	p, err := knx.ParseETSProject(raw, "")
	if err != nil || len(p.GroupAddresses) != len(demo) {
		t.Fatalf("project = %+v, %v", p, err)
	}
	raw, _ = os.ReadFile(kr)
	k, err := knx.ParseKeyring(raw, "keyring-pass")
	if err != nil {
		t.Fatal(err)
	}
	in, auth, err := k.Tunnel("", 0)
	if err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var temps []float64
	dctx, dcancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dcancel()
	tn, err := knx.DialTunnel(dctx, s.TCPAddr(), knx.TunnelOptions{Timeout: 2 * time.Second,
		Secure: &knx.SecureOptions{UserID: byte(in.UserID), PasswordHash: knx.UserPasswordHash(in.Password), DeviceAuth: knx.DeviceAuthCode(auth)},
		OnFrame: func(f knx.LData) {
			if f.Code == knx.LDataInd && f.Group().String() == "1/2/3" {
				v, err := (knx.DPT{Main: 9, Sub: 1}).Decode(f.Value())
				if err == nil {
					mu.Lock()
					temps = append(temps, v.(float64))
					mu.Unlock()
				}
			}
		}})
	if err != nil {
		t.Fatal(err)
	}
	defer tn.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := len(temps)
		mu.Unlock()
		if n >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no temperature reports")
		}
		time.Sleep(20 * time.Millisecond)
	}
	light, _ := knx.ParseGroupAddress("1/1/7")
	if err := tn.Send(dctx, knx.GroupFrame(knx.LDataReq, light, knx.GroupValueWrite, []byte{1}, true)); err != nil {
		t.Fatal(err)
	}
	if got := s.Get(light); !bytes.Equal(got, []byte{1}) {
		t.Errorf("light = %v", got)
	}
	if !strings.Contains(out.String(), "KNX IP Secure, user 2") {
		t.Errorf("banner = %q", out.String())
	}
}

// Flags that cannot work are refused before anything listens.
func TestRunnerFlags(t *testing.T) {
	for _, args := range [][]string{
		{"-secure-user", "0"},
		{"-keyring", "x.knxkeys"},
		{"-nope"},
	} {
		if err := run(context.Background(), args, &bytes.Buffer{}, nil); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
}
