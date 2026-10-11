// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package sim_test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/cB-Sigma/knx"
	"github.com/cB-Sigma/knx-sim/sim"
)

// The server listens where it is told, answers a search with its
// description, and records the writes and reads of a tunnel client.
func TestServer(t *testing.T) {
	probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.LocalAddr().String()
	_ = probe.Close()
	s, err := sim.StartWith(sim.Options{Listen: addr, TCP: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.Addr() != addr || s.TCPAddr() == "" {
		t.Fatalf("addresses %s %s", s.Addr(), s.TCPAddr())
	}
	found, err := knx.Search(context.Background(), s.Addr(), 300*time.Millisecond)
	if err != nil || len(found) != 1 || !found[0].Supports(knx.FamilyTunnelling) || found[0].Control.Addr.String() != addr {
		t.Fatalf("search = %+v, %v", found, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tn, err := knx.DialTunnel(ctx, s.Addr(), knx.TunnelOptions{})
	if err != nil {
		t.Fatal(err)
	}
	g, _ := knx.ParseGroupAddress("1/1/7")
	if err := tn.Send(ctx, knx.GroupFrame(knx.LDataReq, g, knx.GroupValueWrite, []byte{1}, true)); err != nil {
		t.Fatal(err)
	}
	if err := tn.Send(ctx, knx.GroupFrame(knx.LDataReq, g, knx.GroupValueRead, nil, true)); err != nil {
		t.Fatal(err)
	}
	if w := s.Writes(); len(w) != 1 || w[0].GA != g || !bytes.Equal(s.Get(g), []byte{1}) {
		t.Errorf("writes = %+v, value %v", w, s.Get(g))
	}
	if r := s.Reads(); len(r) != 1 || r[0] != g {
		t.Errorf("reads = %v", r)
	}
	if s.Connects() != 1 || s.Channels() != 1 {
		t.Errorf("connects %d channels %d", s.Connects(), s.Channels())
	}
	tn.Close()
	deadline := time.Now().Add(5 * time.Second)
	for s.Channels() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if s.Channels() != 0 {
		t.Error("the tunnel stayed open after DISCONNECT")
	}
}

// A simulated gateway with one group object, and a client that reads it.
func Example() {
	s, _ := sim.Start()
	defer s.Close()
	g, _ := knx.ParseGroupAddress("3/0/1")
	s.Set(g, []byte{0x45, 0x9a, 0x52, 0x00}) // 14.056: 4938.25 W

	got := make(chan []byte, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tn, err := knx.DialTunnel(ctx, s.Addr(), knx.TunnelOptions{OnFrame: func(f knx.LData) {
		if f.APCI == knx.GroupValueResponse {
			got <- f.Value()
		}
	}})
	if err != nil {
		fmt.Println(err)
		return
	}
	defer tn.Close()
	_ = tn.Send(ctx, knx.GroupFrame(knx.LDataReq, g, knx.GroupValueRead, nil, false))
	v, _ := knx.DPT{Main: 14, Sub: 56}.Decode(<-got)
	fmt.Println(v)
	// Output: 4938.25
}

// A unicast SEARCH_REQUEST_EXTENDED (KNXnet/IP core v2) is answered with
// SEARCH_RESPONSE_EXTENDED carrying the tunnelling information DIB and,
// for a secure gateway, the secured service families DIB (xknx 3.20.0
// asks for both before a secure tunnel and gave up without them, interop
// 2026-10-11).
func TestSearchExtended(t *testing.T) {
	for _, secure := range []bool{false, true} {
		o := sim.Options{}
		if secure {
			o.Secure = &sim.SecureConfig{Users: map[byte]string{2: "pw"}, DeviceAuth: "auth"}
		}
		s, err := sim.StartWith(o)
		if err != nil {
			t.Fatal(err)
		}
		c, err := net.Dial("udp4", s.Addr())
		if err != nil {
			t.Fatal(err)
		}
		req := knx.Frame{Service: 0x020B, Body: knx.SearchRequest(knx.HPAIFrom(nil)).Body}
		if _, err := c.Write(req.Encode()); err != nil {
			t.Fatal(err)
		}
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 512)
		n, err := c.Read(buf)
		if err != nil {
			t.Fatalf("secure=%v: no answer: %v", secure, err)
		}
		fr, err := knx.ParseFrame(buf[:n])
		if err != nil || fr.Service != 0x020C {
			t.Fatalf("secure=%v: answer %#x %v", secure, fr.Service, err)
		}
		d, err := knx.ParseSearchResponse(fr.Body)
		if err != nil || d.Device.FriendlyName != "Sigma KNX simulator" {
			t.Errorf("secure=%v: %+v %v", secure, d, err)
		}
		// DIBs after the endpoint: device information (54), families, ...
		tunnelInfo := bytes.Contains(fr.Body, []byte{20, 0x07, 0x00, 0xF8, 0x11, 0xF1})
		securedFams := bytes.Contains(fr.Body, []byte{4, 0x06, knx.FamilyTunnelling, 1})
		if !tunnelInfo || securedFams != secure {
			t.Errorf("secure=%v: tunnelling info %v, secured families %v: % x", secure, tunnelInfo, securedFams, fr.Body)
		}
		c.Close()
		s.Close()
	}
}
