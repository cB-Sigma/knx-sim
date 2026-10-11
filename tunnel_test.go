// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package knx_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/knx"
	knxsim "github.com/cB-Sigma/knx-sim/sim"
)

func dial(t *testing.T, addr string, opts knx.TunnelOptions) *knx.Tunnel {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tn, err := knx.DialTunnel(ctx, addr, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tn.Close)
	return tn
}

// A UDP tunnel: the description and channel come back from the gateway,
// bus writes arrive as indications (a repeated request once), a write is
// acknowledged and confirmed, and a group read is answered.
func TestKNXTunnelUDP(t *testing.T) {
	sim := startSim(t)
	log := &frameLog{}
	tn := dial(t, sim.Addr(), knx.TunnelOptions{Heartbeat: time.Hour, Timeout: 2 * time.Second, OnFrame: log.add})
	if tn.Gateway == nil || tn.Gateway.Device.FriendlyName != "Sigma KNX simulator" || tn.Channel == 0 || tn.Address == 0 {
		t.Fatalf("tunnel = channel %d address %s gateway %+v", tn.Channel, tn.Address, tn.Gateway)
	}
	g := ga(t, "3/0/1")
	sim.Inject(g, enc(t, "14.056", 1234.5), false)
	sim.InjectDuplicate(g, enc(t, "14.056", 99.0), false)
	sim.Inject(g, enc(t, "14.056", 7.0), false)
	eventually(t, 5*time.Second, "three indications", func() bool { return len(log.writes(g)) == 3 })
	time.Sleep(100 * time.Millisecond)
	if w := log.writes(g); len(w) != 3 {
		t.Errorf("indications = %x, want the duplicate once", w)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	light := ga(t, "1/1/7")
	if err := tn.Send(ctx, knx.GroupFrame(knx.LDataReq, light, knx.GroupValueWrite, []byte{1}, true)); err != nil {
		t.Fatal(err)
	}
	if w := sim.Writes(); len(w) != 1 || w[0].GA != light || !bytes.Equal(w[0].Data, []byte{1}) {
		t.Errorf("writes = %+v", w)
	}
	temp := ga(t, "1/2/3")
	sim.Set(temp, enc(t, "9.001", 21.5))
	if err := tn.Send(ctx, knx.GroupFrame(knx.LDataReq, temp, knx.GroupValueRead, nil, true)); err != nil {
		t.Fatal(err)
	}
	eventually(t, 5*time.Second, "the read response", func() bool {
		for _, f := range log.all() {
			if f.APCI == knx.GroupValueResponse && f.Group() == temp {
				v, err := (knx.DPT{Main: 9, Sub: 1}).Decode(f.Value())
				return err == nil && v == 21.5
			}
		}
		return false
	})
}

// Without acknowledgements the one repeat fails the send and ends the
// tunnel; a silent gateway fails three heartbeats and ends it too.
func TestKNXTunnelAckAndHeartbeat(t *testing.T) {
	sim := startSim(t)
	opts := knx.TunnelOptions{Heartbeat: 200 * time.Millisecond, Timeout: 150 * time.Millisecond, AckTimeout: 100 * time.Millisecond}
	tn := dial(t, sim.Addr(), opts)
	sim.DropAcks(true)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := tn.Send(ctx, knx.GroupFrame(knx.LDataReq, ga(t, "1/1/7"), knx.GroupValueWrite, []byte{1}, true))
	if !errors.Is(err, knx.ErrConnectionLost) || !strings.Contains(err.Error(), "after one repeat") {
		t.Errorf("write without acknowledgement = %v", err)
	}
	select {
	case <-tn.Lost():
	case <-time.After(5 * time.Second):
		t.Fatal("the tunnel survived the missing acknowledgement")
	}
	sim.DropAcks(false)

	tn = dial(t, sim.Addr(), opts)
	sim.SetSilent(true)
	select {
	case <-tn.Lost():
		if e := tn.Err(); !errors.Is(e, knx.ErrConnectionLost) || !strings.Contains(e.Error(), "heartbeats failed") {
			t.Errorf("end reason = %v", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the tunnel survived a silent gateway")
	}
}

// A TCP tunnel needs no TUNNELLING_ACK and ends when the stream closes.
func TestKNXTunnelTCP(t *testing.T) {
	sim := startSimWith(t, knxsim.Options{TCP: true})
	log := &frameLog{}
	tn := dial(t, sim.TCPAddr(), knx.TunnelOptions{TCP: true, Heartbeat: time.Hour, Timeout: 2 * time.Second, OnFrame: log.add})
	g := ga(t, "1/1/7")
	sim.InjectDuplicate(g, []byte{1}, true)
	eventually(t, 5*time.Second, "both indications", func() bool { return len(log.writes(g)) == 2 })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := tn.Send(ctx, knx.GroupFrame(knx.LDataReq, ga(t, "1/1/8"), knx.GroupValueWrite, []byte{0x80}, false)); err != nil {
		t.Fatal(err)
	}
	if n := sim.TCPAcks(); n != 0 {
		t.Errorf("the client sent %d TUNNELLING_ACKs over TCP", n)
	}
	sim.DropStreams()
	select {
	case <-tn.Lost():
	case <-time.After(5 * time.Second):
		t.Fatal("the tunnel survived a closed stream")
	}
}

// A secure tunnel is refused for a wrong user password or a gateway whose
// device authentication code does not match.
func TestKNXSecureTunnelRefusals(t *testing.T) {
	sim := secureSim(t, 0)
	for _, tc := range []struct {
		name, password, device, want string
	}{
		{"wrong password", "nope", "gateway-auth", "authentication failed"},
		{"wrong device code", "tunnel-pass", "other-gateway", "device authentication"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			tn, err := knx.DialTunnel(ctx, sim.TCPAddr(), knx.TunnelOptions{Timeout: 2 * time.Second,
				Secure: &knx.SecureOptions{UserID: 2, PasswordHash: knx.UserPasswordHash(tc.password), DeviceAuth: knx.DeviceAuthCode(tc.device)}})
			if err == nil {
				tn.Close()
				t.Fatal("connected")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want %q", err, tc.want)
			}
		})
	}
	if sim.Sessions() != 0 {
		t.Errorf("sessions = %d", sim.Sessions())
	}
}

// Routing to a unicast peer: a ROUTING_INDICATION in becomes a frame, and a
// frame out is an L_Data.ind from the configured source.
func TestKNXRoutingUnicast(t *testing.T) {
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	listen := probe.LocalAddr().String()
	_ = probe.Close()
	got := make(chan knx.LData, 4)
	src, _ := knx.ParseIndividualAddress("1.1.200")
	r, err := knx.ListenRouting(knx.RoutingOptions{Group: peer.LocalAddr().String(), Listen: listen, Source: src,
		OnFrame: func(f knx.LData) { got <- f }})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	ind := knx.GroupFrame(knx.LDataInd, ga(t, "1/2/3"), knx.GroupValueWrite, enc(t, "9.001", 19.5), false)
	ind.Source = 0x1105
	if _, err := peer.WriteToUDP(knx.RoutingIndication(ind.Encode()).Encode(), r.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	select {
	case f := <-got:
		if f.Group().String() != "1/2/3" || f.Source.String() != "1.1.5" {
			t.Errorf("received = %+v", f)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no frame from the router")
	}

	if err := r.Send(context.Background(), knx.GroupFrame(knx.LDataReq, ga(t, "1/1/7"), knx.GroupValueWrite, []byte{1}, true)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 256)
	_ = peer.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := peer.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	fr, err := knx.ParseFrame(buf[:n])
	if err != nil || fr.Service != knx.SvcRoutingIndication {
		t.Fatalf("frame = %+v, %v", fr, err)
	}
	f, err := knx.ParseLData(fr.Body)
	if err != nil || f.Code != knx.LDataInd || f.Group().String() != "1/1/7" || f.Source.String() != "1.1.200" || !f.IsShort || f.Short != 1 {
		t.Errorf("routed write = %+v, %v", f, err)
	}
}
