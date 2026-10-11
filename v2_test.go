// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package knx_test

import (
	"bytes"
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/cB-Sigma/knx"
	knxsim "github.com/cB-Sigma/knx-sim/sim"
)

func dataSecurePair(t *testing.T, senders map[knx.IndividualAddress]uint64) (client, server *knx.DataSecure, secured knx.GroupAddress) {
	t.Helper()
	secured = ga(t, "0/4/0")
	keys := map[knx.GroupAddress][]byte{secured: bytes.Repeat([]byte{0x42}, 16)}
	c, err := knx.NewDataSecure(knx.DataSecureOptions{GroupKeys: keys, Senders: map[knx.IndividualAddress]uint64{knxsim.Device10: 0}})
	if err != nil {
		t.Fatal(err)
	}
	s, err := knx.NewDataSecure(knx.DataSecureOptions{GroupKeys: keys, Senders: senders})
	if err != nil {
		t.Fatal(err)
	}
	return c, s, secured
}

// A tunnel with KNX Data Secure writes a secured group (the simulator
// opens it), reads it back sealed from 1.1.10 and gets a sealed injected
// write; a plain write to the secured group is refused by the simulator.
// Covers: SIG-IPE-6701
func TestSimDataSecureTunnel(t *testing.T) {
	cds, sds, secured := dataSecurePair(t, map[knx.IndividualAddress]uint64{0x11F1: 0, 0x11F2: 0})
	s := startSimWith(t, knxsim.Options{DataSecure: sds})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var mu sync.Mutex
	var got []knx.LData
	var errs []error
	tn, err := knx.DialTunnel(ctx, s.Addr(), knx.TunnelOptions{DataSecure: cds,
		OnFrame: func(f knx.LData) { mu.Lock(); got = append(got, f); mu.Unlock() },
		OnError: func(e error) { mu.Lock(); errs = append(errs, e); mu.Unlock() }})
	if err != nil {
		t.Fatal(err)
	}
	defer tn.Close()
	if err := tn.Send(ctx, knx.GroupFrame(knx.LDataReq, secured, knx.GroupValueWrite, []byte{0x0C, 0x1A}, false)); err != nil {
		t.Fatal(err)
	}
	if w := s.Writes(); len(w) != 1 || w[0].GA != secured || !bytes.Equal(w[0].Data, []byte{0x0C, 0x1A}) {
		t.Fatalf("simulator writes %+v", w)
	}
	if err := tn.Send(ctx, knx.GroupFrame(knx.LDataReq, secured, knx.GroupValueRead, nil, true)); err != nil {
		t.Fatal(err)
	}
	s.Inject(secured, []byte{0x0C, 0x33}, false)
	eventually(t, 3*time.Second, "secured response and indication", func() bool {
		mu.Lock()
		defer mu.Unlock()
		resp, ind := false, false
		for _, f := range got {
			resp = resp || (f.APCI == knx.GroupValueResponse && bytes.Equal(f.Value(), []byte{0x0C, 0x1A}))
			ind = ind || (f.Code == knx.LDataInd && f.APCI == knx.GroupValueWrite && bytes.Equal(f.Value(), []byte{0x0C, 0x33}))
		}
		return resp && ind
	})
	// A plain tunnel's write to the secured group is refused.
	plain, err := knx.DialTunnel(ctx, s.Addr(), knx.TunnelOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	if err := plain.Send(ctx, knx.GroupFrame(knx.LDataReq, secured, knx.GroupValueWrite, []byte{0, 0}, false)); err != nil {
		t.Logf("plain send: %v", err)
	}
	if s.DataSecureRefused() != 1 || len(s.Writes()) != 1 {
		t.Errorf("refused %d, writes %+v", s.DataSecureRefused(), s.Writes())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(errs) != 0 {
		t.Errorf("client errors %v", errs)
	}
}

// A busmonitor tunnel sees the bus device's writes and other tunnels'
// frames as L_Busmon.ind (TP1 frames with a valid check octet) and cannot
// send; a raw tunnel is refused.
// Covers: SIG-IPE-6707
func TestSimBusmonitor(t *testing.T) {
	s := startSim(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var mu sync.Mutex
	var mons []knx.Busmon
	mon, err := knx.DialTunnel(ctx, s.Addr(), knx.TunnelOptions{Layer: knx.LayerBusmonitor,
		OnBusmon: func(m knx.Busmon) { mu.Lock(); mons = append(mons, m); mu.Unlock() }})
	if err != nil {
		t.Fatal(err)
	}
	defer mon.Close()
	if err := mon.Send(ctx, knx.GroupFrame(knx.LDataReq, ga(t, "1/1/7"), knx.GroupValueWrite, []byte{1}, true)); err == nil {
		t.Error("a busmonitor tunnel sent")
	}
	link, err := knx.DialTunnel(ctx, s.Addr(), knx.TunnelOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer link.Close()
	if err := link.Send(ctx, knx.GroupFrame(knx.LDataReq, ga(t, "1/1/7"), knx.GroupValueWrite, []byte{1}, true)); err != nil {
		t.Fatal(err)
	}
	s.Inject(ga(t, "1/2/3"), []byte{0x0C, 0x33}, false)
	eventually(t, 3*time.Second, "two busmonitor frames", func() bool { mu.Lock(); defer mu.Unlock(); return len(mons) >= 2 })
	mu.Lock()
	for _, m := range mons {
		var x byte
		for _, b := range m.Raw {
			x ^= b
		}
		if x != 0xFF || len(m.Raw) < 8 {
			t.Errorf("TP1 frame % x has a bad check octet", m.Raw)
		}
	}
	if !bytes.Equal(mons[0].Raw[3:5], []byte{0x09, 0x07}) || !bytes.Equal(mons[1].Raw[1:3], []byte{0x11, 0x0A}) {
		t.Errorf("frames % x / % x", mons[0].Raw, mons[1].Raw)
	}
	mu.Unlock()
	if _, err := knx.DialTunnel(ctx, s.Addr(), knx.TunnelOptions{Layer: knx.LayerRaw}); err == nil {
		t.Error("a raw tunnel was accepted")
	}
}

// Device management to the gateway: DeviceDescriptor_Read gets the mask
// version, PropertyValue_Read the serial number; IndividualAddress_Read is
// answered only in programming mode; an extended search selects by
// programming mode and service family and reports the tunnelling slots.
// Covers: SIG-IPE-6704, SIG-IPE-6705
func TestSimManagementAndExtendedSearch(t *testing.T) {
	for _, prog := range []bool{false, true} {
		s := startSimWith(t, knxsim.Options{ProgrammingMode: prog, TCP: true})
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		var mu sync.Mutex
		var got []knx.LData
		tn, err := knx.DialTunnel(ctx, s.Addr(), knx.TunnelOptions{OnFrame: func(f knx.LData) { mu.Lock(); got = append(got, f); mu.Unlock() }})
		if err != nil {
			t.Fatal(err)
		}
		_ = tn.Send(ctx, knx.IndividualFrame(knx.LDataReq, knxsim.Address, knx.DeviceDescriptorRead, 0, nil))
		_ = tn.Send(ctx, knx.IndividualFrame(knx.LDataReq, knxsim.Address, knx.PropertyValueRead, 0, []byte{0, 11, 0x10, 0x01}))
		_ = tn.Send(ctx, knx.GroupFrame(knx.LDataReq, 0, knx.IndividualAddressRead, nil, true))
		eventually(t, 3*time.Second, "management answers", func() bool {
			mu.Lock()
			defer mu.Unlock()
			n := 0
			for _, f := range got {
				if f.Code == knx.LDataInd {
					n++
				}
			}
			return n >= 2
		})
		time.Sleep(200 * time.Millisecond)
		mu.Lock()
		var dd, pv, ia bool
		for _, f := range got {
			if f.Code != knx.LDataInd {
				continue
			}
			switch f.APCI {
			case knx.DeviceDescriptorResponse:
				dd = bytes.Equal(f.Data, []byte{0x09, 0x1A}) && f.Source == knxsim.Address
			case knx.PropertyValueResponse:
				pv = bytes.Equal(f.Data, []byte{0, 11, 0x10, 0x01, 0x00, 0xC5, 0x01, 0x02, 0x03, 0x04})
			case knx.IndividualAddressResponse:
				ia = f.Source == knxsim.Address
			}
		}
		mu.Unlock()
		if !dd || !pv || ia != prog {
			t.Errorf("programming mode %v: descriptor %v property %v address response %v", prog, dd, pv, ia)
		}
		if n := len(s.Management()); n != 3 {
			t.Errorf("%d management requests recorded", n)
		}
		tn.Close()
		cancel()

		found, err := knx.SearchExtended(context.Background(), s.Addr(), 300*time.Millisecond, knx.SRPByProgrammingMode())
		if err != nil || len(found) != map[bool]int{false: 0, true: 1}[prog] {
			t.Errorf("programming mode %v: search by programming mode found %d (%v)", prog, len(found), err)
		}
		found, err = knx.SearchExtended(context.Background(), s.Addr(), 300*time.Millisecond, knx.SRPByService(knx.FamilyTunnelling, 2))
		if err != nil || len(found) != 1 || found[0].Tunnels == nil || len(found[0].Tunnels.Slots) != 4 || !found[0].Tunnels.Slots[0].Free {
			t.Errorf("search by tunnelling v2: %+v %v", found, err)
		}
		if found, _ = knx.SearchExtended(context.Background(), s.Addr(), 300*time.Millisecond, knx.SRPByService(knx.FamilyRouting, 1)); len(found) != 0 {
			t.Errorf("a gateway without routing answered a search for routing")
		}
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().String()
}

// The simulated router stores routed writes, answers reads, and sends
// ROUTING_BUSY when flooded, which slows the client router down; over a
// secure backbone with KNX Data Secure it does the same with wrapped and
// sealed frames.
// Covers: SIG-IPE-6709
func TestSimRouter(t *testing.T) {
	for _, secure := range []bool{false, true} {
		pc, ps := freeAddr(t), freeAddr(t)
		ro := knxsim.RouterOptions{Group: pc, Listen: ps, BusyAbove: 3, BusyWait: 300 * time.Millisecond}
		co := knx.RoutingOptions{Group: ps, Listen: pc, Source: 0x1105, MinInterval: -1}
		secured := ga(t, "1/1/7")
		if secure {
			key := bytes.Repeat([]byte{7}, 16)
			ro.Secure = &knx.SecureRoutingOptions{BackboneKey: key, Latency: 200 * time.Millisecond}
			co.Secure = &knx.SecureRoutingOptions{BackboneKey: key, Latency: 200 * time.Millisecond}
			cds, sds, g := dataSecurePair(t, map[knx.IndividualAddress]uint64{0x1105: 0})
			ro.DataSecure, co.DataSecure, secured = sds, cds, g
		}
		r, err := knxsim.StartRouter(ro)
		if err != nil {
			t.Fatal(err)
		}
		var mu sync.Mutex
		var got []knx.LData
		co.OnFrame = func(f knx.LData) { mu.Lock(); got = append(got, f); mu.Unlock() }
		c, err := knx.ListenRouting(co)
		if err != nil {
			t.Fatal(err)
		}
		if secure && (!r.TimeKeeper() || c.TimeKeeper()) {
			t.Errorf("time keepers: simulator %v client %v", r.TimeKeeper(), c.TimeKeeper())
		}
		ctx := context.Background()
		if err := c.Send(ctx, knx.GroupFrame(0, secured, knx.GroupValueWrite, []byte{0x0C, 0x1A}, false)); err != nil {
			t.Fatal(err)
		}
		if err := c.Send(ctx, knx.GroupFrame(0, secured, knx.GroupValueRead, nil, true)); err != nil {
			t.Fatal(err)
		}
		eventually(t, 3*time.Second, "response", func() bool {
			mu.Lock()
			defer mu.Unlock()
			for _, f := range got {
				if f.APCI == knx.GroupValueResponse && bytes.Equal(f.Value(), []byte{0x0C, 0x1A}) && f.Source == knxsim.Device10 {
					return true
				}
			}
			return false
		})
		if w := r.Writes(); len(w) != 1 || !bytes.Equal(w[0].Data, []byte{0x0C, 0x1A}) {
			t.Errorf("secure %v: writes %+v", secure, w)
		}
		// Flood: the simulator answers with ROUTING_BUSY and the client
		// waits.
		// The pause falls inside the flood or before the send after it.
		start := time.Now()
		for i := range 4 {
			if err := c.Send(ctx, knx.GroupFrame(0, ga(t, "2/0/1"), knx.GroupValueWrite, []byte{byte(i)}, false)); err != nil {
				t.Fatal(err)
			}
		}
		eventually(t, 2*time.Second, "ROUTING_BUSY", func() bool { b, _ := c.Busy(); return b > 0 })
		if err := c.Send(ctx, knx.GroupFrame(0, ga(t, "2/0/1"), knx.GroupValueWrite, []byte{9}, false)); err != nil {
			t.Fatal(err)
		}
		if r.BusySent() != 1 || time.Since(start) < 250*time.Millisecond {
			t.Errorf("secure %v: busy sent %d, flood and next send took %v", secure, r.BusySent(), time.Since(start))
		}
		c.Close()
		r.Close()
	}
}
