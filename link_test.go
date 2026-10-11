// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package knx_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cB-Sigma/knx"
	knxsim "github.com/cB-Sigma/knx-sim/sim"
)

// slowReader returns at most n bytes per Read, splitting frames.
type slowReader struct {
	r io.Reader
	n int
}

func (s slowReader) Read(p []byte) (int, error) {
	if len(p) > s.n {
		p = p[:s.n]
	}
	return s.r.Read(p)
}

// Frames on a KNXnet/IP TCP stream are delimited only by the header's total
// length, and the TCP HPAI is host protocol 0x02 in the route-back form.
//
// Covers: SIG-IPE-845
func TestKNXTCPStreamFraming(t *testing.T) {
	// Stream framing: two frames back to back, read in 3-byte pieces.
	a := knx.TunnelRequest{Channel: 7, Seq: 1, CEMI: knx.GroupFrame(knx.LDataInd, 0x0A03, knx.GroupValueWrite, []byte{1}, true).Encode()}.Frame()
	b := knx.ChannelRequest{Channel: 7, Control: knx.TCPHPAI()}.Frame(knx.SvcConnectionStateRequest)
	stream := append(a.Encode(), b.Encode()...)
	r := slowReader{bytes.NewReader(stream), 3}
	for i, want := range []knx.Frame{a, b} {
		got, err := knx.ReadStreamFrame(r)
		if err != nil || got.Service != want.Service || !bytes.Equal(got.Body, want.Body) {
			t.Fatalf("frame %d = %+v, %v", i, got, err)
		}
	}
	if _, err := knx.ReadStreamFrame(r); err != io.EOF {
		t.Errorf("end of stream = %v", err)
	}
	if _, err := knx.ReadStreamFrame(bytes.NewReader([]byte{0x06, 0x20, 0x02, 0x05, 0x00, 0x08})); err == nil {
		t.Error("a wrong protocol version was accepted")
	}
	if _, err := knx.ReadStreamFrame(bytes.NewReader([]byte{0x06, 0x10, 0x02, 0x05, 0x00, 0x04})); err == nil {
		t.Error("a total length below the header was accepted")
	}
	// The TCP HPAI.
	if got := b.Body[2:]; !bytes.Equal(got, []byte{0x08, 0x02, 0, 0, 0, 0, 0, 0}) {
		t.Errorf("TCP HPAI = % x", got)
	}
	cr, err := knx.ParseConnectRequest(knx.ConnectRequest{Control: knx.TCPHPAI(), Data: knx.TCPHPAI()}.Frame().Body)
	if err != nil || !cr.Control.TCP || !cr.Data.TCP || !cr.Control.Zero() {
		t.Errorf("TCP connect request = %+v, %v", cr, err)
	}

}

type frameLog struct {
	mu sync.Mutex
	fs []knx.LData
}

func (l *frameLog) add(f knx.LData) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fs = append(l.fs, f)
}

func (l *frameLog) all() []knx.LData {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]knx.LData(nil), l.fs...)
}

func (l *frameLog) writes(g knx.GroupAddress) [][]byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out [][]byte
	for _, f := range l.fs {
		if f.Code == knx.LDataInd && f.GroupTarget && f.Group() == g {
			out = append(out, f.Value())
		}
	}
	return out
}

func dialSecure(t *testing.T, sim *knxsim.Server, keepalive time.Duration, log *frameLog, errs chan error) *knx.Tunnel {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tn, err := knx.DialTunnel(ctx, sim.TCPAddr(), knx.TunnelOptions{Heartbeat: time.Hour, Timeout: 2 * time.Second,
		Secure: &knx.SecureOptions{UserID: 2, PasswordHash: knx.UserPasswordHash("tunnel-pass"),
			DeviceAuth: knx.DeviceAuthCode("gateway-auth"), Keepalive: keepalive},
		OnFrame: log.add, OnError: func(err error) {
			select {
			case errs <- err:
			default:
			}
		}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tn.Close)
	return tn
}

// Received wrappers are accepted only for our session, with a sequence
// number above every earlier one and a valid MAC: replays and altered
// frames are dropped. Plain frames on a secure endpoint are ignored, and a
// SESSION_STATUS close from the gateway ends the tunnel.
//
// Covers: SIG-IPE-849
func TestKNXSecureWrapperChecks(t *testing.T) {
	sim := secureSim(t, 0)
	log := &frameLog{}
	errs := make(chan error, 16)
	tn := dialSecure(t, sim, time.Minute, log, errs)
	g := ga(t, "2/0/1")

	sim.Inject(g, []byte{0x11}, false)
	eventually(t, 5*time.Second, "the first indication", func() bool { return len(log.writes(g)) == 1 })
	// The same wrapper again (old sequence number): dropped.
	sim.ReplayLast()
	// An altered wrapper: dropped.
	sim.InjectTampered(g, []byte{0x22}, false)
	sim.Inject(g, []byte{0x33}, false)
	eventually(t, 5*time.Second, "the next valid indication", func() bool { return len(log.writes(g)) >= 2 })
	time.Sleep(100 * time.Millisecond)
	if w := log.writes(g); len(w) != 2 || w[0][0] != 0x11 || w[1][0] != 0x33 {
		t.Errorf("delivered = %x, want only 11 and 33", w)
	}
	var sawReplay, sawMAC bool
	for len(errs) > 0 {
		e := <-errs
		sawReplay = sawReplay || strings.Contains(e.Error(), "sequence")
		sawMAC = sawMAC || strings.Contains(e.Error(), "MAC")
		if !errors.Is(e, knx.ErrSecure) {
			t.Errorf("unexpected error %v", e)
		}
	}
	if !sawReplay || !sawMAC {
		t.Errorf("replay reported %v, MAC failure reported %v", sawReplay, sawMAC)
	}
	// The tunnel still works in both directions.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := tn.Send(ctx, knx.GroupFrame(knx.LDataReq, g, knx.GroupValueWrite, []byte{0x44}, false)); err != nil {
		t.Errorf("send after the rejected frames: %v", err)
	}

	// A plain CONNECT_REQUEST on the secure endpoint is ignored.
	raw, err := net.Dial("tcp4", sim.TCPAddr())
	if err != nil {
		t.Fatal(err)
	}
	before := sim.Rejected()
	_, _ = raw.Write(knx.ConnectRequest{Control: knx.TCPHPAI(), Data: knx.TCPHPAI()}.Frame().Encode())
	_ = raw.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, _ := raw.Read(make([]byte, 64)); n != 0 {
		t.Errorf("the secure endpoint answered a plain connect (%d bytes)", n)
	}
	_ = raw.Close()
	if sim.Rejected() != before+1 {
		t.Errorf("rejected = %d, want %d", sim.Rejected(), before+1)
	}

	// The gateway closes the session.
	sim.EndSessions(knx.SessionClose)
	select {
	case <-tn.Lost():
		if e := tn.Err(); e == nil || !strings.Contains(e.Error(), "session closed") {
			t.Errorf("end reason = %v", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the tunnel survived SESSION_STATUS close")
	}
}

// An idle session is kept alive with SESSION_STATUS keepalives; without
// them the gateway's session timeout ends it.
//
// Covers: SIG-IPE-850
func TestKNXSecureKeepalive(t *testing.T) {
	sim := secureSim(t, 500*time.Millisecond)
	tn := dialSecure(t, sim, 100*time.Millisecond, &frameLog{}, make(chan error, 16))
	time.Sleep(1500 * time.Millisecond)
	select {
	case <-tn.Lost():
		t.Fatalf("session with keepalives ended: %v", tn.Err())
	default:
	}
	if sim.Keepalives() < 3 {
		t.Errorf("keepalives = %d", sim.Keepalives())
	}
	// No keepalive within the gateway's timeout: the session times out.
	idle := dialSecure(t, sim, time.Minute, &frameLog{}, make(chan error, 16))
	select {
	case <-idle.Lost():
		if e := idle.Err(); e == nil || !strings.Contains(e.Error(), "session timeout") {
			t.Errorf("end reason = %v", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the idle session did not time out")
	}

}

// A search sent to a gateway's address is answered with its description:
// name, individual address, control endpoint and service families.
//
// Covers: SIG-IPE-446
func TestKNXGatewaySearch(t *testing.T) {
	sim := startSim(t)
	found, err := knx.Search(context.Background(), sim.Addr(), 500*time.Millisecond)
	if err != nil || len(found) != 1 {
		t.Fatalf("search = %v, %v", found, err)
	}
	g := found[0]
	if g.Device.FriendlyName != "Sigma KNX simulator" || !g.Supports(knx.FamilyTunnelling) || g.Control.Addr.String() != sim.Addr() ||
		g.Device.Address.String() != "1.1.255" {
		t.Errorf("search response = %+v", g)
	}
}

// TestKNXRoutingMulticastLoopback tries the real multicast group; it is
// skipped where the sandbox has no multicast route.
func TestKNXRoutingMulticastLoopback(t *testing.T) {
	got := make(chan knx.LData, 1)
	r, err := knx.ListenRouting(knx.RoutingOptions{Group: "224.0.23.12:53671", OnFrame: func(f knx.LData) {
		select {
		case got <- f:
		default:
		}
	}})
	if err != nil {
		t.Skipf("multicast unavailable: %v", err)
	}
	defer r.Close()
	if err := r.Send(context.Background(), knx.GroupFrame(0, 0x0A03, knx.GroupValueWrite, []byte{1}, true)); err != nil {
		t.Skipf("multicast send unavailable: %v", err)
	}
	select {
	case f := <-got:
		if f.Group() != 0x0A03 {
			t.Errorf("looped frame = %+v", f)
		}
	case <-time.After(2 * time.Second):
		t.Skip("multicast loopback not delivered in this environment")
	}
}
