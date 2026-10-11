// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package sim

import (
	"context"
	"sync"
	"time"

	"github.com/cB-Sigma/knx"
)

// RouterOptions configure a simulated KNX IP router.
type RouterOptions struct {
	// Group is the routing group (default 224.0.23.12:3671); a unicast
	// address sends point to point, with Listen the local address.
	Group, Listen, Interface string
	// Secure runs KNX IP Secure routing with this backbone key.
	Secure *knx.SecureRoutingOptions
	// DataSecure seals and opens frames of secured groups.
	DataSecure *knx.DataSecure
	// BusyAbove sends ROUTING_BUSY (wait BusyWait, default 100ms) when more
	// than this many indications arrive within 100ms; 0 never does.
	BusyAbove int
	BusyWait  time.Duration
}

// Router is a simulated KNX IP router with a small bus behind it: it keeps
// group objects, records the writes and reads it receives, answers reads
// from the bus device 1.1.10, and can be made busy.
type Router struct {
	r    *knx.Router
	o    RouterOptions
	mu   sync.Mutex
	objs map[knx.GroupAddress][]byte
	shrt map[knx.GroupAddress]bool
	wr   []Write
	rd   []knx.GroupAddress
	seen []time.Time
	busy int
}

// StartRouter joins the routing group. With Secure it first synchronises
// its timer with the backbone (or becomes its time keeper).
func StartRouter(o RouterOptions) (*Router, error) {
	if o.BusyWait <= 0 {
		o.BusyWait = 100 * time.Millisecond
	}
	s := &Router{o: o, objs: map[knx.GroupAddress][]byte{}, shrt: map[knx.GroupAddress]bool{}}
	ready := make(chan struct{})
	r, err := knx.ListenRouting(knx.RoutingOptions{Group: o.Group, Listen: o.Listen, Interface: o.Interface, Source: Device10,
		Secure: o.Secure, DataSecure: o.DataSecure, MinInterval: -1,
		OnFrame: func(f knx.LData) { <-ready; s.onFrame(f) }})
	if err != nil {
		return nil, err
	}
	s.r = r
	close(ready)
	return s, nil
}

func (s *Router) onFrame(f knx.LData) {
	if !f.GroupTarget || f.Source == Device10 {
		return
	}
	now := time.Now()
	s.mu.Lock()
	keep := s.seen[:0]
	for _, t := range s.seen {
		if now.Sub(t) < 100*time.Millisecond {
			keep = append(keep, t)
		}
	}
	s.seen = append(keep, now)
	sendBusy := s.o.BusyAbove > 0 && len(s.seen) > s.o.BusyAbove
	if sendBusy {
		s.busy++
		s.seen = s.seen[:0]
	}
	var resp []byte
	short := false
	answer := false
	switch f.APCI {
	case knx.GroupValueWrite, knx.GroupValueResponse:
		if f.APCI == knx.GroupValueWrite {
			s.wr = append(s.wr, Write{GA: f.Group(), Data: append([]byte(nil), f.Value()...)})
		}
		s.objs[f.Group()] = append([]byte(nil), f.Value()...)
		s.shrt[f.Group()] = f.IsShort
	case knx.GroupValueRead:
		s.rd = append(s.rd, f.Group())
		resp, answer = append([]byte(nil), s.objs[f.Group()]...), s.objs[f.Group()] != nil
		short = s.shrt[f.Group()]
	}
	s.mu.Unlock()
	if sendBusy {
		_ = s.r.SendBusy(s.o.BusyWait)
	}
	if answer {
		go func() {
			_ = s.r.Send(context.Background(), knx.GroupFrame(knx.LDataInd, f.Group(), knx.GroupValueResponse, resp, short))
		}()
	}
}

// Set stores a group object's value without telling anyone.
func (s *Router) Set(ga knx.GroupAddress, data []byte, short bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.objs[ga] = append([]byte(nil), data...)
	s.shrt[ga] = short
}

// Get returns a group object's value.
func (s *Router) Get(ga knx.GroupAddress) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.objs[ga]...)
}

// Inject makes the bus device 1.1.10 write a group object: the value is
// stored and the indication routed.
func (s *Router) Inject(ctx context.Context, ga knx.GroupAddress, data []byte, short bool) error {
	s.Set(ga, data, short)
	return s.r.Send(ctx, knx.GroupFrame(knx.LDataInd, ga, knx.GroupValueWrite, data, short))
}

// SendBusy routes a ROUTING_BUSY asking senders to wait.
func (s *Router) SendBusy(wait time.Duration) error { return s.r.SendBusy(wait) }

// SendLostMessage routes a ROUTING_LOST_MESSAGE.
func (s *Router) SendLostMessage(n uint16) error { return s.r.SendLostMessage(n) }

// Writes lists the group writes received.
func (s *Router) Writes() []Write {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Write(nil), s.wr...)
}

// Reads lists the group addresses read.
func (s *Router) Reads() []knx.GroupAddress {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]knx.GroupAddress(nil), s.rd...)
}

// BusySent counts the ROUTING_BUSY frames sent because of BusyAbove.
func (s *Router) BusySent() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.busy
}

// TimeKeeper reports whether the router keeps the secure backbone's time.
func (s *Router) TimeKeeper() bool { return s.r.TimeKeeper() }

// Addr is the router's receive address.
func (s *Router) Addr() string { return s.r.LocalAddr().String() }

// Close leaves the group.
func (s *Router) Close() { s.r.Close() }
