// Package sim is an in-process KNXnet/IP tunnelling server for tests: it
// answers search and description requests, accepts link-layer tunnel
// connections, acknowledges tunnelling requests, confirms them with
// L_Data.con, keeps group objects (group address → application data),
// answers GroupValue_Read and can put frames from other bus devices on the
// tunnel. It can also go silent or stop acknowledging to exercise the
// client's heartbeat and repeat handling.
//
// Besides UDP it can listen on TCP (KNXnet/IP core v2: stream framing, no
// TUNNELLING_ACK) and run KNX IP Secure sessions on those streams
// (SESSION_REQUEST / RESPONSE / AUTHENTICATE / STATUS, SECURE_WRAPPER with
// sequence and MAC checks, session timeout).
//
// The bus behind it can secure groups with KNX Data Secure; busmonitor
// tunnels see every frame; the gateway answers device management and, in
// programming mode, IndividualAddress_Read. [StartRouter] is a simulated
// KNX IP router (plain or KNX IP Secure, with flow control).
package sim

import (
	"bufio"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/cB-Sigma/knx"
)

// Options select the extra endpoints.
type Options struct {
	// TCP also listens for KNXnet/IP TCP connections (TCPAddr).
	TCP bool
	// Secure runs KNX IP Secure on the TCP endpoint (implies TCP).
	Secure *SecureConfig
	// Listen is the UDP address to listen on (default 127.0.0.1 on a free
	// port). The search and description answers name it, so give a
	// concrete address rather than 0.0.0.0 when clients search.
	Listen string
	// ListenTCP is the TCP address (default 127.0.0.1 on a free port).
	ListenTCP string
	// DataSecure makes the simulated bus use KNX Data Secure: secured
	// writes from tunnels are opened (and refused when they do not
	// verify), and reads of and injected writes to secured groups are
	// answered sealed, from 1.1.10. Its senders must include the tunnel
	// addresses (1.1.241 to 1.1.244) that write secured groups.
	DataSecure *knx.DataSecure
	// ProgrammingMode puts the gateway in programming mode: it answers
	// IndividualAddress_Read and extended searches that ask for it.
	ProgrammingMode bool
}

// Address is the gateway's individual address; Device10 is the simulated
// bus device whose writes Inject puts on the tunnels.
const (
	Address  knx.IndividualAddress = 0x11FF // 1.1.255
	Device10 knx.IndividualAddress = 0x110A // 1.1.10
)

// MaskVersion is the device descriptor type 0 the gateway reports
// (DeviceDescriptor_Response): a KNXnet/IP device on TP1.
const MaskVersion uint16 = 0x091A

// SecureConfig describes the simulated secure gateway.
type SecureConfig struct {
	// Users maps tunnelling user ids to their passwords.
	Users map[byte]string
	// DeviceAuth is the device authentication password.
	DeviceAuth string
	// Serial is the gateway's serial number in its wrappers.
	Serial [6]byte
	// SessionTimeout closes an idle session with SESSION_STATUS timeout
	// (default 60s).
	SessionTimeout time.Duration
	// AllowPlain also accepts plain (unsecured) tunnels on the TCP endpoint.
	AllowPlain bool
}

// Server is the simulated gateway.
type Server struct {
	conn *net.UDPConn
	ln   net.Listener
	desc knx.Description
	sec  *SecureConfig
	pw   map[byte][]byte
	dev  []byte

	mu        sync.Mutex
	objects   map[knx.GroupAddress][]byte
	short     map[knx.GroupAddress]bool
	channels  map[byte]*channel
	streams   map[*stream]bool
	next      byte
	nextSess  uint16
	silent    bool
	dropAcks  bool
	connects  int
	sessions  int
	keepalive int
	rejected  int
	dsRefused int
	mgmt      []knx.LData
	ds        *knx.DataSecure
	progMode  bool
	tcpAcks   int
	writes    []Write
	reads     []knx.GroupAddress
	wg        sync.WaitGroup
	closed    bool
}

// Write is a GroupValue_Write the server received from a client.
type Write struct {
	GA   knx.GroupAddress
	Data []byte
}

type channel struct {
	id      byte
	control func(knx.Frame)
	data    func(knx.Frame)
	st      *stream // nil on UDP
	addr    knx.IndividualAddress
	layer   byte
	txSeq   byte
	rxSeq   byte
}

// stream is one TCP connection, optionally carrying a secure session.
type stream struct {
	c   net.Conn
	wmu sync.Mutex

	// secure session (guarded by wmu for the tx side)
	secure    bool
	key       []byte
	sessionID uint16
	clientPub []byte
	serverPub []byte
	authed    bool
	lastRx    int64
	txSeq     uint64
	lastWrap  []byte
}

// Start listens on 127.0.0.1 on a free UDP port.
func Start() (*Server, error) { return StartWith(Options{}) }

// StartWith listens on UDP and, when asked, on TCP.
func StartWith(o Options) (*Server, error) {
	if o.Listen == "" {
		o.Listen = "127.0.0.1:0"
	}
	if o.ListenTCP == "" {
		o.ListenTCP = "127.0.0.1:0"
	}
	ua, err := net.ResolveUDPAddr("udp4", o.Listen)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp4", ua)
	if err != nil {
		return nil, err
	}
	s := &Server{conn: conn, objects: map[knx.GroupAddress][]byte{}, short: map[knx.GroupAddress]bool{},
		channels: map[byte]*channel{}, streams: map[*stream]bool{}, next: 1, nextSess: 1,
		ds: o.DataSecure, progMode: o.ProgrammingMode}
	families := []knx.Family{{ID: knx.FamilyCore, Version: 1}, {ID: knx.FamilyDeviceMgmt, Version: 1}, {ID: knx.FamilyTunnelling, Version: 1}}
	if o.Secure != nil {
		o.TCP = true
		sc := *o.Secure
		if sc.SessionTimeout <= 0 {
			sc.SessionTimeout = 60 * time.Second
		}
		s.sec = &sc
		s.pw = map[byte][]byte{}
		for id, p := range sc.Users {
			s.pw[id] = knx.UserPasswordHash(p)
		}
		s.dev = knx.DeviceAuthCode(sc.DeviceAuth)
		families = append(families, knx.Family{ID: knx.FamilySecurity, Version: 1})
	}
	if o.TCP {
		families[0].Version, families[2].Version = 2, 2
		if s.ln, err = net.Listen("tcp4", o.ListenTCP); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	s.desc = knx.Description{
		Control: knx.HPAIFrom(conn.LocalAddr().(*net.UDPAddr)),
		Device: knx.DeviceInfo{Medium: knx.MediumTP1, Address: 0x11FF, // 1.1.255
			Serial: [6]byte{0x00, 0xC5, 0x01, 0x02, 0x03, 0x04}, Multicast: netip.MustParseAddr("224.0.23.12"),
			MAC: [6]byte{0x02, 0, 0, 0, 0, 0x01}, FriendlyName: "Sigma KNX simulator"},
		Families: families,
	}
	if o.ProgrammingMode {
		s.desc.Device.Status |= 0x01
	}
	s.wg.Add(1)
	go func() { defer s.wg.Done(); s.loop() }()
	if s.ln != nil {
		s.wg.Add(1)
		go func() { defer s.wg.Done(); s.accept() }()
	}
	return s, nil
}

// Addr is the UDP control endpoint, such as "127.0.0.1:3671".
func (s *Server) Addr() string { return s.conn.LocalAddr().String() }

// TCPAddr is the TCP endpoint ("" without TCP).
func (s *Server) TCPAddr() string {
	if s.ln == nil {
		return ""
	}
	return s.ln.Addr().String()
}

// Close stops the server.
func (s *Server) Close() {
	s.mu.Lock()
	s.closed = true
	var sts []*stream
	for st := range s.streams {
		sts = append(sts, st)
	}
	s.mu.Unlock()
	_ = s.conn.Close()
	if s.ln != nil {
		_ = s.ln.Close()
	}
	for _, st := range sts {
		_ = st.c.Close()
	}
	s.wg.Wait()
}

// Set stores a group object's value without telling anyone.
func (s *Server) Set(ga knx.GroupAddress, data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.objects[ga] = append([]byte(nil), data...)
}

// Get returns a group object's value.
func (s *Server) Get(ga knx.GroupAddress) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.objects[ga]...)
}

// SetSilent makes the server ignore every datagram and stream frame (a
// dead gateway).
func (s *Server) SetSilent(v bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.silent = v
}

// DropAcks makes the server stop acknowledging tunnelling requests (the
// requests are otherwise ignored).
func (s *Server) DropAcks(v bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dropAcks = v
}

// Connects counts accepted tunnel connections.
func (s *Server) Connects() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connects
}

// Channels counts open tunnel connections.
func (s *Server) Channels() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.channels)
}

// Sessions counts authenticated secure sessions.
func (s *Server) Sessions() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessions
}

// Keepalives counts SESSION_STATUS keepalives received.
func (s *Server) Keepalives() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.keepalive
}

// Rejected counts secure frames the server discarded (bad MAC, old
// sequence, wrong session, plain frames on a secure stream).
func (s *Server) Rejected() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rejected
}

// TCPAcks counts TUNNELLING_ACKs received over TCP (there should be none).
func (s *Server) TCPAcks() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tcpAcks
}

// Writes lists the GroupValue_Writes received from clients.
func (s *Server) Writes() []Write {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Write(nil), s.writes...)
}

// Reads lists the group addresses clients read.
func (s *Server) Reads() []knx.GroupAddress {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]knx.GroupAddress(nil), s.reads...)
}

// DropStreams closes every TCP connection (a gateway restart).
func (s *Server) DropStreams() {
	s.mu.Lock()
	var sts []*stream
	for st := range s.streams {
		sts = append(sts, st)
	}
	s.mu.Unlock()
	for _, st := range sts {
		_ = st.c.Close()
	}
}

// ReplayLast sends every secure stream's last wrapper again, unchanged (a
// replay the client must discard).
func (s *Server) ReplayLast() {
	for _, st := range s.secureStreams() {
		st.wmu.Lock()
		b := st.lastWrap
		st.wmu.Unlock()
		if b != nil {
			_, _ = st.c.Write(b)
		}
	}
}

// InjectTampered sends a group write on every secure stream in a wrapper
// whose ciphertext was altered (the client must discard it).
func (s *Server) InjectTampered(ga knx.GroupAddress, data []byte, short bool) {
	f := knx.GroupFrame(knx.LDataInd, ga, knx.GroupValueWrite, data, short)
	f.Source = 0x110A
	for _, c := range s.chans() {
		if c.st == nil || !c.st.secure {
			continue
		}
		s.mu.Lock()
		inner := knx.TunnelRequest{Channel: c.id, Seq: c.txSeq, CEMI: f.Encode()}.Frame()
		c.txSeq++
		s.mu.Unlock()
		c.st.wmu.Lock()
		w := knx.SecureWrapper{SessionID: c.st.sessionID, Seq: c.st.txSeq, Serial: s.sec.Serial, Tag: knx.MessageTagTunnelling}
		c.st.txSeq++
		b := w.Wrap(c.st.key, inner).Encode()
		b[len(b)-20] ^= 0x40
		_, _ = c.st.c.Write(b)
		c.st.wmu.Unlock()
	}
}

// EndSessions sends SESSION_STATUS with status on every secure stream.
func (s *Server) EndSessions(status byte) {
	for _, st := range s.secureStreams() {
		st.send(s, knx.SessionStatusFrame(status))
	}
}

func (s *Server) secureStreams() []*stream {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*stream
	for st := range s.streams {
		st.wmu.Lock()
		ok := st.secure && st.authed
		st.wmu.Unlock()
		if ok {
			out = append(out, st)
		}
	}
	return out
}

func (s *Server) chans() []*channel {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*channel
	for _, c := range s.channels {
		out = append(out, c)
	}
	return out
}

// Inject makes another bus device (1.1.10) write a group object: the value
// is stored and an L_Data.ind goes to every tunnel.
func (s *Server) Inject(ga knx.GroupAddress, data []byte, short bool) {
	s.mu.Lock()
	s.objects[ga] = append([]byte(nil), data...)
	s.short[ga] = short
	s.mu.Unlock()
	f := knx.GroupFrame(knx.LDataInd, ga, knx.GroupValueWrite, data, short)
	f.Source = Device10
	s.broadcast(s.seal(f).Encode(), false)
}

// seal protects a frame of the simulated bus device when its group is
// secured.
func (s *Server) seal(f knx.LData) knx.LData {
	if s.ds == nil {
		return f
	}
	if sf, err := s.ds.Seal(f); err == nil {
		return sf
	}
	return f
}

// DataSecureRefused counts secured frames from tunnels that did not verify
// (and plain frames to secured groups).
func (s *Server) DataSecureRefused() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dsRefused
}

// Management lists the point-to-point frames clients sent to the gateway
// (device management: descriptor, property, memory reads).
func (s *Server) Management() []knx.LData {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]knx.LData(nil), s.mgmt...)
}

// busmon turns a cEMI L_Data frame into the L_Busmon.ind a busmonitor
// tunnel sees: status and timestamp as additional information, then the
// TP1 frame (control field, source, destination, address type with hop
// count and length, the TPDU, and the check octet: the inverted XOR of the
// others).
func busmon(cemi []byte, ts uint16) []byte {
	f, err := knx.ParseLData(cemi)
	if err != nil {
		return nil
	}
	raw := f.Encode()
	ai := int(raw[1])
	l := raw[2+ai:] // ctrl1 ctrl2 src src dst dst len apdu...
	tp := []byte{l[0], l[2], l[3], l[4], l[5], l[1]&0x80 | l[1]&0x70 | l[6]&0x0F}
	tp = append(tp, l[7:]...)
	var x byte
	for _, b := range tp {
		x ^= b
	}
	tp = append(tp, ^x)
	return append([]byte{knx.LBusmonInd, 7, 0x03, 0x01, 0x00, 0x04, 0x02, byte(ts >> 8), byte(ts)}, tp...)
}

// InjectDuplicate sends an indication and then repeats it with the same
// sequence number, as a gateway does when it misses the client's ack.
func (s *Server) InjectDuplicate(ga knx.GroupAddress, data []byte, short bool) {
	f := knx.GroupFrame(knx.LDataInd, ga, knx.GroupValueWrite, data, short)
	f.Source = Device10
	s.broadcast(f.Encode(), true)
}

func (s *Server) broadcast(cemi []byte, twice bool) {
	s.mu.Lock()
	type out struct {
		send func(knx.Frame)
		f    knx.Frame
	}
	var outs []out
	ts := uint16(time.Now().UnixMilli())
	for _, c := range s.channels {
		frame := cemi
		if c.layer == knx.LayerBusmonitor {
			frame = busmon(cemi, ts)
		}
		f := knx.TunnelRequest{Channel: c.id, Seq: c.txSeq, CEMI: frame}.Frame()
		c.txSeq++
		outs = append(outs, out{c.data, f})
	}
	s.mu.Unlock()
	for _, o := range outs {
		o.send(o.f)
		if twice {
			o.send(o.f)
		}
	}
}

// ---- UDP -----------------------------------------------------------------------

func (s *Server) loop() {
	buf := make([]byte, 1024)
	for {
		n, from, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		if s.isSilent() {
			continue
		}
		fr, err := knx.ParseFrame(buf[:n])
		if err != nil {
			continue
		}
		body := append([]byte(nil), fr.Body...)
		s.handle(fr.Service, body, s.udpReply(from), nil)
	}
}

func (s *Server) isSilent() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.silent
}

// A replier sends a frame to the endpoint an HPAI names (UDP) or down the
// stream (TCP, where the HPAI is the route-back form).
type replier func(f knx.Frame, h knx.HPAI)

func (s *Server) udpReply(from *net.UDPAddr) replier {
	return func(f knx.Frame, h knx.HPAI) { _, _ = s.conn.WriteToUDP(f.Encode(), h.UDPAddr(from)) }
}

// ---- TCP -----------------------------------------------------------------------

func (s *Server) accept() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		st := &stream{c: c, lastRx: -1}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			_ = c.Close()
			return
		}
		s.streams[st] = true
		s.mu.Unlock()
		s.wg.Add(1)
		go func() { defer s.wg.Done(); s.serveStream(st) }()
	}
}

// send writes a frame on the stream, wrapped once the session exists.
func (st *stream) send(s *Server, f knx.Frame) {
	st.wmu.Lock()
	defer st.wmu.Unlock()
	b := f.Encode()
	if st.secure {
		w := knx.SecureWrapper{SessionID: st.sessionID, Seq: st.txSeq, Serial: s.sec.Serial, Tag: knx.MessageTagTunnelling}
		st.txSeq++
		b = w.Wrap(st.key, f).Encode()
		st.lastWrap = b
	}
	_ = st.c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, _ = st.c.Write(b)
}

func (s *Server) serveStream(st *stream) {
	defer func() {
		_ = st.c.Close()
		// Closing the stream ends its tunnels.
		s.mu.Lock()
		delete(s.streams, st)
		for id, c := range s.channels {
			if c.st == st {
				delete(s.channels, id)
			}
		}
		s.mu.Unlock()
	}()
	r := bufio.NewReader(st.c)
	reply := func(f knx.Frame, _ knx.HPAI) { st.send(s, f) }
	for {
		if s.sec != nil {
			_ = st.c.SetReadDeadline(time.Now().Add(s.sec.SessionTimeout))
		}
		fr, err := knx.ReadStreamFrame(r)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() && st.secure {
				st.send(s, knx.SessionStatusFrame(knx.SessionTimeout))
			}
			return
		}
		if s.isSilent() {
			continue
		}
		switch {
		case s.sec != nil && fr.Service == knx.SvcSessionRequest && !st.secure:
			if !s.sessionRequest(st, fr.Body) {
				return
			}
		case st.secure:
			if fr.Service != knx.SvcSecureWrapper {
				s.reject()
				continue
			}
			w, inner, err := knx.ParseSecureWrapper(st.key, fr.Body)
			if err != nil || w.SessionID != st.sessionID || int64(w.Seq) <= st.lastRx {
				s.reject()
				continue
			}
			st.lastRx = int64(w.Seq)
			if !s.secureFrame(st, inner, reply) {
				return
			}
		case s.sec == nil || s.sec.AllowPlain:
			s.handle(fr.Service, fr.Body, reply, st)
		default:
			s.reject() // plain frame on a secure-only endpoint
		}
	}
}

func (s *Server) reject() {
	s.mu.Lock()
	s.rejected++
	s.mu.Unlock()
}

// sessionRequest answers SESSION_REQUEST with a new session.
func (s *Server) sessionRequest(st *stream, body []byte) bool {
	clientPub, err := knx.ParseSessionRequest(body)
	if err != nil {
		return false
	}
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return false
	}
	key, err := knx.SharedSessionKey(priv, clientPub)
	if err != nil {
		return false
	}
	s.mu.Lock()
	id := s.nextSess
	s.nextSess++
	s.mu.Unlock()
	st.wmu.Lock()
	st.key, st.sessionID, st.clientPub, st.serverPub = key, id, clientPub, priv.PublicKey().Bytes()
	st.wmu.Unlock()
	mac := knx.SessionResponseMAC(s.dev, id, clientPub, st.serverPub)
	st.send(s, knx.SessionResponse{SessionID: id, ServerPub: st.serverPub, MAC: mac}.Frame())
	st.wmu.Lock()
	st.secure = true // everything after the response is wrapped
	st.wmu.Unlock()
	return true
}

// secureFrame handles a verified inner frame; false ends the stream.
func (s *Server) secureFrame(st *stream, inner knx.Frame, reply replier) bool {
	switch inner.Service {
	case knx.SvcSessionAuthenticate:
		user, mac, err := knx.ParseSessionAuthenticate(inner.Body)
		pw, known := s.pw[user]
		if err != nil || !known || !knx.CheckMAC(mac, knx.SessionAuthenticateMAC(pw, user, st.clientPub, st.serverPub)) {
			st.send(s, knx.SessionStatusFrame(knx.SessionAuthFailed))
			return true
		}
		st.wmu.Lock()
		st.authed = true
		st.wmu.Unlock()
		s.mu.Lock()
		s.sessions++
		s.mu.Unlock()
		st.send(s, knx.SessionStatusFrame(knx.SessionAuthSuccess))
	case knx.SvcSessionStatus:
		if len(inner.Body) > 0 {
			switch inner.Body[0] {
			case knx.SessionKeepalive:
				s.mu.Lock()
				s.keepalive++
				s.mu.Unlock()
			case knx.SessionClose:
				return false
			}
		}
	default:
		if !st.authed {
			st.send(s, knx.SessionStatusFrame(knx.SessionUnauthenticated))
			return true
		}
		s.handle(inner.Service, inner.Body, reply, st)
	}
	return true
}

// ---- services ------------------------------------------------------------------

func (s *Server) handle(svc uint16, body []byte, reply replier, st *stream) {
	switch svc {
	case knx.SvcSearchRequest:
		h, err := knx.ParseEndpointRequest(body)
		if err == nil {
			reply(s.desc.SearchResponseFrame(), h)
		}
	case knx.SvcDescriptionRequest:
		h, err := knx.ParseEndpointRequest(body)
		if err == nil {
			reply(s.desc.DescriptionResponseFrame(), h)
		}
	case svcSearchRequestExt:
		h, srps, err := knx.ParseSearchRequestExtended(body)
		if err == nil && s.desc.Matches(srps) {
			reply(s.searchResponseExt(), h)
		}
	case knx.SvcConnectRequest:
		s.connect(body, reply, st)
	case knx.SvcConnectionStateRequest:
		r, err := knx.ParseChannelRequest(body)
		if err != nil {
			return
		}
		s.mu.Lock()
		c, ok := s.channels[r.Channel]
		ok = ok && c.st == st
		s.mu.Unlock()
		code := knx.StatusOK
		if !ok {
			code = knx.StatusConnectionID
		}
		reply(knx.ChannelResponse{Channel: r.Channel, Status: code}.Frame(knx.SvcConnectionStateResponse), r.Control)
	case knx.SvcDisconnectRequest:
		r, err := knx.ParseChannelRequest(body)
		if err != nil {
			return
		}
		s.mu.Lock()
		c, ok := s.channels[r.Channel]
		ok = ok && c.st == st
		if ok {
			delete(s.channels, r.Channel)
		}
		s.mu.Unlock()
		code := knx.StatusOK
		if !ok {
			code = knx.StatusConnectionID
		}
		reply(knx.ChannelResponse{Channel: r.Channel, Status: code}.Frame(knx.SvcDisconnectResponse), r.Control)
	case knx.SvcTunnellingRequest:
		s.tunnel(body, reply, st)
	case knx.SvcTunnellingAck:
		// The client acknowledged one of our frames; nothing is repeated
		// here, so nothing to do. Over TCP there should be none.
		if st != nil {
			s.mu.Lock()
			s.tcpAcks++
			s.mu.Unlock()
		}
	}
}

// The extended search of KNXnet/IP core v2 (KNX Standard volume 3 part 8
// chapter 2): a unicast SEARCH_REQUEST_EXTENDED is answered with the search
// response's endpoint and DIBs plus the secured service families DIB
// (type 0x06) and the tunnelling information DIB (type 0x07: maximum APDU
// length, then each tunnel address with its usable, authorised and free
// flags). Mandatory search parameter blocks (programming mode, MAC
// address, service family) are evaluated and a gateway that does not meet
// them stays silent; the answer always carries every DIB, which a
// requester that asked for fewer can skip.
const (
	svcSearchRequestExt  uint16 = 0x020B
	svcSearchResponseExt uint16 = 0x020C
	maxChannels                 = 4
)

func (s *Server) searchResponseExt() knx.Frame {
	body := append([]byte(nil), s.desc.SearchResponseFrame().Body...)
	if s.sec != nil {
		fams := []byte{knx.FamilyTunnelling, 1}
		body = append(body, byte(2+len(fams)), 0x06)
		body = append(body, fams...)
	}
	s.mu.Lock()
	used := map[knx.IndividualAddress]bool{}
	for _, c := range s.channels {
		used[c.addr] = true
	}
	s.mu.Unlock()
	body = append(body, byte(4+4*maxChannels), 0x07, 0x00, 0xF8) // max APDU 248
	for i := 1; i <= maxChannels; i++ {
		a := knx.IndividualAddress(0x11F0 + uint16(i))
		flags := byte(0x04) // usable
		if s.sec == nil || s.sec.AllowPlain {
			flags |= 0x02 // authorised without a secure session
		}
		if !used[a] {
			flags |= 0x01 // free
		}
		body = append(body, byte(a>>8), byte(a), 0x00, flags)
	}
	return knx.Frame{Service: svcSearchResponseExt, Body: body}
}

func (s *Server) connect(body []byte, reply replier, st *stream) {
	r, err := knx.ParseConnectRequest(body)
	if err == nil && r.Layer == knx.LayerRaw {
		reply(knx.ConnectResponse{Status: knx.StatusTunnellingLayer}.Frame(), r.Control)
		return
	}
	if err != nil {
		code := knx.StatusConnectionOption
		if knx.IsConnTypeError(err) {
			code = knx.StatusConnectionType
		}
		reply(knx.ConnectResponse{Status: code}.Frame(), knx.HPAIFrom(nil))
		return
	}
	s.mu.Lock()
	if len(s.channels) >= maxChannels {
		s.mu.Unlock()
		reply(knx.ConnectResponse{Status: knx.StatusNoMoreConns}.Frame(), r.Control)
		return
	}
	id := s.next
	s.next++
	if s.next == 0 {
		s.next = 1
	}
	c := &channel{id: id, st: st, addr: knx.IndividualAddress(0x11F0 + uint16(id)), layer: r.Layer,
		control: func(f knx.Frame) { reply(f, r.Control) }, data: func(f knx.Frame) { reply(f, r.Data) }}
	s.channels[id] = c
	s.connects++
	s.mu.Unlock()
	data := knx.HPAIFrom(s.conn.LocalAddr().(*net.UDPAddr))
	if st != nil {
		data = knx.TCPHPAI()
	}
	c.control(knx.ConnectResponse{Channel: id, Status: knx.StatusOK, Data: data, Address: c.addr}.Frame())
}

func (s *Server) tunnel(body []byte, reply replier, st *stream) {
	r, err := knx.ParseTunnelRequest(body)
	if err != nil {
		return
	}
	s.mu.Lock()
	c := s.channels[r.Channel]
	if c != nil && c.st != st {
		c = nil
	}
	drop := s.dropAcks
	if c == nil || drop {
		s.mu.Unlock()
		if c == nil && !drop && st == nil {
			reply(knx.TunnelAck{Channel: r.Channel, Seq: r.Seq, Status: knx.StatusConnectionID}.Frame(), knx.HPAIFrom(nil))
		}
		return
	}
	var dup, fresh bool
	if st != nil {
		// TCP: no acknowledgement and no repeats; every request counts.
		fresh = true
		c.rxSeq = r.Seq + 1
	} else {
		dup = r.Seq == c.rxSeq-1
		fresh = r.Seq == c.rxSeq
		if fresh {
			c.rxSeq++
		}
	}
	s.mu.Unlock()
	if !fresh && !dup {
		return // out of sequence: discarded without an ack
	}
	if st == nil {
		c.data(knx.TunnelAck{Channel: r.Channel, Seq: r.Seq, Status: knx.StatusOK}.Frame())
	}
	if dup {
		return
	}
	f, err := knx.ParseLData(r.CEMI)
	if err != nil || f.Code != knx.LDataReq || c.layer == knx.LayerBusmonitor {
		return // a busmonitor tunnel cannot send
	}
	// The frame "went out on the bus": what it does is recorded, then it is
	// confirmed to the sender and shown to busmonitor tunnels, then any
	// answer follows.
	con := f
	con.Code = knx.LDataCon
	con.Source = c.addr
	ind := f
	ind.Code, ind.Source = knx.LDataInd, c.addr
	var answer func()
	switch {
	case !f.GroupTarget || f.Dest == 0:
		answer = s.management(c, f)
	default:
		answer = s.group(c, f)
	}
	s.sendTo(c, con.Encode())
	s.busmonOnly(ind.Encode())
	if answer != nil {
		answer()
	}
}

// group handles a group frame from a tunnel and returns the answer to send
// after the confirmation, if any.
func (s *Server) group(c *channel, f knx.LData) func() {
	if s.ds != nil {
		f.Source = c.addr
		var err error
		if f, err = s.ds.Open(f); err != nil {
			s.mu.Lock()
			s.dsRefused++
			s.mu.Unlock()
			return nil
		}
	}
	switch f.APCI {
	case knx.GroupValueWrite:
		s.mu.Lock()
		s.objects[f.Group()] = append([]byte(nil), f.Value()...)
		s.short[f.Group()] = f.IsShort
		s.writes = append(s.writes, Write{GA: f.Group(), Data: append([]byte(nil), f.Value()...)})
		s.mu.Unlock()
	case knx.GroupValueRead:
		s.mu.Lock()
		s.reads = append(s.reads, f.Group())
		v, ok := s.objects[f.Group()]
		v = append([]byte(nil), v...)
		s.mu.Unlock()
		if ok {
			resp := knx.GroupFrame(knx.LDataInd, f.Group(), knx.GroupValueResponse, v, s.isShort(f.Group()))
			resp.Source = Device10
			return func() { s.sendTo(c, s.seal(resp).Encode()) }
		}
	}
	return nil
}

// busmonOnly sends a frame to the busmonitor tunnels only.
func (s *Server) busmonOnly(cemi []byte) {
	ts := uint16(time.Now().UnixMilli())
	for _, c := range s.chans() {
		if c.layer == knx.LayerBusmonitor {
			s.sendTo(c, busmon(cemi, ts))
		}
	}
}

// management answers connectionless device management addressed to the
// gateway: DeviceDescriptor_Read (type 0, the mask version),
// PropertyValue_Read of the device object (object 0: serial number PID
// 11, manufacturer PID 12, programming mode PID 54 as one octet) and, in
// programming mode, the broadcast IndividualAddress_Read. Other requests
// are recorded only.
func (s *Server) management(c *channel, f knx.LData) func() {
	s.mu.Lock()
	s.mgmt = append(s.mgmt, f)
	prog := s.progMode
	serial := s.desc.Device.Serial
	s.mu.Unlock()
	var out [][]byte
	send := func() {
		for _, b := range out {
			s.sendTo(c, b)
		}
	}
	reply := func(apci uint16, short byte, data []byte) {
		r := knx.IndividualFrame(knx.LDataInd, c.addr, apci, short, data)
		r.Source = Address
		out = append(out, r.Encode())
	}
	if f.GroupTarget { // broadcast
		if f.APCI == knx.IndividualAddressRead && prog {
			r := knx.GroupFrame(knx.LDataInd, 0, knx.IndividualAddressResponse, nil, true)
			r.Source = Address
			out = append(out, r.Encode())
		}
		return send
	}
	if knx.IndividualAddress(f.Dest) != Address || f.Control() {
		return send
	}
	switch f.APCI {
	case knx.DeviceDescriptorRead:
		if f.Short == 0 {
			reply(knx.DeviceDescriptorResponse, 0, []byte{byte(MaskVersion >> 8), byte(MaskVersion & 0xFF)})
		}
	case knx.PropertyValueRead:
		if len(f.Data) != 4 {
			return send
		}
		obj, pid, count, start := f.Data[0], f.Data[1], f.Data[2]>>4, uint16(f.Data[2]&0x0F)<<8|uint16(f.Data[3])
		var v []byte
		if obj == 0 && count == 1 && start == 1 {
			switch pid {
			case 11:
				v = serial[:]
			case 12:
				v = []byte{0x00, 0xC5}
			case 54:
				if prog {
					v = []byte{1}
				} else {
					v = []byte{0}
				}
			}
		}
		hdr := append([]byte(nil), f.Data...)
		if v == nil {
			hdr[2] &= 0x0F // count 0: the property cannot be read
		}
		reply(knx.PropertyValueResponse, 0, append(hdr, v...))
	}
	return send
}

// SetShort stores a 6-bit (DPT 1/2/3) group object.
func (s *Server) SetShort(ga knx.GroupAddress, v byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.objects[ga] = []byte{v & 0x3F}
	s.short[ga] = true
}

func (s *Server) isShort(ga knx.GroupAddress) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.short[ga]
}

func (s *Server) sendTo(c *channel, cemi []byte) {
	s.mu.Lock()
	cur, ok := s.channels[c.id]
	if !ok || cur != c {
		s.mu.Unlock()
		return
	}
	f := knx.TunnelRequest{Channel: c.id, Seq: c.txSeq, CEMI: cemi}.Frame()
	c.txSeq++
	s.mu.Unlock()
	c.data(f)
}
