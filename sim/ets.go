package sim

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"crypto/rand"
	"fmt"
	"hash/crc32"
	"html"
	"sort"
	"strings"

	"github.com/cB-Sigma/knx"
)

// ETS exports shaped like the files ETS writes, for import tests.

// ETSGroup is one group address of a simulated project.
type ETSGroup struct {
	Address string // three-level, such as 1/2/3
	Name    string
	DPT     string // as ETS writes it: DPST-9-1 or DPT-1; empty for none
	// Read and Write set a linked group object's flags ("" leaves the
	// flag out, as when the application program's default applies).
	Read, Write string
}

// ETSRange is a middle group range of a simulated project.
type ETSRange struct {
	Name   string
	Groups []ETSGroup
}

// ETSProjectOptions shape a simulated project export.
type ETSProjectOptions struct {
	ID     string // project id, default P-0A1B
	Name   string
	Ranges []ETSRange
	// Password protects the export: ETS6 (AES) when ETS6, else ETS 5
	// (ZipCrypto).
	Password string
	ETS6     bool
	// LinksAttr writes group object links as an ETS 6 Links attribute
	// instead of Connectors/Send elements.
	LinksAttr bool
}

// ProjectXML returns a 0.xml for the options.
func ProjectXML(o ETSProjectOptions) []byte {
	id := o.ID
	if id == "" {
		id = "P-0A1B"
	}
	ns := "http://knx.org/xml/project/20"
	if o.ETS6 {
		ns = "http://knx.org/xml/project/21"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<KNX xmlns=\"%s\" CreatedBy=\"ETS6\" ToolVersion=\"6.1.0\">\n", ns)
	fmt.Fprintf(&b, "  <Project Id=\"%s\">\n    <Installations>\n      <Installation Name=\"%s\" InstallationId=\"0\">\n", id, html.EscapeString(o.Name))
	b.WriteString("        <Topology>\n          <Area Id=\"" + id + "-0_A-1\" Address=\"1\" Name=\"Area\">\n            <Line Id=\"" + id + "-0_L-1\" Address=\"1\" Name=\"Line\">\n")
	b.WriteString("              <DeviceInstance Id=\"" + id + "-0_DI-1\" Address=\"10\" Name=\"Actuator\">\n                <ComObjectInstanceRefs>\n")
	n := 0
	for _, r := range o.Ranges {
		for _, g := range r.Groups {
			n++
			if g.Read == "" && g.Write == "" {
				continue
			}
			flags := ""
			if g.Read != "" {
				flags += fmt.Sprintf(" ReadFlag=\"%s\"", g.Read)
			}
			if g.Write != "" {
				flags += fmt.Sprintf(" WriteFlag=\"%s\"", g.Write)
			}
			if o.LinksAttr {
				fmt.Fprintf(&b, "                  <ComObjectInstanceRef RefId=\"O-%d_R-%d\"%s Links=\"GA-%d\" />\n", n, n, flags, n)
			} else {
				fmt.Fprintf(&b, "                  <ComObjectInstanceRef RefId=\"O-%d_R-%d\"%s>\n                    <Connectors><Send GroupAddressRefId=\"%s-0_GA-%d\" /></Connectors>\n                  </ComObjectInstanceRef>\n", n, n, flags, id, n)
			}
		}
	}
	b.WriteString("                </ComObjectInstanceRefs>\n              </DeviceInstance>\n            </Line>\n          </Area>\n        </Topology>\n")
	b.WriteString("        <GroupAddresses>\n          <GroupRanges>\n            <GroupRange Id=\"" + id + "-0_GR-1\" RangeStart=\"0\" RangeEnd=\"32767\" Name=\"Building\">\n")
	n = 0
	for i, r := range o.Ranges {
		// A middle range spans whole middle groups around its addresses,
		// as ETS writes RangeStart and RangeEnd on every range.
		lo, hi := knx.GroupAddress(0xFFFF), knx.GroupAddress(0)
		for _, g := range r.Groups {
			if a, err := knx.ParseGroupAddress(g.Address); err == nil {
				lo, hi = min(lo, a), max(hi, a)
			}
		}
		if lo > hi {
			lo, hi = 0, 0
		}
		fmt.Fprintf(&b, "              <GroupRange Id=\"%s-0_GR-%d\" RangeStart=\"%d\" RangeEnd=\"%d\" Name=\"%s\">\n", id, i+2, lo&^0xFF, hi|0xFF, html.EscapeString(r.Name))
		for _, g := range r.Groups {
			n++
			a, err := knx.ParseGroupAddress(g.Address)
			if err != nil {
				panic(err)
			}
			dpt := ""
			if g.DPT != "" {
				dpt = fmt.Sprintf(" DatapointType=\"%s\"", g.DPT)
			}
			fmt.Fprintf(&b, "                <GroupAddress Id=\"%s-0_GA-%d\" Address=\"%d\" Name=\"%s\"%s />\n", id, n, a, html.EscapeString(g.Name), dpt)
		}
		b.WriteString("              </GroupRange>\n")
	}
	b.WriteString("            </GroupRange>\n          </GroupRanges>\n        </GroupAddresses>\n      </Installation>\n    </Installations>\n  </Project>\n</KNX>\n")
	return []byte(b.String())
}

func deflate(b []byte) []byte {
	var out bytes.Buffer
	w, _ := flate.NewWriter(&out, flate.DefaultCompression)
	w.Write(b)
	w.Close()
	return out.Bytes()
}

// ETSProject builds a .knxproj export for the options.
func ETSProject(o ETSProjectOptions) []byte {
	id := o.ID
	if id == "" {
		id = "P-0A1B"
	}
	x := ProjectXML(o)
	meta := []byte(fmt.Sprintf("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<KNX><Project Id=\"%s\"><ProjectInformation Name=\"%s\" GroupAddressStyle=\"ThreeLevel\" /></Project></KNX>\n", id, html.EscapeString(o.Name)))
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	put := func(w *zip.Writer, name string, data []byte) {
		f, _ := w.Create(name)
		f.Write(data)
	}
	// The master data's namespace carries the schema version (20 for ETS 5,
	// 21 for ETS 6), from which readers such as xknxproject tell how the
	// project zip password is formed.
	ns := "http://knx.org/xml/project/20"
	if o.ETS6 {
		ns = "http://knx.org/xml/project/21"
	}
	put(zw, "knx_master.xml", []byte("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<KNX xmlns=\""+ns+"\"><MasterData /></KNX>\n"))
	put(zw, id+".signature", []byte("signature"))
	if o.Password == "" {
		put(zw, id+"/0.xml", x)
		put(zw, id+"/project.xml", meta)
	} else {
		var inner bytes.Buffer
		iz := zip.NewWriter(&inner)
		for _, e := range []struct {
			name string
			data []byte
		}{{"0.xml", x}, {"project.xml", meta}} {
			comp := deflate(e.data)
			crc := crc32.ChecksumIEEE(e.data)
			fh := &zip.FileHeader{Name: e.name, UncompressedSize64: uint64(len(e.data))}
			var body []byte
			if o.ETS6 {
				salt := make([]byte, 16)
				rand.Read(salt)
				var err error
				body, fh.Extra, err = knx.WinZipAESEncrypt(comp, knx.ETSZipPassword(o.Password), salt, zip.Deflate)
				if err != nil {
					panic(err)
				}
				fh.Method = 99
				fh.Flags = 1 // AE-2: no CRC
			} else {
				hdr := make([]byte, 11)
				rand.Read(hdr)
				body = knx.ZipCryptoEncrypt(comp, []byte(o.Password), hdr, byte(crc>>24))
				fh.Method = zip.Deflate
				fh.Flags = 1
				fh.CRC32 = crc
			}
			fh.CompressedSize64 = uint64(len(body))
			w, err := iz.CreateRaw(fh)
			if err != nil {
				panic(err)
			}
			w.Write(body)
		}
		iz.Close()
		put(zw, id+".zip", inner.Bytes())
	}
	zw.Close()
	return buf.Bytes()
}

// KeyringTunnel is one secure tunnel of a simulated keyring.
type KeyringTunnel struct {
	Address  string // individual address of the tunnel, such as 1.1.251
	UserID   int
	Password string
}

// KeyringOptions shape a simulated keyring export.
type KeyringOptions struct {
	Project    string
	Password   string // the keyring password
	Host       string // the IP interface's individual address
	DeviceAuth string // its device authentication code
	Tunnels    []KeyringTunnel
	GroupKeys  int // KNX Data Secure group keys to list (all-zero demo keys)
	// SecureGroups are KNX Data Secure groups with their real keys (group
	// address such as "1/1/7" → 16-byte key), listed for every tunnel
	// with Senders as the addresses that send to them.
	SecureGroups map[string][]byte
	Senders      []string
	// BackboneKey adds a secure routing backbone (multicast 224.0.23.12,
	// latency 1000ms) with this 16-byte key.
	BackboneKey []byte
}

// ETSKeyring builds a signed .knxkeys export.
func ETSKeyring(o KeyringOptions) []byte {
	created := "2026-10-05T09:30:00"
	seal := func(v string) string {
		var f [8]byte
		rand.Read(f[:])
		return knx.SealKeyringPassword(o.Password, created, v, f)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<Keyring Project=\"%s\" CreatedBy=\"ETS 6.1.0\" Created=\"%s\" Signature=\"SIG\" xmlns=\"http://knx.org/xml/keyring/1\">\n", html.EscapeString(o.Project), created)
	// ETS writes the host's device authentication code on each of its
	// tunnelling interfaces too (as the ETS keyrings in xknx's test suite
	// show), and clients such as xknx take it from the interface.
	if o.BackboneKey != nil {
		fmt.Fprintf(&b, "  <Backbone MulticastAddress=\"224.0.23.12\" Latency=\"1000\" Key=\"%s\" />\n", knx.SealKeyringKey(o.Password, created, o.BackboneKey))
	}
	var gas []string
	for g := range o.SecureGroups {
		gas = append(gas, g)
	}
	sort.Strings(gas)
	raw := func(g string) int {
		a, err := knx.ParseGroupAddress(g)
		if err != nil {
			panic(err)
		}
		return int(a)
	}
	for _, t := range o.Tunnels {
		fmt.Fprintf(&b, "  <Interface Type=\"Tunneling\" Host=\"%s\" IndividualAddress=\"%s\" UserID=\"%d\" Password=\"%s\" Authentication=\"%s\"",
			o.Host, t.Address, t.UserID, seal(t.Password), seal(o.DeviceAuth))
		if len(gas) == 0 {
			b.WriteString(" />\n")
			continue
		}
		b.WriteString(">\n")
		for _, g := range gas {
			fmt.Fprintf(&b, "    <Group Address=\"%d\" Senders=\"%s\" />\n", raw(g), strings.Join(o.Senders, " "))
		}
		b.WriteString("  </Interface>\n")
	}
	if o.GroupKeys > 0 || len(gas) > 0 {
		b.WriteString("  <GroupAddresses>\n")
		for i := range o.GroupKeys {
			fmt.Fprintf(&b, "    <Group Address=\"%d\" Key=\"AAAAAAAAAAAAAAAAAAAAAA==\" />\n", 2048+i)
		}
		for _, g := range gas {
			fmt.Fprintf(&b, "    <Group Address=\"%d\" Key=\"%s\" />\n", raw(g), knx.SealKeyringKey(o.Password, created, o.SecureGroups[g]))
		}
		b.WriteString("  </GroupAddresses>\n")
	}
	fmt.Fprintf(&b, "  <Devices>\n    <Device IndividualAddress=\"%s\" SerialNumber=\"00C501020304\" Authentication=\"%s\" ManagementPassword=\"%s\" />\n  </Devices>\n</Keyring>\n",
		o.Host, seal(o.DeviceAuth), seal("mgmt"))
	doc := b.String()
	sig, err := knx.SignKeyring([]byte(doc), o.Password)
	if err != nil {
		panic(err)
	}
	return []byte(strings.Replace(doc, `Signature="SIG"`, `Signature="`+sig+`"`, 1))
}
