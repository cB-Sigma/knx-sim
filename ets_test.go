package knx_test

import (
	"archive/zip"
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/cB-Sigma/knx"
	knxsim "github.com/cB-Sigma/knx-sim/sim"
)

func etsRanges() []knxsim.ETSRange {
	return []knxsim.ETSRange{
		{Name: "Living Room", Groups: []knxsim.ETSGroup{
			{Address: "1/2/3", Name: "Temperature", DPT: "DPST-9-1", Read: "Enabled", Write: "Disabled"},
			{Address: "1/1/7", Name: "Ceiling light", DPT: "DPST-1-1", Write: "Enabled"},
			{Address: "1/1/8", Name: "Ceiling light dim", DPT: "DPST-5-1"},
			{Address: "1/1/9", Name: "Scene", DPT: ""},
		}},
		{Name: "Meter", Groups: []knxsim.ETSGroup{
			{Address: "3/0/1", Name: "Power", DPT: "DPST-14-56"},
			{Address: "3/0/2", Name: "Power", DPT: "DPT-13"},
		}},
	}
}

// An ETS project export becomes points: unprotected, ETS 5 password
// protection (ZipCrypto) and ETS 6 protection (WinZip AES with the derived
// password) all read; devices come from the group ranges, writability from
// the linked group objects' flags (else from the datapoint type), and a
// group address without a datapoint type is left out. A wrong password is
// told apart from a damaged file.
// Covers: SIG-IMP-199
func TestETSProjectImport(t *testing.T) {
	for _, tc := range []struct {
		name string
		o    knxsim.ETSProjectOptions
	}{
		{"plain", knxsim.ETSProjectOptions{Name: "Home"}},
		{"ets5 protected", knxsim.ETSProjectOptions{Name: "Home", Password: "geheim"}},
		{"ets6 protected", knxsim.ETSProjectOptions{Name: "Home", Password: "geheim", ETS6: true, LinksAttr: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.o.Ranges = etsRanges()
			raw := knxsim.ETSProject(tc.o)
			p, err := knx.ParseETSProject(raw, tc.o.Password)
			if err != nil {
				t.Fatal(err)
			}
			if p.Name != "Home" || len(p.GroupAddresses) != 6 {
				t.Fatalf("project %q with %d addresses", p.Name, len(p.GroupAddresses))
			}
			pts, noDPT := knx.ETSPoints(p, []knx.ETSPoint{{Name: "power", GroupAddress: "3/0/1", DPT: "14.056"}}, "bus")
			if len(noDPT) != 1 || noDPT[0] != "1/1/9" {
				t.Errorf("without DPT = %v", noDPT)
			}
			got := map[string]knx.ETSPoint{}
			for _, ps := range pts {
				got[ps.GroupAddress] = ps
			}
			if len(got) != 4 {
				t.Fatalf("points = %+v", pts)
			}
			if ps := got["1/2/3"]; ps.Name != "temperature" || ps.Device != "living-room" || ps.DPT != "9.001" || ps.Writable || !ps.ReadOnStart {
				t.Errorf("temperature = %+v", ps)
			}
			if ps := got["1/1/7"]; ps.Name != "ceiling-light" || !ps.Writable || ps.DPT != "1.001" {
				t.Errorf("light = %+v", ps)
			}
			if ps := got["1/1/8"]; !ps.Writable { // no flags: 5.001 is an actuator type
				t.Errorf("dimmer = %+v", ps)
			}
			// 3/0/1 is configured already; 3/0/2's name "power" is taken.
			if ps := got["3/0/2"]; ps.Name != "power-3-0-2" || ps.Device != "meter" || ps.Writable {
				t.Errorf("energy = %+v", ps)
			}
			if tc.o.Password != "" {
				if _, err := knx.ParseETSProject(raw, ""); !errors.Is(err, knx.ErrProjectPassword) {
					t.Errorf("no password: %v", err)
				}
				if _, err := knx.ParseETSProject(raw, "wrong"); !errors.Is(err, knx.ErrZipPassword) {
					t.Errorf("wrong password: %v", err)
				}
			}
		})
	}
	// A bare 0.xml inline works too.
	p, err := knx.ParseETSProject(knxsim.ProjectXML(knxsim.ETSProjectOptions{Ranges: etsRanges()}), "")
	if err != nil || len(p.GroupAddresses) != 6 {
		t.Fatalf("inline 0.xml: %v", err)
	}
	if _, err := knx.ParseETSProject([]byte("PK\x03\x04garbage"), ""); err == nil {
		t.Error("garbage accepted")
	}
}

// An ETS keyring is checked against its password (signature) and
// decrypted; it gives the secure tunnel (user id, password, the gateway's
// device authentication code) by address, by user or the first. A wrong
// password and a tampered keyring are refused before anything is
// decrypted.
// Covers: SIG-IMP-200
func TestETSKeyring(t *testing.T) {
	kr := knxsim.ETSKeyring(knxsim.KeyringOptions{Project: "Home", Password: "keyring-pass", Host: "1.1.250",
		DeviceAuth: "gateway-auth", GroupKeys: 2, Tunnels: []knxsim.KeyringTunnel{
			{Address: "1.1.251", UserID: 2, Password: "tunnel-pass"},
			{Address: "1.1.252", UserID: 3, Password: "other-pass"}}})
	k, err := knx.ParseKeyring(kr, "keyring-pass")
	if err != nil {
		t.Fatal(err)
	}
	if k.Project != "Home" || len(k.Interfaces) != 2 || k.GroupKeys != 2 || len(k.Devices) != 1 || k.Devices[0].ManagementPassword != "mgmt" {
		t.Fatalf("keyring = %+v", k)
	}
	in, auth, err := k.Tunnel("", 0)
	if err != nil || in.UserID != 2 || in.Password != "tunnel-pass" || auth != "gateway-auth" {
		t.Errorf("first tunnel = %+v %q %v", in, auth, err)
	}
	// Like ETS, the simulator writes the host's device authentication code
	// on the interfaces too; xknx reads it from there (a placeholder there
	// failed xknx's secure session set-up, interop 2026-10-11).
	for _, in := range k.Interfaces {
		if in.Authentication != "gateway-auth" {
			t.Errorf("interface %s authentication %q, want the host's", in.IndividualAddress, in.Authentication)
		}
	}
	if in, _, _ := k.Tunnel("1.1.252", 0); in.UserID != 3 || in.Password != "other-pass" {
		t.Errorf("tunnel by address = %+v", in)
	}
	if in, _, _ := k.Tunnel("", 3); in.IndividualAddress != "1.1.252" {
		t.Errorf("tunnel by user = %+v", in)
	}
	if _, err := knx.ParseKeyring(kr, "nope"); !errors.Is(err, knx.ErrKeyringPassword) {
		t.Errorf("wrong password: %v", err)
	}
	tampered := bytes.Replace(kr, []byte(`UserID="3"`), []byte(`UserID="4"`), 1)
	if _, err := knx.ParseKeyring(tampered, "keyring-pass"); !errors.Is(err, knx.ErrKeyringPassword) {
		t.Errorf("tampered keyring: %v", err)
	}
	if _, err := knx.ParseKeyring(kr, ""); err == nil {
		t.Error("a keyring without its password was read")
	}
}

// The simulated exports have the parts other readers rely on (found when
// xknxproject 3.10.0 could not read them, interop 2026-10-11): the master
// data's namespace says ETS 5 (schema 20) or ETS 6 (21), and every group
// range has RangeStart and RangeEnd.
func TestETSProjectShape(t *testing.T) {
	for _, ets6 := range []bool{false, true} {
		raw := knxsim.ETSProject(knxsim.ETSProjectOptions{Name: "Home", ETS6: ets6, Ranges: etsRanges()})
		zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
		if err != nil {
			t.Fatal(err)
		}
		files := map[string][]byte{}
		for _, f := range zr.File {
			rc, _ := f.Open()
			files[f.Name], _ = io.ReadAll(rc)
			rc.Close()
		}
		want := []byte("project/20")
		if ets6 {
			want = []byte("project/21")
		}
		if !bytes.Contains(files["knx_master.xml"], want) {
			t.Errorf("ETS6=%v: knx_master.xml %s", ets6, files["knx_master.xml"])
		}
		x := files["P-0A1B/0.xml"]
		if n, m := bytes.Count(x, []byte("<GroupRange ")), bytes.Count(x, []byte("RangeStart=")); n == 0 || n != m {
			t.Errorf("ETS6=%v: %d group ranges, %d with RangeStart", ets6, n, m)
		}
		if !bytes.Contains(x, []byte(`RangeStart="2304" RangeEnd="2815" Name="Living Room"`)) {
			t.Errorf("ETS6=%v: living room range:\n%s", ets6, x)
		}
	}
}
