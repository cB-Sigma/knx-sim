# knx-sim

A simulated KNXnet/IP gateway and router in Go, with KNX IP Secure and KNX Data Secure, for testing KNX clients without an installation.

[![Go Reference](https://pkg.go.dev/badge/github.com/cB-Sigma/knx-sim.svg)](https://pkg.go.dev/github.com/cB-Sigma/knx-sim) [![test](https://github.com/cB-Sigma/knx-sim/actions/workflows/test.yml/badge.svg)](https://github.com/cB-Sigma/knx-sim/actions/workflows/test.yml) [![Licence: Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](LICENSE) [![Go](https://img.shields.io/badge/go-1.24.0-00ADD8.svg)](go.mod)

The simulator answers search, extended search (with its search
parameter blocks) and description requests, accepts tunnels over UDP and
TCP, optionally inside KNX IP Secure sessions, on the link or busmonitor
layer, keeps group objects, answers group reads, puts other bus devices'
writes on the tunnels, can secure groups with KNX Data Secure, answers
device management (descriptor, properties, individual address in
programming mode), and has switches that make it fail (silence, dropped
acknowledgements, dropped streams, replayed and tampered secure
wrappers, ended sessions). A simulated KNX IP router routes plain or KNX
IP Secure, with Data Secure and flow control. It also writes ETS project
exports (plain, ETS 5 or ETS 6 protected) and signed ETS keyrings (with
Data Secure group keys and a backbone key) for a simulated installation.
It runs in-process or from the command line and is built on
[knx](https://github.com/cB-Sigma/knx). Written for SigmaM2M, a oneM2M
platform; it has no dependency on it.

## What is simulated

| Package | What it does |
|---|---|
| `sim` | `Start`, `StartWith(Options)`: the gateway on UDP and, with `TCP` or `Secure`, on TCP; group objects (`Set`, `SetShort`, `Get`), other bus devices (`Inject`, `InjectDuplicate`), what clients sent (`Writes`, `Reads`, `Connects`, `Channels`, `Sessions`, `Keepalives`, `Rejected`, `TCPAcks`), faults (`SetSilent`, `DropAcks`, `DropStreams`, `ReplayLast`, `InjectTampered`, `EndSessions`); ETS files (`ETSProject`, `ProjectXML`, `ETSKeyring`) |
| `sim` (v0.2.0) | `Options.DataSecure` (secured groups: sealed writes opened, refused ones counted in `DataSecureRefused`, reads and injected writes answered sealed), busmonitor tunnels (L_Busmon.ind of every frame), `Options.ProgrammingMode`, device management to the gateway (`Management`, `Address`, `MaskVersion`), search parameter blocks of the extended search; `StartRouter(RouterOptions)`: a KNX IP router (plain or `Secure`, `DataSecure`, `BusyAbove` for ROUTING_BUSY, `SendBusy`, `SendLostMessage`, `Writes`, `Reads`, `TimeKeeper`); keyrings with `SecureGroups`, `Senders` and `BackboneKey` |
| `cmd/knxsim` | Serves the gateway with a small demo installation (and with `-routing` a router), and writes a matching project export and keyring |

Not simulated: raw tunnels (refused), connection-oriented device
management sessions, KNX Data Secure with tool keys, multicast search, a
real gateway's limits and timing beyond four tunnels.

## Install

```
go get github.com/cB-Sigma/knx-sim@latest
```

Requires Go 1.24.0 or later. The command:

```
go install github.com/cB-Sigma/knx-sim/cmd/knxsim@latest
```

## Command line

```
knxsim -listen 127.0.0.1:3671
knxsim -listen 127.0.0.1:3671 -tcp 127.0.0.1:3671 -secure-password tunnel-pass \
    -project demo.knxproj -keyring demo.knxkeys
```

| Flag | Default | Meaning |
|---|---|---|
| `-listen` | `127.0.0.1:3671` | UDP address of the gateway |
| `-tcp` | | also serve KNXnet/IP over TCP on this address |
| `-secure-password` | | run KNX IP Secure on the TCP endpoint with this user password (implies `-tcp`) |
| `-secure-user` | `2` | tunnelling user ID of the secure tunnel |
| `-device-auth` | `gateway-auth` | device authentication code of the secure gateway |
| `-report` | `10s` | how often the temperature is reported (0: never) |
| `-project` | | write an ETS project export of the demo installation to this file |
| `-keyring` | | write an ETS keyring for the secure tunnel to this file |
| `-keyring-password` | `keyring-pass` | password of the keyring |
| `-routing` | | also act as a KNX IP router on this routing group, such as `224.0.23.12:3671` |
| `-routing-interface` | | network interface for `-routing` |
| `-busy-above` | `0` | send ROUTING_BUSY when more than this many indications arrive within 100ms (0: never) |
| `-programming-mode` | `false` | put the gateway in programming mode |

The demo installation: 1/2/3 temperature (9.001, reported every
`-report`), 1/1/7 light (1.001), 1/1/8 dimmer (5.001), 3/0/1 power
(14.056), 3/0/2 energy (13.010).

## In Go tests

From `Example`:

```go
gw, _ := sim.Start()
defer gw.Close()
temp, _ := knx.ParseGroupAddress("1/2/3")
v, _ := knx.DPT{Main: 9, Sub: 1}.Encode(21.5)
gw.Set(temp, v)
tn, err := knx.DialTunnel(ctx, gw.Addr(), knx.TunnelOptions{OnFrame: onFrame})
// a GroupValue_Read of 1/2/3 is answered with 21.5; gw.Writes() lists
// what the client wrote
```

## Demo values

Every password, key, serial number and address in this module is a
made-up demo value. Do not use them for real installations.

## Documentation

Reference: https://pkg.go.dev/github.com/cB-Sigma/knx-sim

## Testing

```
go vet ./...
go test -race ./...
```

The tests at the module root drive the knx client against the
simulator: tunnelling over UDP and TCP, repeats and duplicates, the
heartbeat, KNX IP Secure (handshake, wrong passwords, replayed and
tampered wrappers, keepalive, session end), KNX Data Secure, busmonitor
tunnels, device management, extended search parameters, the router
(plain and secure, flow control), and ETS import of the
generated files. Tests carry `// Covers: SIG-...` comments: requirement
IDs of the SigmaM2M project's compliance report, with no meaning outside
it. The simulator and the knx client are written by the same author from
the same descriptions, so these tests show the two agree; the interop
tests are the independent check.

`interop/` is a nested module with its own go.mod. It runs xknx 3.20.0
(MIT), Home Assistant's KNX library, and xknxproject 3.10.0
(GPL-2.0-only) in a container (`interop/xknx`) against the simulator. It
is skipped unless `SIGMA_KNX_INTEROP=1` is set and Docker is running:

```
cd interop && SIGMA_KNX_INTEROP=1 go test -v ./...
```

### Interop tested against

On 2026-10-11, Docker Desktop 29.4.3 on arm64, the simulator on the host
and xknx in a container (v0.1.0 unless marked):

- xknx 3.20.0's description request and extended search read the
  simulator's name, address, tunnelling over UDP and TCP.
- xknx tunnelled over UDP (route back, through NAT), over TCP and over
  KNX IP Secure (TCP) with a keyring the simulator wrote: it wrote 1/1/7
  and 1/1/8, read 1/2/3 (21.5 °C), and received two writes of another bus
  device; the simulator recorded the writes and the read, and no
  TUNNELLING_ACK over TCP. All passed.
- xknx read a generated keyring (signature, two tunnels, passwords,
  device authentication code, management password), and xknxproject
  3.10.0 read generated project exports (plain, ETS 5 and ETS 6
  protected) with the same group addresses, names and DPTs.
- Three defects in the simulator were found this way and fixed before
  the first release (see CHANGELOG.md), each with a regression test.
- xknx 3.20.0 with KNX Data Secure (v0.2.0): xknx read the group keys and
  senders of a keyring the simulator wrote and tunnelled over UDP to a
  simulator whose bus secures 1/1/7 and 1/2/3; the simulator opened
  xknx's sealed write, xknx opened the simulator's sealed answer to its
  read of 1/2/3, plain groups worked, and nothing was refused. Passed.
- The simulated router is built on the knx module's router, which was run
  against xknx 3.20.0 as a router (plain, KNX IP Secure, Data Secure; see
  the knx module); the router simulator itself was run only against the
  knx module.
- Not yet: a client other than xknx and knx, multicast search (the
  simulator answers search only on its unicast address).

## Related repositories

- [knx](https://github.com/cB-Sigma/knx): the KNXnet/IP client and ETS
  import.

## Status

v0.x. The API may change before v1.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md).

## Licence

Apache-2.0 (see [LICENSE](LICENSE)). Copyright 2026 Abhinav Gautam.
[NOTICE](NOTICE) names the trademarks used. KNX and ETS are trademarks of
the KNX Association; this project is not affiliated with or endorsed by
it.
