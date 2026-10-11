# Provenance

## How the code was written

Written for SigmaM2M, a oneM2M platform, in Go, by the author of the knx
module and from the same descriptions (see that module's PROVENANCE.md).
No code was ported or copied from another implementation. The simulated
gateway was first written next to SigmaM2M's KNX integration to test it
without an installation; the KNX IP Secure gateway and the ETS file
generators were added on 2026-10-05. The simulator, its command and the
tests that drive it moved out of the knx module into this one on
2026-10-11 (with `git mv`), so the library does not depend on its
simulator.

On 2026-10-11, before the first release, xknx 3.20.0 and xknxproject
3.10.0 were run against the simulator (interop/). Three things they
needed were added or fixed: the extended search answer, the device
authentication code on keyring interfaces, and the schema version and
group range bounds of project exports (CHANGELOG.md). What the extended
search answer and the files must contain was read from the behaviour and
public APIs of xknx and xknxproject and from ETS keyrings and projects in
their test suites; no code was taken from them.

## Sources

| Area (files) | Followed |
|---|---|
| Gateway (sim/sim.go) | KNX Standard v2.1 volume 3 part 8 (KNXnet/IP core, core v2 over TCP, tunnelling, KNXnet/IP Secure), as the knx module reads it; it reuses that module's frames and secure primitives |
| ETS files (sim/ets.go) | the ETS project and keyring layouts as the knx module reads them; the zip encryption of the knx module (PKWARE APPNOTE 6.1, WinZip AES) |
| Command (cmd/knxsim) | none (flags are our own) |
| Interop peers (interop/) | xknx's and xknxproject's public APIs, read to write interop/xknx/client.py |

No specification text is reproduced; comments cite volume, part and
chapter numbers in our own words.

## Tests

| Test | Source |
|---|---|
| tunnel_test.go, link_test.go, ets_test.go, example_test.go, sim/sim_test.go, cmd/knxsim/main_test.go | the knx client against this simulator, written from the same descriptions; not a real gateway |
| interop/xknx_test.go | xknx 3.20.0 and xknxproject 3.10.0 as independent client and reader |

All passwords, keys and addresses are made-up demo values.
