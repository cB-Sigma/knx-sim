# Changelog

## v0.1.0 (2026-10-11)

First published release: a simulated KNXnet/IP gateway (UDP, TCP, KNX IP
Secure) with fault switches, ETS project and keyring generators, and
`cmd/knxsim`.

Changes made while testing it with xknx 3.20.0 before the first release:

- The gateway answers SEARCH_REQUEST_EXTENDED with the tunnelling
  information DIB and, when secure, the secured service families DIB;
  xknx asks for both before a secure tunnel.
- Generated keyrings carry the host's device authentication code on each
  tunnelling interface, as ETS writes it (they carried a placeholder,
  which made xknx's secure session fail).
- Generated project exports name schema 20 (ETS 5) or 21 (ETS 6) in
  knx_master.xml, and every group range has RangeStart and RangeEnd, so
  xknxproject reads them.
