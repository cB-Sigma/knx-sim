# Changelog

## v0.2.0 (2026-10-11)

Added, on knx v0.2.0:

- KNX Data Secure on the simulated bus (`Options.DataSecure`,
  `DataSecureRefused`), tested with xknx 3.20.0.
- Busmonitor tunnels: every frame on the bus as L_Busmon.ind with a TP1
  frame and check octet; raw tunnels are refused with the tunnelling
  layer status.
- Device management to the gateway: DeviceDescriptor_Read,
  PropertyValue_Read of the device object, IndividualAddress_Read in
  programming mode (`Options.ProgrammingMode`, `Management`).
- The extended search evaluates mandatory search parameter blocks.
- `StartRouter`: a simulated KNX IP router, plain or KNX IP Secure, with
  Data Secure and ROUTING_BUSY when flooded (`BusyAbove`).
- Keyrings with Data Secure group keys and senders (`SecureGroups`,
  `Senders`) and a backbone key (`BackboneKey`).
- `cmd/knxsim`: `-routing`, `-routing-interface`, `-busy-above`,
  `-programming-mode`.

Changed:

- A tunnel's frame is recorded (`Writes`, `Reads`, `Management`) before
  its L_Data.con is sent, so a client that has its confirmation can rely
  on the record; answers still follow the confirmation.
- Frames to individual addresses are now handled as device management
  (they were ignored).

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
