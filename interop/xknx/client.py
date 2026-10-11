# Copyright 2026 Abhinav Gautam
# SPDX-License-Identifier: Apache-2.0
"""An xknx client for the interop tests of knx-sim: it tunnels to a
gateway, switches 1/1/7 on, reads 1/2/3, waits for writes from other bus
devices, and prints one line per event:

    CONNECTED <tunnel address>
    READ <group address> <hex value>
    TELEGRAM <group address> <service> <hex value>
    DONE

    client.py udp|tcp HOST PORT
    client.py secure HOST PORT USER_ID KEYRING_PASSWORD   (keyring on stdin)
    client.py datasecure HOST PORT KEYRING_PASSWORD      (UDP, Data Secure; keyring on stdin)
    client.py search HOST PORT                            (unicast description)
"""

import asyncio
import os
import sys
import tempfile

from xknx import XKNX
from xknx.core.value_reader import ValueReader
from xknx.dpt import DPTArray, DPTBinary
from xknx.io import ConnectionConfig, ConnectionType, SecureConfig
from xknx.telegram import GroupAddress, Telegram
from xknx.telegram.apci import GroupValueWrite


def say(*parts):
    print(*parts, flush=True)


def hexval(payload):
    v = getattr(payload, "value", None)
    if isinstance(v, DPTBinary):
        return "%02x" % v.value
    if isinstance(v, DPTArray):
        return bytes(v.value).hex()
    return ""


async def tunnel(kind, host, port, user_id=None, keyring_password=None):
    if kind == "udp":
        cfg = ConnectionConfig(connection_type=ConnectionType.TUNNELING, gateway_ip=host, gateway_port=port,
                               route_back=True, auto_reconnect=False)
    elif kind == "tcp":
        cfg = ConnectionConfig(connection_type=ConnectionType.TUNNELING_TCP, gateway_ip=host, gateway_port=port,
                               auto_reconnect=False)
    elif kind == "datasecure":
        # A plain UDP tunnel; KNX Data Secure from the keyring on stdin.
        fd, path = tempfile.mkstemp(suffix=".knxkeys")
        with os.fdopen(fd, "wb") as f:
            f.write(sys.stdin.buffer.read())
        cfg = ConnectionConfig(connection_type=ConnectionType.TUNNELING, gateway_ip=host, gateway_port=port,
                               route_back=True, auto_reconnect=False,
                               secure_config=SecureConfig(knxkeys_file_path=path, knxkeys_password=keyring_password))
    else:
        fd, path = tempfile.mkstemp(suffix=".knxkeys")
        with os.fdopen(fd, "wb") as f:
            f.write(sys.stdin.buffer.read())
        cfg = ConnectionConfig(connection_type=ConnectionType.TUNNELING_TCP_SECURE, gateway_ip=host, gateway_port=port,
                               auto_reconnect=False,
                               secure_config=SecureConfig(user_id=user_id, knxkeys_file_path=path,
                                                          knxkeys_password=keyring_password))

    def received(t):
        say("TELEGRAM", t.destination_address, type(t.payload).__name__, hexval(t.payload))

    xknx = XKNX(connection_config=cfg, telegram_received_cb=received)
    await xknx.start()
    say("CONNECTED", xknx.current_address)
    await xknx.telegrams.put(Telegram(destination_address=GroupAddress("1/1/7"), payload=GroupValueWrite(DPTBinary(1))))
    await xknx.telegrams.put(Telegram(destination_address=GroupAddress("1/1/8"), payload=GroupValueWrite(DPTArray((0x80,)))))
    reply = await ValueReader(xknx, GroupAddress("1/2/3"), timeout_in_seconds=5).read()
    say("READ", "1/2/3", hexval(reply.payload) if reply else "none")
    await asyncio.sleep(3)
    await xknx.stop()
    say("DONE")


async def search(host, port):
    from xknx.io.self_description import request_description

    d = await request_description(gateway_ip=host, gateway_port=port)
    say("GATEWAY", d.name, d.individual_address, "tunnelling" if d.supports_tunnelling else "-",
        "tcp" if d.supports_tunnelling_tcp else "-", "secure" if d.tunnelling_requires_secure else "-")
    say("DONE")


def keyring(password):
    from xknx.secure.keyring import sync_load_keyring

    fd, path = tempfile.mkstemp(suffix=".knxkeys")
    with os.fdopen(fd, "wb") as f:
        f.write(sys.stdin.buffer.read())
    k = sync_load_keyring(path, password)
    say("PROJECT", k.project_name)
    for i in k.interfaces:
        dev = k.get_device_by_interface(i)
        say("INTERFACE", i.individual_address, i.host, i.user_id, i.decrypted_password,
            i.decrypted_authentication, dev.decrypted_authentication if dev else None)
    for d in k.devices:
        say("DEVICE", d.individual_address, d.decrypted_authentication, d.decrypted_management_password)
    say("DONE")


def project(password):
    from xknxproject import XKNXProj

    fd, path = tempfile.mkstemp(suffix=".knxproj")
    with os.fdopen(fd, "wb") as f:
        f.write(sys.stdin.buffer.read())
    p = XKNXProj(path, None if password == "-" else password).parse()
    say("PROJECT", p["info"]["name"])
    for ga in p["group_addresses"].values():
        dpt = ga.get("dpt") or {}
        say("GA", ga["address"], "%s.%s" % (dpt.get("main"), dpt.get("sub")), ga["name"])
    say("DONE")


def main():
    if sys.argv[1] == "keyring":
        keyring(sys.argv[2])
        return
    if sys.argv[1] == "project":
        project(sys.argv[2])
        return
    kind, host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
    if kind == "search":
        asyncio.run(search(host, port))
    elif kind == "secure":
        asyncio.run(tunnel(kind, host, port, int(sys.argv[4]), sys.argv[5]))
    elif kind == "datasecure":
        asyncio.run(tunnel(kind, host, port, None, sys.argv[4]))
    else:
        asyncio.run(tunnel(kind, host, port))


if __name__ == "__main__":
    main()
