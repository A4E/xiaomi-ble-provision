#!/usr/bin/env python3
"""Provision Wi-Fi on Xiaomi "combo" (Wi-Fi + BLE) devices over Bluetooth LE, without the Mi Home / Xiaomi Home app.

Some newer Xiaomi Wi-Fi devices (BL602 / ESP32 modules, advertised as "MIBLE_*") no longer open a setup access
point after a Wi-Fi reset: they can only be configured over Bluetooth, by the app. This tool speaks the same
"standard auth" + Wi-Fi configuration protocol from a computer.

  python xiaomi_ble_provision.py scan
  python xiaomi_ble_provision.py provision --ssid MyIoT --uid 1234567890 --region us [--mac AA:BB:..] [--address ...]
  python xiaomi_ble_provision.py selftest          # offline check of the crypto / framing, no Bluetooth

See README.md for the protocol, the findings and the caveats (the device token is NOT delivered over BLE).
"""
import argparse
import asyncio
import getpass
import locale
import os
import socket
import struct
import sys
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

MI_SERVICE = "0000fe95-0000-1000-8000-00805f9b34fb"
U = lambda x: f"0000{x:04x}-0000-1000-8000-00805f9b34fb"
CH_STATUS, CH_CTRL, CH_AUTH = U(0x0005), U(0x0010), U(0x0019)

ACK_READY = bytes.fromhex("00000101")
ACK_OK = bytes.fromhex("00000100")
OP_DEV_INFO_GET = bytes.fromhex("a2000000")
OP_REG_START_WO_PKI = bytes.fromhex("15000000")
OP_REG_SUCCESS = bytes.fromhex("11000000")
PKG_PUBKEY = 0x03
PKG_WIFI_CONFIG = 0x0F
DMTU = 18

STATUS = {
    0: "waiting for configuration",
    1: "configuration accepted, connecting to the router",
    2: "connected to the router",
    3: "connected to the Xiaomi cloud",
    4: "error on the BLE side (decryption / format)",
    5: "router rejected the connection (wrong password / network not found)",
    16: "DHCP error", 17: "Wi-Fi authentication error", 18: "network not found", 19: "cannot reach the server",
}

# TLV types of the Wi-Fi configuration package (0x0F)
T_UID, T_SSID, T_PASSWD, T_GMT_OFFSET, T_COUNTRY_DOMAIN, T_TZ, T_CONFIG_TYPE, T_BIND_KEY, T_CC = 0, 1, 2, 5, 6, 7, 8, 9, 10


def log(msg):
    print(f"{time.strftime('%H:%M:%S')} {msg}", flush=True)


# ---------------------------------------------------------------------------------------------- protocol helpers

def frames(data, dmtu=DMTU):
    """Split a payload into numbered data frames: <seq u16 LE, 1-based><up to dmtu bytes>."""
    return [struct.pack("<H", i // dmtu + 1) + data[i:i + dmtu] for i in range(0, len(data), dmtu)]


def ctr(pkg_type, n_frames):
    """Control packet that announces a multi-frame transfer."""
    return bytes([0, 0, 0, pkg_type]) + struct.pack("<H", n_frames)


def tlv(t, value):
    if len(value) > 255:
        raise ValueError(f"TLV {t} too long")
    return bytes([t, len(value)]) + value


def derive_keys(shared_secret):
    """HKDF-SHA256(ECDH x, salt=None, info='mible-setup-info', 64 B); split used by combo devices."""
    k = HKDF(hashes.SHA256(), 64, None, b"mible-setup-info").derive(shared_secret)
    return {"dev_key": k[0:16], "app_key": k[16:32], "dev_iv": k[32:36], "app_iv": k[36:40]}


def region_bytes(region):
    region = region.lower()
    if region == "cn":
        return b"\0\0\0"                                  # mainland China = empty domain
    return region.encode()[:3].ljust(3, b"\0")


def wifi_config_plaintext(ssid, password, uid, region, tz, gmt_offset, country=None, bind_key=None):
    pt = b""
    if uid is not None:
        pt += tlv(T_UID, struct.pack("<q", uid))
    pt += tlv(T_SSID, ssid.encode()) + tlv(T_PASSWD, password.encode())
    pt += tlv(T_GMT_OFFSET, struct.pack("<i", gmt_offset))
    pt += tlv(T_COUNTRY_DOMAIN, region_bytes(region)) + tlv(T_TZ, tz.encode()) + tlv(T_CONFIG_TYPE, b"app")
    if country:
        pt += tlv(T_CC, country.upper().encode())
    if bind_key:
        pt += tlv(T_BIND_KEY, bind_key.encode())
    return pt


def encrypt_wifi_config(keys, plaintext, counter=1):
    """message = counter u16 LE || AES-128-CCM(app_key, app_iv || 0000 || counter u32 LE, tag 4 B, no AAD)."""
    nonce = keys["app_iv"] + bytes(4) + struct.pack("<I", counter)
    return struct.pack("<H", counter) + AESCCM(keys["app_key"], tag_length=4).encrypt(nonce, plaintext, None)


def parse_mibeacon(sd):
    """Parse FE95 service data (MiBeacon). Returns a dict or None."""
    if len(sd) < 5:
        return None
    fc, pid, cnt = struct.unpack("<HHB", sd[:5])
    info = {"frame_control": fc, "product_id": pid, "counter": cnt, "encrypted": bool(fc & 0x08),
            "registered": bool(fc & 0x100), "auth_mode": (fc >> 10) & 3, "version": fc >> 12,
            "mac": None, "bond_ability": None}
    pos = 5
    if fc & 0x10 and len(sd) >= pos + 6:
        info["mac"] = ":".join(f"{b:02x}" for b in reversed(sd[pos:pos + 6]))
        pos += 6
    if fc & 0x20 and len(sd) > pos:
        cap = sd[pos]
        info["bond_ability"] = (cap >> 3) & 3              # 3 = combo (Wi-Fi + BLE)
        info["capability"] = cap
    return info


# ---------------------------------------------------------------------------------------------- BLE transport

class Link:
    def __init__(self, client, verbose=False):
        self.c, self.verbose = client, verbose
        self.auth, self.ctrl, self.status = asyncio.Queue(), asyncio.Queue(), []

    def _on_auth(self, _, d):
        d = bytes(d)
        if self.verbose:
            log(f"  0019 <- {d.hex()}")
        self.auth.put_nowait(d)

    def _on_ctrl(self, _, d):
        d = bytes(d)
        if self.verbose:
            log(f"  0010 <- {d.hex()}")
        self.ctrl.put_nowait(d)

    def _on_status(self, _, d):
        d = bytes(d)
        if d and (not self.status or self.status[-1] != d):
            log(f"status {d[0]}: {STATUS.get(d[0], 'unknown')}")
        self.status.append(d)

    async def start(self):
        await self.c.start_notify(CH_STATUS, self._on_status)
        await self.c.start_notify(CH_CTRL, self._on_ctrl)
        await self.c.start_notify(CH_AUTH, self._on_auth)
        await asyncio.sleep(0.5)

    async def write_auth(self, b):
        if self.verbose:
            log(f"  0019 -> {b.hex()}")
        await self.c.write_gatt_char(CH_AUTH, b, response=False)

    async def write_ctrl(self, b):
        if self.verbose:
            log(f"  0010 -> {b.hex()}")
        await self.c.write_gatt_char(CH_CTRL, b, response=False)

    async def get(self, timeout=10.0):
        return await asyncio.wait_for(self.auth.get(), timeout)

    async def recv_transfer(self, timeout=10.0):
        p = await self.get(timeout)
        if p[:3] == b"\0\0\x02":                           # SINGLE packet
            await self.write_auth(bytes.fromhex("00000300"))
            return p[3], p[4:]
        if p[:3] != b"\0\0\0" or len(p) < 6:
            raise RuntimeError(f"expected a transfer start, got {p.hex()}")
        typ, n = p[3], struct.unpack("<H", p[4:6])[0]
        await self.write_auth(ACK_READY)
        parts = {}
        while len(parts) < n:
            f = await self.get(timeout)
            seq = struct.unpack("<H", f[:2])[0]
            if seq:
                parts[seq] = f[2:]
        await self.write_auth(ACK_OK)
        return typ, b"".join(parts[i] for i in range(1, n + 1))

    async def send_transfer(self, typ, data, timeout=10.0):
        fr = frames(data)
        await self.write_auth(ctr(typ, len(fr)))
        a = await self.get(timeout)
        if a != ACK_READY:
            raise RuntimeError(f"device not ready for package {typ}: {a.hex()}")
        for f in fr:
            await self.write_auth(f)
            await asyncio.sleep(0.03)
        while True:
            a = await self.get(timeout)
            if a == ACK_OK:
                return
            if a[:4] == bytes.fromhex("00000105"):         # SYNC: resend listed frames
                for i in range(4, len(a) - 1, 2):
                    await self.write_auth(fr[struct.unpack("<H", a[i:i + 2])[0] - 1])
                    await asyncio.sleep(0.03)
                continue
            raise RuntimeError(f"package {typ} rejected: {a.hex()}")


# ---------------------------------------------------------------------------------------------- commands

async def scan(seconds=12.0, show_all=False):
    """Collect every advertisement (devices alternate packets, so the last one alone may lack FE95 data)."""
    from bleak import BleakScanner
    seen = {}

    def on_adv(dev, adv):
        sd = (adv.service_data or {}).get(MI_SERVICE)
        b = parse_mibeacon(bytes(sd)) if sd else None
        name = adv.local_name or dev.name
        prev = seen.get(dev.address)
        if b:
            seen[dev.address] = (name or (prev[0] if prev else "-"), adv.rssi, b)
        elif prev and name and prev[0] == "-":
            seen[dev.address] = (name, prev[1], prev[2])

    async with BleakScanner(detection_callback=on_adv):
        await asyncio.sleep(seconds)
    out = []
    for addr, (name, rssi, b) in seen.items():
        combo_setup = b["bond_ability"] == 3 and not b["registered"] and b["auth_mode"] == 2
        if combo_setup or show_all:
            out.append((addr, name, rssi, b, combo_setup))
    return out


async def provision(a):
    from bleak import BleakClient
    address = a.address
    if not address:
        cands = [c for c in await scan() if c[4] and (not a.mac or (c[3]["mac"] or "").lower() == a.mac.lower())]
        if len(cands) != 1:
            for addr, name, rssi, b, _ in cands:
                log(f"candidate: address={addr} name={name} mac={b['mac']} product_id={b['product_id']} rssi={rssi}")
            raise SystemExit("need exactly one device in setup mode: pass --mac or --address (see `scan`)")
        address = cands[0][0]
        log(f"device: {cands[0][1]} mac={cands[0][3]['mac']} product_id={cands[0][3]['product_id']}")

    password = a.password if a.password is not None else os.environ.get("WIFI_PASSWORD")
    if password is None:
        password = getpass.getpass(f"Wi-Fi password for {a.ssid!r}: ")

    async with BleakClient(address, timeout=25) as client:
        link = Link(client, a.verbose)
        await link.start()

        await link.write_ctrl(OP_DEV_INFO_GET)
        _, info = await link.recv_transfer()
        did = info[4:].rstrip(b"\0").decode(errors="replace")
        log(f"device id (DID): {did}")

        await link.write_ctrl(OP_REG_START_WO_PKI)
        priv = ec.generate_private_key(ec.SECP256R1())
        await link.send_transfer(PKG_PUBKEY, priv.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)[1:])
        typ, dev_pub = await link.recv_transfer()
        if typ != PKG_PUBKEY or len(dev_pub) != 64:
            raise RuntimeError(f"unexpected device key package: type {typ}, {len(dev_pub)} bytes")
        shared = priv.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + dev_pub))
        keys = derive_keys(shared)
        log("key exchange done")

        pt = wifi_config_plaintext(a.ssid, password, a.uid, a.region, a.tz, a.gmt_offset, a.country, a.bind_key)
        await link.send_transfer(PKG_WIFI_CONFIG, encrypt_wifi_config(keys, pt))
        log("Wi-Fi configuration accepted by the device, waiting for it to connect")
        try:
            r = await asyncio.wait_for(link.ctrl.get(), 5)
            if r == OP_REG_SUCCESS:
                log("device reports registration success")
        except asyncio.TimeoutError:
            pass
        deadline = time.time() + a.wait
        while time.time() < deadline:
            await asyncio.sleep(1)
            last = link.status[-1][0] if link.status else None
            if last == 3 or (last in (2,) and a.region.lower() == "zz"):
                break
            if last in (4, 5, 16, 17, 18, 19):
                raise SystemExit(f"device reported failure: {STATUS.get(last)}")
    if did.isdigit():
        ip = find_ip(int(did))
        log(f"device answers miIO hello at {ip}" if ip else "device not found by miIO hello yet (try again in a minute)")


def find_ip(did, seconds=15, broadcast="255.255.255.255"):
    """Broadcast a miIO hello and return the IP whose reply carries this device id."""
    hello = bytes.fromhex("21310020" + "ff" * 28)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.settimeout(0.5)
    end = time.time() + seconds
    while time.time() < end:
        s.sendto(hello, (broadcast, 54321))
        t = time.time() + 1
        while time.time() < t:
            try:
                d, (ip, _) = s.recvfrom(1024)
            except socket.timeout:
                continue
            if len(d) >= 32 and d[:2] == b"\x21\x31" and int.from_bytes(d[8:12], "big") == did:
                return ip
    return None


def selftest():
    """Offline round trip: build exactly what we send and decode it the way the device-side code does."""
    app, dev = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    raw = lambda k: k.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)[1:]
    load = lambda b: ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + b)
    s1, s2 = app.exchange(ec.ECDH(), load(raw(dev))), dev.exchange(ec.ECDH(), load(raw(app)))
    assert s1 == s2
    k = derive_keys(s1)
    assert k == {"dev_key": k["dev_key"], "app_key": k["app_key"], "dev_iv": k["dev_iv"], "app_iv": k["app_iv"]}
    assert HKDF(hashes.SHA256(), 64, bytes(16), b"mible-setup-info").derive(s1)[16:32] == k["app_key"]
    pt = wifi_config_plaintext("Net", "secret", 1234567890, "us", "Europe/Madrid", 3600, "ES")
    msg = encrypt_wifi_config(k, pt)
    counter = struct.unpack("<H", msg[:2])[0]
    nonce = k["app_iv"] + bytes(4) + struct.pack("<HH", counter, 0)
    dec = AESCCM(k["app_key"], tag_length=4).decrypt(nonce, msg[2:], None)
    fields, i = {}, 0
    while i < len(dec):
        fields[dec[i]] = dec[i + 2:i + 2 + dec[i + 1]]
        i += 2 + dec[i + 1]
    assert struct.unpack("<q", fields[T_UID])[0] == 1234567890 and fields[T_SSID] == b"Net"
    assert fields[T_COUNTRY_DOMAIN] == b"us\0" and struct.unpack("<i", fields[T_GMT_OFFSET])[0] == 3600
    assert [f[:2] for f in frames(bytes(40))] == [b"\x01\x00", b"\x02\x00", b"\x03\x00"]
    b = parse_mibeacon(bytes.fromhex("3058ea4300665544332211" + "1d" + "2211"))
    assert b["auth_mode"] == 2 and b["bond_ability"] == 3 and not b["registered"] and b["mac"] == "11:22:33:44:55:66"
    print("selftest OK")


def system_tz():
    try:
        p = os.path.realpath("/etc/localtime")
        if "zoneinfo/" in p:
            return p.split("zoneinfo/", 1)[1]
    except OSError:
        pass
    return "UTC"


def system_country():
    loc = (locale.getlocale()[0] or "") or os.environ.get("LANG", "")
    return loc.split(".")[0].split("_")[1].upper() if "_" in loc else None


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="list Xiaomi devices waiting for BLE setup")
    s.add_argument("--all", action="store_true", help="list every FE95 advertiser")
    s.add_argument("--seconds", type=float, default=12)
    pr = sub.add_parser("provision", help="send Wi-Fi settings to a device in setup mode")
    pr.add_argument("--ssid", required=True, help="2.4 GHz network name")
    pr.add_argument("--password", help="Wi-Fi password (default: $WIFI_PASSWORD or prompt)")
    pr.add_argument("--uid", type=int, required=True,
                    help="YOUR Xiaomi account id (numeric). The tested device ignores configs without it. "
                         "Never use someone else's id: the device binds to that account.")
    pr.add_argument("--region", required=True,
                    help="cloud region (country_domain): cn, de, us, ru, tw, sg, in, i2 ... "
                         "A non-existent one such as 'zz' keeps the device off the cloud (see README)")
    pr.add_argument("--tz", default=system_tz(), help="IANA time zone (default: system)")
    pr.add_argument("--gmt-offset", type=int, default=time.localtime().tm_gmtoff, help="seconds (default: system)")
    pr.add_argument("--country", default=system_country(), help="Wi-Fi country code, e.g. US (default: locale)")
    pr.add_argument("--bind-key", help="bind key issued by the Xiaomi cloud (optional)")
    pr.add_argument("--mac", help="BLE MAC from `scan`, to choose among several devices")
    pr.add_argument("--address", help="bleak address (CoreBluetooth UUID on macOS), skips the scan")
    pr.add_argument("--wait", type=int, default=60, help="seconds to watch the device status")
    pr.add_argument("-v", "--verbose", action="store_true", help="log raw BLE packets (never the plaintext)")
    sub.add_parser("selftest", help="offline protocol self-test")
    a = p.parse_args()

    if a.cmd == "selftest":
        selftest()
    elif a.cmd == "scan":
        rows = asyncio.run(scan(a.seconds, a.all))
        if not rows:
            print("no device in BLE setup mode found (reset its Wi-Fi first; keep it close)")
        for addr, name, rssi, b, combo in rows:
            print(f"{addr}  {name:14} mac={b['mac']} product_id={b['product_id']} rssi={rssi} "
                  f"auth_mode={b['auth_mode']} registered={b['registered']} {'<- combo, setup mode' if combo else ''}")
    else:
        asyncio.run(provision(a))


if __name__ == "__main__":
    sys.exit(main())
