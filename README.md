# xiaomi-ble-provision

Put a Xiaomi Wi-Fi device back on your Wi-Fi **over Bluetooth, from a computer, without the Mi Home / Xiaomi Home
app**.

Newer Xiaomi Wi-Fi devices with "combo" modules (Wi-Fi + BLE, e.g. Bouffalo BL602, advertised as `MIBLE_BL602`)
no longer open a `*_miap*` setup access point after a Wi-Fi reset. The only way to give them a network is the
app's Bluetooth flow, so `python-miio`'s `configure_wifi` (AP mode) cannot reach them. This tool speaks that
Bluetooth flow itself: Xiaomi "standard auth" key exchange, then the encrypted Wi-Fi configuration package.

## Status

| Device | Model | Module | BLE fw | Device fw | Result |
|---|---|---|---|---|---|
| Xiaomi Smart Dehumidifier Lite | `xiaomi.derh.lite` | BL602 | `3.6.5_0581` | `1.0.1` | works |

Only one device has been tested. Reports for other combo devices (bondAbility 3 / auth mode 2 in the MiBeacon
advertisement) are welcome.

## Usage

Requirements: Python 3.10+, `pip install bleak cryptography`, a Bluetooth adapter. Tested on macOS (CoreBluetooth);
bleak also supports Linux (BlueZ) and Windows.

1. Reset the device's Wi-Fi (for the dehumidifier: hold *Power* + *Mode* for 7 s until it beeps). Xiaomi devices
   stay in setup mode for about 30 minutes; a power cycle restarts that window.
2. Find it:
   ```
   python xiaomi_ble_provision.py scan
   ```
3. Provision it (the password is prompted for, or taken from `$WIFI_PASSWORD`):
   ```
   python xiaomi_ble_provision.py provision --ssid MyIoT --uid <your Xiaomi account id> --region us
   ```
   It prints the device id, the status reported by the device, and finally the IP that answers the miIO hello.

`python xiaomi_ble_provision.py selftest` checks the crypto and framing offline.

The same flow is proposed for python-miio as `miiocli ble provision`:
[rytilahti/python-miio#2102](https://github.com/rytilahti/python-miio/pull/2102).

## What we found on the real device

* **Your Xiaomi account id (`uid`) is mandatory.** Without it the device accepts and decrypts the configuration,
  reports registration success (`11 00 00 00`) and status 1 ("connecting"), and then never even tries to join the
  network. A random `bind_key` does not replace the uid. Never use someone else's id: the device binds itself to
  that account in the cloud.
* **Region.** With a real region (`us`) the status goes 1 → 3 (cloud connected) in about 16–18 s. A region that
  does not exist (`zz`, i.e. `zz.ot.io.mi.com` → NXDOMAIN, the trick from
  [miio-cloudfree](https://github.com/SahajJain01/miio-cloudfree)) is accepted too: the device joins Wi-Fi but
  never reaches the cloud.
* **The token is not available locally.** It is not sent over BLE, and the miIO hello reply carries `ff…ff` in the
  token field both after a cloud connection and with the dead region. So a device provisioned with `zz` is on your
  network but cannot be controlled. What worked for local control:
  1. provision with your uid and a real region;
  2. read the token once from the Xiaomi cloud (for example with
     [Xiaomi-cloud-tokens-extractor](https://github.com/PiotrMachowski/Xiaomi-cloud-tokens-extractor));
  3. block the device's internet access on your router.
  The token keeps working locally after the block (miIO `get_properties` / `set_properties`, e.g. with python-miio).
* The `a4` link negotiation step is not needed. Replying `13 00 00 00` to the device's `11 00 00 00` changes
  nothing.
* After provisioning the device stops advertising over BLE.

## Protocol

All integers are little-endian. GATT service `FE95`; the device exposes `0001`, `0002` (product id), `0004`
(BLE firmware version), `0005` (status, notify), `0010` (control point, write without response) and `0019`
(data channel, write without response).

**Framing on `0019`.** A packet whose first u16 is 0 is a control packet, otherwise it is a data frame and the u16
is its 1-based sequence number, followed by up to 18 bytes.

```
start transfer   00 00 00 <type> <frames u16>
ack              00 00 01 <status>          status 0 ok, 1 ready, 5 resend (followed by seq numbers)
single packet    00 00 02 <type> <payload>  answered with 00 00 03 00
data frame       <seq u16> <≤18 bytes>
```
Sender: start → wait `00 00 01 01` → frames → wait `00 00 01 00`. Receiver: the mirror image.

**Flow.**
1. `0010 ← a2 00 00 00` (device info). The device sends type 0: `01 00 00 00` + its DID as ASCII.
2. `0010 ← 15 00 00 00` (register without PKI).
3. Send our P-256 public key (X‖Y, 64 bytes) as type 3, then receive the device key as type 3.
4. `K = HKDF-SHA256(ECDH shared x, salt = none, info = "mible-setup-info", 64 bytes)`;
   for combo devices `app_key = K[16:32]`, `app_iv = K[36:40]` (`dev_key = K[0:16]`, `dev_iv = K[32:36]`).
5. Plaintext = TLV records `[type u8][len u8][value]`:
   `0` uid (int64), `1` ssid, `2` password, `5` gmt offset (int32, seconds), `6` country domain (3 bytes, e.g.
   `us\0`; mainland China = `00 00 00`), `7` time zone (IANA name), `8` config type `app`, `9` bind key (optional),
   `10` Wi-Fi country code (e.g. `US`).
6. Message = counter u16 (1) ‖ AES-128-CCM(app_key, nonce = app_iv ‖ `00 00 00 00` ‖ counter u32, 4-byte tag,
   no associated data). Send it as type `0x0F`.
7. The device answers `11 00 00 00` on `0010` and reports its state on `0005`: 0 waiting, 1 accepted / connecting,
   2 router connected, 3 cloud connected, 4 BLE-side error, 5 router refused (older firmware: 16 DHCP error,
   17 auth error, 18 network not found, 19 server unreachable).

The module then hands the same fields to its miIO client as `local.ble.config_router` — the BLE counterpart of
`miIO.config_router` used in AP mode.

## Sources and credits

The Wi-Fi step was reconstructed from public sources, then confirmed on the device:

* device side of the protocol: the `com.mijiasdk.bleserver` package (`BleComboStandardAuth`,
  `BleStandAuthGattCallback`) in [OpenMico/MicoLauncher](https://github.com/OpenMico/MicoLauncher), a decompiled
  Xiaomi speaker launcher that Mi Home provisions as a combo device; Mi Home's channel classes in the same tree;
* standard auth and framing: [dnandha/miauth](https://github.com/dnandha/miauth),
  [pvvx TelinkMiFlasher](https://github.com/pvvx/pvvx.github.io), dentra's
  [esphome-components](https://github.com/dentra/esphome-components) `miot_cwbs01` PoC;
* MiBeacon fields: MiEcosystem `mijia_ble_common`;
* Xiaomi IoT developer documentation on combo / BLE provisioning (iot.mi.com);
* the dead-region idea and the token re-keying observation:
  [SahajJain01/miio-cloudfree](https://github.com/SahajJain01/miio-cloudfree) and
  [python-miio#2094](https://github.com/rytilahti/python-miio/issues/2094).

No code from these projects is included.

## Disclaimer

For your own devices. Not affiliated with or endorsed by Xiaomi. The protocol may differ on other modules and
firmware versions.

## License

MIT, see `LICENSE`.
