# Omnipod 5 support: port plan

This branch (`omnipod-five-v2`) adds an Omnipod 5 (O5) mode to the pod simulator,
selected with `-mode o5` (default `-mode dash`). It is a re-port of the old `five`
branch onto the current LoopKit/pod `main`, with
[loopandlearn/OmnipodKit](https://github.com/loopandlearn/OmnipodKit) as the
authority for every O5 protocol detail. Where the old branch and OmnipodKit
disagree, OmnipodKit wins.

## Why the old `five` branch no longer pairs

Checked against OmnipodKit `main` (Oct 2026):

| Old branch behaviour | What OmnipodKit expects now |
|---|---|
| Advertised two 128-bit service UUIDs (pod + a "heartbeat" `ECF301E2-…`) | `PodAdvertisement` requires **exactly one** service UUID, `CE1F923D-C539-48EA-7300-0A<pdmId>00`; any extra UUID makes the advert invalid (`PodAdvertisementO5Tests.testO5InvalidServiceCount`) |
| Vendored paypal/gatt wrote every UUID as a *16-bit* list | A 128-bit UUID has to go out under AD type 0x07 or iOS parses it as eight 16-bit UUIDs |
| No SPS0 stage in pairing | `O5LTKExchanger` sends `SPS0=00 01 09 <crc16-xmodem>` after SP1/SP2 and waits for the pod's `SPS0=00 00 09 <crc>` before SPS1 |
| Response CRC16 left as `00 00` | `BlePodMessageTransport.parseResponse` verifies the CRC16 on O5 responses (`Message(encodedData:checkCRC: isO5)`) |
| Fault advertised only through the manufacturer data | O5 fault = the single UUID's trailing byte flips `00` → `02` (`o5FaultAdvertisementUUID`) |
| Unsigned 0x1a/0x1c/0x1f accepted | O5 sends those as Type 4 (ENCRYPTED_SIGNED); a real pod answers an unsigned one with error `0x2A` |

Everything below is organised by package, with the OmnipodKit source that defines it.

## Mode selection — `main.go`, `pkg/mode`, `pkg/pod/state.go`

* `-mode dash|o5`, default `dash`. `pkg/mode` holds the enum and TOML text form.
* The mode is persisted in `state.toml`. On `-fresh` the flag wins; on a restart the
  persisted mode wins and a differing flag is a warning, so `./pod -q` after an O5
  pairing does not silently turn the pod into a DASH pod.
* `Status` (control panel, `/status`) reports `mode` and, in O5, the controller id.

## Bluetooth — `pkg/bluetooth`

Source: `BluetoothServices.swift`, `BlePodProfile.swift`, `PodAdvertisement.swift`,
`PeripheralManager+OmnipodKit.swift`, `Packet/*.swift`.

| | DASH (unchanged) | O5 |
|---|---|---|
| Service | `1A7E4024-…` | same |
| Command characteristic | `1A7E2441-…` | same |
| Data characteristic | `1A7E2442-…` | `1A7E2443-…` |
| Phone write type | with response | without response |
| Advertisement | nine 16-bit UUIDs, name ` :: Fake POD ::` | one 128-bit UUID `CE1F923D-C539-48EA-7300-0A<id>00`, `<id>` = `FFFFFFFE` until paired, then the **controller** id; `…02` on a fault |
| Packet MTU | 20 | 244 |
| RTS/CTS before a message | yes | **no** (both sides write data directly; SUCCESS/NACK still used) |
| HELLO | `06 01 04 <controllerId>` first write | same |

* `packet.go`: one split/join implementation, a port of `PayloadSplitter` /
  `PayloadJoiner` parameterised by the layout (`BlePacketLayout`). The DASH layout
  reproduces the old hand-rolled framing; the O5 layout is the 244-byte one.
* `bluetooth.go`: the message loop takes a data packet as the start of a message in
  O5 mode (no RTS), skips RTS/CTS on writes, and still exchanges SUCCESS/NACK/FAIL.
* `gatt_linux.go` / `impossible.go`: pick the data characteristic UUID and the
  advertisement by mode. The vendored paypal/gatt gets a minimal patch so a 128-bit
  UUID is advertised with the right AD type and the O5 manufacturer data goes out.
* ImpossiBLE reports `maximumWriteValueLength` = 512, so the Simulator transport
  needs no MTU work.

## Pairing — `pkg/pair`

Source: `O5LTKExchanger.swift`, `O5KeyExchange.swift`, `O5CertificateStore.swift`.

```
SP1=<podId>,SP2=<GetStatus cmd>     -> (no reply)
SPS0=00 01 09 <crc16-xmodem>        -> SPS0=00 00 09 <crc16-xmodem>
SPS1=<P-256 pub 64> <nonce 16>      -> SPS1=<pod P-256 pub 64> <pod nonce 16>
SPS2.1=AES-CCM(conf, intermediate CA cert DER)      -> SPS2.1=AES-CCM(conf, pod cert DER)
SPS2=AES-CCM(conf, TLS cert DER || ECDSA sig 64)    -> SPS2=AES-CCM(conf, pod cert DER || pod sig 64)
SP0,GP0                             -> P0=a5
```

* Keys: ECDH P-256 shared secret, then `SHA-256(len64||FIRMWARE_ID || len64||0000 ||
  len64||pdmPub || len64||podPub || len64||secret)`; first 16 bytes `conf`, last 16 `ltk`.
  `FIRMWARE_ID = 9b0ab96a76f4`.
* SPS AES-CCM: key `conf`, 8-byte tag, no AAD, 13-byte nonce
  `01||pdmNonce[0:6]||podNonce[0:6]` (phone→pod) or `02||podNonce[0:6]||pdmNonce[0:6]`
  (pod→phone); after each message the sender's nonce counter (first 8 bytes,
  little-endian) increments.
* Signatures (raw r||s) over the 171-byte transcripts:
  phone `01||FIRMWARE_ID||0000||pdmPub||podPub||pdmNonce||podNonce`,
  pod `02||0000||FIRMWARE_ID||podPub||pdmPub||podNonce||pdmNonce`, each with the
  nonces as they stood when the signer built it (OmnipodKit documents the
  decrement it applies on its side).
* The pod keeps a persistent P-256 identity (self-signed cert) in `state.toml`; the
  phone extracts only the SubjectPublicKeyInfo, so no chain is needed. The phone's
  public key from its SPS2 cert is kept to verify Type 4 commands.
* The controller id is recorded (from HELLO / SP1) for the paired advertisement.

## Session — `pkg/eap`, `pkg/encrypt`, `pkg/message`

Source: `SessionEstablisher.swift`, `EnDecrypt.swift`, `MessagePacket.swift`,
`BleMessageTransport.swift`.

* EAP-AKA is PRIMARY mode for O5 too (the phone sends the challenge); same Milenage
  constants, same nonce prefix `pdmIV||podIV`. Both modes now use a random pod IV and
  check AUTN.
* `MessageType 4` (ENCRYPTED_SIGNED): same AES-CCM payload as Type 1 followed by a
  64-byte ECDSA signature over `header(16) || ciphertext+tag`; the header length
  excludes the signature. The 11-bit length field is now decoded without the uint8
  truncation that broke payloads over 255 bytes.

## Commands and responses — `pkg/command`, `pkg/response`, `pkg/crc`, `pkg/aid`

Source: `BlePodComms.swift`, `O5AidCommands.swift`, `VersionResponse.swift`,
`ErrorResponse.swift`, `CRC16.swift`, `BolusExtraCommand.swift`.

* AID setup (between 0x07 AssignAddress and 0x03 SetupPod), plain ASCII, not
  SLPE-wrapped: `SE255.2=<utc>`→`ES255.2=0`, `S3.2=…,G3.2`→`3.2=<echo>`,
  `S3.1=…,G3.1`→`3.1=<echo>`, `S3.9=8,G3.9`→`3.9=8`, `S3.7=3670015,G3.7`→`3.7=<echo>`,
  `SE2.1=…`×3→`ES2.1=0`, optional `G3.11`/`G3.12`.
* Version responses are built from fields; O5 reports product id 5, firmware 9.0.3
  / 6.0.2 and the lot/tid from OmnipodKit's capture. DASH bytes are unchanged.
* O5 responses carry the real CRC16 (table CRC, vector `1f01482a10030e0100` → `802c`).
  DASH keeps `00 00` as before.
* 0x1a (with the 18-byte O5 BolusExtra), 0x1c and 0x1f must arrive as Type 4 in O5;
  an unsigned or badly signed one gets `06 03 2A <fault> <progress>`.

## Pod — `pkg/pod`

* `StartAcceptingCommands` parses HELLO for the controller id.
* `StartActivation` runs the DASH or O5 sequence above, then EAP-AKA as today.
* `CommandLoop` verifies Type 4 signatures, answers AID commands, and re-advertises
  with the controller id after SetupPod in O5 mode.

## Verification

* `go vet ./... && go test ./...` on every step (CI runs Go 1.21).
* Unit tests: packet layouts (incl. OmnipodKit's 242/243/500/953 cases), message
  Type 4 and long payloads, CRC16 vector, SPS0 CRC, SPS2.1/SPS2 round trips with a
  Go port of the phone side, AID fixtures from `O5CommLogFixtures.swift`, both
  radios' advertisements, and an end-to-end O5 pairing + session + command exchange
  between a pod and a Go "phone" over an in-memory wire.
