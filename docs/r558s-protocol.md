# R558S Protocol Verification

The ESP32-C3 exchanges packets with the R558S on UART1 at 57,600 baud, 8N1.
All verified replies use the default address `FF FF FF FF`.

## Packet Validation

An R558S reply is accepted only after checking:

1. Header `EF 01`.
2. Default address.
3. Packet type `07` for acknowledgement.
4. Declared packet length.
5. Checksum over the packet type, length, and payload.
6. Confirmation code and the expected command payload size.

## Verified Commands

| Command | Instruction | Verified response |
| --- | --- | --- |
| Set LED | `3C` | Successful acknowledgement |
| Get template count | `1D` | Two-byte count |
| Read index table page 0 | `1F 00` | 32-byte occupancy bitmap |
| Capture image | `01` | Successful acknowledgement during enrollment |
| Convert image to template | `02` | Successful acknowledgement during enrollment |
| Create model | `05` | Successful acknowledgement after four scans |
| Store model | `06` | Successful acknowledgement for slot 1 |
| Search model | `04` | Slot ID and score for the enrolled fingerprint |
| Empty database | `0D` | Successful acknowledgement followed by a zero template count |

The temporary test enrollment used four scans with full finger removal between scans and a 120-second total deadline. It stored and found a test fingerprint in slot 1. The index table first byte changed from `00` to `02`, then returned to `00` after database cleanup.

## Search Rejection ACK Format (2026-11-03)

The device returns Search (`04`) confirmation `09` (no matching fingerprint)
with a five-byte payload: confirmation plus the four unused ID/score bytes.
The previous driver required a one-byte rejection payload and consequently
reported `duplicate_search_failed` on the first enrollment scan.

Search now explicitly accepts either the one-byte or five-byte rejection
format. Other commands retain the one-byte rejection contract. Nonzero
confirmations remain failures; only Search confirmation `09` means `NotFound`.
Success payload length, checksum, address and packet-type validation are unchanged.

The extended response was observed on the actual board; a read-only Search probe
after the fix returned `NotFound` rather than `InvalidResponse`. Host regression
tests cover both rejection formats, unexpected lengths and truncated successes.
The temporary boot probe was removed after verification. Physical four-scan
enrollment with the corrected driver still requires user acceptance.
