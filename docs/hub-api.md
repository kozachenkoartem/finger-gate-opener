# Hub API v1

Finger Gate exposes a versioned HTTPS API for one trusted local Atlas hub. The
device accepts connections only on the LAN: Atlas, not Finger Gate, is the
component that may be exposed to the Internet. Local fingerprint access keeps
working when Atlas, Wi-Fi, SSE, or the hub token is unavailable.

Atlas connects over HTTPS and pins the device certificate or certificate
fingerprint. A self-signed certificate is therefore acceptable only with an
explicit pin; a certificate change requires Atlas to establish trust again.

## Token

An authenticated device administrator creates or rotates exactly one Atlas token
in the HTTPS UI. It is 32 cryptographically random bytes encoded as 64 lowercase
hexadecimal characters and is shown once in the successful response. The UI
never displays an existing token. The device stores only a constant-time
SHA-256 verifier in NVS, not the token value.

Atlas supplies it with every hub request:

```http
Authorization: Bearer <token>
```

The token grants only `status.read`, `events.read`, and `gate.open`. It cannot
administer Wi-Fi, passwords, fingerprints, users, AP recovery, firmware, or
device configuration. Failed authorization is rate-limited and audited without
recording the supplied token. Rotation atomically replaces the previous verifier;
revocation deletes it.

All hub routes use HTTPS, require a valid Bearer token, and reject cookies,
CSRF headers, unexpected JSON fields, and oversized bodies.

## REST API

| Route | Semantics |
| --- | --- |
| `GET /api/v1/status` | Read-only device state and API/schema version. |
| `GET /api/v1/events?after=<id>&limit=<n>` | Events strictly after opaque `after`, in ascending order. `limit` is bounded; the response includes `next_after`, `has_more`, and the retained range. |
| `GET /api/v1/events/stream` | SSE stream for one client, with retained replay then live events. |
| `POST /api/v1/gate/open` | JSON `{"request_id":"..."}` requesting a gate pulse. |

Event IDs are opaque `<epoch>:<sequence>` strings so JavaScript clients do not
lose 64-bit precision. A REST cursor or SSE `Last-Event-ID` from another epoch,
outside the retained range, or after the newest event receives `409 Conflict`
with the retained range. The client must reset its cursor and read available
history.

## SSE

The response is `text/event-stream` with `Cache-Control: no-store`. Each message
has `id`, `event`, and a one-line JSON `data`; its event name is
`<type>.<result>`. `Last-Event-ID` resumes at the next sequence. Retained replay
and live subscription are ordered so no event can disappear between them.

Only one SSE client is supported. A second subscriber receives `409 Conflict`.
If the bounded outgoing queue is full or sending fails, the server closes the
stream. Atlas reconnects using its last completed ID and reads history via SSE or
REST. Token rotation or revocation closes the active stream before a replacement
token can subscribe.

## Gate Command

`POST /api/v1/gate/open` accepts only an ASCII `request_id` of 16--64 bytes. A
durable 16-entry command ledger makes retained IDs idempotent across retries and
reboots. `202` is returned only after durable acceptance.

The command first reserves its ledger entry and writes an `accepted` audit event,
then becomes executable through the same fingerprint-task queue used for local
access. A failure before that state produces no pulse. It follows the same
actuator and cooldown rules as fingerprint access and cannot bypass a busy or
failed actuator. A duplicate request returns its saved accepted or terminal state
without another pulse.

On reboot, an accepted but unresolved command becomes `interrupted` and is never
replayed. This is at-most-once physical execution, not an impossible exactly-once
claim. The final decision is published as an audit and SSE event with
`source: "hub"`. The ledger does not evict unresolved entries and retains the
latest 16 terminal IDs. Revocation cancels accepted commands that have not begun;
a pulse that has started finishes normally.

## Audit Privacy And Migration

The dedicated flash journal retains up to 512 events. It records fingerprint
results, gate-pulse decisions, enrollment results, user changes, authentication
results, hub-token lifecycle, and hub gate requests. Event types are `access`,
`enrollment`, `user`, `authentication`, `network`, `gate`, and `system`; sources
are `fingerprint`, `admin`, `hub`, and `device`.

Secrets never appear in the journal, REST, SSE, logs, or error text: this
includes token values, passwords, Wi-Fi credentials, and TLS private keys. Names
and request IDs are size-bounded and JSON-escaped on output.

Adding the audit partition is a one-time USB maintenance migration, not an OTA
update. Back up the current NVS range before writing the partition table. Power
loss during migration can require serial recovery; the recovery procedure
restores the NVS backup, which must never be published. On first use, an
unformatted audit partition is erased without erasing existing NVS data.
