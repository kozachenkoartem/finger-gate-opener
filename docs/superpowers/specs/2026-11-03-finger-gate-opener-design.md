# Finger Gate Opener Design

## Intent

Finger Gate Opener is a local fingerprint-controlled gate relay for an ESP32-C3 and R558S sensor. It must continue making local access decisions when Wi-Fi is unavailable, while providing a secured web interface for administration and audit records.

## Goals

- Recognize fingerprints stored in the R558S and actuate the gate relay for authorized users.
- Store user names and roles separately from sensor templates in ESP flash.
- Provide reliable enrollment, deletion, role assignment, and audit viewing through a secured administrative UI and API.
- Allow Wi-Fi provisioning without requiring a preconfigured network.
- Reserve safe OTA capacity for future firmware updates.

## Non-goals

- The ESP32 does not export, import, or persist fingerprint images or templates; templates remain only in the R558S.
- No cloud service, remote unlock endpoint, or user self-service enrollment is included.
- GPIO10 relay wiring is deferred until the relay hardware is connected; the software relay abstraction and configuration are included before physical actuation is enabled.

## Hardware And Existing Contract

- ESP32-C3 SuperMini, 4 MB flash, ESP-IDF 5.5.3, C++17 and FreeRTOS.
- R558S UART1: ESP GPIO4 RX from R558S TX, ESP GPIO5 TX to R558S RX, 57,600 baud, 8N1.
- R558S `TOUCH_OUT`: GPIO3 input with both internal pulls disabled.
- ESP32-C3 built-in LED: GPIO8.
- GPIO10 is reserved for a future relay output and must remain unconfigured until the relay stage.
- The validated `r558s::Driver` is the only component that communicates on UART1. Every command keeps its current packet validation, bounded parser, stale-input flush, and no automatic retry for mutating sensor operations.

## Local Access Behavior

- A dedicated fingerprint task owns the driver and executes every sensor request received through an internal command queue.
- Touch events are debounced in that task. A successful identification is looked up in the local metadata store. Only users whose role has access may request a relay pulse.
- A 10-second cooldown starts when a relay pulse begins. No additional pulse may begin during the cooldown and new matches do not extend it. Relay pulse duration is a separate persisted setting, initially 1,000 ms.
- Master and User are the only fingerprint roles. Both may open the gate; Master may additionally begin a local enrollment gesture. At most two active fingerprints may have the Master role, and this limit is enforced by business logic and the REST API.
- The master gesture is exactly three distinct successful matches of the same active Master template within a fixed 10-second window. The finger must be removed between matches. A different finger resets the sequence. It opens one local enrollment operation only; it does not expose credentials or change Wi-Fi configuration.
- Every recognition, rejection, enrollment result, deletion, relay decision, and security-relevant administration result creates an audit record when flash storage is available. Each record has a monotonic sequence number, event type, applicable fingerprint ID and captured name, operation result, and either a UTC timestamp or a boot ID plus elapsed boot time. Rate-limit repeated equivalent events to reduce flash wear.

## LED Behavior

- Idle: blue.
- Provisioning AP active: one blue ring pulse every two seconds.
- Enrollment active: yellow.
- Success: three green flashes, then blue.
- Failure or rejection: three red flashes, then blue.
- The built-in GPIO8 LED remains a simple heartbeat/diagnostic indicator and is not part of the user-visible state contract.

## Enrollment And Template Lifecycle

- Enrollment has one absolute 120-second deadline.
- Local enrollment starts only after the third master match and after that master finger is released. The fingerprint task captures the protocol-required scans with finger removal between scans, rejects an already existing template, selects a confirmed free R558S slot, creates and stores the model, then persists the paired metadata atomically enough that an interrupted operation is recoverable on boot.
- A locally enrolled record is an active User named `Палец №N`, where `N` is the allocated sensor slot. One master gesture can create one record only. The overall enrollment deadline is 120 seconds.
- On metadata persistence failure after template storage, the task deletes the newly stored template and records the failure.
- Deleting a user removes the sensor template first and removes metadata only after sensor acknowledgement; inconsistent boot state is surfaced in the audit log and UI rather than silently granting access.
- An authorized web administrator may delete a Master record or remove its Master role, subject to never creating more than two Masters.

## Persistent Data

- Use NVS namespaces for device configuration, credentials and compact user metadata; use a bounded 512-record append-only audit store in a dedicated data partition with explicit versioning and recovery of an interrupted final record.
- Persist Wi-Fi credentials, an administrator password verifier, an AP passphrase, TLS material or its source data, user records, relay duration, cooldown configuration, and audit records.
- Never store plaintext administrator passwords. Derive the verifier with a unique random salt and a deliberately slow password KDF available in ESP-IDF; compare verifiers in constant time.
- Seed all device secrets from `esp_random()` and refuse administrative setup if cryptographic random generation or NVS initialization fails.

## Provisioning And Administration

- On first boot, the device starts an AP and its initial setup web interface. The published web credentials are `admin` / `admin`; the first successful login must change the password before any sensitive operation, including enrollment, role changes, relay commands, or Wi-Fi changes, is accepted.
- The administrator account is separate from fingerprints. The first registered fingerprint is not made Master automatically; the administrator assigns that role explicitly.
- Wi-Fi provisioning creates an AP named `FingerGate-XXXX`, where `XXXX` derives from the device MAC, at `192.168.1.1/24`. The default AP passphrase may be documented for developers. A persisted individual AP passphrase can be set by the administrator and is recommended for installation.
- After successful station configuration, the AP stops. A normal station disconnect never starts the AP; background reconnects must not affect local access. The authenticated administrator can start a protected network recovery flow that temporarily reopens provisioning without USB.
- While in provisioning mode the device serves setup only at `192.168.1.1`. After initial setup, administration is available only through HTTPS. All administrative API requests require an authenticated session protected by secure, HttpOnly, SameSite cookies and CSRF validation for state-changing methods.
- Authentication rate limits failed logins and creates audit records. Administrative sessions have an idle timeout and an absolute lifetime.
- APIs use JSON, enforce strict request sizes and content types, and never return secrets, Wi-Fi passphrases, password verifiers, or raw fingerprint data.

## Web UI And API Scope

- An authenticated administrator can view device/network status, list users, add or cancel enrollment, delete and rename users, assign or remove the Master role subject to the two-Master limit, configure relay pulse duration and Wi-Fi, change the administrator password, inspect and clear the audit log, start protected network recovery, and request a reboot.
- The UI is embedded static content served by the ESP32; it uses the JSON API and does not require a frontend framework or internet access.
- Enrollment status is polled from the API; one enrollment operation can be active at a time.

## Firmware Layout And Resilience

- Replace the current single app partition layout with factory/OTA data plus two equal OTA app slots and dedicated NVS/audit storage, all fitting in 4 MB flash.
- OTA updates are authenticated by the existing ESP-IDF secure update mechanism selected during implementation; the device preserves the previous bootable image until the new image has passed its boot-health check.
- Wi-Fi, HTTP, TLS, NTP, and web-task failures must not block the fingerprint task, relay control, cooldown enforcement, or local audit queue. NTP updates UTC time only when available.
- Boot replays or repairs interrupted persistent operations before accepting administrative changes. If metadata and sensor template state cannot be reconciled safely, the affected slot remains denied until an administrator resolves it.

## Verification Expectations

- Core state machines, metadata serialization/recovery, access decisions, cooldown, master gesture timing, password verification/rate limiting, CSRF/session checks, and API validation have host-runnable unit tests.
- ESP-IDF builds after each stage; hardware stages verify the sensor, first-boot provisioning, AP/station behavior, HTTPS authentication, local unlock behavior with Wi-Fi off, and OTA rollback separately.
- No destructive R558S database operation is automated outside an explicitly invoked administrative delete or an operator-confirmed hardware test.

## Builder Decisions

- GPIO10 remains high impedance until the relay hardware stage. Earlier stages use GPIO8 as a 1,000 ms stand-in lock actuator and never configure GPIO10. The relay stage must guarantee no pulse during boot, reset, or error recovery.
- The exact NVS key names, audit record binary layout, password KDF parameters, embedded UI visual style, API URL spelling, TLS certificate generation flow, and OTA image-signing mechanism are implementation decisions. They must meet the stated security and resilience constraints and be documented next to the implementation.
