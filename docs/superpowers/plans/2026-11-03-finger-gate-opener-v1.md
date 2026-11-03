# Finger Gate Opener V1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a local-first, fingerprint-operated gate controller with secure web administration, audit history, and a relay-safe hardware integration.

**Architecture:** The existing `r558s::Driver`, the mutable user registry, and all sensor/template lifecycle transitions are owned solely by a fingerprint FreeRTOS task. Platform-independent access, enrollment, metadata, event, and authentication state machines have host tests; ESP-IDF adapters own NVS, Wi-Fi, HTTPS, time, and relay hardware. Web handlers submit serialized commands to that task and receive immutable result snapshots; bounded queues isolate local recognition and access decisions from networking and administration.

**Tech Stack:** ESP-IDF 5.5.3, C++17, FreeRTOS, NVS, ESP Wi-Fi, ESP HTTPS server, mbedTLS, SNTP, host CMake/CTest.

**Spec:** `docs/superpowers/specs/2026-11-03-finger-gate-opener-design.md`

## Global Constraints

- UART1 uses GPIO4 RX, GPIO5 TX, 57,600 baud, 8N1; GPIO3 is `TOUCH_OUT` with no internal pull.
- `r558s::Driver` is the sole UART owner; no web, relay, or Wi-Fi task accesses UART1.
- Master and User can open the gate; no more than two active Masters are allowed.
- A match during a 10-second gate cooldown never creates another or extended relay pulse.
- GPIO10 remains unconfigured before the relay hardware stage; earlier code uses a logging stand-in actuator.
- Sensitive operations are denied until the initial `admin` password is changed.
- Password verifiers use a unique salt and a deliberately slow resource-appropriate KDF; plaintext passwords and secrets never enter logs or API responses.
- If NVS configuration/credential initialization, read, or entropy validation fails, administration fails closed without resetting credentials or erasing NVS. Report the degraded state locally while preserving unaffected safe fingerprint access.
- Relay duration defaults to 1,000 ms, is validated and persisted separately from the fixed cooldown, and takes effect only for the next accepted pulse.
- Local recognition and access decisions continue with Wi-Fi, HTTP, TLS, NTP, or Home Assistant unavailable.
- The audit log retains 512 events, recovers incomplete writes, and throttles repeated equivalent events.
- Incomplete add/delete records quarantine their slot from access and new allocation until the fingerprint task reconciles R558S state at boot. Store intent before a sensor mutation; after an uncertain acknowledgement, never retry blindly.
- The indicator publishes desired state transitions only. The fingerprint task executes every R558S LED transaction and may interleave it with sensing; no component sleeps while owning the UART.
- The OTA implementation includes authenticated update acceptance, pending-image boot health confirmation, rollback on health failure, and a hardware verification procedure.
- Build and run host tests after every task; perform a physical test only when the required hardware is connected.

## Review Focus

- A corrupted or incomplete persisted record must deny access and remain recoverable; test in Task 2.
- A third Master assignment must fail even if the request bypasses the UI; test in Task 2 and Task 7.
- Holding a finger down must not produce a second match, gesture count, or unlock; test in Task 4.
- A different matching finger must reset the master gesture; test in Task 5.
- A station disconnect, failed NTP request, or web request backlog must not delay sensor transactions; integration test in Task 6.

---

### Task 1: Record Hardware Verification And Prepare The Application Boundary

**Files:**
- Modify: `README.md`
- Modify: `docs/r558s-protocol.md`
- Modify: `firmware/main/main.cpp`
- Test: `firmware/tests/r558s_protocol_test.cpp`

**Interfaces:**
- Consumes `r558s::Driver` from the completed Stage 1 driver.
- Produces a clean application entry point with no destructive test enrollment path.

- [x] Verify LED commands, UART packet parsing, a four-scan enrollment, persisted search after reboot, and explicit database cleanup on the real device.
- [x] Record the verified commands, response shapes, and test lifecycle in `docs/r558s-protocol.md`.
- [x] Remove temporary enrollment and database-clear code from `main.cpp`.
- [x] Run `ctest --test-dir /tmp/opencode/finger-gate-tests --output-on-failure` and `idf.py -C firmware build`.
- [x] Commit as `b4a8b79 docs: record R558S hardware verification`.

### Task 2: User Metadata And Access Policy

**Files:**
- Create: `firmware/main/finger_gate_model.hpp`
- Create: `firmware/main/finger_gate_model.cpp`
- Create: `firmware/tests/finger_gate_model_test.cpp`
- Modify: `firmware/tests/CMakeLists.txt`

**Interfaces:**
- Produces `fg::User`, `fg::Role`, `fg::UserRegistry`, and `fg::AccessDecision`.
- `UserRegistry::add(User)`, `rename(slot, std::string)`, `set_role(slot, Role)`, `remove(slot)`, and `find(slot)` return typed outcomes without platform dependencies.

- [ ] Add failing host tests for User access, a two-Master limit, role removal, duplicate slots, invalid names, and corrupted/inactive records denying access.
- [ ] Implement bounded slot-indexed metadata and validation. Enforce the Master limit in `add` and `set_role`, and default newly constructed local enrollment records to `User`.
- [ ] Run the host target and CTest; confirm all metadata tests pass.
- [ ] Commit the platform-independent model and tests.

### Task 3: Persistent Metadata, Recovery, And Audit Events

**Files:**
- Create: `firmware/main/user_store.hpp`
- Create: `firmware/main/user_store.cpp`
- Create: `firmware/main/nvs_storage.hpp`
- Create: `firmware/main/nvs_storage.cpp`
- Create: `firmware/main/audit_events.hpp`
- Create: `firmware/main/audit_events.cpp`
- Create: `firmware/tests/user_store_test.cpp`
- Modify: `firmware/main/CMakeLists.txt`
- Modify: `firmware/tests/CMakeLists.txt`

**Interfaces:**
- Consumes `fg::UserRegistry` from Task 2.
- Produces `fg::UserStore::load()`, `stage(User)`, `commit(slot)`, `stage_delete(slot)`, `commit_delete(slot)`, and `recover()`; produces `fg::AuditEventSink` with a bounded nonblocking producer queue.

- [ ] Add tests using an in-memory key-value adapter for interrupted add/delete before and after uncertain sensor acknowledgement, malformed versioned records, round-trip Unicode user names, unresolved-slot denial while unaffected slots remain usable, and audit queue overflow throttling.
- [ ] Implement versioned staged records. `load()` must expose only committed active records; `recover()` returns a quarantined slot set. The fingerprint task consumes that set before recognition or free-slot selection and reconciles sensor state without granting access.
- [ ] Specify and implement ordering: stage intent, attempt sensor mutation once, reconcile from index/search after an uncertain result, then commit metadata only after confirmed sensor state. Deletion stages intent before sensor deletion and removes metadata only after confirmed deletion.
- [ ] Add the ESP-IDF NVS adapter with explicit namespace initialization and error classification.
- [ ] Run host tests and `idf.py -C firmware build`.
- [ ] Commit persistence and recovery separately from access policy.

### Task 4: Autonomous Recognition And Gate Stand-In

**Files:**
- Create: `firmware/main/access_controller.hpp`
- Create: `firmware/main/access_controller.cpp`
- Create: `firmware/main/gate_actuator.hpp`
- Create: `firmware/main/gate_actuator.cpp`
- Create: `firmware/main/fingerprint_task.hpp`
- Create: `firmware/main/fingerprint_task.cpp`
- Create: `firmware/tests/access_controller_test.cpp`
- Modify: `firmware/main/main.cpp`
- Modify: `firmware/main/CMakeLists.txt`

**Interfaces:**
- Consumes `fg::UserRegistry` and `r558s::Driver`.
- Produces `fg::AccessController::on_match(slot, pulse_started_at_ms)`, `fg::GateActuator::request_pulse(duration_ms)`, and a dedicated `fg::FingerprintTask` command queue.

- [ ] Add failing host tests for active User/Master unlock, unknown or inactive slot denial, exact 10-second cooldown, and repeated held-finger suppression.
- [ ] Implement access decisions and the GPIO8 stand-in `GateActuator` with a 1,000 ms pulse; do not configure GPIO10. Start cooldown only when the actuator accepts and timestamps a pulse request.
- [ ] Implement a fingerprint task that is the only reader/mutator of the registry and store. Web commands are serialized through a bounded queue and return immutable snapshots; storage work never holds a lock needed for recognition.
- [ ] At boot, make the fingerprint task load and reconcile quarantined slots before it accepts recognition, enrollment, or administrative mutations.
- [ ] Run host tests and ESP-IDF build. With the sensor connected, verify recognition and stand-in gate logs; record the physical result separately.
- [ ] Commit autonomous access behavior.

### Task 5: Master Gesture, Enrollment, And Nonblocking Indication

**Files:**
- Create: `firmware/main/master_gesture.hpp`
- Create: `firmware/main/master_gesture.cpp`
- Create: `firmware/main/indicator.hpp`
- Create: `firmware/main/indicator.cpp`
- Create: `firmware/tests/master_gesture_test.cpp`
- Modify: `firmware/main/fingerprint_task.cpp`
- Modify: `firmware/main/main.cpp`

**Interfaces:**
- Consumes match/release events and `fg::UserStore`.
- Produces `fg::MasterGesture::on_match(slot, now_ms)` and `fg::Indicator::publish(IndicatorEvent)`; only the indicator owns LED commands.

- [ ] Add failing tests for three same-Master matches in 10 seconds, release requirements, a different fingerprint reset, timeout reset, and a cooldown match still contributing to a valid gesture.
- [ ] Implement a nonblocking indicator scheduler: idle blue, enrollment yellow, and three green/red flashes returning to blue. Only the fingerprint task drains it and performs LED commands between sensor transactions; coalesce stale cosmetic events so indication cannot starve recognition.
- [ ] Implement enrollment as a fingerprint-task state machine with a 120-second absolute deadline across all UART waits, mandatory release before start and between scans, duplicate search, full-database detection, serialized command rejection, cancellation, free-slot selection excluding quarantined slots, sensor/metadata compensation, automatic `Палец №N` User record, and mandatory release after success.
- [ ] Test every persistence boundary and uncertain store/delete acknowledgement by restarting the model before recovery; test compensation failure as a quarantined denied slot.
- [ ] Run host tests and ESP-IDF build. Perform the approved sensor enrollment test only when hardware is available, then commit.

### Task 6: Configuration, Authentication, And Network Provisioning

**Files:**
- Create: `firmware/main/config_store.hpp`
- Create: `firmware/main/config_store.cpp`
- Create: `firmware/main/auth.hpp`
- Create: `firmware/main/auth.cpp`
- Create: `firmware/main/wifi_manager.hpp`
- Create: `firmware/main/wifi_manager.cpp`
- Create: `firmware/tests/auth_test.cpp`
- Create: `firmware/tests/wifi_state_test.cpp`
- Modify: `firmware/main/main.cpp`
- Modify: `firmware/main/CMakeLists.txt`

**Interfaces:**
- Produces `fg::AuthService`, `fg::Session`, `fg::DeviceConfig`, and `fg::WifiManager` state notifications.

- [ ] Add host tests for first-login password-change enforcement, salted verifier success/failure, rate limiting, session idle/absolute expiry, provisioning transition, no AP restart from a normal station disconnect, unavailable entropy, and NVS initialization/read failure fail-closed behavior.
- [ ] Implement NVS configuration, a salted mbedTLS-backed slow password verifier, constant-time comparison, validated random session/CSRF tokens, and default `admin` credentials marked as requiring replacement. Initialization failures must prohibit provisioning changes, password replacement, and session issuance without erasing or silently replacing stored credentials.
- [ ] Implement persisted relay duration with a 500 ms default and a bounded safe range. A change is serialized through the fingerprint command queue and applies only to a subsequent pulse.
- [ ] Implement initial `FingerGate-XXXX` AP at `192.168.1.1`, station setup, persistent AP password override, reconnection, and authenticated temporary recovery provisioning. Networking failure events must only notify, never block the fingerprint task.
- [ ] Run host tests and ESP-IDF build; perform AP/station hardware verification when available.
- [ ] Commit security and provisioning before adding administrative handlers.

### Task 7: HTTPS Server, REST API, And Embedded Admin UI

**Files:**
- Create: `firmware/main/http_server.hpp`
- Create: `firmware/main/http_server.cpp`
- Create: `firmware/main/api_router.hpp`
- Create: `firmware/main/api_router.cpp`
- Create: `firmware/web/index.html`
- Create: `firmware/web/app.js`
- Create: `firmware/web/app.css`
- Create: `firmware/tests/api_router_test.cpp`
- Modify: `firmware/main/CMakeLists.txt`
- Modify: `firmware/main/main.cpp`

**Interfaces:**
- Consumes `AuthService`, `WifiManager`, fingerprint command queue, and `AuditEventSink` from Task 3; persistent audit storage arrives in Task 8.
- Produces HTTPS-only session-authenticated JSON endpoints and embedded static UI content.

- [ ] Add router tests for unauthenticated denial, password-change gating, CSRF rejection, malformed/oversized JSON rejection, two-Master API enforcement, relay-duration range/persistence, relay-duration authorization/CSRF, and secret redaction.
- [ ] Implement login/logout/session endpoints and authenticated status, user, enrollment, password, Wi-Fi, network recovery, relay-duration, reboot, and audit endpoints. Mutations enqueue work; handlers never operate UART or relay directly.
- [ ] Implement the embedded UI for status, first password change, Wi-Fi, users/roles, enrollment, relay duration, and audit history without external network assets.
- [ ] Run host tests and ESP-IDF build; verify HTTPS login, cookie flags, strict content types, CSRF behavior, and fingerprint responsiveness while handlers are busy on hardware before committing.

### Task 8: Persistent Audit Log, Time, Partitioning, OTA, And Relay Hardware

**Files:**
- Create: `firmware/main/audit_log.hpp`
- Create: `firmware/main/audit_log.cpp`
- Create: `firmware/main/time_service.hpp`
- Create: `firmware/main/time_service.cpp`
- Create: `firmware/main/ota_manager.hpp`
- Create: `firmware/main/ota_manager.cpp`
- Create: `firmware/tests/audit_log_test.cpp`
- Create: `firmware/partitions.csv`
- Modify: `firmware/sdkconfig.defaults`
- Modify: `firmware/main/gate_actuator.cpp`
- Modify: `firmware/main/CMakeLists.txt`
- Modify: `README.md`

**Interfaces:**
- Produces `fg::AuditLog::append(Event)`, `list(after_sequence, limit)`, `clear()`, and `fg::TimeService::current_time()`.

- [ ] Add failing tests for 512-event overwrite order, sequence continuity, interrupted final record recovery, event throttling, UTC/null timestamp representation, and boot-ID elapsed-time fallback.
- [ ] Implement a versioned bounded append-only data partition log, connect the Task 3 producer queue, and add asynchronous SNTP time updates.
- [ ] Add a 4 MB partition layout with NVS, OTA data, two app slots, and audit storage. Build must confirm the image fits both OTA slots.
- [ ] Implement an authenticated signed update mechanism, pending-image boot health confirmation after fingerprint/NVS initialization, rollback when health is not confirmed, and an explicit API/UI status surface. Test rejected unsigned/invalid image metadata and rollback selection with host-modelled boot-state tests; run the physical rollback procedure when a second image is available.
- [ ] Replace the stand-in gate actuator only after relay hardware is connected: initialize GPIO10 to its inactive level before enabling output, pulse for configured duration, and prove no boot/reset pulse with a physical test.
- [ ] Run all host tests and `idf.py -C firmware build`; document hardware and OTA verification facts, then commit.

## Execution Notes

- Tasks 2-5 are local-first and can proceed without a networked board.
- Tasks 6-8 require current ESP-IDF documentation before choosing component APIs and TLS/OTA configuration.
- Each task must retain unrelated work and create one focused commit after its stated verification succeeds.
