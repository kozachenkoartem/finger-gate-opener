# ESP32-C3 Board Check Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create a minimal ESP-IDF firmware that confirms an ESP32-C3 SuperMini starts correctly and controls its presumed GPIO8 WS2812 LED.

**Architecture:** `firmware/` is an independent ESP-IDF application. Its single `app_main()` logs board diagnostics, initializes one LED-strip RMT device, then cycles RGB colors in the FreeRTOS task. Future features will be introduced as separate ESP-IDF components under `firmware/components/` only when needed.

**Tech Stack:** C++17, ESP-IDF 5.x, FreeRTOS, CMake, ESP Component Registry `espressif/led_strip`.

**Spec:** User request in this session; no separate design document is needed because this is a single board-check deliverable with explicitly approved scope.

## Global Constraints

- Target must be `esp32c3`.
- Use C++17, ESP-IDF, FreeRTOS, and CMake; do not use Arduino Framework.
- Depend on the ESP Component Registry `espressif/led_strip` driver.
- Log chip model, ESP-IDF version, last reset reason, and currently free heap.
- Drive one presumed WS2812 on GPIO8 red, green, then blue, holding each color for one second.
- Every recurring delay must use `vTaskDelay()`; do not introduce busy-wait loops.
- Do not implement Wi-Fi, R558S UART support, lock control, or placeholder components.
- Do not modify `STL/`, STEP, or CadQuery sources.

## Review Focus

- Missing ESP-IDF setup must fail with a clear documented setup command rather than suggesting an Arduino workflow.
- The build target must remain `esp32c3`, avoiding a binary that cannot boot on the connected board.
- LED color order must explicitly select WS2812 GRB transport order so requested displayed colors are correct.
- RMT initialization and every LED driver call must surface ESP-IDF errors through `ESP_ERROR_CHECK`.
- The infinite color cycle must yield to FreeRTOS for every one-second wait.

---

### Task 1: Create the ESP-IDF board-check application

**Files:**
- Create: `firmware/CMakeLists.txt`
- Create: `firmware/sdkconfig.defaults`
- Create: `firmware/main/CMakeLists.txt`
- Create: `firmware/main/idf_component.yml`
- Create: `firmware/main/main.cpp`

**Interfaces:**
- Consumes: ESP-IDF `app_main()`, `esp_chip_info()`, `esp_get_idf_version()`, `esp_reset_reason()`, `esp_get_free_heap_size()`, FreeRTOS `vTaskDelay()`, and `led_strip_new_rmt_device()`.
- Produces: An `esp32c3` firmware image that logs diagnostics and cycles one GPIO8 WS2812 LED.

- [ ] **Step 1: Create the root and main ESP-IDF CMake files**

Use the standard `project.cmake` include, define the `finger_gate_opener` project, compile `main.cpp` as an `app_main` component, and require C++17 for the application component.

- [ ] **Step 2: Declare the LED Strip Registry dependency**

Add `espressif/led_strip` with a compatible 3.x version in `firmware/main/idf_component.yml`, so the component manager resolves the official driver during configuration.

- [ ] **Step 3: Pin the project target**

Set `CONFIG_IDF_TARGET="esp32c3"` in `firmware/sdkconfig.defaults`.

- [ ] **Step 4: Implement `extern "C" void app_main()` in `firmware/main/main.cpp`**

Log the chip target/model and core count from `esp_chip_info_t`, `esp_get_idf_version()`, `esp_reset_reason()`, and `esp_get_free_heap_size()`. Map known `esp_reset_reason_t` values to readable strings while retaining the numeric value in the log.

- [ ] **Step 5: Initialize and run the WS2812 test**

Configure one WS2812 as an RMT LED-strip device on GPIO8 with GRB component order. Set and refresh red `(255, 0, 0)`, green `(0, 255, 0)`, and blue `(0, 0, 255)` in order, using `vTaskDelay(pdMS_TO_TICKS(1000))` after each refresh forever. Check LED-strip driver calls with `ESP_ERROR_CHECK`.

- [ ] **Step 6: Build the target**

Run: `. "$IDF_PATH/export.sh" && idf.py -C firmware set-target esp32c3 && idf.py -C firmware build`

Expected: Component manager resolves `espressif/led_strip` and CMake produces an ESP32-C3 firmware image without compilation errors.

### Task 2: Document use and ignore generated files

**Files:**
- Modify: `README.md`
- Create: `.gitignore`

**Interfaces:**
- Consumes: The Task 1 firmware layout and ESP-IDF CLI.
- Produces: Reproducible commands for configuring ESP-IDF, building, flashing through the board USB serial port, and monitoring logs.

- [ ] **Step 1: Add a firmware section to `README.md`**

Document installing/activating ESP-IDF 5.x, `idf.py -C firmware set-target esp32c3`, building, locating the USB serial port, flashing with `idf.py -C firmware -p <PORT> flash`, and monitoring with `idf.py -C firmware -p <PORT> monitor`. State GPIO8 and the red-green-blue one-second behavior as the expected board-check result.

- [ ] **Step 2: Add ESP-IDF generated outputs to `.gitignore`**

Ignore project build directories, generated `sdkconfig`, managed-component downloads, Python cache files, and common IDE files, while keeping `sdkconfig.defaults` and source configuration tracked.

- [ ] **Step 3: Inspect the final diff and repository status**

Run: `git diff --check` and `git status --short`

Expected: No whitespace errors; only firmware files, documentation, and `.gitignore` are changed.

### Task 3: Verify and commit

**Files:**
- Modify: Files produced by Tasks 1 and 2 only if verification identifies a defect.

**Interfaces:**
- Consumes: Build output and final Git diff.
- Produces: One commit containing the minimal board-check firmware.

- [ ] **Step 1: Rebuild from a clean `firmware/build` directory**

Run: `. "$IDF_PATH/export.sh" && idf.py -C firmware build`

Expected: Build completes successfully for `esp32c3`.

- [ ] **Step 2: Review the code and build configuration**

Check that no Arduino dependency, Wi-Fi initialization, UART/R558S code, actuator code, or edits below `STL/` were introduced.

- [ ] **Step 3: Commit the verified changes**

Run: `git add .gitignore README.md firmware docs/superpowers/plans/2026-11-02-esp32c3-board-check.md && git commit -m "feat: add ESP32-C3 board check firmware"`

Expected: A single commit contains the firmware, documentation, and implementation plan.
