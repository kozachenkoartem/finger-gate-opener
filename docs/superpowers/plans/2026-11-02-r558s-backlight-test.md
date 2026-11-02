# R558S Backlight Test Plan

1. Configure GPIO3 as a floating input and UART1 as 57,600 baud, 8N1 on GPIO4
   (RX) and GPIO5 (TX).
2. Send exactly one R558S `setLED(blue)` command at startup and wait at most
   300 ms for a valid acknowledgement. Do not issue enrollment, search, delete,
   storage, relay, Wi-Fi, or web commands.
3. Retain the existing GPIO8 status LED blink loop and report the UART test
   result in the serial log.
4. Build the firmware without flashing the connected board.
