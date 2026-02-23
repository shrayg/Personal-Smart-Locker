# Milestone 2 — Personal Smart Locker

ECE 2804 / IDP — Spring 2026. This folder contains the Milestone 2 firmware and documentation. (Milestone 1 plans were subject to change.)

---

## Files in this folder

### `keypadreader.ino`
- **Role:** 4×3 keypad input and lock/unlock state from keypad.
- **Hardware:** Columns on D2–D4; rows read via a single analog pin A0 with a resistor ladder (1.0k, 3.3k, 8.2k, 22k to A0; 10k from A0 to 5V). Layout: `1 2 3` / `4 5 6` / `7 8 9` / `* 0 #`.
- **Behavior:** Scans keypad with debounce; collects 4 digits then `#` to submit. Correct match vs. stored password sets state to UNLOCKED; `*` sets state to LOCKED. Sends `LOCKED` / `UNLOCKED` (repeated) and key presses over Serial.
- **Password:** Uses a fixed 4-digit password in code (`STORED_PASSWORD`); no EEPROM.

### `passwordlogic.ino`
- **Role:** Store and verify a password in EEPROM (AVR).
- **Behavior:** Uses low-level EEPROM access (EECR, EEAR, EEDR). Saves/loads a password (up to 8 bytes) with a 2-byte magic header. Serial commands: `S <password>` to save, `T <password>` to test; replies `UNLOCK` / `DENIED` or `Password saved.` / `No password set.` / `Incorrect length.`
- **Dependencies:** `Arduino.h`, `avr/io.h`, `avr/interrupt.h`, `string.h`.

### `servologic.ino`
- **Role:** Servo control on pin 9 for lock/unlock.
- **Behavior:** Uses Timer1 (phase-correct PWM, 20 ms period). Pulse widths: LOCK = 1500 µs, UNLOCK = 2470 µs, RESET = 1500 µs. Serial commands: `L` lock, `U` unlock, `R` reset.
- **Hardware:** Servo signal on digital pin 9.

### `finalcode.ino`
- **Role:** Single sketch that merges keypad, EEPROM password, and servo into one program.
- **Stored password:** One password only, stored in EEPROM. Keypad unlock and Serial `T` both use it. Set via Serial `S <password>` or via keypad when unlocked (see below).
- **Change password on keypad:** When **unlocked**, enter `#` `#` `#` `#` then `#` again (five `#` in a row). System enters “save password” mode: enter a new 4-digit code, then `#` to save to EEPROM. Press `*` to cancel without saving.
- **Behavior:** One `setup()` and one `loop()`. Keypad flow (4 digits + `#` / `*`) drives lock state and triggers servo. Serial still accepts: `S <password>` / `T <password>` (EEPROM), and `L` / `U` / `R` (servo).
- **Serial:** 115200 baud.

---

## Wiring (from keypadreader.ino)

- **Keypad columns:** C1 → D2, C2 → D3, C3 → D4.  
- **Keypad rows (A0 node):** 10k from A0 to 5V; Row1 → 1.0k → A0; Row2 → 3.3k → A0; Row3 → 8.2k → A0; Row4 → 22k → A0.  
- **Servo:** Signal on D9 (from servologic.ino).

---

## Usage

- **Keypad:** Enter 4 digits, press `#` to unlock; press `*` to lock.  
- **Change password (when unlocked):** Press `#` five times (`####` then `#` again) → enter new 4-digit password → press `#` to save. Press `*` to cancel.  
- **Serial (EEPROM):** `S 5274` to save `5274`; `T 5274` to test.  
- **Serial (servo):** `L` lock, `U` unlock, `R` reset.
