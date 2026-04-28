// Personal Smart Locker - Keegan Hoyne & Shray Gupta
//
// Pin summary:
// D2  - Keypad column 1 output.
// D3  - Keypad column 2 output.
// D4  - Keypad column 3 output.
// A0  - Keypad row resistor-ladder analog input and keypad wake input.
// A1  - Servo current-sense analog input across the 1 ohm sense resistor.
// D5  - Passive buzzer output driven by tone() at 2 kHz.
// D6  - Red LED output for locked, critical battery (pre-sleep alert only), wrong password, blocked motor.
// D7  - Green LED output for unlocked and wake feedback.
// D8  - Yellow LED output for password-save mode, warning battery (pre-sleep alert only), saved-password feedback.
// D9  - Servo PWM output using Timer1 OC1A.
// A3  - Servo power-control output for the PMOS high-side switch on PC3 / physical pin 26.
//
// Wiring summary:
// Keypad columns connect to D2, D3, and D4.
// Keypad rows share an A0 resistor ladder with a 10k pullup to 5 V.
// Row 1 uses 1.0k to A0, row 2 uses 3.3k to A0, row 3 uses 8.2k to A0, and row 4 uses 22k to A0.
// Servo signal connects to D9, servo current sense connects to A1, and servo power is switched by A3.
// Red, green, and yellow LEDs connect through their series resistors to D6, D7, and D8.
// Buzzer connects to D5 and ground.
// Standalone ATmega328P uses regulated 5 V, common ground, 16 MHz clock hardware, reset pullup, and local decoupling.
//
// Features:
// a. Keypad input system.
// b. Timer1 servo control.
// c. Password state machine and EEPROM storage.
// d. Secure salted SHA-256 password storage.
// e. Servo blockage detection.
// f. Standalone ATmega328P hardware support.
// g. Sleep mode and keypad wake.
// h. Low battery: measured before sleep only; buzzer + LED for 3 s if rail is low, then sleep.
// i. LED and buzzer user interface.
// j. Battery life optimization and servo power switching.

#include <Arduino.h>
#include <avr/io.h>
#include <avr/interrupt.h>
#include <avr/pgmspace.h>
#include <stdint.h>
#include <string.h>

// TUNABLE SETTINGS
// Sets the inactivity time before the locker enters power-down sleep.
static const unsigned long IDLE_SLEEP_MS = 5000UL;
// Sets how long normal state LEDs stay visible after user activity.
static const unsigned long UI_HOLD_MS    = 2500UL;
// Sets the Serial command awake-hold duration for testing and measurements.
static const unsigned long AWAKE_HOLD_MS = 60000UL;
// Enables watchdog wake so the firmware can periodically recover from sleep.
static const bool USE_WDT_WAKE           = true;
// Selects servo power polarity: true for direct PMOS gate, false for an NPN-inverted PMOS driver.
static const bool SERVO_PWR_ACTIVE_LOW   = true;

// PINS
// Stores the three keypad column pins scanned by the firmware.
const uint8_t COL_PINS[3]      = {2, 3, 4};
// Reads the keypad resistor-ladder voltage and wake key activity.
const uint8_t ROW_ANALOG_PIN   = A0;
// Reads the voltage across the servo current-sense resistor.
const uint8_t SERVO_SENSE_PIN  = A1;
// Drives the passive buzzer output.
const uint8_t BUZZER_PIN       = 5;
// Drives the red status LED.
const uint8_t redPin           = 6;
// Drives the green status LED.
const uint8_t greenPin         = 7;
// Drives the yellow status LED.
const uint8_t yellowPin        = 8;
// Outputs the Timer1 servo PWM signal.
const uint8_t SERVO_PIN        = 9;
// Controls servo power through the PMOS switch on PC3 / ADC3 / physical pin 26.
const uint8_t SERVO_PWR_PIN    = A3;

// BATTERY / BUZZER
// Sets the alert tone frequency used for warning and critical battery bursts.
static const uint16_t BUZZER_HZ = 2000;
// Sets the warning threshold for the measured 5 V rail.
static const uint16_t RAIL_WARN_MV = 4700;
// Sets the critical threshold for the measured 5 V rail.
static const uint16_t RAIL_CRIT_MV = 4400;
// Clears a low-battery state only after the rail rises above this recovery point.
static const uint16_t RAIL_RECOVER_MV = 4750;
// Keeps the warning tone on for the required warning pulse width.
static const uint16_t BUZZ_WARN_ON_MS  = 80;
// Keeps the warning tone off for the required warning gap width.
static const uint16_t BUZZ_WARN_GAP_MS = 120;
// Keeps the critical tone on for the required critical pulse width.
static const uint16_t BUZZ_CRIT_ON_MS  = 45;
// Keeps the critical tone off for the required critical gap width.
static const uint16_t BUZZ_CRIT_GAP_MS = 55;
// Pre-sleep low-battery warning duration (fixed-length; then power-down sleep).
static const unsigned long RAIL_ALERT_SLEEP_PRE_MS = 3000UL;
// Tracks the alert level currently being played by the buzzer and alert LED.
static uint8_t railAlertLevel = 0;
// Stores when the current low-battery alert burst should stop.
static uint32_t railAlertUntilMs = 0;
// Stores the next tone toggle time for the non-blocking buzzer pattern.
static uint32_t buzzerNextMs = 0;
// Tracks whether the buzzer tone is currently on during an alert burst.
static bool buzzerToneOn = false;
// Prevents repeating the pre-sleep 3 s rail alert on watchdog-only wake loops.
static bool preSleepAlertPlayed = false;

// KEYPAD
// Maps detected row and column indices to keypad characters.
const char KEYMAP[4][3] = {
  {'1','2','3'},
  {'4','5','6'},
  {'7','8','9'},
  {'*','0','#'}
};
// Sets the ADC upper threshold for row 1.
const int TH_ROW0_MAX = 173;
// Sets the ADC upper threshold for row 2.
const int TH_ROW1_MAX = 357;
// Sets the ADC upper threshold for row 3.
const int TH_ROW2_MAX = 582;
// Sets the ADC upper threshold for row 4.
const int TH_ROW3_MAX = 863;
// Requires this many stable scans before accepting a key.
const uint8_t DEBOUNCE_SCANS = 5;
// Requires this many no-key scans before accepting another key.
const uint8_t RELEASE_SCANS  = 5;

// PASSWORD/EEPROM
// Limits password storage to the EEPROM record size used by this sketch.
static const uint8_t maxLength = 8;
// Marks older plaintext EEPROM records that can be migrated.
static const uint8_t LEGACY_M0 = 'A';
// Marks older plaintext EEPROM records that can be migrated.
static const uint8_t LEGACY_M1 = 'B';
// Marks the first byte of a valid secure EEPROM record.
static const uint8_t SEC_MAGIC0 = 'S';
// Marks the second byte of a valid secure EEPROM record.
static const uint8_t SEC_MAGIC1 = 'H';
// Identifies the secure EEPROM record format version.
static const uint8_t SEC_VERSION = 1;
// Sets the base EEPROM address for password storage.
static const uint16_t EE_BASE = 0;
// Stores the 16-byte salt loaded from EEPROM.
static uint8_t storedSalt[16];
// Stores the 32-byte SHA-256 digest loaded from EEPROM.
static uint8_t storedHash[32];
// Tracks whether a valid stored password record is available.
static bool hasStoredPassword = false;

// STATE MACHINE
enum LockState {
  STATE_LOCKED = 0,
  STATE_UNLOCKED = 1,
  STATE_SAVE_PASSWORD = 2,
  STATE_LOCKING = 3,
  STATE_UNLOCKING = 4
};
enum LedEvent {
  LED_EVENT_NONE = 0,
  LED_EVENT_WRONG = 1,
  LED_EVENT_BLOCKED = 2,
  LED_EVENT_SAVED = 3,
  LED_EVENT_WAKE = 4
};
// Tracks the current state-machine state.
static LockState lockState = STATE_LOCKED;
// Remembers where to return after password-save mode exits.
static LockState saveReturnState = STATE_UNLOCKED;
// Stores the stable state before a servo motion starts.
static LockState motionPrevState = STATE_LOCKED;
// Stores the stable state expected after a successful servo motion.
static LockState motionNextState = STATE_LOCKED;
// Stores four keypad password digits plus the null terminator.
static char enteredPassword[5] = {0,0,0,0,0};
// Tracks how many keypad password digits are currently buffered.
static uint8_t enteredLen = 0;
// Counts # presses while unlocked to enter password-save mode.
static uint8_t unlockHashCount = 0;
// Counts empty # presses while locked to enter password-save mode.
static uint8_t lockedHashCount = 0;

// SERVO TIMING/MOTION
// Sets the 20 ms servo frame period used for 50 Hz control.
static const uint16_t PERIOD = 20000;
// Sets the reset/default servo pulse width in microseconds.
static const uint16_t RESET  = 1500;
// Sets the locked servo pulse width in microseconds.
static const uint16_t LOCK   = 1500;
// Sets the unlocked servo pulse width in microseconds.
static const uint16_t UNLOCK = 2470;
// Sets the ADC current-sense threshold for blocked-servo detection.
static const uint16_t BLOCK_ADC_THRESHOLD = 70;
// Ignores the normal startup current spike for this motion window.
static const uint16_t MOVE_GRACE_MS       = 250;
// Requires high current for this long before declaring blockage.
static const uint16_t BLOCK_CONFIRM_MS    = 80;
// Ends normal servo motion after this timeout.
static const uint16_t MOVE_TIMEOUT_MS     = 700;
// Waits after servo power turns on before PWM movement starts.
static const uint16_t SERVO_POWER_SETTLE_MS = 50;
// Stores the time when the current servo motion began.
static uint32_t motionStartTime = 0;
// Stores when blocked-current readings first went high.
static uint32_t blockHighStartTime = 0;
// Tracks whether Timer1 is currently connected to the servo output pin.
static bool servoAttached = false;
// Stores the last measured unlock movement time.
static uint32_t lastUnlockMoveMs = 0;
// Stores the last measured lock movement time.
static uint32_t lastLockMoveMs   = 0;
// Stores the last complete unlock-lock cycle time.
static uint32_t lastCycleMs      = 0;

// SLEEP/UI
// Stores the last time keypad or Serial activity happened.
static uint32_t lastActivityTime = 0;
// Stores when normal state LEDs should turn off.
static uint32_t uiVisibleUntil = 0;
// Stores the end of a forced-awake window.
static uint32_t stayAwakeUntilMs = 0;
// Gets set by the keypad pin-change interrupt.
volatile bool wokeFromKeypad = false;
// Gets set by the watchdog interrupt.
volatile bool wokeFromWDT = false;
// Prevents repeated sleep-entry messages.
static bool sleepMessagePrinted = false;
// Tracks the temporary LED feedback pattern currently active.
static LedEvent ledEvent = LED_EVENT_NONE;
// Stores the start time of the temporary LED event.
static uint32_t ledEventStart = 0;
// Forces LEDs off while the controller is asleep.
static bool ledsSleeping = false;

// SHA256
typedef struct {
  uint8_t data[64];
  uint32_t datalen;
  uint64_t bitlen;
  uint32_t state[8];
} Sha256Ctx;
static bool verifyPassword(const char* s);
static bool cryptoEepromSectionActive(void);
static bool batteryAlertActive(void);
static void startBatteryAlert(uint8_t level, uint32_t burstMs);

// UTILITY
// Prints a short state/status message to Serial.
static void spamStatus(const __FlashStringHelper *msg) {
  Serial.println(msg);
}
// Marks user activity and keeps the state LEDs visible briefly.
static void markActivity() {
  uint32_t now = millis();
  lastActivityTime = now;
  uiVisibleUntil = now + UI_HOLD_MS;
  sleepMessagePrinted = false;
  preSleepAlertPlayed = false;
}
// Keeps the controller awake for a requested window.
static void holdAwakeForMs(uint32_t ms) {
  uint32_t now = millis();
  stayAwakeUntilMs = now + ms;
  lastActivityTime = now;
  uiVisibleUntil = now + UI_HOLD_MS;
  sleepMessagePrinted = false;
  preSleepAlertPlayed = false;
}
// Clears the keypad password entry buffer.
static void clearEntered() {
  for (uint8_t i = 0; i < 5; i++) {
    enteredPassword[i] = 0;
  }
  enteredLen = 0;
}
// Checks the current 4-digit keypad entry against the stored password hash.
static bool passwordMatches() {
  if (!hasStoredPassword || enteredLen != 4) {
    return false;
  }
  enteredPassword[4] = 0;
  return verifyPassword(enteredPassword);
}

// LEDS
// Writes the three LED outputs in one place.
static void setLeds(bool redOn, bool greenOn, bool yellowOn) {
  digitalWrite(redPin, redOn ? HIGH : LOW);
  digitalWrite(greenPin, greenOn ? HIGH : LOW);
  digitalWrite(yellowPin, yellowOn ? HIGH : LOW);
}
// Initializes all LED pins and turns them off.
static void initLeds() {
  pinMode(redPin, OUTPUT);
  pinMode(greenPin, OUTPUT);
  pinMode(yellowPin, OUTPUT);
  setLeds(false, false, false);
}
// Starts a temporary LED feedback pattern.
static void startLedEvent(uint8_t eventValue) {
  ledEvent = (LedEvent)eventValue;
  ledEventStart = millis();
}
// Enters keypad password-save mode and clears any old input.
static void enterSavePasswordMode(uint8_t returnState) {
  saveReturnState = (LockState)returnState;
  lockState = STATE_SAVE_PASSWORD;
  unlockHashCount = 0;
  lockedHashCount = 0;
  clearEntered();
  Serial.println(F("SAVE MODE: enter new 4-digit password, then #"));
}
// Services normal LED states and temporary LED events without blocking.
static void runLeds() {
  uint32_t now = millis();
  if (ledsSleeping || cryptoEepromSectionActive()) {
    setLeds(false, false, false);
    return;
  }
  if (ledEvent != LED_EVENT_NONE) {
    uint32_t dt = now - ledEventStart;
    if (ledEvent == LED_EVENT_WRONG) {
      if (dt < 900) {
        bool redOn = ((dt / 120) % 2) == 0;
        setLeds(redOn, false, false);
        return;
      }
      ledEvent = LED_EVENT_NONE;
    }
    else if (ledEvent == LED_EVENT_BLOCKED) {
      if (dt < 1000) {
        bool on = ((dt / 120) % 2) == 0;
        setLeds(on, false, on);
        return;
      }
      ledEvent = LED_EVENT_NONE;
    }
    else if (ledEvent == LED_EVENT_SAVED) {
      if (dt < 900) {
        bool yellowOn = ((dt / 150) % 2) == 0;
        setLeds(false, false, yellowOn);
        return;
      }
      ledEvent = LED_EVENT_NONE;
    }
    else if (ledEvent == LED_EVENT_WAKE) {
      if (dt < 500) {
        bool greenOn = ((dt / 125) % 2) == 0;
        setLeds(false, greenOn, false);
        return;
      }
      ledEvent = LED_EVENT_NONE;
    }
    else {
      ledEvent = LED_EVENT_NONE;
    }
  }
  if (lockState == STATE_SAVE_PASSWORD) {
    bool yellowOn = ((now / 300) % 2) == 0;
    setLeds(false, false, yellowOn);
    return;
  }
  if (batteryAlertActive()) {
    if (railAlertLevel >= 2) {
      setLeds(buzzerToneOn, false, false);
    } else {
      setLeds(false, false, buzzerToneOn);
    }
    return;
  }
  if ((long)(now - uiVisibleUntil) > 0) {
    setLeds(false, false, false);
    return;
  }
  if (lockState == STATE_UNLOCKED || lockState == STATE_UNLOCKING) {
    setLeds(false, true, false);
    return;
  }
  setLeds(true, false, false);
}

// BUZZER/BATTERY
// Starts the buzzer tone for the current alert pulse.
static void buzzerPlayTone() {
  tone(BUZZER_PIN, BUZZER_HZ);
}
// Stops the buzzer tone and forces the pin low.
static void buzzerStopTone() {
  noTone(BUZZER_PIN);
  digitalWrite(BUZZER_PIN, LOW);
}
// Initializes the buzzer output in a quiet state.
static void buzzerInit() {
  pinMode(BUZZER_PIN, OUTPUT);
  digitalWrite(BUZZER_PIN, LOW);
  buzzerStopTone();
}
// Gives one blocking beep for the manual serial buzzer test.
static void buzzerBeepOnce() {
  tone(BUZZER_PIN, BUZZER_HZ);
  delay(120);
  buzzerStopTone();
}
// Reports whether a finite low-battery alert burst is currently active.
static bool batteryAlertActive() {
  return railAlertLevel != 0 && (long)(millis() - railAlertUntilMs) < 0;
}
// Starts a finite warning or critical alert burst (pre-sleep only in this sketch).
static void startBatteryAlert(uint8_t level, uint32_t burstMs) {
  railAlertLevel = level;
  railAlertUntilMs = millis() + burstMs;
  buzzerToneOn = false;
  buzzerNextMs = 0;
}
// Stops any active low-battery alert burst.
static void stopBatteryAlert() {
  railAlertLevel = 0;
  buzzerToneOn = false;
  buzzerNextMs = 0;
  buzzerStopTone();
}
// Services the non-blocking buzzer pattern for active low-battery alert bursts.
static void serviceBuzzer() {
  uint32_t now = millis();
  // Keeps EEPROM and hashing sections electrically quiet.
  if (cryptoEepromSectionActive()) {
    stopBatteryAlert();
    return;
  }
  // Stops the buzzer once the finite alert burst has expired.
  if (!batteryAlertActive()) {
    stopBatteryAlert();
    return;
  }
  // Toggles the buzzer according to the warning or critical timing pattern.
  if (buzzerNextMs == 0 || (long)(now - buzzerNextMs) >= 0) {
    buzzerToneOn = !buzzerToneOn;
    if (railAlertLevel >= 2) {
      buzzerNextMs = now + (buzzerToneOn ? BUZZ_CRIT_ON_MS : BUZZ_CRIT_GAP_MS);
    } 
    else {
      buzzerNextMs = now + (buzzerToneOn ? BUZZ_WARN_ON_MS : BUZZ_WARN_GAP_MS);
    }
    if (buzzerToneOn) buzzerPlayTone();
    else buzzerStopTone();
  }
}
// Releases all keypad columns so only the selected scan column is driven.
static void setAllColumnsHiZ() {
  for (uint8_t i = 0; i < 3; i++) {
    pinMode(COL_PINS[i], INPUT);
    digitalWrite(COL_PINS[i], LOW);
  }
}
// Pulls all keypad columns low so pressing a key can wake the controller through A0.
static void setAllColumnsLowForWake() {
  for (uint8_t i = 0; i < 3; i++) {
    pinMode(COL_PINS[i], OUTPUT);
    digitalWrite(COL_PINS[i], LOW);
  }
}
// Averages A0 readings for keypad row detection.
static int readAnalogAveraged(uint8_t samples) {
  long sum = 0;
  for (uint8_t i = 0; i < samples; i++) {
    sum += analogRead(ROW_ANALOG_PIN);
  }
  return (int)(sum / samples);
}
// Averages A1 readings for servo current-sense blockage detection.
static int readServoSenseAveraged(uint8_t samples) {
  long sum = 0;
  for (uint8_t i = 0; i < samples; i++) {
    sum += analogRead(SERVO_SENSE_PIN);
  }
  return (int)(sum / samples);
}
// Estimates AVcc in millivolts by measuring the internal 1.1 V bandgap against AVcc.
static uint16_t readAvccMilliVolts() {
  ADCSRA |= _BV(ADEN);
  ADMUX = (uint8_t)(_BV(REFS0) | _BV(MUX3) | _BV(MUX2) | _BV(MUX1));
  delayMicroseconds(250);
  // Discards the first conversion after changing the ADC mux for better stability.
  ADCSRA |= _BV(ADSC);
  while (ADCSRA & _BV(ADSC)) {}
  // Uses the second conversion for the actual rail estimate.
  ADCSRA |= _BV(ADSC);
  while (ADCSRA & _BV(ADSC)) {}

  uint8_t low = ADCL;
  uint8_t high = ADCH;
  uint32_t adc = ((uint32_t)high << 8) | low;
  if (adc == 0) return 5000;
  return (uint16_t)(1125300UL / adc);
}
// Averages four AVcc estimates before threshold comparison.
static uint16_t readFiveVRailMilliVoltsAveraged() {
  uint32_t sum = 0;
  for (uint8_t i = 0; i < 4; i++) {
    sum += readAvccMilliVolts();
    delayMicroseconds(100);
  }
  return (uint16_t)(sum / 4);
}
// Prints the measured 5 V rail estimate in volts.
static void printRailMilliVolts(uint16_t rail_mv) {
  Serial.print(F("5 V rail (AVcc est.) ~"));
  Serial.print(rail_mv / 1000);
  Serial.print('.');
  Serial.print((rail_mv % 1000) / 100);
  Serial.println(F(" V"));
}
// Serial-only rail read: no buzzer, no LEDs, no state change (testing / debug).
static void printRailDiagnostic() {
  uint16_t rail = readFiveVRailMilliVoltsAveraged();
  printRailMilliVolts(rail);
  if (rail < RAIL_CRIT_MV) {
    Serial.println(F(" (below critical threshold — pre-sleep would use red LED + fast pattern)"));
  } else if (rail < RAIL_WARN_MV) {
    Serial.println(F(" (below warning threshold — pre-sleep would use yellow LED + slow pattern)"));
  } else if (rail >= RAIL_RECOVER_MV) {
    Serial.println(F(" (OK)"));
  } else {
    Serial.println(F(" (between warn/recover — hysteresis band)"));
  }
}

// KEYPAD SCAN
// Converts a keypad ADC value into a row index.
static int adcToRow(int adc) {
  if (adc < TH_ROW0_MAX) return 0;
  if (adc < TH_ROW1_MAX) return 1;
  if (adc < TH_ROW2_MAX) return 2;
  if (adc < TH_ROW3_MAX) return 3;
  return -1;
}
// Scans keypad columns once and returns the raw key if one is pressed.
static char scanKeyRaw() {
  for (uint8_t col = 0; col < 3; col++) {
    setAllColumnsHiZ();
    pinMode(COL_PINS[col], OUTPUT);
    digitalWrite(COL_PINS[col], LOW);
    delayMicroseconds(80);
    int adc = readAnalogAveraged(4);
    int row = adcToRow(adc);
    if (row >= 0) return KEYMAP[row][col];
  }
  return 0;
}
// Debounces keypad input and returns one event per physical key press.
static char getKeyEvent() {
  static char candidate = 0;
  static uint8_t stableCount = 0;
  static bool waitingForRelease = false;
  static uint8_t releaseCount = 0;
  char raw = scanKeyRaw();
  if (waitingForRelease) {
    if (raw == 0) {
      if (releaseCount < 255) releaseCount++;
      if (releaseCount >= RELEASE_SCANS) {
        waitingForRelease = false;
        candidate = 0;
        stableCount = 0;
        releaseCount = 0;
      }
    } 
    else {
      releaseCount = 0;
    }
    return 0;
  }
  if (raw == 0) {
    candidate = 0;
    stableCount = 0;
    return 0;
  }
  if (raw == candidate) {
    if (stableCount < 255) stableCount++;
  } 
  else {
    candidate = raw;
    stableCount = 1;
  }
  if (stableCount >= DEBOUNCE_SCANS) {
    waitingForRelease = true;
    releaseCount = 0;
    return candidate;
  }
  return 0;
}

// SHA256
#define SHA_ROTR(x, n) (((x) >> (n)) | ((x) << (32u - (n))))
#define SHA_CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define SHA_MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHA_EP0(x) (SHA_ROTR((x), 2) ^ SHA_ROTR((x), 13) ^ SHA_ROTR((x), 22))
#define SHA_EP1(x) (SHA_ROTR((x), 6) ^ SHA_ROTR((x), 11) ^ SHA_ROTR((x), 25))
#define SHA_SIG0(x) (SHA_ROTR((x), 7) ^ SHA_ROTR((x), 18) ^ ((x) >> 3))
#define SHA_SIG1(x) (SHA_ROTR((x), 17) ^ SHA_ROTR((x), 19) ^ ((x) >> 10))
static const uint32_t sha256_k[64] PROGMEM = {
  0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL,
  0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
  0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL,
  0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
  0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
  0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
  0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL,
  0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
  0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL,
  0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
  0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL,
  0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
  0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL,
  0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
  0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
  0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
};
static uint32_t sha256_w[64];
// Runs one SHA-256 compression block.
static void sha256_transform(Sha256Ctx* ctx, const uint8_t* data) {
  uint32_t a, b, c, d, e, f, g, h;
  uint32_t* const m = sha256_w;
  uint8_t i;
  uint8_t j;
  for (i = 0, j = 0; i < 16; i++, j += 4) {
    m[i] = ((uint32_t)data[j] << 24) | ((uint32_t)data[j + 1] << 16) |
           ((uint32_t)data[j + 2] << 8) | (uint32_t)data[j + 3];
  }
  for (; i < 64; i++) {
    m[i] = SHA_SIG1(m[i - 2]) + m[i - 7] + SHA_SIG0(m[i - 15]) + m[i - 16];
  }
  a = ctx->state[0];
  b = ctx->state[1];
  c = ctx->state[2];
  d = ctx->state[3];
  e = ctx->state[4];
  f = ctx->state[5];
  g = ctx->state[6];
  h = ctx->state[7];
  for (uint8_t r = 0; r < 64; r++) {
    uint32_t kr = pgm_read_dword(&sha256_k[r]);
    uint32_t t1 = h + SHA_EP1(e) + SHA_CH(e, f, g) + kr + m[r];
    uint32_t t2 = SHA_EP0(a) + SHA_MAJ(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }
  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
  ctx->state[4] += e;
  ctx->state[5] += f;
  ctx->state[6] += g;
  ctx->state[7] += h;
}
// Initializes a SHA-256 context.
static void sha256_init(Sha256Ctx* ctx) {
  ctx->datalen = 0;
  ctx->bitlen = 0;
  ctx->state[0] = 0x6a09e667UL;
  ctx->state[1] = 0xbb67ae85UL;
  ctx->state[2] = 0x3c6ef372UL;
  ctx->state[3] = 0xa54ff53aUL;
  ctx->state[4] = 0x510e527fUL;
  ctx->state[5] = 0x9b05688cUL;
  ctx->state[6] = 0x1f83d9abUL;
  ctx->state[7] = 0x5be0cd19UL;
}
// Feeds bytes into the SHA-256 context.
static void sha256_update(Sha256Ctx* ctx, const uint8_t* data, size_t len) {
  for (size_t n = 0; n < len; n++) {
    ctx->data[ctx->datalen] = data[n];
    ctx->datalen++;
    if (ctx->datalen == 64) {
      sha256_transform(ctx, ctx->data);
      ctx->bitlen += 512;
      ctx->datalen = 0;
    }
  }
}
// Finishes SHA-256 padding and outputs the 32-byte digest.
static void sha256_final(Sha256Ctx* ctx, uint8_t* hash) {
  uint32_t i = ctx->datalen;

  if (ctx->datalen < 56) {
    ctx->data[i++] = 0x80;
    while (i < 56) ctx->data[i++] = 0;
  } 
  else {
    ctx->data[i++] = 0x80;
    while (i < 64) ctx->data[i++] = 0;
    sha256_transform(ctx, ctx->data);
    memset(ctx->data, 0, 56);
  }
  ctx->bitlen += (uint64_t)ctx->datalen * 8ULL;
  ctx->data[56] = (uint8_t)(ctx->bitlen >> 56);
  ctx->data[57] = (uint8_t)(ctx->bitlen >> 48);
  ctx->data[58] = (uint8_t)(ctx->bitlen >> 40);
  ctx->data[59] = (uint8_t)(ctx->bitlen >> 32);
  ctx->data[60] = (uint8_t)(ctx->bitlen >> 24);
  ctx->data[61] = (uint8_t)(ctx->bitlen >> 16);
  ctx->data[62] = (uint8_t)(ctx->bitlen >> 8);
  ctx->data[63] = (uint8_t)(ctx->bitlen);
  sha256_transform(ctx, ctx->data);
  for (i = 0; i < 4; i++) {
    hash[i]      = (uint8_t)((ctx->state[0] >> (24 - i * 8)) & 0xff);
    hash[i + 4]  = (uint8_t)((ctx->state[1] >> (24 - i * 8)) & 0xff);
    hash[i + 8]  = (uint8_t)((ctx->state[2] >> (24 - i * 8)) & 0xff);
    hash[i + 12] = (uint8_t)((ctx->state[3] >> (24 - i * 8)) & 0xff);
    hash[i + 16] = (uint8_t)((ctx->state[4] >> (24 - i * 8)) & 0xff);
    hash[i + 20] = (uint8_t)((ctx->state[5] >> (24 - i * 8)) & 0xff);
    hash[i + 24] = (uint8_t)((ctx->state[6] >> (24 - i * 8)) & 0xff);
    hash[i + 28] = (uint8_t)((ctx->state[7] >> (24 - i * 8)) & 0xff);
  }
}
// Hashes a complete buffer with SHA-256.
static void sha256_buffer(const uint8_t* data, size_t len, uint8_t* hash32) {
  static Sha256Ctx sha256_ctx_static;
  sha256_init(&sha256_ctx_static);
  sha256_update(&sha256_ctx_static, data, len);
  sha256_final(&sha256_ctx_static, hash32);
}

// EEPROM/SECURE STORAGE
static uint8_t cryptoEepromHold = 0;
// Begins a quiet section for hashing and EEPROM writes.
static void beginCryptoEepromSection() {
  if (cryptoEepromHold == 0) {
    buzzerStopTone();
    buzzerToneOn = false;
    setLeds(false, false, false);
  }
  cryptoEepromHold++;
}
// Ends a quiet section for hashing and EEPROM writes.
static void endCryptoEepromSection() {
  if (cryptoEepromHold > 0) cryptoEepromHold--;
}
// Reports whether hashing or EEPROM writing is currently active.
static bool cryptoEepromSectionActive() {
  return cryptoEepromHold != 0;
}
// Reads one byte directly from EEPROM.
static uint8_t eeRead(uint16_t a) {
  while (EECR & (1 << EEPE)) {}
  EEAR = a;
  EECR |= (1 << EERE);
  return EEDR;
}
// Writes one byte directly to EEPROM using the required timed sequence.
static void eeWrite(uint16_t a, uint8_t v) {
  while (EECR & (1 << EEPE)) {}
  uint8_t s = SREG;
  cli();
  EEAR = a;
  EEDR = v;
  EECR |= (1 << EEMPE);
  EECR |= (1 << EEPE);
  SREG = s;
  delayMicroseconds(4500);
}
// Clears sensitive temporary buffers from RAM.
static void secureWipe(uint8_t* p, size_t n) {
  for (size_t i = 0; i < n; i++) 
    p[i] = 0;
}
// Compares byte arrays without early exit.
static bool constTimeEqual(const uint8_t* a, const uint8_t* b, uint8_t n) {
  uint8_t d = 0;
  for (uint8_t i = 0; i < n; i++) 
    d |= (uint8_t)(a[i] ^ b[i]);
  return d == 0;
}
// Generates a 16-byte salt from analog noise and timing jitter.
static void generateSalt16(uint8_t* salt) {
  for (uint8_t i = 0; i < 16; i++) {
    uint32_t v = (uint32_t)analogRead(ROW_ANALOG_PIN) ^ (uint32_t)analogRead(SERVO_SENSE_PIN) ^
                 (uint32_t)micros() ^ ((uint32_t)millis() << 3) ^ ((uint32_t)i * 0x9e3779b1UL);
    salt[i] = (uint8_t)(v ^ (v >> 8) ^ (v >> 16) ^ (v >> 24));
    delayMicroseconds(31U + (uint16_t)(i * 13U));
  }
}
// Builds salt plus password bytes and hashes them.
static void hashPasswordBytesCore(const uint8_t* salt16, const uint8_t* pw, uint8_t pwLen, uint8_t out32[32]) {
  uint8_t buf[24];
  memcpy(buf, salt16, 16);
  memcpy(buf + 16, pw, pwLen);
  sha256_buffer(buf, (size_t)(16 + pwLen), out32);
  secureWipe(buf, sizeof(buf));
}
// Hashes a password while suppressing LEDs and buzzer noise.
static void hashPasswordBytes(const uint8_t* salt16, const uint8_t* pw, uint8_t pwLen, uint8_t out32[32]) {
  beginCryptoEepromSection();
  hashPasswordBytesCore(salt16, pw, pwLen, out32);
  endCryptoEepromSection();
}
// Writes the secure EEPROM record with magic bytes committed last.
static void writeSecureRecordCore(const uint8_t* salt16, const uint8_t* hash32, uint8_t pwLenMeta) {
  eeWrite(EE_BASE + 0, 0xFF);
  eeWrite(EE_BASE + 1, 0xFF);
  delay(15);
  eeWrite(EE_BASE + 2, SEC_VERSION);
  eeWrite(EE_BASE + 3, pwLenMeta);
  for (uint8_t i = 0; i < 16; i++) {
    eeWrite(EE_BASE + 4 + i, salt16[i]);
    if ((i & 3) == 3) delay(5);
  }
  for (uint8_t i = 0; i < 32; i++) {
    eeWrite(EE_BASE + 20 + i, hash32[i]);
    if ((i & 3) == 3) delay(5);
  }
  delay(12);
  eeWrite(EE_BASE + 0, SEC_MAGIC0);
  eeWrite(EE_BASE + 1, SEC_MAGIC1);
  delay(4);
}
// Saves a salted password hash into EEPROM.
static bool savePasswordHash(const uint8_t* p, uint8_t n) {
  if (n == 0 || n > maxLength) return false;
  beginCryptoEepromSection();
  generateSalt16(storedSalt);
  uint8_t h[32];
  hashPasswordBytesCore(storedSalt, p, n, h);
  memcpy(storedHash, h, 32);
  writeSecureRecordCore(storedSalt, h, n);
  bool committed = (eeRead(EE_BASE + 0) == SEC_MAGIC0 && eeRead(EE_BASE + 1) == SEC_MAGIC1 &&
                    eeRead(EE_BASE + 2) == SEC_VERSION && eeRead(EE_BASE + 3) == n);
  secureWipe(h, sizeof(h));
  endCryptoEepromSection();
  if (!committed) {
    hasStoredPassword = false;
    memset(storedSalt, 0, sizeof(storedSalt));
    memset(storedHash, 0, sizeof(storedHash));
    return false;
  }
  hasStoredPassword = true;
  return true;
}
// Migrates an old plaintext EEPROM password into the secure format.
static bool migrateLegacyPlaintext() {
  if (eeRead(EE_BASE + 0) != LEGACY_M0 || eeRead(EE_BASE + 1) != LEGACY_M1) 
    return false;
  uint8_t n = eeRead(EE_BASE + 2);
  if (n == 0 || n > maxLength) 
    return false;
  uint8_t buf[8];
  for (uint8_t i = 0; i < n; i++) 
    buf[i] = eeRead(EE_BASE + 3 + i);
  Serial.println(F("Migrating EEPROM from legacy plaintext to salted SHA-256."));
  bool ok = savePasswordHash(buf, n);
  secureWipe(buf, sizeof(buf));
  if (!ok) {
    Serial.println(F("Migrate save failed."));
    return false;
  }
  return true;
}
// Loads the secure password record or migrates an older record.
static bool loadStoredPassword() {
  if (eeRead(EE_BASE + 0) == SEC_MAGIC0 && eeRead(EE_BASE + 1) == SEC_MAGIC1 && eeRead(EE_BASE + 2) == SEC_VERSION) {
    for (uint8_t i = 0; i < 16; i++) storedSalt[i] = eeRead(EE_BASE + 4 + i);
    for (uint8_t i = 0; i < 32; i++) storedHash[i] = eeRead(EE_BASE + 20 + i);
    hasStoredPassword = true;
    return true;
  }
  if (migrateLegacyPlaintext()) return true;
  hasStoredPassword = false;
  return false;
}
// Verifies a candidate password against the stored salted hash.
static bool verifyPassword(const char* s) {
  if (!hasStoredPassword) 
    return false;
  uint8_t n = (uint8_t)strlen(s);
  if (n == 0 || n > maxLength) 
    return false;
  uint8_t candidate[32];
  hashPasswordBytes(storedSalt, (const uint8_t*)s, n, candidate);
  bool ok = constTimeEqual(candidate, storedHash, 32);
  secureWipe(candidate, sizeof(candidate));
  return ok;
}

// SERVO CONTROL
// Initializes the servo power switch in the off state.
static void servoPowerInit() {
  pinMode(SERVO_PWR_PIN, OUTPUT);
  digitalWrite(SERVO_PWR_PIN, SERVO_PWR_ACTIVE_LOW ? HIGH : LOW);
}
// Turns on servo power before motion.
static void servoPowerOn() {
  digitalWrite(SERVO_PWR_PIN, SERVO_PWR_ACTIVE_LOW ? LOW : HIGH);
  delay(SERVO_POWER_SETTLE_MS);
}
// Turns off servo power after motion.
static void servoPowerOff() {
  digitalWrite(SERVO_PWR_PIN, SERVO_PWR_ACTIVE_LOW ? HIGH : LOW);
}
// Enables Timer1 OC1A output to drive the servo signal.
static void servoAttach() {
  if (!servoAttached) {
    TCCR1A |= _BV(COM1A1);
    servoAttached = true;
  }
}
// Disables Timer1 OC1A output and drives the servo pin low.
static void servoDetach() {
  TCCR1A &= (uint8_t)~_BV(COM1A1);
  digitalWrite(SERVO_PIN, LOW);
  servoAttached = false;
}
// Updates the Timer1 compare value for the requested servo pulse width.
static inline void setServoPulse(uint16_t us) {
  uint16_t ticks = us * 2;
  noInterrupts();
  OCR1A = ticks;
  interrupts();
}
// Configures Timer1 for 50 Hz servo PWM.
static void setupTimer1() {
  servoPowerInit();
  pinMode(SERVO_PIN, OUTPUT);
  digitalWrite(SERVO_PIN, LOW);
  TCCR1A = 0;
  TCCR1B = 0;
  TCCR1A |= _BV(WGM11);
  TCCR1B |= _BV(WGM13) | _BV(WGM12);
  TCCR1B |= _BV(CS11);
  ICR1 = PERIOD * 2;
  servoDetach();
  setServoPulse(RESET);
}
// Starts a monitored servo movement between lock states.
static void startServoMotion(uint8_t prevState, uint8_t nextState, uint8_t motionState, uint16_t pulse) {
  motionPrevState = (LockState)prevState;
  motionNextState = (LockState)nextState;
  motionStartTime = millis();
  blockHighStartTime = 0;
  lockState = (LockState)motionState;
  servoPowerOn();
  servoAttach();
  setServoPulse(pulse);
  markActivity();
}
// Records and prints the last lock or unlock movement time.
static void recordMotionTime(uint32_t dt) {
  if (motionNextState == STATE_UNLOCKED) {
    lastUnlockMoveMs = dt;
    Serial.print(F("Unlock move time: "));
    Serial.print(dt);
    Serial.println(F(" ms"));
  } 
  else if (motionNextState == STATE_LOCKED) {
    lastLockMoveMs = dt;
    Serial.print(F("Lock move time: "));
    Serial.print(dt);
    Serial.println(F(" ms"));
  }
}
// Completes a servo movement that reached its timeout without blockage.
static void finishServoMotionSuccess() {
  uint32_t dt = millis() - motionStartTime;
  recordMotionTime(dt);
  lockState = motionNextState;
  servoDetach();
  servoPowerOff();
  if (lockState == STATE_LOCKED) 
    spamStatus(F("LOCKED"));
  else if (lockState == STATE_UNLOCKED) 
    spamStatus(F("UNLOCKED"));
  markActivity();
}
// Cancels a blocked servo movement and returns to the previous state.
static void finishServoMotionBlocked() {
  uint32_t dt = millis() - motionStartTime;
  recordMotionTime(dt);
  lockState = motionPrevState;
  servoDetach();
  servoPowerOff();
  if (motionPrevState == STATE_UNLOCKED) 
    spamStatus(F("BLOCKED MOTOR -> REVERTED TO UNLOCKED"));
  else 
    spamStatus(F("BLOCKED MOTOR -> REVERTED TO LOCKED"));
  startLedEvent(LED_EVENT_BLOCKED);
  clearEntered();
  unlockHashCount = 0;
  lockedHashCount = 0;
  markActivity();
}
// Monitors servo current and finishes motion states without blocking.
static void serviceServoMotion() {
  if (lockState != STATE_LOCKING && lockState != STATE_UNLOCKING) return;
  uint32_t now = millis();
  int sense = readServoSenseAveraged(8);
  if ((uint32_t)(now - motionStartTime) >= MOVE_GRACE_MS) {
    if (sense >= BLOCK_ADC_THRESHOLD) {
      if (blockHighStartTime == 0) {
        blockHighStartTime = now;
      } 
      else if ((uint32_t)(now - blockHighStartTime) >= BLOCK_CONFIRM_MS) {
        finishServoMotionBlocked();
        return;
      }
    } 
    else {
      blockHighStartTime = 0;
    }
  }
  if ((uint32_t)(now - motionStartTime) >= MOVE_TIMEOUT_MS) {
    finishServoMotionSuccess();
  }
}

// SLEEP/WAKE
// Handles keypad pin-change wake events.
ISR(PCINT1_vect) {
  wokeFromKeypad = true;
}
// Handles watchdog wake events.
ISR(WDT_vect) {
  wokeFromWDT = true;
}
// Enables A0 pin-change interrupt wake.
static void enableWakeOnA0() {
  PCIFR |= _BV(PCIF1);
  PCICR |= _BV(PCIE1);
  PCMSK1 |= _BV(PCINT8);
}
// Disables A0 pin-change interrupt wake.
static void disableWakeOnA0() {
  PCMSK1 &= (uint8_t)~_BV(PCINT8);
  PCICR &= (uint8_t)~_BV(PCIE1);
}
// Enables watchdog interrupt wake.
static void enableWatchdogWake() {
  MCUSR &= (uint8_t)~_BV(WDRF);
  cli();
  WDTCSR = _BV(WDCE) | _BV(WDE);
  WDTCSR = _BV(WDIE) | _BV(WDP1);
  sei();
}
// Disables watchdog interrupt wake.
static void disableWatchdogWake() {
  MCUSR &= (uint8_t)~_BV(WDRF);
  cli();
  WDTCSR = _BV(WDCE) | _BV(WDE);
  WDTCSR = 0;
  sei();
}
// Enters ATmega328P power-down sleep mode.
static inline void enterPowerDownSleepRaw() {
  SMCR = 0;
  SMCR |= _BV(SM1);
  SMCR |= _BV(SE);
  sei();
  asm volatile("sleep" ::: "memory");
  SMCR &= (uint8_t)~_BV(SE);
}
// Enters sleep after inactivity when no critical task is active.
static void enterSleepIfIdle() {
  uint32_t now = millis();
  if ((unsigned long)(now - lastActivityTime) < IDLE_SLEEP_MS) 
    return;
  if ((long)(stayAwakeUntilMs - now) > 0) 
    return;
  if (lockState == STATE_LOCKING || lockState == STATE_UNLOCKING) 
    return;
  // Right before sleep: one rail check; if low, fixed 3 s buzzer + LED (no holdAwake — preserves idle timer).
  // Gate it so watchdog-only wake cycles do not replay the burst indefinitely.
  {
    uint16_t rail = readFiveVRailMilliVoltsAveraged();
    uint8_t preSleepLevel = 0;
    if (rail < RAIL_CRIT_MV) {
      preSleepLevel = 2;
    } 
    else if (rail < RAIL_WARN_MV) {
      preSleepLevel = 1;
    }
    if (preSleepLevel != 0 && !preSleepAlertPlayed) {
      // Reduce concurrent load during alert burst.
      servoDetach();
      servoPowerOff();
      ledEvent = LED_EVENT_NONE;
      Serial.println(F("Low supply before sleep: 3 s alert, then sleep."));
      Serial.flush();
      startBatteryAlert(preSleepLevel, RAIL_ALERT_SLEEP_PRE_MS);
      uint32_t preSleepEnd = millis() + RAIL_ALERT_SLEEP_PRE_MS;
      while ((long)(millis() - preSleepEnd) < 0) {
        serviceBuzzer();
        runLeds();
        delay(2);
      }
      stopBatteryAlert();
      preSleepAlertPlayed = true;
    }
    if (preSleepLevel == 0) preSleepAlertPlayed = false;
  }
  wokeFromKeypad = false;
  wokeFromWDT = false;
  setAllColumnsLowForWake();
  pinMode(ROW_ANALOG_PIN, INPUT);
  digitalWrite(ROW_ANALOG_PIN, LOW);
  enableWakeOnA0();
  if (USE_WDT_WAKE) 
    enableWatchdogWake();
  if (!sleepMessagePrinted) {
    Serial.println(F("Entering sleep mode..."));
    Serial.flush();
    delay(10);
    sleepMessagePrinted = true;
  }
  ledsSleeping = true;
  setLeds(false, false, false);
  buzzerStopTone();
  servoDetach();
  servoPowerOff();
  ADCSRA &= (uint8_t)~_BV(ADEN);
  cli();
  enterPowerDownSleepRaw();
  ADCSRA |= _BV(ADEN);
  disableWakeOnA0();
  if (USE_WDT_WAKE) 
    disableWatchdogWake();
  setAllColumnsHiZ();
  delay(20);
  ledsSleeping = false;
  char raw = scanKeyRaw();
  if (wokeFromKeypad || raw != 0) {
    markActivity();
    Serial.println(F("Woke from sleep."));
    startLedEvent(LED_EVENT_WAKE);
  }
}

// MEASUREMENT HELPERS
// Runs one unlock/lock cycle for timing and current measurement.
static void runOneCycleTest() {
  Serial.println(F("Starting 1-cycle test..."));
  uint32_t t0 = millis();
  if (lockState != STATE_LOCKED) {
    lockState = STATE_LOCKED;
    servoDetach();
    servoPowerOff();
    delay(100);
  }
  startServoMotion(STATE_LOCKED, STATE_UNLOCKED, STATE_UNLOCKING, UNLOCK);
  while (lockState == STATE_UNLOCKING) {
    serviceServoMotion();
    serviceBuzzer();
    runLeds();
  }
  delay(250);
  startServoMotion(STATE_UNLOCKED, STATE_LOCKED, STATE_LOCKING, LOCK);
  while (lockState == STATE_LOCKING) {
    serviceServoMotion();
    serviceBuzzer();
    runLeds();
  }
  lastCycleMs = millis() - t0;
  Serial.print(F("1-cycle total time: "));
  Serial.print(lastCycleMs);
  Serial.println(F(" ms"));
}
// Runs repeated unlock-lock cycles for endurance and timing tests.
static void runRepeatedCycleTest(uint8_t n) {
  Serial.print(F("Starting "));
  Serial.print(n);
  Serial.println(F(" cycles..."));
  uint32_t t0 = millis();
  for (uint8_t i = 0; i < n; i++) {
    if (lockState != STATE_LOCKED) {
      lockState = STATE_LOCKED;
      servoDetach();
      servoPowerOff();
      delay(100);
    }
    startServoMotion(STATE_LOCKED, STATE_UNLOCKED, STATE_UNLOCKING, UNLOCK);
    while (lockState == STATE_UNLOCKING) {
      serviceServoMotion();
      serviceBuzzer();
      runLeds();
    }
    delay(250);
    startServoMotion(STATE_UNLOCKED, STATE_LOCKED, STATE_LOCKING, LOCK);
    while (lockState == STATE_LOCKING) {
      serviceServoMotion();
      serviceBuzzer();
      runLeds();
    }
    delay(250);
  }
  lastCycleMs = millis() - t0;
  Serial.print(F("Total time for "));
  Serial.print(n);
  Serial.print(F(" cycles: "));
  Serial.print(lastCycleMs);
  Serial.println(F(" ms"));
}
// Prints the latest motion timing measurements.
static void printTimingSummary() {
  Serial.print(F("Last unlock move: "));
  Serial.print(lastUnlockMoveMs);
  Serial.println(F(" ms"));
  Serial.print(F("Last lock move: "));
  Serial.print(lastLockMoveMs);
  Serial.println(F(" ms"));
  Serial.print(F("Last total cycle: "));
  Serial.print(lastCycleMs);
  Serial.println(F(" ms"));
}
// SETUP/LOOP
// Initializes hardware, firmware state, EEPROM data, and Serial commands.
void setup() {
  Serial.begin(115200);
  ACSR |= _BV(ACD);
  PRR   |= _BV(PRSPI) | _BV(PRTWI);
  setAllColumnsHiZ();
  pinMode(ROW_ANALOG_PIN, INPUT);
  pinMode(SERVO_SENSE_PIN, INPUT);
  buzzerInit();
  initLeds();
  setupTimer1();
  servoPowerOn();
  servoAttach();
  setServoPulse(RESET);
  delay(250);
  servoDetach();
  servoPowerOff();
  if (loadStoredPassword()) {
    Serial.println(F("Loaded password hash from EEPROM."));
  } 
  else {
    Serial.println(F("No password found in EEPROM."));
  }
  Serial.println(F("Commands:"));
  Serial.println(F("  S <code> : save password (salted SHA-256)"));
  Serial.println(F("  T <code> : test password"));
  Serial.println(F("  L        : lock"));
  Serial.println(F("  U        : unlock"));
  Serial.println(F("  R        : servo reset pulse"));
  Serial.println(F("  B        : print 5V rail (Serial only, no buzzer/LED)"));
  Serial.println(F("  P        : beep buzzer once"));
  Serial.println(F("  A        : stay awake for 60 s"));
  Serial.println(F("  X        : run 1 unlock-lock cycle"));
  Serial.println(F("  Z        : run 10 unlock-lock cycles"));
  Serial.println(F("  M        : print last motion times"));
  Serial.println(F("  Keypad   : ##### <code> # saves password, <code> # tests password, * locks"));
  markActivity();
  runLeds();
}
// Runs the main non-blocking locker state machine.
void loop() {
  serviceServoMotion();
  serviceBuzzer();
  runLeds();
  // Leaves input handling alone while the servo is moving and being monitored.
  if (lockState == STATE_LOCKING || lockState == STATE_UNLOCKING) {
    return;
  }
  enterSleepIfIdle();
  char key = getKeyEvent();
  if (key != 0) {
    markActivity();
    Serial.print(F("Key pressed: "));
    Serial.println(key);
    // Routes all keypad input to password-save behavior while in save mode.
    if (lockState == STATE_SAVE_PASSWORD) {
      // Cancels password-save mode when * is pressed.
      if (key == '*') {
        lockState = saveReturnState;
        clearEntered();
        unlockHashCount = 0;
        lockedHashCount = 0;
        Serial.println(F("Canceled."));
        return;
      }
      // Stores numeric keypad entries until four password digits are collected.
      if (key >= '0' && key <= '9') {
        if (enteredLen < 4) {
          enteredPassword[enteredLen] = key;
          enteredLen++;
        }
        return;
      }
      // Saves a new four-digit password when # is pressed.
      if (key == '#') {
        if (enteredLen == 4) {
          uint8_t tmp[8];
          for (uint8_t i = 0; i < 4; i++) tmp[i] = (uint8_t)enteredPassword[i];
          if (savePasswordHash(tmp, 4)) {
            secureWipe(tmp, sizeof(tmp));
            Serial.println(F("Password saved."));
            lockState = saveReturnState;
            clearEntered();
            unlockHashCount = 0;
            lockedHashCount = 0;
            startLedEvent(LED_EVENT_SAVED);
          } 
          else {
            secureWipe(tmp, sizeof(tmp));
            Serial.println(F("Save failed."));
          }
        } 
        else {
          Serial.println(F("SAVE MODE: enter 4 digits, then #"));
        }
        return;
      }
      return;
    }
    // Treats * as clear in locked states and as the lock command when unlocked.
    if (key == '*') {
      clearEntered();
      unlockHashCount = 0;
      lockedHashCount = 0;

      if (lockState == STATE_UNLOCKED) {
        startServoMotion(STATE_UNLOCKED, STATE_LOCKED, STATE_LOCKING, LOCK);
        Serial.println(F("Locking..."));
      }
      return;
    }
    // Watches for five # presses from unlocked state to enter save mode.
    if (lockState == STATE_UNLOCKED) {
      lockedHashCount = 0;
      if (key == '#') {
        unlockHashCount++;
        if (unlockHashCount >= 5) enterSavePasswordMode(STATE_UNLOCKED);
      } 
      else {
        unlockHashCount = 0;
      }
      return;
    }
    // Stores numeric keypad entries until four password digits are collected.
    if (key >= '0' && key <= '9') {
      lockedHashCount = 0;
      if (enteredLen < 4) {
        enteredPassword[enteredLen] = key;
        enteredLen++;
      }
      return;
    }
    // Submits the entered password when # is pressed.
    if (key == '#') {
      if (enteredLen == 0) {
        if (lockedHashCount < 255) lockedHashCount++;
        if (lockedHashCount >= 5) enterSavePasswordMode(STATE_LOCKED);
        return;
      }
      if (enteredLen != 4) {
        clearEntered();
        if (lockedHashCount < 255) lockedHashCount++;
        if (lockedHashCount >= 5) enterSavePasswordMode(STATE_LOCKED);
        return;
      }
      lockedHashCount = 0;
      if (passwordMatches()) {
        clearEntered();
        unlockHashCount = 0;
        startServoMotion(STATE_LOCKED, STATE_UNLOCKED, STATE_UNLOCKING, UNLOCK);
        Serial.println(F("Unlocking..."));
      } 
      else {
        clearEntered();
        Serial.println(F("WRONG PASSWORD"));
        startLedEvent(LED_EVENT_WRONG);
      }
      return;
    }
    lockedHashCount = 0;
  }
  // Handles Serial test and debug commands when connected to a computer.
  if (Serial.available()) {
    markActivity();
    char c = (char)Serial.read();
    if (c == 'S' || c == 'T') {
      char line[32];
      line[0] = c;
      size_t n = Serial.readBytesUntil('\n', line + 1, sizeof(line) - 2);
      line[n + 1] = 0;
      if (n && line[n] == '\r') line[n] = 0;
      if (c == 'S' && line[1] == ' ') {
        const char* p = line + 2;
        uint8_t L = (uint8_t)strlen(p);
        if (L == 0 || L > maxLength) {
          Serial.println(F("Incorrect length."));
          return;
        }
        uint8_t tmp[8];
        for (uint8_t i = 0; i < L; i++) tmp[i] = (uint8_t)p[i];
        if (savePasswordHash(tmp, L)) {
          secureWipe(tmp, sizeof(tmp));
          Serial.println(F("Password saved."));
          startLedEvent(LED_EVENT_SAVED);
        } 
        else {
          secureWipe(tmp, sizeof(tmp));
          Serial.println(F("Password save failed."));
        }
      }
      else if (c == 'T' && line[1] == ' ') {
        const char* p = line + 2;
        if (!hasStoredPassword) {
          Serial.println(F("No password set."));
          return;
        }
        Serial.println(verifyPassword(p) ? F("UNLOCK") : F("DENIED"));
      }
    }
    else if (c == 'L') {
      if (lockState == STATE_UNLOCKED) {
        startServoMotion(STATE_UNLOCKED, STATE_LOCKED, STATE_LOCKING, LOCK);
        Serial.println(F("Locking..."));
      }
    }
    else if (c == 'U') {
      if (lockState == STATE_LOCKED) {
        startServoMotion(STATE_LOCKED, STATE_UNLOCKED, STATE_UNLOCKING, UNLOCK);
        Serial.println(F("Unlocking..."));
      }
    }
    else if (c == 'R') {
      servoPowerOn();
      servoAttach();
      setServoPulse(RESET);
      delay(250);
      servoDetach();
      servoPowerOff();
      Serial.println(F("Servo reset pulse sent."));
    }
    else if (c == 'B' || c == 'b') {
      printRailDiagnostic();
    }
    else if (c == 'P' || c == 'p') {
      buzzerBeepOnce();
      Serial.println(F("Buzzer test beep."));
    }
    else if (c == 'A' || c == 'a') {
      holdAwakeForMs(AWAKE_HOLD_MS);
      Serial.println(F("Awake-hold started for 60 s."));
    }
    else if (c == 'X' || c == 'x') {
      runOneCycleTest();
    }
    else if (c == 'Z' || c == 'z') {
      runRepeatedCycleTest(10);
    }
    else if (c == 'M' || c == 'm') {
      printTimingSummary();
    }
  }
}
