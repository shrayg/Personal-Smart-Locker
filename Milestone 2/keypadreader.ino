/*
  Wiring summary:
    Columns: C1->D2, C2->D3, C3->D4
    A0 node:
      - 10k from A0 to 5V
      - Row1 -> 1.0k -> A0
      - Row2 -> 3.3k -> A0
      - Row3 -> 8.2k -> A0
      - Row4 -> 22k  -> A0
*/

const uint8_t COL_PINS[3] = {2, 3, 4};
const uint8_t ROW_ANALOG_PIN = A0;

// Key layout assumes rows are: [1 2 3], [4 5 6], [7 8 9], [* 0 #]
const char KEYMAP[4][3] = {
  {'1','2','3'},
  {'4','5','6'},
  {'7','8','9'},
  {'*','0','#'}
};

// Thresholds are midpoints between expected ADC values:
// expected: 93, 254, 461, 703, (none ~1023)
const int TH_ROW0_MAX = 173;  // < 173  -> row 0
const int TH_ROW1_MAX = 357;  // < 357  -> row 1
const int TH_ROW2_MAX = 582;  // < 582  -> row 2
const int TH_ROW3_MAX = 863;  // < 863  -> row 3
// >= 863 -> none

const uint8_t DEBOUNCE_SCANS = 5;
const uint8_t RELEASE_SCANS  = 5;

/* ---------------- Password and lock logic ---------------- */

enum LockState {
  STATE_LOCKED = 0,
  STATE_UNLOCKED = 1
};

static LockState lockState = STATE_LOCKED;

// Change this to any 4 digit password you want
static const char STORED_PASSWORD[5] = "5274";

static char enteredPassword[5] = {0, 0, 0, 0, 0};
static uint8_t enteredLen = 0;

static void spamStatus(const char *msg) {
  Serial.println(msg);
  Serial.println(msg);
  Serial.println(msg);
}

static void clearEntered() {
  for (uint8_t i = 0; i < 5; i++) enteredPassword[i] = 0;
  enteredLen = 0;
}

static bool passwordMatches() {
  for (uint8_t i = 0; i < 4; i++) {
    if (enteredPassword[i] != STORED_PASSWORD[i]) return false;
  }
  return true;
}

/* ---------------- Keypad scan functions ---------------- */

static void setAllColumnsHiZ() {
  for (uint8_t i = 0; i < 3; i++) {
    pinMode(COL_PINS[i], INPUT);     // high impedance
    digitalWrite(COL_PINS[i], LOW);  // ensure pullup not enabled
  }
}

static int readAnalogAveraged(uint8_t samples) {
  long sum = 0;
  for (uint8_t i = 0; i < samples; i++) {
    sum += analogRead(ROW_ANALOG_PIN);
  }
  return (int)(sum / samples);
}

static int adcToRow(int adc) {
  if (adc < TH_ROW0_MAX) return 0;
  if (adc < TH_ROW1_MAX) return 1;
  if (adc < TH_ROW2_MAX) return 2;
  if (adc < TH_ROW3_MAX) return 3;
  return -1; // none
}

// Returns a key char if any key is currently held, else returns 0
static char scanKeyRaw() {
  for (uint8_t col = 0; col < 3; col++) {
    setAllColumnsHiZ();

    // Drive this column low
    pinMode(COL_PINS[col], OUTPUT);
    digitalWrite(COL_PINS[col], LOW);

    delayMicroseconds(80); // settle time for ADC sampling

    int adc = readAnalogAveraged(4);
    int row = adcToRow(adc);

    if (row >= 0) {
      return KEYMAP[row][col];
    }
  }
  return 0;
}

// Debounced, one event per physical press
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
    } else {
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
  } else {
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

/* ---------------- Arduino setup and loop ---------------- */

void setup() {
  Serial.begin(115200);

  // Columns start high impedance
  setAllColumnsHiZ();

  // A0 is analog input, external 10k to 5V provides the pull
  pinMode(ROW_ANALOG_PIN, INPUT);

  Serial.println("Keypad ready. Enter 4 digits then press #. Press * to lock.");
  spamStatus("LOCKED");
}

void loop() {
  char key = getKeyEvent();
  if (key == 0) return;

  // Optional: show every key press
  Serial.print("Key pressed: ");
  Serial.println(key);

  // * is always the lock button
  if (key == '*') {
    lockState = STATE_LOCKED;
    clearEntered();
    spamStatus("LOCKED");
    return;
  }

  // If already unlocked, ignore everything except *
  if (lockState == STATE_UNLOCKED) {
    return;
  }

  // Locked state behavior:
  // Collect exactly 4 digits, then user presses # to submit.
  if (key >= '0' && key <= '9') {
    if (enteredLen < 4) {
      enteredPassword[enteredLen] = key;
      enteredLen++;
    }
    return;
  }

  if (key == '#') {
    if (enteredLen == 4 && passwordMatches()) {
      lockState = STATE_UNLOCKED;
      clearEntered();
      spamStatus("UNLOCKED");
    } else {
      clearEntered();
      Serial.println("WRONG PASSWORD");
    }
    return;
  }
}
