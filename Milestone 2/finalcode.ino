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

#include <Arduino.h>
#include <avr/io.h>
#include <avr/interrupt.h>
#include <string.h>

const uint8_t COL_PINS[3] = {2, 3, 4};
const uint8_t ROW_ANALOG_PIN = A0;

const char KEYMAP[4][3] = {
  {'1','2','3'},
  {'4','5','6'},
  {'7','8','9'},
  {'*','0','#'}
};

const int TH_ROW0_MAX = 173;
const int TH_ROW1_MAX = 357;
const int TH_ROW2_MAX = 582;
const int TH_ROW3_MAX = 863;

const uint8_t DEBOUNCE_SCANS = 5;
const uint8_t RELEASE_SCANS  = 5;

enum LockState {
  STATE_LOCKED = 0,
  STATE_UNLOCKED = 1,
  STATE_SAVE_PASSWORD = 2,
  STATE_LOCKING = 3
};

static LockState lockState = STATE_LOCKED;

static char enteredPassword[5] = {0, 0, 0, 0, 0};
static uint8_t enteredLen = 0;

static uint8_t unlockHashCount = 0;

static const unsigned long LOCK_DELAY_MS = 1000;
static uint32_t lockStartTime = 0;

static void spamStatus(const char *msg) {
  Serial.println(msg);
  Serial.println(msg);
  Serial.println(msg);
}

static void clearEntered() {
  for (uint8_t i = 0; i < 5; i++) enteredPassword[i] = 0;
  enteredLen = 0;
}

static bool match(const char* s);

static bool passwordMatches() {
  if (pwLen != 4) return false;
  enteredPassword[4] = 0;
  return match(enteredPassword);
}

static void setAllColumnsHiZ() {
  for (uint8_t i = 0; i < 3; i++) {
    pinMode(COL_PINS[i], INPUT);
    digitalWrite(COL_PINS[i], LOW);
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
  return -1;
}

static char scanKeyRaw() {
  for (uint8_t col = 0; col < 3; col++) {
    setAllColumnsHiZ();
    pinMode(COL_PINS[col], OUTPUT);
    digitalWrite(COL_PINS[col], LOW);
    delayMicroseconds(80);
    int adc = readAnalogAveraged(4);
    int row = adcToRow(adc);
    if (row >= 0) {
      return KEYMAP[row][col];
    }
  }
  return 0;
}

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

static const uint16_t base = 0;
static const uint8_t  M0 = 'A';
static const uint8_t  M1 = 'B';
static const uint8_t  maxLength = 8;

static uint8_t pw[maxLength];
static uint8_t pwLen = 0;

static uint8_t eeRead(uint16_t a) {
  while (EECR & (1 << EEPE)) { }
  EEAR = a;
  EECR |= (1 << EERE);
  return EEDR;
}

static void eeWrite(uint16_t a, uint8_t v) {
  while (EECR & (1 << EEPE)) { }
  uint8_t s = SREG;
  cli();
  EEAR = a;
  EEDR = v;
  EECR |= (1 << EEMPE);
  EECR |= (1 << EEPE);
  SREG = s;
}

static void savePw(const uint8_t* p, uint8_t n) {
  if (n > maxLength) n = maxLength;
  eeWrite(base + 0, M0);
  eeWrite(base + 1, M1);
  eeWrite(base + 2, n);
  for (uint8_t i = 0; i < n; i++) eeWrite(base + 3 + i, p[i]);
}

static bool loadPw() {
  if (eeRead(base + 0) != M0)
    return false;
  if (eeRead(base + 1) != M1)
    return false;

  uint8_t n = eeRead(base + 2);
  if (n == 0 || n > maxLength)
    return false;

  for (uint8_t i = 0; i < n; i++)
    pw[i] = eeRead(base + 3 + i);
  pwLen = n;
  return true;
}

static bool match(const char* s) {
  uint8_t n = (uint8_t)strlen(s);
  if (n != pwLen) return false;
  for (uint8_t i = 0; i < n; i++) {
    if ((uint8_t)s[i] != pw[i]) return false;
  }
  return true;
}

static const uint16_t PERIOD = 20000;
static const uint16_t RESET = 1500;
static const uint16_t LOCK = 1500;
static const uint16_t UNLOCK = 2470;

static inline void setServoPulse(uint16_t us) {
  uint16_t ticks = us * 2;
  noInterrupts();
  OCR1A = ticks;
  interrupts();
}

static void setupTimer1() {
  pinMode(9, OUTPUT);
  TCCR1A = 0;
  TCCR1B = 0;
  TCCR1A |= (1 << COM1A1);
  TCCR1A |= (1 << WGM11);
  TCCR1B |= (1 << WGM13) | (1 << WGM12);
  TCCR1B |= (1 << CS11);
  ICR1 = PERIOD * 2;
  setServoPulse(RESET);
}

void setup() {
  Serial.begin(115200);

  setAllColumnsHiZ();
  pinMode(ROW_ANALOG_PIN, INPUT);

  if (loadPw())
    Serial.println("Loaded password from EEPROM.");
  else
    Serial.println("No password found in EEPROM.");

  Serial.println("Commands: S ____  or  T ____");

  setupTimer1();
  Serial.println("L is to lock and U is to unlock, and R is to reset");

  Serial.println("Keypad ready. Enter 4 digits then press #. Press * to lock.");
  spamStatus("LOCKED");
}

void loop() {
  if (lockState == STATE_LOCKING) {
    if ((unsigned long)(millis() - lockStartTime) >= LOCK_DELAY_MS) {
      lockState = STATE_LOCKED;
      spamStatus("LOCKED");
    }
    return;
  }

  char key = getKeyEvent();
  if (key != 0) {
    Serial.print("Key pressed: ");
    Serial.println(key);

    if (lockState == STATE_SAVE_PASSWORD) {
      if (key == '*') {
        lockState = STATE_UNLOCKED;
        clearEntered();
        unlockHashCount = 0;
        Serial.println("Canceled.");
        return;
      }
      if (key >= '0' && key <= '9') {
        if (enteredLen < 4) {
          enteredPassword[enteredLen] = key;
          enteredLen++;
        }
        return;
      }
      if (key == '#') {
        if (enteredLen == 4) {
          for (uint8_t i = 0; i < 4; i++) pw[i] = (uint8_t)enteredPassword[i];
          pwLen = 4;
          savePw(pw, pwLen);
          Serial.println("Password saved.");
          lockState = STATE_UNLOCKED;
          clearEntered();
          unlockHashCount = 0;
        }
        return;
      }
      return;
    }

    if (key == '*') {
      lockState = STATE_LOCKING;
      clearEntered();
      unlockHashCount = 0;
      setServoPulse(LOCK);
      lockStartTime = millis();
      Serial.println("Locking...");
      return;
    }

    if (lockState == STATE_UNLOCKED) {
      if (key == '#') {
        unlockHashCount++;
        if (unlockHashCount >= 5) {
          lockState = STATE_SAVE_PASSWORD;
          unlockHashCount = 0;
          clearEntered();
          Serial.println("Enter new 4-digit password, then #");
        }
      } else {
        unlockHashCount = 0;
      }
      return;
    }

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
        unlockHashCount = 0;
        spamStatus("UNLOCKED");
        setServoPulse(UNLOCK);
      } else {
        clearEntered();
        Serial.println("WRONG PASSWORD");
      }
      return;
    }
  }

  if (Serial.available()) {
    char c = (char)Serial.read();
    if (c == 'S' || c == 'T') {
      char line[32];
      line[0] = c;
      size_t n = Serial.readBytesUntil('\n', line + 1, sizeof(line) - 2);
      line[n + 1] = 0;
      if (n && line[n] == '\r')
        line[n] = 0;
      if (c == 'S' && line[1] == ' ') {
        const char* p = line + 2;
        uint8_t L = (uint8_t)strlen(p);
        if (L == 0 || L > maxLength) {
          Serial.println("Incorrect length.");
          return;
        }
        for (uint8_t i = 0; i < L; i++)
          pw[i] = (uint8_t)p[i];
        pwLen = L;
        savePw(pw, pwLen);
        Serial.println("Password saved.");
      } else if (c == 'T' && line[1] == ' ') {
        const char* p = line + 2;
        if (pwLen == 0) {
          Serial.println("No password set.");
          return;
        }
        Serial.println(match(p) ? "UNLOCK" : "DENIED");
      }
    } else if (c == 'L') {
      setServoPulse(LOCK);
      lockState = STATE_LOCKING;
      lockStartTime = millis();
      Serial.println("Locking...");
    } else if (c == 'U') {
      setServoPulse(UNLOCK);
    } else if (c == 'R') {
      setServoPulse(RESET);
    }
  }
}
