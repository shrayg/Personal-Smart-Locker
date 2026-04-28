/*
  Wiring summary:
    Columns: C1->D2, C2->D3, C3->D4
    A0 node:
      - 10k from A0 to 5V
      - Row1 -> 1.0k -> A0
      - Row2 -> 3.3k -> A0
      - Row3 -> 8.2k -> A0
      - Row4 -> 22k  -> A0

  Milestone 3a addition:
    Servo current sense -> A1
    (Assumes you added hardware to measure servo current / blockage)

  Notes:
    - This code keeps Milestone 2 behavior.
    - It adds blocked-servo detection during LOCKING and UNLOCKING.
    - If blockage is detected, the system reverts to the previous state.
    - You MUST tune BLOCK_ADC_THRESHOLD on real hardware.
*/

#include <Arduino.h>
#include <avr/io.h>
#include <avr/interrupt.h>
#include <string.h>

const uint8_t COL_PINS[3] = {2, 3, 4};
const uint8_t ROW_ANALOG_PIN = A0;
const uint8_t SERVO_SENSE_PIN = A1;

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

static const uint16_t base = 0;
static const uint8_t  M0 = 'A';
static const uint8_t  M1 = 'B';
static const uint8_t  maxLength = 8;

static uint8_t pw[maxLength];
static uint8_t pwLen = 0;

enum LockState {
  STATE_LOCKED = 0,
  STATE_UNLOCKED = 1,
  STATE_SAVE_PASSWORD = 2,
  STATE_LOCKING = 3,
  STATE_UNLOCKING = 4
};

static LockState lockState = STATE_LOCKED;
static LockState saveReturnState = STATE_UNLOCKED;

static LockState motionPrevState = STATE_LOCKED;
static LockState motionNextState = STATE_LOCKED;

static char enteredPassword[5] = {0, 0, 0, 0, 0};
static uint8_t enteredLen = 0;

static uint8_t unlockHashCount = 0;
static uint8_t lockedHashCount = 0;


static const uint16_t PERIOD = 20000;
static const uint16_t RESET  = 1500;
static const uint16_t LOCK   = 1500;
static const uint16_t UNLOCK = 2470;

static const uint16_t BLOCK_ADC_THRESHOLD = 20;  
static const uint16_t MOVE_GRACE_MS       = 250;  
static const uint16_t BLOCK_CONFIRM_MS    = 80;  
static const uint16_t MOVE_TIMEOUT_MS     = 700;  

static uint32_t motionStartTime = 0;
static uint32_t blockHighStartTime = 0;

static void spamStatus(const char *msg) {
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

static int readServoSenseAveraged(uint8_t samples) {
  long sum = 0;
  for (uint8_t i = 0; i < samples; i++) {
    sum += analogRead(SERVO_SENSE_PIN);
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
  if (eeRead(base + 0) != M0) return false;
  if (eeRead(base + 1) != M1) return false;

  uint8_t n = eeRead(base + 2);
  if (n == 0 || n > maxLength) return false;

  for (uint8_t i = 0; i < n; i++) {
    pw[i] = eeRead(base + 3 + i);
  }
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

  // Fast PWM, TOP = ICR1, non-inverting on OC1A
  TCCR1A |= (1 << COM1A1);
  TCCR1A |= (1 << WGM11);
  TCCR1B |= (1 << WGM13) | (1 << WGM12);

  // prescaler = 8
  TCCR1B |= (1 << CS11);

  // 16 MHz / 8 = 2 MHz => 0.5 us per tick
  ICR1 = PERIOD * 2;
  setServoPulse(RESET);
}

static void startServoMotion(LockState prevState, LockState nextState, LockState motionState, uint16_t pulse) {
  motionPrevState = prevState;
  motionNextState = nextState;
  motionStartTime = millis();
  blockHighStartTime = 0;
  lockState = motionState;
  setServoPulse(pulse);
}

static void finishServoMotionSuccess() {
  lockState = motionNextState;

  if (lockState == STATE_LOCKED) {
    spamStatus("LOCKED");
  } else if (lockState == STATE_UNLOCKED) {
    spamStatus("UNLOCKED");
  }
}

static void finishServoMotionBlocked() {
  lockState = motionPrevState;

  if (motionPrevState == STATE_UNLOCKED) {
    setServoPulse(UNLOCK);
    spamStatus("BLOCKED MOTOR -> REVERTED TO UNLOCKED");
  } else {
    setServoPulse(LOCK);
    spamStatus("BLOCKED MOTOR -> REVERTED TO LOCKED");
  }

  clearEntered();
  unlockHashCount = 0;
  lockedHashCount = 0;
}

static void serviceServoMotion() {
  if (lockState != STATE_LOCKING && lockState != STATE_UNLOCKING) {
    return;
  }

  uint32_t now = millis();
  int sense = readServoSenseAveraged(8);


  if ((uint32_t)(now - motionStartTime) >= MOVE_GRACE_MS) {
    if (sense >= BLOCK_ADC_THRESHOLD) {
      if (blockHighStartTime == 0) {
        blockHighStartTime = now;
      } else if ((uint32_t)(now - blockHighStartTime) >= BLOCK_CONFIRM_MS) {
        finishServoMotionBlocked();
        return;
      }
    } else {
      blockHighStartTime = 0;
    }
  }

  if ((uint32_t)(now - motionStartTime) >= MOVE_TIMEOUT_MS) {
    finishServoMotionSuccess();
  }
}

void setup() {
  Serial.begin(115200);

  setAllColumnsHiZ();
  pinMode(ROW_ANALOG_PIN, INPUT);
  pinMode(SERVO_SENSE_PIN, INPUT);

  if (loadPw())
    Serial.println("Loaded password from EEPROM.");
  else
    Serial.println("No password found in EEPROM.");

  Serial.println("Manual commands: S <code> to save password, T <code> to test password, L to lock, U to unlock, R to reset");
  Serial.println("User commands: ##### <code> # to save password, <code> # to test password, * to lock");

  setupTimer1();
}

void loop() {
  serviceServoMotion();

  if (lockState == STATE_LOCKING || lockState == STATE_UNLOCKING) {
    return;
  }

  char key = getKeyEvent();
  if (key != 0) {
    Serial.print("Key pressed: ");
    Serial.println(key);

    if (lockState == STATE_SAVE_PASSWORD) {
      if (key == '*') {
        lockState = saveReturnState;
        clearEntered();
        unlockHashCount = 0;
        lockedHashCount = 0;
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
          for (uint8_t i = 0; i < 4; i++) {
            pw[i] = (uint8_t)enteredPassword[i];
          }
          pwLen = 4;
          savePw(pw, pwLen);
          Serial.println("Password saved.");
          lockState = saveReturnState;
          clearEntered();
          unlockHashCount = 0;
          lockedHashCount = 0;
        }
        return;
      }

      return;
    }

    if (key == '*') {
      clearEntered();
      unlockHashCount = 0;
      lockedHashCount = 0;

      if (lockState == STATE_UNLOCKED) {
        startServoMotion(STATE_UNLOCKED, STATE_LOCKED, STATE_LOCKING, LOCK);
        Serial.println("Locking...");
      }
      return;
    }

    // In unlocked state, ##### enters save-password mode
    if (lockState == STATE_UNLOCKED) {
      lockedHashCount = 0;

      if (key == '#') {
        unlockHashCount++;
        if (unlockHashCount >= 5) {
          saveReturnState = STATE_UNLOCKED;
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
      lockedHashCount = 0;
      if (enteredLen < 4) {
        enteredPassword[enteredLen] = key;
        enteredLen++;
      }
      return;
    }

    if (key == '#') {
      if (enteredLen == 0) {
        if (lockedHashCount < 255) lockedHashCount++;
        if (lockedHashCount >= 5) {
          saveReturnState = STATE_LOCKED;
          lockState = STATE_SAVE_PASSWORD;
          unlockHashCount = 0;
          lockedHashCount = 0;
          clearEntered();
          Serial.println("Enter new 4-digit password, then #");
        }
        return;
      }

      if (enteredLen != 4) {
        lockedHashCount = 0;
        return;
      }

      lockedHashCount = 0;

      if (passwordMatches()) {
        clearEntered();
        unlockHashCount = 0;

        startServoMotion(STATE_LOCKED, STATE_UNLOCKED, STATE_UNLOCKING, UNLOCK);
        Serial.println("Unlocking...");
      } else {
        clearEntered();
        Serial.println("WRONG PASSWORD");
      }
      return;
    }

    lockedHashCount = 0;
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

        for (uint8_t i = 0; i < L; i++) {
          pw[i] = (uint8_t)p[i];
        }
        pwLen = L;
        savePw(pw, pwLen);
        Serial.println("Password saved.");
      }
      else if (c == 'T' && line[1] == ' ') {
        const char* p = line + 2;

        if (pwLen == 0) {
          Serial.println("No password set.");
          return;
        }

        Serial.println(match(p) ? "UNLOCK" : "DENIED");
      }
    }
    else if (c == 'L') {
      if (lockState == STATE_UNLOCKED) {
        startServoMotion(STATE_UNLOCKED, STATE_LOCKED, STATE_LOCKING, LOCK);
        Serial.println("Locking...");
      }
    }
    else if (c == 'U') {
      if (lockState == STATE_LOCKED) {
        startServoMotion(STATE_LOCKED, STATE_UNLOCKED, STATE_UNLOCKING, UNLOCK);
        Serial.println("Unlocking...");
      }
    }
    else if (c == 'R') {
      setServoPulse(RESET);
      Serial.println("Servo reset pulse sent.");
    }
  }
}