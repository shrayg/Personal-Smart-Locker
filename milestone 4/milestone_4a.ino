/*
  Milestone 4 (milestone_4a.ino) — cloned from milestone_3_part_c.ino (Milestone 3c).

  Wiring summary:
    Columns: C1->D2, C2->D3, C3->D4
    A0 node:
      - 10k from A0 to 5V
      - Row1 -> 1.0k -> A0
      - Row2 -> 3.3k -> A0
      - Row3 -> 8.2k -> A0
      - Row4 -> 22k  -> A0

  Milestone 3a:
    Servo current sense -> A1

  Milestone 3c.b:
    Sleep after inactivity
    Wake on keypad press using A0 pin-change interrupt + watchdog check

  Milestone 4a — battery monitor (low average current):
    Sense raw battery BEFORE the 5V regulator (9 V pack / external Vin), not VCC.
    Divider: BAT+ ---[ Rtop 1 MΩ ]--- A2 ---[ Rbottom 330 kΩ ]--- GND
      Quiescent current from a 9 V nominal pack: ~9 V / 1.33 MΩ ≈ 6.8 µA.
    Low-battery idea: as cells discharge, Vin to the LDO falls. Thresholds are in
    millivolts at the pack (tune BAT_WARN_MV / BAT_CRIT_MV for your chemistry).
    Software reads A2 only once per BAT_CHECK_INTERVAL_MS (not continuously), and
    uses the internal 1.1 V bandgap to infer actual AVcc so ADC scaling stays
    reasonable as the rail moves slightly (excellent-aspect: self-calibrated reading).
    Serial: type B for an instant one-shot reading (still brief ADC use).
*/

#include <Arduino.h>
#include <avr/io.h>
#include <avr/interrupt.h>
#include <string.h>

const uint8_t COL_PINS[3] = {2, 3, 4};
const uint8_t ROW_ANALOG_PIN = A0;
const uint8_t SERVO_SENSE_PIN = A1;
const uint8_t BAT_ADC_PIN     = A2;

static const uint32_t BAT_RTOP_OHM = 1000000UL;
static const uint32_t BAT_RBOT_OHM = 330000UL;

static const uint16_t BAT_WARN_MV = 7200;
static const uint16_t BAT_CRIT_MV = 6600;

static const unsigned long BAT_CHECK_INTERVAL_MS = 60000UL;
static const unsigned long BAT_ALERT_REPEAT_MS   = 300000UL;
static const uint8_t     BAT_CONSEC_BELOW_WARN   = 2;

static uint32_t lastBatCheckMs = 0;
static uint32_t lastBatAlertMs = 0;
static uint8_t  batBelowWarnStreak = 0;
static uint8_t  batLevel = 0;

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

static const uint16_t BLOCK_ADC_THRESHOLD = 70;
static const uint16_t MOVE_GRACE_MS       = 250;
static const uint16_t BLOCK_CONFIRM_MS    = 80;
static const uint16_t MOVE_TIMEOUT_MS     = 700;

// Change this for demo if needed
static const unsigned long IDLE_SLEEP_MS  = 15000;

static uint32_t motionStartTime = 0;
static uint32_t blockHighStartTime = 0;
static uint32_t lastActivityTime = 0;

volatile bool wokeFromKeypad = false;
volatile bool wokeFromWDT = false;

static bool sleepMessagePrinted = false;

static void spamStatus(const char *msg) {
  Serial.println(msg);
}

static void markActivity() {
  lastActivityTime = millis();
  sleepMessagePrinted = false;
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

static void setAllColumnsLowForWake() {
  for (uint8_t i = 0; i < 3; i++) {
    pinMode(COL_PINS[i], OUTPUT);
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

static uint16_t readAvccMilliVolts() {
  ADMUX = (uint8_t)(_BV(REFS0) | _BV(MUX3) | _BV(MUX2) | _BV(MUX1));
  delayMicroseconds(200);
  ADCSRA |= _BV(ADSC);
  while (ADCSRA & _BV(ADSC)) { }
  uint8_t low  = ADCL;
  uint8_t high = ADCH;
  uint32_t adc = ((uint32_t)high << 8) | low;
  if (adc == 0) {
    return 5000;
  }
  return (uint16_t)(1125300UL / adc);
}

static uint32_t readBatteryPackMilliVolts() {
  uint32_t vcc = readAvccMilliVolts();
  uint32_t sum = 0;
  for (uint8_t i = 0; i < 4; i++) {
    sum += (uint32_t)analogRead(BAT_ADC_PIN);
    delayMicroseconds(120);
  }
  uint32_t adc = sum / 4;
  if (adc < 8) {
    return 99999UL;
  }
  uint32_t vdiv_mv = (adc * vcc) / 1023UL;
  uint32_t rsum = BAT_RTOP_OHM + BAT_RBOT_OHM;
  return (vdiv_mv * rsum) / BAT_RBOT_OHM;
}

static void printBatteryReading(uint32_t vbat_mv) {
  Serial.print("Battery ~");
  Serial.print(vbat_mv / 1000);
  Serial.print('.');
  Serial.print((vbat_mv % 1000) / 100);
  Serial.println(" V (pack, pre-regulator estimate)");
}

static void maybeCheckBattery() {
  unsigned long now = millis();
  if ((unsigned long)(now - lastBatCheckMs) < BAT_CHECK_INTERVAL_MS) {
    return;
  }
  lastBatCheckMs = now;

  uint32_t vbat = readBatteryPackMilliVolts();

  if (vbat >= BAT_WARN_MV) {
    batBelowWarnStreak = 0;
    if (batLevel != 0) {
      Serial.println("Battery OK (above warning threshold).");
      batLevel = 0;
    }
    return;
  }

  if (batBelowWarnStreak < 255) {
    batBelowWarnStreak++;
  }
  if (batBelowWarnStreak < BAT_CONSEC_BELOW_WARN) {
    return;
  }

  uint8_t newLevel = (vbat < BAT_CRIT_MV) ? 2u : 1u;
  bool escalate = (newLevel > batLevel);
  batLevel = newLevel;

  if (!escalate && (unsigned long)(now - lastBatAlertMs) < BAT_ALERT_REPEAT_MS) {
    return;
  }
  lastBatAlertMs = now;

  Serial.print("ALERT: ");
  if (batLevel >= 2) {
    Serial.print("BATTERY CRITICAL — ");
    printBatteryReading(vbat);
    Serial.println("Replace before lockout.");
  } else {
    Serial.print("BATTERY LOW — ");
    printBatteryReading(vbat);
    Serial.println("Replace soon.");
  }
}

static void batteryStatusOnDemand() {
  uint32_t vcc = readAvccMilliVolts();
  uint32_t sum = 0;
  for (uint8_t i = 0; i < 4; i++) {
    sum += (uint32_t)analogRead(BAT_ADC_PIN);
    delayMicroseconds(120);
  }
  uint32_t adc = sum / 4;
  if (adc < 8) {
    Serial.println("Battery sense: no signal on A2 (check 1M/330k divider from pack+).");
    return;
  }
  uint32_t vdiv_mv = (adc * vcc) / 1023UL;
  uint32_t rsum = BAT_RTOP_OHM + BAT_RBOT_OHM;
  uint32_t vbat = (vdiv_mv * rsum) / BAT_RBOT_OHM;
  printBatteryReading(vbat);
  if (vbat < BAT_CRIT_MV) {
    Serial.println("(below critical threshold)");
  } else if (vbat < BAT_WARN_MV) {
    Serial.println("(below warning threshold)");
  } else {
    Serial.println("(above warning threshold)");
  }
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

  TCCR1A |= (1 << COM1A1);
  TCCR1A |= (1 << WGM11);
  TCCR1B |= (1 << WGM13) | (1 << WGM12);
  TCCR1B |= (1 << CS11);

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
  markActivity();
}

static void finishServoMotionSuccess() {
  lockState = motionNextState;

  if (lockState == STATE_LOCKED) {
    spamStatus("LOCKED");
  } else if (lockState == STATE_UNLOCKED) {
    spamStatus("UNLOCKED");
  }

  markActivity();
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
  markActivity();
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

ISR(PCINT1_vect) {
  wokeFromKeypad = true;
}

ISR(WDT_vect) {
  wokeFromWDT = true;
}

static void enableWakeOnA0() {
  PCIFR  |= (1 << PCIF1);
  PCICR  |= (1 << PCIE1);
  PCMSK1 |= (1 << PCINT8);
}

static void disableWakeOnA0() {
  PCMSK1 &= ~(1 << PCINT8);
  PCICR  &= ~(1 << PCIE1);
}

static void enableWatchdogWake() {
  MCUSR &= ~(1 << WDRF);

  cli();
  WDTCSR = (1 << WDCE) | (1 << WDE);
  WDTCSR = (1 << WDIE) | (1 << WDP1);   // ~64 ms interrupt only
  sei();
}

static void disableWatchdogWake() {
  MCUSR &= ~(1 << WDRF);

  cli();
  WDTCSR = (1 << WDCE) | (1 << WDE);
  WDTCSR = 0;
  sei();
}

static inline void enterPowerDownSleepRaw() {
  SMCR = 0;
  SMCR |= (1 << SM1);   // Power-down mode
  SMCR |= (1 << SE);    // Sleep enable
  sei();
  asm volatile("sleep" ::: "memory");
  SMCR &= ~(1 << SE);
}

static void enterSleepIfIdle() {
  if ((unsigned long)(millis() - lastActivityTime) < IDLE_SLEEP_MS) {
    return;
  }

  if (lockState == STATE_LOCKING || lockState == STATE_UNLOCKING) {
    return;
  }

  wokeFromKeypad = false;
  wokeFromWDT = false;

  setAllColumnsLowForWake();
  pinMode(ROW_ANALOG_PIN, INPUT);
  digitalWrite(ROW_ANALOG_PIN, LOW);

  enableWakeOnA0();
  enableWatchdogWake();

  if (!sleepMessagePrinted) {
    Serial.println("Entering sleep mode...");
    Serial.flush();
    delay(10);
    sleepMessagePrinted = true;
  }

  ADCSRA &= ~(1 << ADEN);

  cli();
  enterPowerDownSleepRaw();

  disableWakeOnA0();
  disableWatchdogWake();

  ADCSRA |= (1 << ADEN);

  setAllColumnsHiZ();
  delay(20);

  char raw = scanKeyRaw();
  if (wokeFromKeypad || raw != 0) {
    markActivity();
    Serial.println("Woke from sleep.");
  }
}

void setup() {
  Serial.begin(115200);

  setAllColumnsHiZ();
  pinMode(ROW_ANALOG_PIN, INPUT);
  pinMode(SERVO_SENSE_PIN, INPUT);
  pinMode(BAT_ADC_PIN, INPUT);

  if (loadPw())
    Serial.println("Loaded password from EEPROM.");
  else
    Serial.println("No password found in EEPROM.");

  Serial.println("Manual commands: S <code> to save password, T <code> to test password, L to lock, U to unlock, R to reset, B battery");
  Serial.println("User commands: ##### <code> # to save password, <code> # to test password, * to lock");

  setupTimer1();
  markActivity();
}

void loop() {
  serviceServoMotion();

  maybeCheckBattery();

  if (lockState == STATE_LOCKING || lockState == STATE_UNLOCKING) {
    return;
  }

  enterSleepIfIdle();

  char key = getKeyEvent();
  if (key != 0) {
    markActivity();
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
    markActivity();

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
    else if (c == 'B' || c == 'b') {
      batteryStatusOnDemand();
    }
  }
}
