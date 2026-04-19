
 /*
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

  Milestone 4a:
    Low-battery / weak-supply monitor on the 5 V rail
    Passive buzzer on D5 for battery alerts

  Milestone 4b:
    LED user interface
      D6 -> red LED
      D7 -> green LED
      D8 -> yellow LED
*/

#include <Arduino.h>
#include <avr/io.h>
#include <avr/interrupt.h>
#include <string.h>

const uint8_t COL_PINS[3] = {2, 3, 4};
const uint8_t ROW_ANALOG_PIN = A0;
const uint8_t SERVO_SENSE_PIN = A1;
const uint8_t BUZZER_PIN      = 5;

const uint8_t redPin = 6;
const uint8_t greenPin = 7;
const uint8_t yellowPin = 8;

static const uint16_t BUZZER_HZ = 2000;

static const uint16_t BUZZ_WARN_ON_MS  = 80;
static const uint16_t BUZZ_WARN_GAP_MS = 120;
static const uint8_t  BUZZ_WARN_COUNT  = 5;

static const uint16_t BUZZ_CRIT_ON_MS  = 45;
static const uint16_t BUZZ_CRIT_GAP_MS = 55;

static const uint16_t RAIL_WARN_MV = 4700;
static const uint16_t RAIL_CRIT_MV = 4400;

static const unsigned long RAIL_CHECK_INTERVAL_MS = 60000UL;
static const unsigned long RAIL_ALERT_REPEAT_MS   = 300000UL;
static const uint8_t       RAIL_CONSEC_BELOW_WARN = 2;

static uint32_t lastRailCheckMs = 0;
static uint32_t lastRailAlertMs = 0;
static uint8_t railBelowWarnStreak = 0;
static uint8_t railLevel = 0;

static bool buzzerWarnBurstPending = false;

enum BuzzerMode {
  BUZZ_IDLE = 0,
  BUZZ_WARN_FIVE = 1,
  BUZZ_CRIT_FAST = 2
};

static BuzzerMode buzzerMode = BUZZ_IDLE;
static uint32_t buzzerNextMs = 0;
static uint8_t buzzerBeepDone = 0;
static bool buzzerToneOn = false;

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
static const uint8_t M0 = 'A';
static const uint8_t M1 = 'B';
static const uint8_t maxLength = 8;

static uint8_t pw[maxLength];
static uint8_t pwLen = 0;

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

static const unsigned long IDLE_SLEEP_MS = 15000;

static uint32_t motionStartTime = 0;
static uint32_t blockHighStartTime = 0;
static uint32_t lastActivityTime = 0;

volatile bool wokeFromKeypad = false;
volatile bool wokeFromWDT = false;

static bool sleepMessagePrinted = false;

static LedEvent ledEvent = LED_EVENT_NONE;
static uint32_t ledEventStart = 0;
static bool ledsSleeping = false;

static bool match(const char* s);

static void spamStatus(const char *msg) {
  Serial.println(msg);
}

static void markActivity() {
  lastActivityTime = millis();
  sleepMessagePrinted = false;
}

static void clearEntered() {
  for (uint8_t i = 0; i < 5; i++) {
    enteredPassword[i] = 0;
  }
  enteredLen = 0;
}

static bool passwordMatches() {
  if (pwLen != 4) {
    return false;
  }

  enteredPassword[4] = 0;
  return match(enteredPassword);
}

static void setLeds(bool redOn, bool greenOn, bool yellowOn) {
  digitalWrite(redPin, redOn ? HIGH : LOW);
  digitalWrite(greenPin, greenOn ? HIGH : LOW);
  digitalWrite(yellowPin, yellowOn ? HIGH : LOW);
}

static void initLeds() {
  pinMode(redPin, OUTPUT);
  pinMode(greenPin, OUTPUT);
  pinMode(yellowPin, OUTPUT);
  setLeds(false, false, false);
}

static void startLedEvent(uint8_t eventValue) {
  ledEvent = (LedEvent)eventValue;
  ledEventStart = millis();
}

static void enterSavePasswordMode(uint8_t returnState) {
  saveReturnState = (LockState)returnState;
  lockState = STATE_SAVE_PASSWORD;
  unlockHashCount = 0;
  lockedHashCount = 0;
  clearEntered();
  Serial.println("SAVE MODE: enter new 4-digit password, then #");
}

static void runLeds() {
  uint32_t now = millis();

  if (ledsSleeping) {
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

  if (lockState == STATE_UNLOCKED || lockState == STATE_UNLOCKING) {
    setLeds(false, true, false);
    return;
  }

  setLeds(true, false, false);
}

static void buzzerPlayTone() {
  tone(BUZZER_PIN, BUZZER_HZ);
}

static void buzzerStopTone() {
  noTone(BUZZER_PIN);
  digitalWrite(BUZZER_PIN, LOW);
}

static void buzzerQueueWarnFiveBeeps() {
  buzzerWarnBurstPending = true;
}

static void buzzerInit() {
  pinMode(BUZZER_PIN, OUTPUT);
  digitalWrite(BUZZER_PIN, LOW);
  buzzerStopTone();
}

static void buzzerBeepOnce() {
  tone(BUZZER_PIN, BUZZER_HZ);
  delay(120);
  buzzerStopTone();
}

static void serviceBuzzer() {
  uint32_t now = millis();

  if (railLevel == 0) {
    buzzerMode = BUZZ_IDLE;
    buzzerWarnBurstPending = false;
    buzzerBeepDone = 0;
    buzzerToneOn = false;
    buzzerStopTone();
    return;
  }

  if (railLevel >= 2) {
    buzzerWarnBurstPending = false;

    if (buzzerMode != BUZZ_CRIT_FAST) {
      buzzerMode = BUZZ_CRIT_FAST;
      buzzerToneOn = false;
      buzzerNextMs = now;
    }

    if ((long)(now - buzzerNextMs) >= 0) {
      if (!buzzerToneOn) {
        buzzerPlayTone();
        buzzerToneOn = true;
        buzzerNextMs = now + BUZZ_CRIT_ON_MS;
      } else {
        buzzerStopTone();
        buzzerToneOn = false;
        buzzerNextMs = now + BUZZ_CRIT_GAP_MS;
      }
    }
    return;
  }

  if (railLevel == 1) {
    if (buzzerMode == BUZZ_CRIT_FAST) {
      buzzerMode = BUZZ_IDLE;
      buzzerToneOn = false;
      buzzerStopTone();
    }

    if (buzzerWarnBurstPending && buzzerMode == BUZZ_IDLE) {
      buzzerWarnBurstPending = false;
      buzzerMode = BUZZ_WARN_FIVE;
      buzzerBeepDone = 0;
      buzzerToneOn = false;
      buzzerNextMs = now;
    }

    if (buzzerMode != BUZZ_WARN_FIVE) {
      return;
    }

    if (buzzerBeepDone >= BUZZ_WARN_COUNT && !buzzerToneOn) {
      buzzerMode = BUZZ_IDLE;
      return;
    }

    if ((long)(now - buzzerNextMs) >= 0) {
      if (!buzzerToneOn) {
        buzzerPlayTone();
        buzzerToneOn = true;
        buzzerNextMs = now + BUZZ_WARN_ON_MS;
      } else {
        buzzerStopTone();
        buzzerToneOn = false;
        buzzerBeepDone++;
        buzzerNextMs = now + BUZZ_WARN_GAP_MS;
      }
    }
  }
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

  while (ADCSRA & _BV(ADSC)) {
  }

  uint8_t low = ADCL;
  uint8_t high = ADCH;
  uint32_t adc = ((uint32_t)high << 8) | low;

  if (adc == 0) {
    return 5000;
  }

  return (uint16_t)(1125300UL / adc);
}

static uint16_t readFiveVRailMilliVoltsAveraged() {
  uint32_t sum = 0;

  for (uint8_t i = 0; i < 4; i++) {
    sum += readAvccMilliVolts();
    delayMicroseconds(80);
  }

  return (uint16_t)(sum / 4);
}

static void printRailMilliVolts(uint16_t rail_mv) {
  Serial.print("5 V rail (AVcc est.) ~");
  Serial.print(rail_mv / 1000);
  Serial.print('.');
  Serial.print((rail_mv % 1000) / 100);
  Serial.println(" V");
}

static void maybeCheckBattery() {
  unsigned long now = millis();

  if ((unsigned long)(now - lastRailCheckMs) < RAIL_CHECK_INTERVAL_MS) {
    return;
  }

  lastRailCheckMs = now;

  uint16_t rail = readFiveVRailMilliVoltsAveraged();

  if (rail >= RAIL_WARN_MV) {
    railBelowWarnStreak = 0;

    if (railLevel != 0) {
      Serial.println("Supply OK (5 V rail above warning threshold).");
      railLevel = 0;
    }
    return;
  }

  if (railBelowWarnStreak < 255) {
    railBelowWarnStreak++;
  }

  if (railBelowWarnStreak < RAIL_CONSEC_BELOW_WARN) {
    return;
  }

  uint8_t newLevel = 1;
  if (rail < RAIL_CRIT_MV) {
    newLevel = 2;
  }

  bool escalate = newLevel > railLevel;
  railLevel = newLevel;

  if (!escalate && (unsigned long)(now - lastRailAlertMs) < RAIL_ALERT_REPEAT_MS) {
    return;
  }

  lastRailAlertMs = now;

  Serial.print("ALERT: ");
  if (railLevel >= 2) {
    Serial.print("POWER CRITICAL - ");
    printRailMilliVolts(rail);
    Serial.println("Battery/source too weak; replace before lockout.");
  } else {
    Serial.print("POWER LOW - ");
    printRailMilliVolts(rail);
    Serial.println("Replace battery or recharge soon.");
    buzzerQueueWarnFiveBeeps();
  }
}

static void batteryStatusOnDemand() {
  uint16_t rail = readFiveVRailMilliVoltsAveraged();
  printRailMilliVolts(rail);

  if (rail < RAIL_CRIT_MV) {
    Serial.println("(below critical threshold)");
  } else if (rail < RAIL_WARN_MV) {
    Serial.println("(below warning threshold)");
  } else {
    Serial.println("(nominal 5 V rail - OK)");
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
      if (releaseCount < 255) {
        releaseCount++;
      }

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
    if (stableCount < 255) {
      stableCount++;
    }
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
  while (EECR & (1 << EEPE)) {
  }

  EEAR = a;
  EECR |= (1 << EERE);
  return EEDR;
}

static void eeWrite(uint16_t a, uint8_t v) {
  while (EECR & (1 << EEPE)) {
  }

  uint8_t s = SREG;
  cli();

  EEAR = a;
  EEDR = v;
  EECR |= (1 << EEMPE);
  EECR |= (1 << EEPE);

  SREG = s;
}

static void savePw(const uint8_t* p, uint8_t n) {
  if (n > maxLength) {
    n = maxLength;
  }

  eeWrite(base + 0, M0);
  eeWrite(base + 1, M1);
  eeWrite(base + 2, n);

  for (uint8_t i = 0; i < n; i++) {
    eeWrite(base + 3 + i, p[i]);
  }
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

  if (n != pwLen) {
    return false;
  }

  for (uint8_t i = 0; i < n; i++) {
    if ((uint8_t)s[i] != pw[i]) {
      return false;
    }
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

static void startServoMotion(uint8_t prevState, uint8_t nextState, uint8_t motionState, uint16_t pulse) {
  motionPrevState = (LockState)prevState;
  motionNextState = (LockState)nextState;
  motionStartTime = millis();
  blockHighStartTime = 0;
  lockState = (LockState)motionState;
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

  startLedEvent(LED_EVENT_BLOCKED);
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
  PCIFR |= (1 << PCIF1);
  PCICR |= (1 << PCIE1);
  PCMSK1 |= (1 << PCINT8);
}

static void disableWakeOnA0() {
  PCMSK1 &= ~(1 << PCINT8);
  PCICR &= ~(1 << PCIE1);
}

static void enableWatchdogWake() {
  MCUSR &= ~(1 << WDRF);

  cli();
  WDTCSR = (1 << WDCE) | (1 << WDE);
  WDTCSR = (1 << WDIE) | (1 << WDP1);
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
  SMCR |= (1 << SM1);
  SMCR |= (1 << SE);
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

  ledsSleeping = true;
  setLeds(false, false, false);

  buzzerStopTone();
  buzzerMode = BUZZ_IDLE;
  buzzerToneOn = false;

  ADCSRA &= ~(1 << ADEN);

  cli();
  enterPowerDownSleepRaw();

  disableWakeOnA0();
  disableWatchdogWake();

  ADCSRA |= (1 << ADEN);

  setAllColumnsHiZ();
  delay(20);

  ledsSleeping = false;

  char raw = scanKeyRaw();
  if (wokeFromKeypad || raw != 0) {
    markActivity();
    Serial.println("Woke from sleep.");
    startLedEvent(LED_EVENT_WAKE);
  }
}

void setup() {
  Serial.begin(115200);

  setAllColumnsHiZ();
  pinMode(ROW_ANALOG_PIN, INPUT);
  pinMode(SERVO_SENSE_PIN, INPUT);

  buzzerInit();
  initLeds();

  if (loadPw()) {
    Serial.println("Loaded password from EEPROM.");
  } else {
    Serial.println("No password found in EEPROM.");
  }

  Serial.println("Commands:");
  Serial.println("  S <code> : save password");
  Serial.println("  T <code> : test password");
  Serial.println("  L        : lock");
  Serial.println("  U        : unlock");
  Serial.println("  R        : servo reset pulse");
  Serial.println("  B        : print 5V rail check");
  Serial.println("  P        : beep buzzer once");
  Serial.println("  Keypad   : ##### <code> # saves password, <code> # tests password, * locks");

  setupTimer1();
  markActivity();
  runLeds();
}

void loop() {
  serviceServoMotion();

  maybeCheckBattery();
  serviceBuzzer();
  runLeds();

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
          startLedEvent(LED_EVENT_SAVED);
        } else {
          Serial.println("SAVE MODE: enter 4 digits, then #");
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
          enterSavePasswordMode(STATE_UNLOCKED);
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
        if (lockedHashCount < 255) {
          lockedHashCount++;
        }

        if (lockedHashCount >= 5) {
          enterSavePasswordMode(STATE_LOCKED);
        }
        return;
      }

      if (enteredLen != 4) {
        // Recover from partial/ghost numeric entry (e.g., wake noise on keypad):
        // clear partial code and treat this '#' as part of the "#####"
        // save-password trigger sequence.
        clearEntered();
        if (lockedHashCount < 255) {
          lockedHashCount++;
        }
        if (lockedHashCount >= 5) {
          enterSavePasswordMode(STATE_LOCKED);
        }
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
        startLedEvent(LED_EVENT_WRONG);
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

      if (n && line[n] == '\r') {
        line[n] = 0;
      }

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
        startLedEvent(LED_EVENT_SAVED);
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
    else if (c == 'P' || c == 'p') {
      buzzerBeepOnce();
      Serial.println("Buzzer test beep.");
    }
  }
}
