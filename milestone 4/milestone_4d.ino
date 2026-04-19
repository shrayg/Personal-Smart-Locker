/*
  milestone_4d.ino

  Wiring summary:
    Columns: C1->D2, C2->D3, C3->D4
    A0 node:
      - 10k from A0 to 5V
      - Row1 -> 1.0k -> A0
      - Row2 -> 3.3k -> A0
      - Row3 -> 8.2k -> A0
      - Row4 -> 22k  -> A0

    Servo current sense -> A1
    Buzzer -> D5
    Red LED -> D6
    Green LED -> D7
    Yellow LED -> D8
    Servo signal -> D9 / OC1A
    Servo power enable -> D11 / PB3 (physical pin 26 on TQFP ATmega328P)
*/

#include <Arduino.h>
#include <avr/io.h>
#include <avr/interrupt.h>
#include <string.h>

// -------------------- User-tunable settings --------------------
static const unsigned long IDLE_SLEEP_MS = 5000UL;   // baseline was 15000 ms
static const unsigned long UI_HOLD_MS    = 2500UL;   // steady LEDs visible briefly after activity
static const unsigned long AWAKE_HOLD_MS = 60000UL; // measurement helper
static const bool USE_WDT_WAKE = true;               // restored to match your original wake behavior

// -------------------- Pins --------------------
const uint8_t COL_PINS[3] = {2, 3, 4};
const uint8_t ROW_ANALOG_PIN = A0;
const uint8_t SERVO_SENSE_PIN = A1;
const uint8_t BUZZER_PIN      = 5;
const uint8_t redPin          = 6;
const uint8_t greenPin        = 7;
const uint8_t yellowPin       = 8;
const uint8_t SERVO_PIN       = 9;
const uint8_t SERVO_PWR_PIN   = 11;   // PB3, physical pin 26 on TQFP package

// -------------------- Battery / buzzer --------------------
static const uint16_t BUZZER_HZ = 2000;
static const uint16_t RAIL_WARN_MV = 4700;
static const uint16_t RAIL_CRIT_MV = 4400;
static const uint16_t BUZZ_WARN_ON_MS  = 80;
static const uint16_t BUZZ_WARN_GAP_MS = 120;
static const uint16_t BUZZ_CRIT_ON_MS  = 45;
static const uint16_t BUZZ_CRIT_GAP_MS = 55;
static const unsigned long RAIL_CHECK_INTERVAL_MS = 300000UL;  // 5 min
static const unsigned long RAIL_ALERT_REPEAT_MS   = 300000UL;
static const uint8_t RAIL_CONSEC_BELOW_WARN = 2;

static uint32_t lastRailCheckMs = 0;
static uint32_t lastRailAlertMs = 0;
static uint8_t railBelowWarnStreak = 0;
static uint8_t railLevel = 0;
static uint32_t buzzerNextMs = 0;
static bool buzzerToneOn = false;

// -------------------- Keypad --------------------
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

// -------------------- Password (plaintext EEPROM for 4b branch) --------------------
static const uint8_t M0 = 'A';
static const uint8_t M1 = 'B';
static const uint16_t EE_BASE = 0;
static const uint8_t maxLength = 8;

static uint8_t pw[maxLength];
static uint8_t pwLen = 0;

// -------------------- State machine --------------------
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

static char enteredPassword[5] = {0,0,0,0,0};
static uint8_t enteredLen = 0;
static uint8_t unlockHashCount = 0;
static uint8_t lockedHashCount = 0;

// -------------------- Servo timing / motion --------------------
static const uint16_t PERIOD = 20000;
static const uint16_t RESET  = 1500;
static const uint16_t LOCK   = 1500;
static const uint16_t UNLOCK = 2470;

static const uint16_t BLOCK_ADC_THRESHOLD = 70;
static const uint16_t MOVE_GRACE_MS       = 250;
static const uint16_t BLOCK_CONFIRM_MS    = 80;
static const uint16_t MOVE_TIMEOUT_MS     = 700;
static const uint16_t SERVO_POWER_SETTLE_MS = 50;

static uint32_t motionStartTime = 0;
static uint32_t blockHighStartTime = 0;
static bool servoAttached = false;

// Measured motion timing for report math / rough cycle estimates
static uint32_t lastUnlockMoveMs = 0;
static uint32_t lastLockMoveMs   = 0;
static uint32_t lastCycleMs      = 0;

// -------------------- Sleep / UI --------------------
static uint32_t lastActivityTime = 0;
static uint32_t uiVisibleUntil = 0;
static uint32_t stayAwakeUntilMs = 0;
volatile bool wokeFromKeypad = false;
volatile bool wokeFromWDT = false;
static bool sleepMessagePrinted = false;
static LedEvent ledEvent = LED_EVENT_NONE;
static uint32_t ledEventStart = 0;
static bool ledsSleeping = false;

// -------------------- Utility --------------------
static void spamStatus(const char *msg) {
  Serial.println(msg);
}

static void markActivity() {
  uint32_t now = millis();
  lastActivityTime = now;
  uiVisibleUntil = now + UI_HOLD_MS;
  sleepMessagePrinted = false;
}

static void holdAwakeForMs(uint32_t ms) {
  uint32_t now = millis();
  stayAwakeUntilMs = now + ms;
  lastActivityTime = now;
  uiVisibleUntil = now + UI_HOLD_MS;
  sleepMessagePrinted = false;
}


static void clearEntered() {
  for (uint8_t i = 0; i < 5; i++) {
    enteredPassword[i] = 0;
  }
  enteredLen = 0;
}

static bool match(const char* s) {
  uint8_t n = (uint8_t)strlen(s);
  if (n != pwLen) return false;
  for (uint8_t i = 0; i < pwLen; i++) {
    if ((uint8_t)s[i] != pw[i]) return false;
  }
  return true;
}

static bool passwordMatches() {
  if (pwLen != 4 || enteredLen != 4) {
    return false;
  }
  enteredPassword[4] = 0;
  return match(enteredPassword);
}

// -------------------- LEDs --------------------
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

  // Battery alerts override normal steady-state LEDs.
  if (railLevel >= 2) {
    setLeds(buzzerToneOn, false, false);
    return;
  }
  if (railLevel == 1) {
    setLeds(false, false, buzzerToneOn);
    return;
  }

  // Normal state LEDs only stay on briefly after activity.
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

// -------------------- Buzzer / battery --------------------
static void buzzerPlayTone() {
  tone(BUZZER_PIN, BUZZER_HZ);
}

static void buzzerStopTone() {
  noTone(BUZZER_PIN);
  digitalWrite(BUZZER_PIN, LOW);
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
    buzzerToneOn = false;
    buzzerStopTone();
    return;
  }

  if ((long)(now - buzzerNextMs) >= 0) {
    buzzerToneOn = !buzzerToneOn;
    if (railLevel >= 2) {
      buzzerNextMs = now + (buzzerToneOn ? BUZZ_CRIT_ON_MS : BUZZ_CRIT_GAP_MS);
    } else {
      buzzerNextMs = now + (buzzerToneOn ? BUZZ_WARN_ON_MS : BUZZ_WARN_GAP_MS);
    }

    if (buzzerToneOn) buzzerPlayTone();
    else buzzerStopTone();
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
  while (ADCSRA & _BV(ADSC)) {}

  uint8_t low = ADCL;
  uint8_t high = ADCH;
  uint32_t adc = ((uint32_t)high << 8) | low;
  if (adc == 0) return 5000;
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
  if ((unsigned long)(now - lastRailCheckMs) < RAIL_CHECK_INTERVAL_MS) return;
  lastRailCheckMs = now;

  uint16_t rail = readFiveVRailMilliVoltsAveraged();

  if (rail >= RAIL_WARN_MV) {
    railBelowWarnStreak = 0;
    if (railLevel != 0) {
      Serial.println("Supply OK (5 V rail above warning threshold).");
      railLevel = 0;
      buzzerToneOn = false;
      buzzerStopTone();
    }
    return;
  }

  if (railBelowWarnStreak < 255) railBelowWarnStreak++;
  if (railBelowWarnStreak < RAIL_CONSEC_BELOW_WARN) return;

  uint8_t newLevel = (rail < RAIL_CRIT_MV) ? 2 : 1;
  bool escalate = newLevel > railLevel;
  railLevel = newLevel;

  if (!escalate && (unsigned long)(now - lastRailAlertMs) < RAIL_ALERT_REPEAT_MS) return;
  lastRailAlertMs = now;

  Serial.print("ALERT: ");
  if (railLevel >= 2) {
    Serial.print("POWER CRITICAL - ");
    printRailMilliVolts(rail);
    Serial.println("Battery/source too weak; replace before lockout. (red LED + buzzer)");
  } else {
    Serial.print("POWER LOW - ");
    printRailMilliVolts(rail);
    Serial.println("Replace battery or recharge soon. (yellow LED + buzzer)");
  }
}

static void batteryStatusOnDemand() {
  uint16_t rail = readFiveVRailMilliVoltsAveraged();
  printRailMilliVolts(rail);
  if (rail < RAIL_CRIT_MV) Serial.println("(below critical threshold)");
  else if (rail < RAIL_WARN_MV) Serial.println("(below warning threshold)");
  else Serial.println("(nominal 5 V rail - OK)");
}

// -------------------- Keypad scan --------------------
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
    if (row >= 0) return KEYMAP[row][col];
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

// -------------------- EEPROM helpers --------------------
static uint8_t eeRead(uint16_t a) {
  while (EECR & (1 << EEPE)) {}
  EEAR = a;
  EECR |= (1 << EERE);
  return EEDR;
}

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

static bool savePw(const uint8_t* p, uint8_t n) {
  if (n == 0 || n > maxLength) return false;
  eeWrite(EE_BASE + 0, M0);
  eeWrite(EE_BASE + 1, M1);
  eeWrite(EE_BASE + 2, n);
  for (uint8_t i = 0; i < n; i++) {
    eeWrite(EE_BASE + 3 + i, p[i]);
    pw[i] = p[i];
  }
  pwLen = n;
  return true;
}

static bool loadPw() {
  if (eeRead(EE_BASE + 0) != M0 || eeRead(EE_BASE + 1) != M1) {
    pwLen = 0;
    return false;
  }
  uint8_t n = eeRead(EE_BASE + 2);
  if (n == 0 || n > maxLength) {
    pwLen = 0;
    return false;
  }
  for (uint8_t i = 0; i < n; i++) {
    pw[i] = eeRead(EE_BASE + 3 + i);
  }
  pwLen = n;
  return true;
}

// -------------------- Servo control --------------------
static void servoPowerInit() {
  pinMode(SERVO_PWR_PIN, OUTPUT);
  digitalWrite(SERVO_PWR_PIN, LOW);   // LOW = servo power OFF (PMOS gate released high)
}

static void servoPowerOn() {
  digitalWrite(SERVO_PWR_PIN, HIGH);  // HIGH = NPN on -> PMOS gate low -> servo power ON
  delay(SERVO_POWER_SETTLE_MS);
}

static void servoPowerOff() {
  digitalWrite(SERVO_PWR_PIN, LOW);   // LOW = servo power OFF
}

static void servoAttach() {
  if (!servoAttached) {
    TCCR1A |= _BV(COM1A1);
    servoAttached = true;
  }
}

static void servoDetach() {
  TCCR1A &= (uint8_t)~_BV(COM1A1);
  digitalWrite(SERVO_PIN, LOW);
  servoAttached = false;
}

static inline void setServoPulse(uint16_t us) {
  uint16_t ticks = us * 2;
  noInterrupts();
  OCR1A = ticks;
  interrupts();
}

static void setupTimer1() {
  servoPowerInit();
  pinMode(SERVO_PIN, OUTPUT);
  digitalWrite(SERVO_PIN, LOW);

  TCCR1A = 0;
  TCCR1B = 0;
  TCCR1A |= _BV(WGM11);
  TCCR1B |= _BV(WGM13) | _BV(WGM12);
  TCCR1B |= _BV(CS11);  // prescaler 8
  ICR1 = PERIOD * 2;

  servoDetach();
  setServoPulse(RESET);
}

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

static void recordMotionTime(uint32_t dt) {
  if (motionNextState == STATE_UNLOCKED) {
    lastUnlockMoveMs = dt;
    Serial.print("Unlock move time: ");
    Serial.print(dt);
    Serial.println(" ms");
  } else if (motionNextState == STATE_LOCKED) {
    lastLockMoveMs = dt;
    Serial.print("Lock move time: ");
    Serial.print(dt);
    Serial.println(" ms");
  }
}

static void finishServoMotionSuccess() {
  uint32_t dt = millis() - motionStartTime;
  recordMotionTime(dt);
  lockState = motionNextState;
  servoDetach();
  servoPowerOff();

  if (lockState == STATE_LOCKED) spamStatus("LOCKED");
  else if (lockState == STATE_UNLOCKED) spamStatus("UNLOCKED");

  markActivity();
}

static void finishServoMotionBlocked() {
  uint32_t dt = millis() - motionStartTime;
  recordMotionTime(dt);
  lockState = motionPrevState;
  servoDetach();
  servoPowerOff();

  if (motionPrevState == STATE_UNLOCKED) spamStatus("BLOCKED MOTOR -> REVERTED TO UNLOCKED");
  else spamStatus("BLOCKED MOTOR -> REVERTED TO LOCKED");

  startLedEvent(LED_EVENT_BLOCKED);
  clearEntered();
  unlockHashCount = 0;
  lockedHashCount = 0;
  markActivity();
}

static void serviceServoMotion() {
  if (lockState != STATE_LOCKING && lockState != STATE_UNLOCKING) return;

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

// -------------------- Sleep / wake --------------------
ISR(PCINT1_vect) {
  wokeFromKeypad = true;
}

ISR(WDT_vect) {
  wokeFromWDT = true;
}

static void enableWakeOnA0() {
  PCIFR |= _BV(PCIF1);
  PCICR |= _BV(PCIE1);
  PCMSK1 |= _BV(PCINT8);
}

static void disableWakeOnA0() {
  PCMSK1 &= (uint8_t)~_BV(PCINT8);
  PCICR &= (uint8_t)~_BV(PCIE1);
}

static void enableWatchdogWake() {
  MCUSR &= (uint8_t)~_BV(WDRF);
  cli();
  WDTCSR = _BV(WDCE) | _BV(WDE);
  WDTCSR = _BV(WDIE) | _BV(WDP1);  // ~64 ms
  sei();
}

static void disableWatchdogWake() {
  MCUSR &= (uint8_t)~_BV(WDRF);
  cli();
  WDTCSR = _BV(WDCE) | _BV(WDE);
  WDTCSR = 0;
  sei();
}

static inline void enterPowerDownSleepRaw() {
  SMCR = 0;
  SMCR |= _BV(SM1);   // power-down sleep
  SMCR |= _BV(SE);
  sei();
  asm volatile("sleep" ::: "memory");
  SMCR &= (uint8_t)~_BV(SE);
}

static void enterSleepIfIdle() {
  uint32_t now = millis();

  if ((unsigned long)(now - lastActivityTime) < IDLE_SLEEP_MS) return;
  if (lockState == STATE_LOCKING || lockState == STATE_UNLOCKING) return;

  wokeFromKeypad = false;
  wokeFromWDT = false;

  setAllColumnsLowForWake();
  pinMode(ROW_ANALOG_PIN, INPUT);
  digitalWrite(ROW_ANALOG_PIN, LOW);

  enableWakeOnA0();
  if (USE_WDT_WAKE) enableWatchdogWake();

  if (!sleepMessagePrinted) {
    Serial.println("Entering sleep mode...");
    Serial.flush();
    delay(10);
    sleepMessagePrinted = true;
  }

  ledsSleeping = true;
  setLeds(false, false, false);
  buzzerStopTone();
  servoDetach();
  servoPowerOff();

  // Match your original 3c/4b sleep behavior more closely.
  ADCSRA &= (uint8_t)~_BV(ADEN);

  cli();
  enterPowerDownSleepRaw();

  ADCSRA |= _BV(ADEN);

  disableWakeOnA0();
  if (USE_WDT_WAKE) disableWatchdogWake();

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

// -------------------- Measurement helpers --------------------
static void runOneCycleTest() {
  Serial.println("Starting 1-cycle test...");
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
  Serial.print("1-cycle total time: ");
  Serial.print(lastCycleMs);
  Serial.println(" ms");
}

static void runRepeatedCycleTest(uint8_t n) {
  Serial.print("Starting ");
  Serial.print(n);
  Serial.println(" cycles...");
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
  Serial.print("Total time for ");
  Serial.print(n);
  Serial.print(" cycles: ");
  Serial.print(lastCycleMs);
  Serial.println(" ms");
}

static void printTimingSummary() {
  Serial.print("Last unlock move: ");
  Serial.print(lastUnlockMoveMs);
  Serial.println(" ms");
  Serial.print("Last lock move: ");
  Serial.print(lastLockMoveMs);
  Serial.println(" ms");
  Serial.print("Last total cycle: ");
  Serial.print(lastCycleMs);
  Serial.println(" ms");
}

// -------------------- Setup / loop --------------------
void setup() {
  Serial.begin(115200);

  // Lower-power housekeeping.
  ACSR |= _BV(ACD);                          // disable analog comparator
  PRR   |= _BV(PRSPI) | _BV(PRTWI);        // keep only clearly unused modules off

  setAllColumnsHiZ();
  pinMode(ROW_ANALOG_PIN, INPUT);
  pinMode(SERVO_SENSE_PIN, INPUT);

  buzzerInit();
  initLeds();
  setupTimer1();

  // Brief startup pulse, then remove servo power so it cannot twitch constantly at idle.
  servoPowerOn();
  servoAttach();
  setServoPulse(RESET);
  delay(250);
  servoDetach();
  servoPowerOff();

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
  Serial.println("  X        : run 1 unlock-lock cycle");
  Serial.println("  Z        : run 10 unlock-lock cycles");
  Serial.println("  M        : print last motion times");
  Serial.println("  Keypad   : ##### <code> # saves password, <code> # tests password, * locks");

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
          uint8_t tmp[8];
          for (uint8_t i = 0; i < 4; i++) tmp[i] = (uint8_t)enteredPassword[i];
          if (savePw(tmp, 4)) {
            Serial.println("Password saved.");
            lockState = saveReturnState;
            clearEntered();
            unlockHashCount = 0;
            lockedHashCount = 0;
            startLedEvent(LED_EVENT_SAVED);
          } else {
            Serial.println("Save failed.");
          }
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
        if (unlockHashCount >= 5) enterSavePasswordMode(STATE_UNLOCKED);
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
      if (n && line[n] == '\r') line[n] = 0;

      if (c == 'S' && line[1] == ' ') {
        const char* p = line + 2;
        uint8_t L = (uint8_t)strlen(p);
        if (L == 0 || L > maxLength) {
          Serial.println("Incorrect length.");
          return;
        }
        uint8_t tmp[8];
        for (uint8_t i = 0; i < L; i++) tmp[i] = (uint8_t)p[i];
        if (savePw(tmp, L)) {
          Serial.println("Password saved.");
          startLedEvent(LED_EVENT_SAVED);
        } else {
          Serial.println("Password save failed.");
        }
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
      servoPowerOn();
      servoAttach();
      setServoPulse(RESET);
      delay(250);
      servoDetach();
      servoPowerOff();
      Serial.println("Servo reset pulse sent.");
    }
    else if (c == 'B' || c == 'b') {
      batteryStatusOnDemand();
    }
    else if (c == 'P' || c == 'p') {
      buzzerBeepOnce();
      Serial.println("Buzzer test beep.");
    }
    else if (c == 'A' || c == 'a') {
      holdAwakeForMs(AWAKE_HOLD_MS);
      Serial.println("Awake-hold started for 60 s.");
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
