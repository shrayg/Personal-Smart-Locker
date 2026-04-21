/*
  4.ino

  Combines:
    - Milestone 4c secure password storage (salted SHA-256 in EEPROM)
    - Milestone 4d power optimization / measurement helpers
    - Hardware servo power switch on physical pin 26 of the ATmega328P TQFP

  Important pin note:
    Physical pin 26 on the ATmega328P TQFP is PC3 / ADC3, which is A3 in Arduino code.
    This sketch therefore uses SERVO_PWR_PIN = A3 for a direct-drive PMOS servo power switch (no NPN transistor).

  Wiring summary:
    Columns: C1->D2, C2->D3, C3->D4
    A0 node:
      - 10k from A0 to 5V
      - Row1 -> 1.0k -> A0
      - Row2 -> 3.3k -> A0
      - Row3 -> 8.2k -> A0
      - Row4 -> 22k  -> A0

    Servo current sense -> A1
    Buzzer             -> D5
    Red LED            -> D6
    Green LED          -> D7
    Yellow LED         -> D8
    Servo PWM          -> D9 / OC1A
    Servo power ctrl   -> A3 / PC3 / physical pin 26
*/

#include <Arduino.h>
#include <avr/io.h>
#include <avr/interrupt.h>
#include <avr/pgmspace.h>
#include <stdint.h>
#include <string.h>

// -------------------- User-tunable settings --------------------
static const unsigned long IDLE_SLEEP_MS = 5000UL;
static const unsigned long UI_HOLD_MS    = 2500UL;
static const unsigned long AWAKE_HOLD_MS = 60000UL;
static const bool USE_WDT_WAKE           = true;

// -------------------- Pins --------------------
const uint8_t COL_PINS[3]      = {2, 3, 4};
const uint8_t ROW_ANALOG_PIN   = A0;
const uint8_t SERVO_SENSE_PIN  = A1;
const uint8_t BUZZER_PIN       = 5;
const uint8_t redPin           = 6;
const uint8_t greenPin         = 7;
const uint8_t yellowPin        = 8;
const uint8_t SERVO_PIN        = 9;
const uint8_t SERVO_PWR_PIN    = A3;   // PC3 / ADC3 / physical pin 26 on TQFP ATmega328P

// -------------------- Battery / buzzer --------------------
static const uint16_t BUZZER_HZ = 2000;
static const uint16_t RAIL_WARN_MV = 4700;
static const uint16_t RAIL_CRIT_MV = 4400;
static const uint16_t BUZZ_WARN_ON_MS  = 80;
static const uint16_t BUZZ_WARN_GAP_MS = 120;
static const uint16_t BUZZ_CRIT_ON_MS  = 45;
static const uint16_t BUZZ_CRIT_GAP_MS = 55;
static const unsigned long RAIL_CHECK_INTERVAL_MS = 300000UL;
static const unsigned long RAIL_ALERT_REPEAT_MS   = 300000UL;
static const uint8_t RAIL_CONSEC_BELOW_WARN       = 2;
static const uint16_t PRE_SLEEP_ALERT_MS          = 3000;

static uint32_t lastRailCheckMs = 0;
static uint32_t lastRailAlertMs = 0;
static uint8_t railBelowWarnStreak = 0;
static uint8_t railLevel = 0;
static uint32_t buzzerNextMs = 0;
static bool buzzerToneOn = false;
static bool preSleepAlertPlayed = false;

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

// -------------------- Password / EEPROM --------------------
static const uint8_t maxLength = 8;
static const uint8_t LEGACY_M0 = 'A';
static const uint8_t LEGACY_M1 = 'B';
static const uint8_t SEC_MAGIC0 = 'S';
static const uint8_t SEC_MAGIC1 = 'H';
static const uint8_t SEC_VERSION = 1;
static const uint16_t EE_BASE = 0;

static uint8_t storedSalt[16];
static uint8_t storedHash[32];
static bool hasStoredPassword = false;

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

// -------------------- SHA-256 context --------------------
typedef struct {
  uint8_t data[64];
  uint32_t datalen;
  uint64_t bitlen;
  uint32_t state[8];
} Sha256Ctx;

static bool verifyPassword(const char* s);
static bool cryptoEepromSectionActive(void);

// -------------------- Utility --------------------
static void spamStatus(const __FlashStringHelper *msg) {
  Serial.println(msg);
}

static void markActivity() {
  uint32_t now = millis();
  lastActivityTime = now;
  uiVisibleUntil = now + UI_HOLD_MS;
  sleepMessagePrinted = false;
  preSleepAlertPlayed = false;
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

static bool passwordMatches() {
  if (!hasStoredPassword || enteredLen != 4) {
    return false;
  }
  enteredPassword[4] = 0;
  return verifyPassword(enteredPassword);
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
  Serial.println(F("SAVE MODE: enter new 4-digit password, then #"));
}

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

  if (railLevel >= 2) {
    setLeds(buzzerToneOn, false, false);
    return;
  }
  if (railLevel == 1) {
    setLeds(false, false, buzzerToneOn);
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

  if (cryptoEepromSectionActive()) {
    buzzerToneOn = false;
    buzzerStopTone();
    return;
  }

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
  Serial.print(F("5 V rail (AVcc est.) ~"));
  Serial.print(rail_mv / 1000);
  Serial.print('.');
  Serial.print((rail_mv % 1000) / 100);
  Serial.println(F(" V"));
}

static void evaluateBatteryRail(bool forceCheck) {
  unsigned long now = millis();
  if (!forceCheck && (unsigned long)(now - lastRailCheckMs) < RAIL_CHECK_INTERVAL_MS) return;
  lastRailCheckMs = now;

  uint16_t rail = readFiveVRailMilliVoltsAveraged();

  if (rail >= RAIL_WARN_MV) {
    railBelowWarnStreak = 0;
    if (railLevel != 0) {
      Serial.println(F("Supply OK (5 V rail above warning threshold)."));
      railLevel = 0;
      buzzerToneOn = false;
      buzzerStopTone();
    }
    preSleepAlertPlayed = false;
    return;
  }

  if (railBelowWarnStreak < 255) railBelowWarnStreak++;
  if (railBelowWarnStreak < RAIL_CONSEC_BELOW_WARN) return;

  uint8_t newLevel = (rail < RAIL_CRIT_MV) ? 2 : 1;
  bool escalate = newLevel > railLevel;
  railLevel = newLevel;

  if (!escalate && (unsigned long)(now - lastRailAlertMs) < RAIL_ALERT_REPEAT_MS) return;
  lastRailAlertMs = now;

  Serial.print(F("ALERT: "));
  if (railLevel >= 2) {
    Serial.print(F("POWER CRITICAL - "));
    printRailMilliVolts(rail);
    Serial.println(F("Battery/source too weak; replace before lockout. (red LED + buzzer)"));
  } else {
    Serial.print(F("POWER LOW - "));
    printRailMilliVolts(rail);
    Serial.println(F("Replace battery or recharge soon. (yellow LED + buzzer)"));
  }
}

static void maybeCheckBattery() {
  evaluateBatteryRail(false);
}

static void runPreSleepRailAlertIfNeeded() {
  /* Right before sleep, force a fresh rail evaluation and play one short
     warning/critical alert burst so low-power state is visible/audible. */
  evaluateBatteryRail(true);
  if (railLevel == 0) return;
  if (preSleepAlertPlayed) return;

  buzzerToneOn = false;
  buzzerNextMs = millis();
  uint32_t until = millis() + PRE_SLEEP_ALERT_MS;
  while ((long)(millis() - until) < 0) {
    serviceBuzzer();
    runLeds();
    delay(5);
  }
  preSleepAlertPlayed = true;
}

static void batteryStatusOnDemand() {
  uint16_t rail = readFiveVRailMilliVoltsAveraged();
  printRailMilliVolts(rail);
  if (rail < RAIL_CRIT_MV) Serial.println(F("(below critical threshold)"));
  else if (rail < RAIL_WARN_MV) Serial.println(F("(below warning threshold)"));
  else Serial.println(F("(nominal 5 V rail - OK)"));
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

// -------------------- SHA-256 --------------------
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

static void sha256_final(Sha256Ctx* ctx, uint8_t* hash) {
  uint32_t i = ctx->datalen;

  if (ctx->datalen < 56) {
    ctx->data[i++] = 0x80;
    while (i < 56) ctx->data[i++] = 0;
  } else {
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

static void sha256_buffer(const uint8_t* data, size_t len, uint8_t* hash32) {
  static Sha256Ctx sha256_ctx_static;
  sha256_init(&sha256_ctx_static);
  sha256_update(&sha256_ctx_static, data, len);
  sha256_final(&sha256_ctx_static, hash32);
}

// -------------------- EEPROM / secure storage --------------------
static uint8_t cryptoEepromHold = 0;

static void beginCryptoEepromSection() {
  if (cryptoEepromHold == 0) {
    buzzerStopTone();
    buzzerToneOn = false;
    setLeds(false, false, false);
  }
  cryptoEepromHold++;
}

static void endCryptoEepromSection() {
  if (cryptoEepromHold > 0) cryptoEepromHold--;
}

static bool cryptoEepromSectionActive() {
  return cryptoEepromHold != 0;
}

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

static void secureWipe(uint8_t* p, size_t n) {
  for (size_t i = 0; i < n; i++) p[i] = 0;
}

static bool constTimeEqual(const uint8_t* a, const uint8_t* b, uint8_t n) {
  uint8_t d = 0;
  for (uint8_t i = 0; i < n; i++) d |= (uint8_t)(a[i] ^ b[i]);
  return d == 0;
}

static void generateSalt16(uint8_t* salt) {
  for (uint8_t i = 0; i < 16; i++) {
    uint32_t v = (uint32_t)analogRead(ROW_ANALOG_PIN) ^ (uint32_t)analogRead(SERVO_SENSE_PIN) ^
                 (uint32_t)micros() ^ ((uint32_t)millis() << 3) ^ ((uint32_t)i * 0x9e3779b1UL);
    salt[i] = (uint8_t)(v ^ (v >> 8) ^ (v >> 16) ^ (v >> 24));
    delayMicroseconds(31U + (uint16_t)(i * 13U));
  }
}

static void hashPasswordBytesCore(const uint8_t* salt16, const uint8_t* pw, uint8_t pwLen, uint8_t out32[32]) {
  uint8_t buf[24];
  memcpy(buf, salt16, 16);
  memcpy(buf + 16, pw, pwLen);
  sha256_buffer(buf, (size_t)(16 + pwLen), out32);
  secureWipe(buf, sizeof(buf));
}

static void hashPasswordBytes(const uint8_t* salt16, const uint8_t* pw, uint8_t pwLen, uint8_t out32[32]) {
  beginCryptoEepromSection();
  hashPasswordBytesCore(salt16, pw, pwLen, out32);
  endCryptoEepromSection();
}

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

static bool migrateLegacyPlaintext() {
  if (eeRead(EE_BASE + 0) != LEGACY_M0 || eeRead(EE_BASE + 1) != LEGACY_M1) return false;

  uint8_t n = eeRead(EE_BASE + 2);
  if (n == 0 || n > maxLength) return false;

  uint8_t buf[8];
  for (uint8_t i = 0; i < n; i++) buf[i] = eeRead(EE_BASE + 3 + i);

  Serial.println(F("Migrating EEPROM from legacy plaintext to salted SHA-256."));
  bool ok = savePasswordHash(buf, n);
  secureWipe(buf, sizeof(buf));

  if (!ok) {
    Serial.println(F("Migrate save failed."));
    return false;
  }
  return true;
}

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

static bool verifyPassword(const char* s) {
  if (!hasStoredPassword) return false;

  uint8_t n = (uint8_t)strlen(s);
  if (n == 0 || n > maxLength) return false;

  uint8_t candidate[32];
  hashPasswordBytes(storedSalt, (const uint8_t*)s, n, candidate);
  bool ok = constTimeEqual(candidate, storedHash, 32);
  secureWipe(candidate, sizeof(candidate));
  return ok;
}

// -------------------- Servo control --------------------
static void servoPowerInit() {
  pinMode(SERVO_PWR_PIN, OUTPUT);
  digitalWrite(SERVO_PWR_PIN, HIGH);  // HIGH = gate tied to source -> PMOS OFF
}

static void servoPowerOn() {
  digitalWrite(SERVO_PWR_PIN, LOW);   // LOW = gate low -> PMOS ON
  delay(SERVO_POWER_SETTLE_MS);
}

static void servoPowerOff() {
  digitalWrite(SERVO_PWR_PIN, HIGH);  // HIGH = PMOS OFF
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
  TCCR1B |= _BV(CS11);
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
    Serial.print(F("Unlock move time: "));
    Serial.print(dt);
    Serial.println(F(" ms"));
  } else if (motionNextState == STATE_LOCKED) {
    lastLockMoveMs = dt;
    Serial.print(F("Lock move time: "));
    Serial.print(dt);
    Serial.println(F(" ms"));
  }
}

static void finishServoMotionSuccess() {
  uint32_t dt = millis() - motionStartTime;
  recordMotionTime(dt);
  lockState = motionNextState;
  servoDetach();
  servoPowerOff();

  if (lockState == STATE_LOCKED) spamStatus(F("LOCKED"));
  else if (lockState == STATE_UNLOCKED) spamStatus(F("UNLOCKED"));

  markActivity();
}

static void finishServoMotionBlocked() {
  uint32_t dt = millis() - motionStartTime;
  recordMotionTime(dt);
  lockState = motionPrevState;
  servoDetach();
  servoPowerOff();

  if (motionPrevState == STATE_UNLOCKED) spamStatus(F("BLOCKED MOTOR -> REVERTED TO UNLOCKED"));
  else spamStatus(F("BLOCKED MOTOR -> REVERTED TO LOCKED"));

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
  WDTCSR = _BV(WDIE) | _BV(WDP1);
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
  SMCR |= _BV(SM1);
  SMCR |= _BV(SE);
  sei();
  asm volatile("sleep" ::: "memory");
  SMCR &= (uint8_t)~_BV(SE);
}

static void enterSleepIfIdle() {
  uint32_t now = millis();

  if ((unsigned long)(now - lastActivityTime) < IDLE_SLEEP_MS) return;
  if ((long)(stayAwakeUntilMs - now) > 0) return;
  if (lockState == STATE_LOCKING || lockState == STATE_UNLOCKING) return;

  runPreSleepRailAlertIfNeeded();

  wokeFromKeypad = false;
  wokeFromWDT = false;

  setAllColumnsLowForWake();
  pinMode(ROW_ANALOG_PIN, INPUT);
  digitalWrite(ROW_ANALOG_PIN, LOW);

  enableWakeOnA0();
  if (USE_WDT_WAKE) enableWatchdogWake();

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
  if (USE_WDT_WAKE) disableWatchdogWake();

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

// -------------------- Measurement helpers --------------------
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

// -------------------- Setup / loop --------------------
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
  } else {
    Serial.println(F("No password found in EEPROM."));
  }

  Serial.println(F("Commands:"));
  Serial.println(F("  S <code> : save password (salted SHA-256)"));
  Serial.println(F("  T <code> : test password"));
  Serial.println(F("  L        : lock"));
  Serial.println(F("  U        : unlock"));
  Serial.println(F("  R        : servo reset pulse"));
  Serial.println(F("  B        : print 5V rail check"));
  Serial.println(F("  P        : beep buzzer once"));
  Serial.println(F("  A        : stay awake for 60 s"));
  Serial.println(F("  X        : run 1 unlock-lock cycle"));
  Serial.println(F("  Z        : run 10 unlock-lock cycles"));
  Serial.println(F("  M        : print last motion times"));
  Serial.println(F("  Keypad   : ##### <code> # saves password, <code> # tests password, * locks"));

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
    Serial.print(F("Key pressed: "));
    Serial.println(key);

    if (lockState == STATE_SAVE_PASSWORD) {
      if (key == '*') {
        lockState = saveReturnState;
        clearEntered();
        unlockHashCount = 0;
        lockedHashCount = 0;
        Serial.println(F("Canceled."));
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
          if (savePasswordHash(tmp, 4)) {
            secureWipe(tmp, sizeof(tmp));
            Serial.println(F("Password saved."));
            lockState = saveReturnState;
            clearEntered();
            unlockHashCount = 0;
            lockedHashCount = 0;
            startLedEvent(LED_EVENT_SAVED);
          } else {
            secureWipe(tmp, sizeof(tmp));
            Serial.println(F("Save failed."));
          }
        } else {
          Serial.println(F("SAVE MODE: enter 4 digits, then #"));
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
        Serial.println(F("Locking..."));
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
        Serial.println(F("Unlocking..."));
      } else {
        clearEntered();
        Serial.println(F("WRONG PASSWORD"));
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
          Serial.println(F("Incorrect length."));
          return;
        }
        uint8_t tmp[8];
        for (uint8_t i = 0; i < L; i++) tmp[i] = (uint8_t)p[i];
        if (savePasswordHash(tmp, L)) {
          secureWipe(tmp, sizeof(tmp));
          Serial.println(F("Password saved."));
          startLedEvent(LED_EVENT_SAVED);
        } else {
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
      batteryStatusOnDemand();
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
