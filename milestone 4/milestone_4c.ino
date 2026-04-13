
 

/*
  Milestone 4c (milestone_4c.ino) — Milestone 4b + secure EEPROM password storage.

  Security (assignment part c):
    Passwords are not stored in plaintext. A per-device random salt (16 bytes) and
    SHA-256(salt || password) (32 bytes) are stored in EEPROM. Verification
    recomputes the hash and compares in constant time. SHA-256 is implemented
    here (no external crypto libraries). Legacy plaintext records (magic AB)
    are migrated once to the new format on boot.

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

  Milestone 4c:
    Salted SHA-256 password hash in EEPROM (no external libraries)
*/

#include <Arduino.h>
#include <avr/io.h>
#include <avr/interrupt.h>
#include <stdint.h>
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

static bool verifyPassword(const char* s);

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
  if (!hasStoredPassword || enteredLen != 4) {
    return false;
  }

  enteredPassword[4] = 0;
  return verifyPassword(enteredPassword);
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

// -------------------- SHA-256 (no external libraries) --------------------

typedef struct {
  uint8_t data[64];
  uint32_t datalen;
  uint64_t bitlen;
  uint32_t state[8];
} Sha256Ctx;

#define SHA_ROTR(x, n) (((x) >> (n)) | ((x) << (32u - (n))))
#define SHA_CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define SHA_MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHA_EP0(x) (SHA_ROTR((x), 2) ^ SHA_ROTR((x), 13) ^ SHA_ROTR((x), 22))
#define SHA_EP1(x) (SHA_ROTR((x), 6) ^ SHA_ROTR((x), 11) ^ SHA_ROTR((x), 25))
#define SHA_SIG0(x) (SHA_ROTR((x), 7) ^ SHA_ROTR((x), 18) ^ ((x) >> 3))
#define SHA_SIG1(x) (SHA_ROTR((x), 17) ^ SHA_ROTR((x), 19) ^ ((x) >> 10))

static const uint32_t sha256_k[64] = {
    0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL, 0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
    0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL, 0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
    0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL, 0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
    0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL, 0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
    0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL, 0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
    0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL, 0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
    0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL, 0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
    0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL, 0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
};

static void sha256_transform(Sha256Ctx* ctx, const uint8_t* data) {
  uint32_t a, b, c, d, e, f, g, h;
  uint32_t m[64];
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
    uint32_t t1 = h + SHA_EP1(e) + SHA_CH(e, f, g) + sha256_k[r] + m[r];
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
    while (i < 56) {
      ctx->data[i++] = 0;
    }
  } else {
    ctx->data[i++] = 0x80;
    while (i < 64) {
      ctx->data[i++] = 0;
    }
    sha256_transform(ctx, ctx->data);
    memset(ctx->data, 0, 56);
  }

  ctx->bitlen += (uint64_t)ctx->datalen * 8ULL;
  /* Length field is 64-bit big-endian (FIPS 180-4): MSB at data[56], LSB at data[63]. */
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
  Sha256Ctx ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, data, len);
  sha256_final(&ctx, hash32);
}

// ---------- EEPROM: salted hash only (SHA-256(salt || password)) ----------

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

static void secureWipe(uint8_t* p, size_t n) {
  for (size_t i = 0; i < n; i++) {
    p[i] = 0;
  }
}

static bool constTimeEqual(const uint8_t* a, const uint8_t* b, uint8_t n) {
  uint8_t d = 0;
  for (uint8_t i = 0; i < n; i++) {
    d |= (uint8_t)(a[i] ^ b[i]);
  }
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

static void hashPasswordBytes(const uint8_t* salt16, const uint8_t* pw, uint8_t pwLen, uint8_t out32[32]) {
  uint8_t buf[24];
  memcpy(buf, salt16, 16);
  memcpy(buf + 16, pw, pwLen);
  sha256_buffer(buf, (size_t)(16 + pwLen), out32);
  secureWipe(buf, sizeof(buf));
}

static void writeSecureRecord(const uint8_t* salt16, const uint8_t* hash32, uint8_t pwLenMeta) {
  eeWrite(EE_BASE + 0, SEC_MAGIC0);
  eeWrite(EE_BASE + 1, SEC_MAGIC1);
  eeWrite(EE_BASE + 2, SEC_VERSION);
  eeWrite(EE_BASE + 3, pwLenMeta);
  for (uint8_t i = 0; i < 16; i++) {
    eeWrite(EE_BASE + 4 + i, salt16[i]);
  }
  for (uint8_t i = 0; i < 32; i++) {
    eeWrite(EE_BASE + 20 + i, hash32[i]);
  }
}

static void savePasswordHash(const uint8_t* p, uint8_t n) {
  if (n > maxLength) {
    n = maxLength;
  }

  generateSalt16(storedSalt);
  uint8_t h[32];
  hashPasswordBytes(storedSalt, p, n, h);
  memcpy(storedHash, h, 32);
  writeSecureRecord(storedSalt, h, n);
  hasStoredPassword = true;
  secureWipe(h, sizeof(h));
}

static bool migrateLegacyPlaintext() {
  if (eeRead(EE_BASE + 0) != LEGACY_M0 || eeRead(EE_BASE + 1) != LEGACY_M1) {
    return false;
  }

  uint8_t n = eeRead(EE_BASE + 2);
  if (n == 0 || n > maxLength) {
    return false;
  }

  uint8_t buf[8];
  for (uint8_t i = 0; i < n; i++) {
    buf[i] = eeRead(EE_BASE + 3 + i);
  }

  Serial.println(F("Migrating EEPROM from legacy plaintext to salted SHA-256."));
  savePasswordHash(buf, n);
  secureWipe(buf, sizeof(buf));
  return true;
}

static bool loadStoredPassword() {
  if (eeRead(EE_BASE + 0) == SEC_MAGIC0 && eeRead(EE_BASE + 1) == SEC_MAGIC1 && eeRead(EE_BASE + 2) == SEC_VERSION) {
    for (uint8_t i = 0; i < 16; i++) {
      storedSalt[i] = eeRead(EE_BASE + 4 + i);
    }
    for (uint8_t i = 0; i < 32; i++) {
      storedHash[i] = eeRead(EE_BASE + 20 + i);
    }
    hasStoredPassword = true;
    return true;
  }

  if (migrateLegacyPlaintext()) {
    return true;
  }

  hasStoredPassword = false;
  return false;
}

static bool verifyPassword(const char* s) {
  if (!hasStoredPassword) {
    return false;
  }

  uint8_t n = (uint8_t)strlen(s);
  if (n == 0 || n > maxLength) {
    return false;
  }

  uint8_t candidate[32];
  hashPasswordBytes(storedSalt, (const uint8_t*)s, n, candidate);
  bool ok = constTimeEqual(candidate, storedHash, 32);
  secureWipe(candidate, sizeof(candidate));
  return ok;
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

  if (loadStoredPassword()) {
    Serial.println(F("Loaded password hash from EEPROM (salted SHA-256)."));
  } else {
    Serial.println(F("No password stored in EEPROM."));
  }

  Serial.println("Commands:");
  Serial.println("  S <code> : save password (stored as salted hash)");
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
          uint8_t tmp[8];
          for (uint8_t i = 0; i < 4; i++) {
            tmp[i] = (uint8_t)enteredPassword[i];
          }
          savePasswordHash(tmp, 4);
          secureWipe(tmp, sizeof(tmp));
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

        uint8_t tmp[8];
        for (uint8_t i = 0; i < L; i++) {
          tmp[i] = (uint8_t)p[i];
        }

        savePasswordHash(tmp, L);
        secureWipe(tmp, sizeof(tmp));
        Serial.println("Password saved.");
        startLedEvent(LED_EVENT_SAVED);
      }
      else if (c == 'T' && line[1] == ' ') {
        const char* p = line + 2;

        if (!hasStoredPassword) {
          Serial.println("No password set.");
          return;
        }

        Serial.println(verifyPassword(p) ? "UNLOCK" : "DENIED");
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
