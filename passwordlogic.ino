#include <Arduino.h>
#include <avr/io.h>
#include <avr/interrupt.h>
#include <string.h>

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

void setup() {
  Serial.begin(9600);

  if (loadPw())
    Serial.println("Loaded password from EEPROM.");
  else
    Serial.println("No password found in EEPROM.");

  Serial.println("Commands: S ____  or  T ____");
}

void loop() {
  if (!Serial.available()) return;

  char line[32];
  size_t n = Serial.readBytesUntil('\n', line, sizeof(line) - 1);
  line[n] = 0;
  if (n && line[n - 1] == '\r')
    line[n - 1] = 0;

  if (line[0] == 'S' && line[1] == ' ') {
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
  }
  else if (line[0] == 'T' && line[1] == ' ') {
    const char* p = line + 2;

    if (pwLen == 0) {
      Serial.println("No password set.");
      return;
    }

    Serial.println(match(p) ? "UNLOCK" : "DENIED");
  }
}
