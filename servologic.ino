//all pulse widths are in us
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
  ICR1 = PERIOD * 2;      // period is 20 ms
  setServoPulse(RESET);
}

void setup() {
  Serial.begin(9600);
  setupTimer1();
  Serial.println("L is to lock and U is to unlock, and R is to reset");
}

void loop() {
  if (!Serial.available()) return;
  char c = (char)Serial.read();
  if (c == 'L') {
    setServoPulse(LOCK);
  } 
  else if (c == 'U') {
    setServoPulse(UNLOCK);
  } 
  else if (c == 'R') {
    setServoPulse(RESET);
  }
}
