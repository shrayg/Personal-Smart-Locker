# Two-level battery indicator (LEDs) — `milestone_4c.ino`

Use the **same three UI LEDs** as Milestone 4b. No extra parts are required for the assignment’s two rail levels beyond what you already use for lock state.

## What each level means (software)

| Rail estimate (AVcc) | `railLevel` | LED | Pattern (low average current) |
|----------------------|-------------|-----|--------------------------------|
| Below ~4.70 V (after debounce) | 1 — warning | **Yellow (D8)** | ON 250 ms, OFF 2.25 s (repeat) |
| Below ~4.40 V | 2 — critical | **Red (D6)** | ON 150 ms, OFF 350 ms (repeat) |
| Above ~4.70 V | 0 — OK | (normal lock UI) | Red/green/yellow as before |

Rail is sampled about **once per 60 s** with short ADC bursts (`readFiveVRailMilliVoltsAveraged`), so checking does not run continuously. LED duty cycles are kept short so alerting does not add much load.

## Wiring (identical to 4b UI LEDs)

Connect **each** LED from the ATmega328P Arduino pin → **current-limit resistor** (220 Ω typical) → LED **anode** → LED **cathode** → **GND** (common ground with the MCU).

| Function | Arduino pin | ATmega328P DIP pin (typ.) | Resistor | LED color |
|----------|-------------|---------------------------|----------|-----------|
| Red (critical battery + locked UI) | D6 | 12 | 220 Ω | Red |
| Green (unlocked UI) | D7 | 13 | 220 Ω | Green |
| Yellow (warning battery + save mode UI) | D8 | 14 | 220 Ω | Yellow / amber |

```
                    +5 V (from your regulated rail)
                     |
   D6 ----[220 R]----|---->|---- GND   red
   D7 ----[220 R]----|---->|---- GND   green
   D8 ----[220 R]----|---->|---- GND   yellow
```

Notes:

- Cathodes to **MCU ground**, not the battery negative, unless they are the same node on your board.
- If an LED is too bright or draws more than you want, increase the resistor (e.g. 330 Ω–470 Ω); patterns already minimize ON time for the battery states.

## Buzzer (D5)

The **passive buzzer on D5** is still supported for the **manual** `P` serial test only. **Battery alerts do not use the buzzer** in `milestone_4c.ino`.
