#ifndef SHA256_TYPES_H
#define SHA256_TYPES_H

#include <stdint.h>

/* Used by SHA-256 helpers; kept in a header so Arduino's generated prototypes compile. */
typedef struct {
  uint8_t data[64];
  uint32_t datalen;
  uint64_t bitlen;
  uint32_t state[8];
} Sha256Ctx;

#endif
