#ifndef rng_h
#define rng_h

#include <stddef.h>
#include <stdint.h>

void
randombytes_init(unsigned char *entropy_input,
                 unsigned char *personalization_string,
                 int security_strength);

void
randombytes(uint8_t *x, size_t xlen);

#endif /* rng_h */
