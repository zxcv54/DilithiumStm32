#include <string.h>
#include <stdint.h>
#include "rng.h"
#include "fips202.h"

static uint8_t drbg_seed[48];
static uint64_t drbg_counter;
static uint8_t drbg_block[32];
static size_t drbg_block_pos = sizeof(drbg_block);
static int drbg_initialized;

static void fill_block(void)
{
    uint8_t input[56];

    memcpy(input, drbg_seed, sizeof(drbg_seed));
    input[48] = (uint8_t)(drbg_counter >> 0);
    input[49] = (uint8_t)(drbg_counter >> 8);
    input[50] = (uint8_t)(drbg_counter >> 16);
    input[51] = (uint8_t)(drbg_counter >> 24);
    input[52] = (uint8_t)(drbg_counter >> 32);
    input[53] = (uint8_t)(drbg_counter >> 40);
    input[54] = (uint8_t)(drbg_counter >> 48);
    input[55] = (uint8_t)(drbg_counter >> 56);

    shake256(drbg_block, sizeof(drbg_block), input, sizeof(input));
    drbg_counter++;
    drbg_block_pos = 0;
}

void
randombytes_init(unsigned char *entropy_input,
                 unsigned char *personalization_string,
                 int security_strength)
{
    (void)security_strength;

    if (entropy_input == NULL) {
        memset(drbg_seed, 0, sizeof(drbg_seed));
    } else {
        memcpy(drbg_seed, entropy_input, sizeof(drbg_seed));
    }

    if (personalization_string != NULL) {
        for (size_t i = 0; i < sizeof(drbg_seed); i++) {
            drbg_seed[i] ^= personalization_string[i];
        }
    }

    drbg_counter = 0;
    drbg_block_pos = sizeof(drbg_block);
    drbg_initialized = 1;
}

void
randombytes(uint8_t *x, size_t xlen)
{
    if (!drbg_initialized) {
        static unsigned char default_entropy[48];
        for (size_t i = 0; i < sizeof(default_entropy); i++) {
            default_entropy[i] = (unsigned char)i;
        }
        randombytes_init(default_entropy, NULL, 256);
    }

    while (xlen > 0) {
        size_t available;
        size_t n;

        if (drbg_block_pos >= sizeof(drbg_block)) {
            fill_block();
        }

        available = sizeof(drbg_block) - drbg_block_pos;
        n = (xlen < available) ? xlen : available;
        memcpy(x, drbg_block + drbg_block_pos, n);
        x += n;
        xlen -= n;
        drbg_block_pos += n;
    }
}
