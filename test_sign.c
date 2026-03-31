#include <stdint.h>
#include <stddef.h>

#include "api.h"
#include "randombytes.h"
#include "rng.h"
#include "test_sign.h"

#define TEST_ITERATIONS 5000
#define MSG_LEN 32

int run_random_keygen_sign_5000(test_result_t *result)
{
    static uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    static uint8_t sk[CRYPTO_SECRETKEYBYTES];
    static uint8_t msg[MSG_LEN];
    static uint8_t sm[CRYPTO_BYTES + MSG_LEN];

    unsigned long long smlen = 0;
    uint32_t i;
    int ret;
    uint8_t entropy_input[48];

    if (result == NULL) {
        return -1;
    }

    result->keygen_success = 0;
    result->keygen_fail = 0;
    result->sign_success = 0;
    result->sign_fail = 0;

    for (i = 0; i < sizeof(entropy_input); i++) {
        entropy_input[i] = (uint8_t)i;
    }
    randombytes_init(entropy_input, NULL, 256);

    for (i = 0; i < TEST_ITERATIONS; i++) {
        randombytes(msg, MSG_LEN);

        ret = crypto_sign_keypair(pk, sk);
        if (ret != 0) {
            result->keygen_fail++;
            continue;
        }
        result->keygen_success++;

        ret = crypto_sign(sm, &smlen, msg, MSG_LEN, sk);
        if (ret != 0) {
            result->sign_fail++;
            continue;
        }
        result->sign_success++;
    }

    return 0;
}
